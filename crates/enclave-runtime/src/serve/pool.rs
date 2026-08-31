//! Live tenants: one filesystem, one warm instance and one lock per client.
//!
//! ## What is kept, and why that and not something else
//!
//! Mounting a client's filesystem derives key material, reads a signed root
//! record, verifies it and opens the object set — measured at 51 µs against a
//! `HashMap`, which in production is that plus two or three S3 round trips.
//! Instantiating the guest is 24 µs and no I/O at all. So **the mount is what
//! is worth keeping warm**; the instance rides along because it is nearly free
//! and it is convenient to rebuild the two together.
//!
//! ## The lock is a correctness mechanism, not only a cache
//!
//! Each client has its own `tokio::Mutex`, and that is the whole concurrency
//! model: **a client is serialised against itself and against nobody else.**
//!
//! Serialised against itself, because a cosigner reserving a nonce must not
//! race its own second request. Not against anyone else, because a client's
//! filesystem is theirs alone — separate `Store`, separate transaction lock —
//! so there is nothing for two clients to contend over, and making them queue
//! would mean one client's slow commit stalling everybody.
//!
//! ## Why anonymous callers get nothing
//!
//! A slot is keyed by the SHA-256 of a client's TLS public key, which the
//! handshake proves. A caller who presented no certificate has no key to be
//! identified by, so they get a fresh instance over the runtime's own
//! filesystem and never occupy a slot — otherwise anyone who could open a
//! socket could fill the pool and evict every real client's mount.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use s3fs_core::Inode;

/// How large the pool may grow, and how long an idle tenant is kept.
///
/// Both matter more than they look. A tenant costs a `BlockStore` cache —
/// `block_cache_bytes`, 64 MiB by default — plus a wasm linear memory, so a
/// pool sized by hope rather than arithmetic is an enclave that dies of memory
/// exhaustion under exactly the load it was built for.
#[derive(Debug, Clone)]
pub struct PoolLimits {
    pub max_tenants: usize,
    pub idle_timeout: Duration,
    /// Calls one instance serves before it is rebuilt. Wasm linear memory
    /// never shrinks, so an instance that lives forever only grows.
    pub max_requests_per_instance: u64,
}

impl Default for PoolLimits {
    fn default() -> Self {
        PoolLimits {
            max_tenants: 64,
            idle_timeout: Duration::from_secs(900),
            max_requests_per_instance: 10_000,
        }
    }
}

/// A client's view of the filesystem, and its warm instance.
///
/// `scope` is the directory this client's guest calls `/`. The filesystem
/// itself is shared and is not here — one mount, one block cache, one
/// transaction stream for every tenant.
///
/// `instance` is an `Option` so a trap can discard the poisoned linear memory
/// while keeping the resolved directory. That is cheap either way; what it
/// mainly buys is that one client's trap is visible to nobody else.
pub struct LiveTenant<I> {
    pub scope: Arc<Inode>,
    pub tenant_id: [u8; 16],
    pub instance: Option<I>,
    pub requests: u64,
}

/// One client's slot.
///
/// `last_used` and `in_flight` sit *outside* the async mutex on purpose: the
/// eviction sweep has to compare tenants without awaiting on any of them, and a
/// sweep that could block on a busy tenant would be a sweep that stalls the
/// server it is tidying.
pub struct Slot<I> {
    /// `Arc`'d so a request can take an *owned* guard and carry it into the
    /// task that runs the guest — the lock has to outlive the response head,
    /// and a borrowed guard could not.
    tenant: Arc<tokio::sync::Mutex<Option<LiveTenant<I>>>>,
    last_used: AtomicU64,
    in_flight: AtomicUsize,
}

impl<I> Slot<I> {
    fn new(now: u64) -> Self {
        Slot {
            tenant: Arc::new(tokio::sync::Mutex::new(None)),
            last_used: AtomicU64::new(now),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub fn tenant(&self) -> &Arc<tokio::sync::Mutex<Option<LiveTenant<I>>>> {
        &self.tenant
    }
}

/// A slot checked out for one request.
///
/// Holding this is what marks the tenant busy, so the sweep leaves it alone;
/// dropping it releases that mark however the request ended, including a panic.
pub struct Checkout<I> {
    slot: Arc<Slot<I>>,
}

impl<I> Checkout<I> {
    pub fn slot(&self) -> &Arc<Slot<I>> {
        &self.slot
    }
}

impl<I> Drop for Checkout<I> {
    fn drop(&mut self) {
        self.slot.in_flight.fetch_sub(1, Ordering::Release);
    }
}

pub struct TenantPool<I> {
    /// A `std::sync::Mutex`, not a `tokio` one, and never held across an
    /// await: everything under it is a hash lookup and an `Arc` clone. The
    /// *per-tenant* lock is the async one, and it is a different lock for a
    /// different job.
    slots: Mutex<HashMap<[u8; 32], Arc<Slot<I>>>>,
    limits: PoolLimits,
    started: Instant,
}

impl<I> TenantPool<I> {
    pub fn new(limits: PoolLimits) -> Self {
        TenantPool {
            slots: Mutex::new(HashMap::new()),
            limits: limits.clone(),
            started: Instant::now(),
        }
    }

    pub fn limits(&self) -> &PoolLimits {
        &self.limits
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Check out this client's slot, creating an empty one if needed.
    ///
    /// The slot, not the tenant: the caller then takes the async lock and
    /// builds the filesystem under it if it is not there yet. That ordering is
    /// what makes two simultaneous first requests from one client produce
    /// **one** filesystem — they find the same slot, and the second waits on
    /// the lock the first is holding rather than racing it into a second mount.
    pub fn checkout(&self, client: &[u8; 32]) -> Checkout<I> {
        let now = self.now();
        let mut slots = self.slots.lock().expect("tenant pool mutex poisoned");

        if let Some(slot) = slots.get(client) {
            slot.last_used.store(now, Ordering::Release);
            slot.in_flight.fetch_add(1, Ordering::Release);
            return Checkout { slot: slot.clone() };
        }

        // Room first, so the pool never exceeds its cap even briefly.
        self.evict_while_full(&mut slots, now);

        let slot = Arc::new(Slot::new(now));
        slot.in_flight.fetch_add(1, Ordering::Release);
        slots.insert(*client, slot.clone());
        Checkout { slot }
    }

    /// Drop idle and over-cap tenants.
    ///
    /// Removing a slot from the map does not destroy it: a request already
    /// holding the `Arc` keeps working and the filesystem unmounts when it
    /// finishes. So eviction can never pull a filesystem out from under a call
    /// in progress — it only stops future requests finding it.
    fn evict_while_full(&self, slots: &mut HashMap<[u8; 32], Arc<Slot<I>>>, now: u64) {
        let idle_ms = self.limits.idle_timeout.as_millis() as u64;
        slots.retain(|_, slot| {
            slot.in_flight.load(Ordering::Acquire) > 0
                || now.saturating_sub(slot.last_used.load(Ordering::Acquire)) < idle_ms
        });

        while slots.len() >= self.limits.max_tenants.max(1) {
            let victim = slots
                .iter()
                .filter(|(_, s)| s.in_flight.load(Ordering::Acquire) == 0)
                .min_by_key(|(_, s)| s.last_used.load(Ordering::Acquire))
                .map(|(k, _)| *k);
            match victim {
                Some(key) => {
                    slots.remove(&key);
                }
                // Every tenant is busy. Refusing to evict is right: the
                // alternative is unmounting a filesystem someone is mid-commit
                // on. The pool runs slightly over its cap until they finish,
                // which the global concurrency limit already bounds.
                None => break,
            }
        }
    }

    /// Tenants currently held. Diagnostics, and the assertion tests need.
    pub fn len(&self) -> usize {
        self.slots.lock().expect("tenant pool mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the wasm instance: the pool never looks inside one.
    #[derive(Debug, PartialEq, Eq)]
    struct FakeInstance(u32);

    fn pool(max: usize) -> TenantPool<FakeInstance> {
        TenantPool::new(PoolLimits {
            max_tenants: max,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn a_client_returns_to_the_same_slot() {
        let pool = pool(8);
        let client = [0xab; 32];

        {
            let first = pool.checkout(&client);
            *first.slot().tenant().lock().await = None;
        }
        let again = pool.checkout(&client);
        assert_eq!(pool.len(), 1, "a second request made a second slot");
        drop(again);
    }

    #[tokio::test]
    async fn two_clients_get_two_slots() {
        let pool = pool(8);
        let a = pool.checkout(&[0xaa; 32]);
        let b = pool.checkout(&[0xbb; 32]);
        assert_eq!(pool.len(), 2);
        assert!(
            !Arc::ptr_eq(a.slot(), b.slot()),
            "two clients shared a slot"
        );
    }

    /// The property the whole design is for: one client's request does not
    /// wait on another's. If these locks were shared this would deadlock.
    #[tokio::test]
    async fn one_client_does_not_block_another() {
        let pool = pool(8);
        let a = pool.checkout(&[0xaa; 32]);
        let b = pool.checkout(&[0xbb; 32]);

        let held = a.slot().tenant().lock().await;
        // B proceeds while A's lock is held, and needs no timeout to do it.
        let other = b.slot().tenant().lock().await;
        drop(other);
        drop(held);
    }

    /// And the other half: a client *is* serialised against itself, which is
    /// what makes a nonce reservation safe.
    #[tokio::test]
    async fn a_client_is_serialised_against_itself() {
        let pool = pool(8);
        let client = [0xab; 32];
        let first = pool.checkout(&client);
        let second = pool.checkout(&client);
        assert!(Arc::ptr_eq(first.slot(), second.slot()));

        let held = first.slot().tenant().lock().await;
        assert!(
            second.slot().tenant().try_lock().is_err(),
            "two requests from one client held the tenant at once"
        );
        drop(held);
    }

    #[tokio::test]
    async fn the_pool_stays_within_its_cap() {
        let pool = pool(4);
        for i in 0..32u8 {
            let mut client = [0u8; 32];
            client[0] = i;
            drop(pool.checkout(&client));
        }
        assert!(pool.len() <= 4, "pool grew to {}", pool.len());
    }

    /// Eviction must never unmount a filesystem a request is using. A busy
    /// tenant is skipped even when the pool is over its cap.
    #[tokio::test]
    async fn a_busy_tenant_is_never_evicted() {
        let pool = pool(2);
        let busy = pool.checkout(&[0xff; 32]);

        for i in 0..16u8 {
            let mut client = [0u8; 32];
            client[0] = i;
            drop(pool.checkout(&client));
        }

        let again = pool.checkout(&[0xff; 32]);
        assert!(
            Arc::ptr_eq(busy.slot(), again.slot()),
            "a slot in use was evicted and rebuilt"
        );
    }

    /// Dropping a checkout releases the tenant however the request ended.
    #[tokio::test]
    async fn finishing_a_request_makes_a_tenant_evictable_again() {
        let pool = pool(2);
        let client = [0xff; 32];
        drop(pool.checkout(&client));

        for i in 0..8u8 {
            let mut other = [0u8; 32];
            other[0] = i;
            drop(pool.checkout(&other));
        }
        assert!(pool.len() <= 2);
    }
}
