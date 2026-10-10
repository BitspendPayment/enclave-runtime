//! Live tenants: one lock per client.
//!
//! ## Only the lock is kept
//!
//! Every request, task run and message gets a fresh instance over its
//! tenant's dataset, dropped when the call ends — instantiating is 24 µs and no
//! I/O. Nothing a guest holds in memory survives a call, so there is nothing
//! to invalidate when background work changes the dataset underneath it.
//!
//! ## The lock is a correctness mechanism
//!
//! Each client has its own `tokio::Mutex`, and that is the whole concurrency
//! model: **a client is serialised against itself and against nobody else.**
//!
//! Serialised against itself, because a cosigner reserving a nonce must not
//! race its own second request. Not against anyone else, because a client's
//! dataset is theirs alone, so there is nothing for two clients to contend
//! over in it. (Anchors are serialised across everyone — see [`crate::zfs`].)
//!
//! ## Keyed by tenant id
//!
//! The id the gate resolved from a passkey assertion. Callers with no tenant
//! never get a slot; they share one lock of their own in the serving path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many tenants' locks are held, and how long an idle one is kept.
///
/// A slot is a lock and two counters, so the cap bounds a map, not memory
/// worth worrying about. It stays because registration is open: without one,
/// every passkey that ever called would keep an entry for the life of the
/// process.
#[derive(Debug, Clone)]
pub struct PoolLimits {
    pub max_tenants: usize,
    pub idle_timeout: Duration,
}

impl Default for PoolLimits {
    fn default() -> Self {
        PoolLimits {
            max_tenants: 64,
            idle_timeout: Duration::from_secs(900),
        }
    }
}

/// One client's slot.
///
/// `last_used` and `in_flight` sit *outside* the async mutex on purpose: the
/// eviction sweep has to compare tenants without awaiting on any of them, and a
/// sweep that could block on a busy tenant would be a sweep that stalls the
/// server it is tidying.
pub struct Slot {
    /// `Arc`'d so a request can take an *owned* guard and carry it into the
    /// task that runs the guest — the lock has to outlive the response head,
    /// and a borrowed guard could not.
    lock: Arc<tokio::sync::Mutex<()>>,
    last_used: AtomicU64,
    in_flight: AtomicUsize,
}

impl Slot {
    fn new(now: u64) -> Self {
        Slot {
            lock: Arc::new(tokio::sync::Mutex::new(())),
            last_used: AtomicU64::new(now),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub fn lock(&self) -> &Arc<tokio::sync::Mutex<()>> {
        &self.lock
    }
}

/// A slot checked out for one request.
///
/// Holding this is what marks the tenant busy, so the sweep leaves it alone;
/// dropping it releases that mark however the request ended, including a panic.
pub struct Checkout {
    slot: Arc<Slot>,
}

impl Checkout {
    pub fn slot(&self) -> &Arc<Slot> {
        &self.slot
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        self.slot.in_flight.fetch_sub(1, Ordering::Release);
    }
}

pub struct TenantPool {
    /// A `std::sync::Mutex`, not a `tokio` one, and never held across an
    /// await: everything under it is a hash lookup and an `Arc` clone. The
    /// *per-tenant* lock is the async one, and it is a different lock for a
    /// different job.
    slots: Mutex<HashMap<[u8; 16], Arc<Slot>>>,
    limits: PoolLimits,
    started: Instant,
}

impl TenantPool {
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
    /// The slot, not the tenant: the caller then takes the async lock and finds
    /// or creates the client's dataset under it. That ordering is what makes
    /// two simultaneous first requests from one client produce **one** — they
    /// find the same slot, and the second waits on the lock the first is
    /// holding rather than racing it into a second `zfs create`.
    pub fn checkout(&self, tenant: &[u8; 16]) -> Checkout {
        let now = self.now();
        let mut slots = self.slots.lock().expect("tenant pool mutex poisoned");

        if let Some(slot) = slots.get(tenant) {
            slot.last_used.store(now, Ordering::Release);
            slot.in_flight.fetch_add(1, Ordering::Release);
            return Checkout { slot: slot.clone() };
        }

        // Room first, so the pool never exceeds its cap even briefly.
        self.evict_while_full(&mut slots, now);

        let slot = Arc::new(Slot::new(now));
        slot.in_flight.fetch_add(1, Ordering::Release);
        slots.insert(*tenant, slot.clone());
        Checkout { slot }
    }

    /// Drop idle and over-cap tenants.
    ///
    /// Only slots nobody has checked out, so a lock is never dropped while a
    /// call holds it; a later request for that tenant simply makes a new one.
    fn evict_while_full(&self, slots: &mut HashMap<[u8; 16], Arc<Slot>>, now: u64) {
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
                // alternative is a second lock for a tenant whose first is
                // held. The pool runs over its cap until they finish.
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

    fn pool(max: usize) -> TenantPool {
        TenantPool::new(PoolLimits {
            max_tenants: max,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn a_client_returns_to_the_same_slot() {
        let pool = pool(8);
        let client = [0xab; 16];

        {
            let first = pool.checkout(&client);
            drop(first.slot().lock().lock().await);
        }
        let again = pool.checkout(&client);
        assert_eq!(pool.len(), 1, "a second request made a second slot");
        drop(again);
    }

    #[tokio::test]
    async fn two_clients_get_two_slots() {
        let pool = pool(8);
        let a = pool.checkout(&[0xaa; 16]);
        let b = pool.checkout(&[0xbb; 16]);
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
        let a = pool.checkout(&[0xaa; 16]);
        let b = pool.checkout(&[0xbb; 16]);

        let held = a.slot().lock().lock().await;
        // B proceeds while A's lock is held, and needs no timeout to do it.
        let other = b.slot().lock().lock().await;
        drop(other);
        drop(held);
    }

    /// And the other half: a client *is* serialised against itself, which is
    /// what makes a nonce reservation safe.
    #[tokio::test]
    async fn a_client_is_serialised_against_itself() {
        let pool = pool(8);
        let client = [0xab; 16];
        let first = pool.checkout(&client);
        let second = pool.checkout(&client);
        assert!(Arc::ptr_eq(first.slot(), second.slot()));

        let held = first.slot().lock().lock().await;
        assert!(
            second.slot().lock().try_lock().is_err(),
            "two requests from one client held the tenant at once"
        );
        drop(held);
    }

    #[tokio::test]
    async fn the_pool_stays_within_its_cap() {
        let pool = pool(4);
        for i in 0..32u8 {
            let mut client = [0u8; 16];
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
        let busy = pool.checkout(&[0xff; 16]);

        for i in 0..16u8 {
            let mut client = [0u8; 16];
            client[0] = i;
            drop(pool.checkout(&client));
        }

        let again = pool.checkout(&[0xff; 16]);
        assert!(
            Arc::ptr_eq(busy.slot(), again.slot()),
            "a slot in use was evicted and rebuilt"
        );
    }

    /// Dropping a checkout releases the tenant however the request ended.
    #[tokio::test]
    async fn finishing_a_request_makes_a_tenant_evictable_again() {
        let pool = pool(2);
        let client = [0xff; 16];
        drop(pool.checkout(&client));

        for i in 0..8u8 {
            let mut other = [0u8; 16];
            other[0] = i;
            drop(pool.checkout(&other));
        }
        assert!(pool.len() <= 2);
    }
}
