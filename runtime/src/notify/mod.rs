//! Waking a tenant's devices, without telling anyone what happened.
//!
//! A guest cannot reach its user between requests, and by default it cannot
//! reach the network at all — [`crate::serve::EgressPolicy`] refuses every
//! outgoing request a guest makes, and a deployment that opens any names only
//! specific origins, never a push service. So the runtime holds the push
//! credential and sends on the guest's behalf, and the guest gets a host import
//! instead of a socket.
//!
//! # A wake signal carries nothing
//!
//! The payload crosses the parent instance — the party this enclave exists to
//! exclude — and then Google. So it contains an opaque category, an optional
//! tenant-local reference, and nothing else: no title, no body, no
//! `notification` object. The app wakes and fetches the detail over the
//! attested channel, where the parent is excluded again.
//!
//! That is not a setting. A flag would be something a deployment turns on and a
//! guest then uses, at which point it stops being a property.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use tokio::sync::{mpsc, Notify};
use wasmtime_wasi::HostWallClock;

use crate::clock::WallClockAdapter;
use crate::state::State;

pub mod device;
pub mod fcm;
pub mod oauth;
pub mod transport;

pub use device::{DeviceRegistry, StoredDevice, MAX_DEVICES, MAX_DEVICES_PER_TENANT};
pub use fcm::{FcmClient, FcmTransport, NotifyConfig, SendError};
pub use oauth::{AccessToken, ServiceAccount, TokenResponse};
pub use transport::{web_pki_client_config, HttpsTransport};

/// Wakes waiting to be sent. Beyond this the oldest are dropped: a wake is a
/// hint, and a backlog of stale hints is worth less than a fresh one.
const QUEUE_CAPACITY: usize = 1024;
/// Distinct categories one tenant may have in flight. Reaching it is a guest
/// raising more kinds of signal than it can possibly need at once.
const MAX_INFLIGHT_PER_TENANT: usize = 8;
/// Wakes held back for retry. Also dropped oldest-first.
const MAX_PENDING: usize = 64;
const MIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// One line about drops per interval, never one per drop.
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(60);
/// How long shutdown waits for the queue to empty before abandoning it.
const FLUSH_DEADLINE: Duration = Duration::from_secs(5);

/// How long the startup probe may take before the enclave stops waiting.
///
/// A notification client must never be what decides whether the enclave binds
/// its listener.
pub const NOTIFY_STARTUP_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The per-invocation authority to use notify, stamped by the serving path.
///
/// The tenant comes from the executing instance, never from the caller, which
/// is why no function in the WIT takes a tenant id.
#[derive(Clone)]
pub struct NotifyContext {
    pub notifier: Arc<Notifier>,
    pub tenant: [u8; 16],
    pub interactive: bool,
}

impl std::fmt::Debug for NotifyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyContext")
            .field("interactive", &self.interactive)
            .finish_non_exhaustive()
    }
}

#[derive(Default, Debug)]
struct Counters {
    queued_dropped: AtomicU64,
    pending_dropped: AtomicU64,
    refused: AtomicU64,
    pruned: AtomicU64,
    sent: AtomicU64,
    /// Loop iterations. Only a test reads this, and only to prove an idle
    /// forwarder is not burning a core.
    wakeups: AtomicU64,
}

#[derive(Debug)]
struct Wake {
    tenant: [u8; 16],
    category: String,
    reference: Option<String>,
    /// When this wake may next be attempted. Zero means immediately.
    due_ms: u64,
    attempts: u32,
}

/// The guest-facing half: owns the registry and the queue, owns no network.
pub struct Notifier {
    registry: Arc<DeviceRegistry>,
    clock: Arc<WallClockAdapter>,
    tx: mpsc::Sender<Wake>,
    /// `(tenant, category)` already queued. A wake is idempotent, so a second
    /// one for a category still waiting *is* the one already waiting — and
    /// coalescing is also what stops one tenant filling a shared queue with
    /// repeats of a single signal.
    ///
    /// A `std` mutex, never tokio's: `raise` holds it, and `raise` must contain
    /// nothing that can pend.
    inflight: Mutex<HashSet<([u8; 16], String)>>,
    counters: Arc<Counters>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier")
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl Notifier {
    pub fn now_ms(&self) -> u64 {
        self.clock.now().as_millis().min(u64::MAX as u128) as u64
    }

    /// Enrol a device for this tenant.
    pub async fn register_device(&self, tenant: [u8; 16], token: &str) -> Result<()> {
        let now = self.now_ms();
        self.registry.register(tenant, token, now).await
    }

    pub async fn forget_device(&self, tenant: [u8; 16], token: &str) -> Result<()> {
        self.registry.forget(tenant, token).await
    }

    pub async fn device_count(&self, tenant: [u8; 16]) -> u32 {
        self.registry.count(tenant).await
    }

    /// How many times the forwarder has come round its loop.
    pub fn wakeups(&self) -> u64 {
        self.counters.wakeups.load(Ordering::Relaxed)
    }

    /// Queue a wake signal.
    ///
    /// **Not async, and it must stay that way.** This runs inside a host call
    /// that holds the tenant's only instance slot, so it touches neither the
    /// network nor the filesystem — the same invariant, and the same reason, as
    /// `CloudWatchLogSink::emit`.
    ///
    /// A full queue returns `Ok`: a drop is not the guest's fault and not
    /// something it can act on, and telling it would invite a retry that makes
    /// the queue worse. Exceeding the per-tenant cap *does* return `Err`,
    /// because that one is actionable — the guest is raising more distinct
    /// categories than it has reason to.
    pub fn raise(&self, tenant: [u8; 16], category: &str, reference: Option<&str>) -> Result<()> {
        fcm::check_labels(category, reference)?;

        let key = (tenant, category.to_string());
        {
            let mut inflight = self.inflight.lock().expect("inflight poisoned");
            if inflight.contains(&key) {
                return Ok(());
            }
            let held = inflight.iter().filter(|(t, _)| *t == tenant).count();
            ensure!(
                held < MAX_INFLIGHT_PER_TENANT,
                "this tenant already has {MAX_INFLIGHT_PER_TENANT} wake signals waiting"
            );
            inflight.insert(key.clone());
        }

        let wake = Wake {
            tenant,
            category: category.to_string(),
            reference: reference.map(str::to_string),
            due_ms: 0,
            attempts: 0,
        };
        if self.tx.try_send(wake).is_err() {
            self.inflight
                .lock()
                .expect("inflight poisoned")
                .remove(&key);
            self.counters.queued_dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn release(&self, tenant: [u8; 16], category: &str) {
        self.inflight
            .lock()
            .expect("inflight poisoned")
            .remove(&(tenant, category.to_string()));
    }
}

/// The task that actually talks to FCM.
pub struct NotifyForwarder {
    task: tokio::task::JoinHandle<()>,
    stop: Arc<Notify>,
}

impl NotifyForwarder {
    /// Let the queue drain, then stop. Bounded: a push service having a bad day
    /// must not hold the enclave open.
    pub async fn shutdown(mut self) {
        self.stop.notify_one();
        match tokio::time::timeout(FLUSH_DEADLINE, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "the notification forwarder ended badly"),
            Err(_) => {
                tracing::warn!(
                    "the notification forwarder did not flush in time; dropping queued wakes"
                );
                self.task.abort();
            }
        }
    }
}

/// Build the guest-facing half and the task that drains it.
pub fn start(
    registry: Arc<DeviceRegistry>,
    clock: Arc<WallClockAdapter>,
    client: FcmClient,
) -> (Arc<Notifier>, NotifyForwarder) {
    let (tx, rx) = mpsc::channel::<Wake>(QUEUE_CAPACITY);
    let counters = Arc::new(Counters::default());
    let stop = Arc::new(Notify::new());
    let notifier = Arc::new(Notifier {
        registry: registry.clone(),
        clock: clock.clone(),
        tx,
        inflight: Mutex::new(HashSet::new()),
        counters: counters.clone(),
    });
    let task = tokio::spawn(forward(
        rx,
        client,
        registry,
        notifier.clone(),
        counters,
        clock,
        stop.clone(),
    ));
    (notifier, NotifyForwarder { task, stop })
}

fn backoff_for(attempts: u32) -> Duration {
    MIN_BACKOFF
        .saturating_mul(1u32 << attempts.min(7))
        .min(MAX_BACKOFF)
}

async fn forward(
    mut rx: mpsc::Receiver<Wake>,
    mut client: FcmClient,
    registry: Arc<DeviceRegistry>,
    notifier: Arc<Notifier>,
    counters: Arc<Counters>,
    clock: Arc<WallClockAdapter>,
    stop: Arc<Notify>,
) {
    let mut pending: VecDeque<Wake> = VecDeque::new();
    let mut last_report = tokio::time::Instant::now();

    loop {
        counters.wakeups.fetch_add(1, Ordering::Relaxed);
        let now = clock.now().as_millis().min(u64::MAX as u128) as u64;
        // Only ever computed from a deadline that has something behind it. A
        // timer armed on an empty queue is how an idle forwarder burns a core.
        let wait = pending
            .iter()
            .map(|w| w.due_ms.saturating_sub(now))
            .min()
            .map(Duration::from_millis);

        tokio::select! {
            biased;

            _ = stop.notified() => {
                drain(&mut rx, &mut pending);
                for wake in pending.drain(..) {
                    deliver(&mut client, &registry, &notifier, &counters, wake, now).await;
                }
                report(&counters, true);
                return;
            }

            received = rx.recv() => {
                match received {
                    Some(wake) => pending.push_back(wake),
                    // Every Notifier is gone; nothing can queue again.
                    None => {
                        for wake in pending.drain(..) {
                            deliver(&mut client, &registry, &notifier, &counters, wake, now).await;
                        }
                        report(&counters, true);
                        return;
                    }
                }
            }

            _ = async { tokio::time::sleep(wait.unwrap_or_default()).await }, if wait.is_some() => {}
        }

        while pending.len() > MAX_PENDING {
            pending.pop_front();
            counters.pending_dropped.fetch_add(1, Ordering::Relaxed);
        }

        let now = clock.now().as_millis().min(u64::MAX as u128) as u64;
        let mut carry = VecDeque::new();
        while let Some(wake) = pending.pop_front() {
            if wake.due_ms > now {
                carry.push_back(wake);
                continue;
            }
            if let Some(retry) =
                deliver(&mut client, &registry, &notifier, &counters, wake, now).await
            {
                carry.push_back(retry);
            }
        }
        pending = carry;

        if last_report.elapsed() >= DROP_REPORT_INTERVAL {
            report(&counters, false);
            last_report = tokio::time::Instant::now();
        }
    }
}

fn drain(rx: &mut mpsc::Receiver<Wake>, pending: &mut VecDeque<Wake>) {
    while let Ok(wake) = rx.try_recv() {
        pending.push_back(wake);
    }
}

/// Send one wake to every device the tenant has. Returns the wake again if it
/// is worth another attempt.
async fn deliver(
    client: &mut FcmClient,
    registry: &Arc<DeviceRegistry>,
    notifier: &Arc<Notifier>,
    counters: &Arc<Counters>,
    mut wake: Wake,
    now_ms: u64,
) -> Option<Wake> {
    // Released as the wake leaves the queue, so the next signal for this
    // category can be raised while this one is still being retried.
    notifier.release(wake.tenant, &wake.category);

    let devices = registry.devices(wake.tenant).await;
    if devices.is_empty() {
        return None;
    }

    // Sequential, not fanned out: at most a handful of tokens over one reused
    // connection is cheap, and it orders a token's pruning against the next
    // send rather than racing it.
    let mut retry = false;
    for device in devices {
        match client
            .wake(
                &device.token,
                &wake.category,
                wake.reference.as_deref(),
                now_ms,
            )
            .await
        {
            Ok(()) => {
                counters.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(SendError::DeadToken(detail)) => {
                counters.pruned.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(detail, "pruning a registration token FCM says is gone");
                if let Err(e) = registry
                    .forget_if_unchanged(wake.tenant, &device.token, device.created_ms)
                    .await
                {
                    tracing::warn!(error = %e, "could not prune a dead registration token");
                }
            }
            Err(SendError::Refused(detail)) => {
                counters.refused.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(detail, "FCM refused a wake signal");
            }
            Err(SendError::Transient(detail)) => {
                tracing::debug!(detail, "a wake signal will be retried");
                retry = true;
            }
        }
    }

    if !retry {
        return None;
    }
    wake.attempts += 1;
    wake.due_ms = now_ms.saturating_add(backoff_for(wake.attempts).as_millis() as u64);
    Some(wake)
}

fn report(counters: &Arc<Counters>, final_report: bool) {
    let queued = counters.queued_dropped.swap(0, Ordering::Relaxed);
    let pending = counters.pending_dropped.swap(0, Ordering::Relaxed);
    let refused = counters.refused.swap(0, Ordering::Relaxed);
    let pruned = counters.pruned.swap(0, Ordering::Relaxed);
    let sent = counters.sent.swap(0, Ordering::Relaxed);
    if queued + pending + refused + pruned + sent == 0 {
        return;
    }
    // One line per interval. A warning per dropped wake would bury the console
    // exactly when something is already going wrong.
    tracing::info!(
        sent,
        dropped_queued = queued,
        dropped_pending = pending,
        refused,
        pruned,
        final_report,
        "notification delivery"
    );
}

fn context(state: &State, enrolment: bool) -> Result<NotifyContext> {
    let ctx = state
        .notify
        .clone()
        .context("notifications require an authenticated tenant and a configured sender")?;
    // `wake` is deliberately absent from this check: it spends an enrolment an
    // interactive call already made, and background work raising a wake is the
    // whole point of the feature.
    ensure!(
        !enrolment || ctx.interactive,
        "background work cannot enrol or remove a device"
    );
    Ok(ctx)
}

/// The ABI is defined in wit/notify/notify.wit. No function accepts a tenant id.
pub fn add_to_linker(linker: &mut wasmtime::component::Linker<State>) -> wasmtime::Result<()> {
    let mut notify = linker.instance("enclave:notify/notify@0.1.0")?;

    notify.func_wrap_async("register-device", |store, (token,): (String,)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.notifier.register_device(ctx.tenant, &token).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;

    notify.func_wrap_async("forget-device", |store, (token,): (String,)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.notifier.forget_device(ctx.tenant, &token).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;

    notify.func_wrap_async("devices", |store, (): ()| {
        Box::new(async move {
            let result: Result<u32> = async move {
                let ctx = context(store.data(), false)?;
                Ok(ctx.notifier.device_count(ctx.tenant).await)
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;

    notify.func_wrap_async(
        "wake",
        |store, (category, reference): (String, Option<String>)| {
            Box::new(async move {
                let result = async move {
                    let ctx = context(store.data(), false)?;
                    ctx.notifier
                        .raise(ctx.tenant, &category, reference.as_deref())
                }
                .await;
                Ok((result.map_err(|e| e.to_string()),))
            })
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::fcm::testing::Recorder;
    use super::*;
    use crate::clock::HostClock;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, Fs, MasterSecret};

    const ALICE: [u8; 16] = [1; 16];
    const BOB: [u8; 16] = [2; 16];

    fn token(seed: &str) -> String {
        format!("{seed}{}", "y".repeat(40))
    }

    fn account() -> ServiceAccount {
        ServiceAccount::parse(
            &serde_json::json!({
                "type": "service_account",
                "project_id": "enclave-test",
                "private_key_id": "kid-1",
                "private_key": include_str!("testdata/service-account-key.pem"),
                "client_email": "wake@enclave-test.iam.gserviceaccount.com",
            })
            .to_string(),
        )
        .unwrap()
    }

    async fn fixture(
        replies: Vec<(u16, &str)>,
    ) -> (
        Arc<Notifier>,
        NotifyForwarder,
        Arc<DeviceRegistry>,
        Arc<Recorder>,
    ) {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([3u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        let registry = DeviceRegistry::open(fs).await.unwrap();
        let clock = Arc::new(WallClockAdapter::new(Box::new(HostClock)).unwrap());
        let recorder = Recorder::with(replies);
        let client = FcmClient::new(
            NotifyConfig {
                project_id: "enclave-test".into(),
                service_account: account(),
                endpoint: None,
            },
            recorder.clone(),
        );
        let (notifier, forwarder) = start(registry.clone(), clock, client);
        (notifier, forwarder, registry, recorder)
    }

    /// A `Notifier` with no forwarder behind it.
    ///
    /// `raise` is where coalescing and the per-tenant cap live, and both are
    /// about what is *waiting*. With a forwarder running, a wake's key is
    /// released the moment it is dequeued — before it is even sent — so an
    /// assertion about what is in flight becomes a race with that task. Holding
    /// the receiver and never reading it makes the queue stand still.
    async fn detached() -> (Arc<Notifier>, mpsc::Receiver<Wake>) {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([4u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        let (tx, rx) = mpsc::channel::<Wake>(QUEUE_CAPACITY);
        let notifier = Arc::new(Notifier {
            registry: DeviceRegistry::open(fs).await.unwrap(),
            clock: Arc::new(WallClockAdapter::new(Box::new(HostClock)).unwrap()),
            tx,
            inflight: Mutex::new(HashSet::new()),
            counters: Arc::new(Counters::default()),
        });
        (notifier, rx)
    }

    /// Wait for a condition the forwarder reaches asynchronously.
    async fn until(mut done: impl FnMut() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the forwarder never got there");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wake_reaches_every_device_the_tenant_enrolled() {
        let (notifier, forwarder, _registry, recorder) = fixture(vec![(200, "{}")]).await;
        notifier.register_device(ALICE, &token("a")).await.unwrap();
        notifier.register_device(ALICE, &token("b")).await.unwrap();

        notifier.raise(ALICE, "task-done", Some("job")).unwrap();
        until(|| recorder.messages().len() == 2).await;

        let sent: Vec<_> = recorder.messages();
        assert!(sent
            .iter()
            .all(|m| m["message"]["data"]["category"] == "task-done"));
        forwarder.shutdown().await;
    }

    /// The invariant that keeps a push service out of the request path.
    #[tokio::test(flavor = "multi_thread")]
    async fn raising_a_wake_never_delays_the_guest_call_that_raised_it() {
        let (notifier, forwarder, _registry, recorder) = fixture(vec![(200, "{}")]).await;
        recorder
            .stall
            .store(true, std::sync::atomic::Ordering::Relaxed);
        notifier.register_device(ALICE, &token("a")).await.unwrap();

        let started = std::time::Instant::now();
        for i in 0..QUEUE_CAPACITY * 2 {
            // Distinct categories, so nothing is coalesced away and the queue
            // genuinely fills.
            let _ = notifier.raise(ALICE, &format!("c{i}"), None);
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "raising wakes against a stalled push service took {elapsed:?}"
        );
        forwarder.shutdown().await;
    }

    #[tokio::test]
    async fn repeated_wakes_for_one_category_coalesce_into_one_send() {
        let (notifier, mut rx) = detached().await;
        for _ in 0..50 {
            notifier.raise(ALICE, "task-done", None).unwrap();
        }
        assert_eq!(notifier.inflight.lock().unwrap().len(), 1);

        // And one reached the queue, not fifty.
        let mut queued = 0;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, 1, "a repeated wake was queued {queued} times");
    }

    #[tokio::test]
    async fn one_tenant_cannot_hold_more_than_its_share_of_wakes_in_flight() {
        let (notifier, _rx) = detached().await;
        for i in 0..MAX_INFLIGHT_PER_TENANT {
            notifier.raise(ALICE, &format!("c{i}"), None).unwrap();
        }
        assert!(
            notifier.raise(ALICE, "one-too-many", None).is_err(),
            "a tenant queued more distinct categories than its share"
        );
        // The cap is per tenant, not global: Bob is unaffected.
        notifier.raise(BOB, "mine", None).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dead_token_is_pruned_and_the_tenants_other_devices_still_get_woken() {
        let gone = serde_json::json!({"error": {
            "status": "NOT_FOUND", "message": "gone",
            "details": [{"errorCode": "UNREGISTERED"}]}})
        .to_string();
        // The first device answers UNREGISTERED, the second accepts.
        let (notifier, forwarder, registry, recorder) =
            fixture(vec![(404, &gone), (200, "{}")]).await;
        notifier
            .register_device(ALICE, &token("dead"))
            .await
            .unwrap();
        notifier
            .register_device(ALICE, &token("live"))
            .await
            .unwrap();

        notifier.raise(ALICE, "task-done", None).unwrap();
        until(|| recorder.messages().len() == 2).await;
        // The prune lands after the send it was decided by.
        for _ in 0..200 {
            if registry.devices(ALICE).await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The dead one is gone, the live one remains.
        let left = registry.devices(ALICE).await;
        assert_eq!(left.len(), 1, "the dead token was not pruned: {left:?}");
        assert_eq!(left[0].token, token("live"));
        forwarder.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wake_for_a_tenant_with_no_devices_is_dropped_quietly() {
        let (notifier, forwarder, _registry, recorder) = fixture(vec![(200, "{}")]).await;
        notifier.raise(ALICE, "nobody-home", None).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(recorder.messages().is_empty());
        forwarder.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_category_that_is_not_a_label_is_refused_before_it_is_queued() {
        let (notifier, forwarder, _registry, recorder) = fixture(vec![(200, "{}")]).await;
        notifier.register_device(ALICE, &token("a")).await.unwrap();
        assert!(notifier
            .raise(ALICE, "Approve $4,000 to Acme", None)
            .is_err());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            recorder.messages().is_empty(),
            "prose reached the wire as a category"
        );
        forwarder.shutdown().await;
    }

    /// Five minutes of virtual time with nothing to send is a handful of
    /// ticks, not thousands of iterations.
    #[tokio::test(start_paused = true)]
    async fn an_idle_forwarder_does_not_spin() {
        let (notifier, _forwarder, _registry, _recorder) = fixture(vec![(200, "{}")]).await;
        let before = notifier.wakeups();
        tokio::time::sleep(Duration::from_secs(300)).await;
        let woke = notifier.wakeups() - before;
        assert!(
            woke < 50,
            "the forwarder woke {woke} times while idle over five minutes"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_flushes_what_is_queued_and_cannot_hold_the_enclave_open() {
        let (notifier, forwarder, _registry, recorder) = fixture(vec![(200, "{}")]).await;
        notifier.register_device(ALICE, &token("a")).await.unwrap();
        notifier.raise(ALICE, "last-word", None).unwrap();
        forwarder.shutdown().await;
        assert_eq!(
            recorder.messages().len(),
            1,
            "a queued wake was lost at shutdown"
        );

        // And a stalled service cannot hold shutdown open past the deadline.
        let (notifier, forwarder, _registry, recorder) = fixture(vec![(200, "{}")]).await;
        recorder
            .stall
            .store(true, std::sync::atomic::Ordering::Relaxed);
        notifier.register_device(ALICE, &token("a")).await.unwrap();
        notifier.raise(ALICE, "never-lands", None).unwrap();
        let started = std::time::Instant::now();
        forwarder.shutdown().await;
        assert!(
            started.elapsed() < FLUSH_DEADLINE + Duration::from_secs(2),
            "shutdown waited {:?} on a stalled push service",
            started.elapsed()
        );
    }
}
