//! Guest stdout and stderr, from the enclave to CloudWatch Logs.
//!
//! ```text
//!   GuestLogCollector ──▶ CloudWatchLogSink ──▶ bounded queue ──▶ forwarder task
//!                         (stamps, enqueues,    (drops when       (batches, calls
//!                          never awaits AWS)     full)             PutLogEvents)
//! ```
//!
//! # Why the enclave calls AWS itself
//!
//! Because it already does. KMS, SSM and S3 are all reached from in here, over
//! the tap device and gvproxy, with credentials from the parent's instance
//! role. Relaying logs through a parent-side process would add a wire format, a
//! transport and a second binary to reach a service this runtime can already
//! reach — and it would be *worse*: a relay reads the plaintext.
//!
//! Calling CloudWatch directly terminates TLS **inside** the enclave, against
//! the CA bundle shipped in the image. So:
//!
//! - the parent **cannot read or tamper with** records in flight;
//! - it **can block or delay** them — it carries the packets and answers DNS;
//! - it **can forge records out of band**, because the credentials are its own
//!   instance role and it can write to the same log stream itself. Closing that
//!   needs a distinct, attested identity for the enclave, which does not exist
//!   yet.
//!
//! And the content was never trustworthy: a guest chose the text. These are
//! operational records, not an audit trail.
//!
//! # An unverified dependency, and what protects against it
//!
//! Credentials come from the SDK's default chain, which reaches IMDS on the
//! parent through gvproxy. **That path is unverified.** No test here exercises
//! it — the QEMU harness has no instance metadata service — and it is due to be
//! validated on Nitro hardware before production, along with a real
//! `PutLogEvents`.
//!
//! So the code assumes it may not work. Everything about reaching AWS is
//! transient unless the service itself says otherwise: a connection that
//! fails, a credential that will not resolve, a token that has expired. Only
//! `ResourceNotFoundException` and `AccessDeniedException` are treated as
//! final, because only those name a deployment mistake that waiting cannot fix.
//! And the startup handshake is bounded by [`STARTUP_PROBE_TIMEOUT`], so a
//! credential path that stalls costs logging and never the listener.
//!
//! # Nothing here may delay a request
//!
//! [`CloudWatchLogSink::emit`] stamps a record and `try_send`s it. **It must
//! contain no `.await` that can pend** — that is the invariant the whole
//! subsystem rests on, and the reason the SDK client lives in a separate task
//! behind a second bounded queue. A CloudWatch outage costs dropped records and
//! nothing else.
//!
//! # What is dropped
//!
//! - The **record queue** drops what is *arriving*: `emit` must return in
//!   constant time and cannot reach into a shared structure.
//! - The **pending-batch deque** drops the *oldest*: the forwarder owns it, and
//!   when CloudWatch has been away that long, recent output is what matters.
//! - Records older than [`MAX_RECORD_AGE`] are dropped when a batch is sealed.
//!   CloudWatch refuses events more than 14 days old or spanning more than 24
//!   hours in one call, and stale guest output has almost no value anyway.
//! - Events CloudWatch rejects *inside a 200 response* are counted too — see
//!   [`PutOutcome`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use aws_sdk_cloudwatchlogs::types::InputLogEvent;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use super::{GuestLogRecord, GuestLogSink};

/// Records held between the collector and the forwarder.
pub const TRANSPORT_QUEUE_CAPACITY: usize = 4096;

/// Batches held while CloudWatch is unreachable.
pub const MAX_PENDING_BATCHES: usize = 16;

/// Records in one batch before it is sealed regardless of the linger.
pub const MAX_BATCH_RECORDS: usize = 1024;

/// CloudWatch's ceiling on events in one `PutLogEvents`.
const MAX_PUT_EVENTS: usize = 10_000;

/// CloudWatch's ceiling on one call: 1 MiB including 26 bytes per event. A
/// round million leaves headroom rather than sitting on the limit.
const MAX_PUT_BYTES: usize = 1_000_000;
const EVENT_OVERHEAD: usize = 26;

/// CloudWatch's ceiling on one event. Far above the 16 KiB record cap plus this
/// module's JSON wrapper; asserted in tests so the two cannot drift together.
const MAX_EVENT_BYTES: usize = 256 * 1024;

/// Older than this and a record is dropped rather than sent.
///
/// Bounds two CloudWatch rules at once — no event over 14 days old, and no
/// batch spanning more than 24 hours — with one rule that is easy to reason
/// about. Only reachable after a long outage, which is exactly when the oldest
/// records are the least worth having.
const MAX_RECORD_AGE: Duration = Duration::from_secs(60 * 60);

/// How long a partly-filled batch waits for company.
///
/// Also the rate limiter. CloudWatch allows 5 `PutLogEvents` per second per log
/// stream and that quota cannot be raised, so a fixed stream name sits behind
/// it; half a second between flushes leaves room for a burst to split into
/// several calls without immediately throttling.
const BATCH_LINGER: Duration = Duration::from_millis(500);

/// Spacing between chunk calls within one flush, for the same quota.
const CHUNK_SPACING: Duration = Duration::from_millis(250);

const MIN_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// How long the startup handshake — building the client and writing the boot
/// marker — may take before the boot gives up on it and carries on.
///
/// Load-bearing, not tidiness. Credential resolution reaches IMDS through
/// gvproxy, and whether that path works on a given deployment is unverified
/// (see the module note). An arrangement that could stall here would mean a
/// logging dependency deciding whether the enclave ever serves a request.
pub const STARTUP_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a graceful shutdown spends flushing.
///
/// Must stay longer than the client's operation timeout, or the final flush can
/// never complete and every shutdown silently discards what it was flushing.
const FLUSH_DEADLINE: Duration = Duration::from_secs(5);

/// What produced a record.
///
/// The distinction is kept all the way to the wire. Without it the runtime's
/// own boot marker would be encoded through [`encode_message`] and arrive
/// labelled `source: "guest"` — a runtime event wearing guest clothes, which is
/// exactly the confusion this module refuses everywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A line the guest wrote. Wrapped by [`encode_message`].
    Guest(GuestLogRecord),
    /// The runtime speaking for itself, already encoded.
    Runtime(String),
}

/// A payload with the time it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamped {
    pub timestamp_ms: i64,
    pub payload: Payload,
}

/// What a `PutLogEvents` actually achieved.
///
/// A 200 does not mean every event landed: CloudWatch reports events it refused
/// as too old, too new or expired *inside a successful response*. Counting them
/// is the difference between "delivered" and "the call did not error".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PutOutcome {
    pub accepted: usize,
    pub rejected: usize,
}

/// Why a `PutLogEvents` failed, and whether trying again could help.
#[derive(Debug)]
pub enum PutError {
    /// Worth retrying: throttling, a 5xx, a broken connection.
    Transient(String),
    /// Not worth retrying: the stream does not exist, or we may not write to
    /// it. Retrying forever would bury the real problem in backoff.
    Definitive(String),
}

impl std::fmt::Display for PutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutError::Transient(e) => write!(f, "{e}"),
            PutError::Definitive(e) => write!(f, "{e}"),
        }
    }
}

/// Where framed events go. A trait so batching, backoff and drop accounting can
/// be tested without HTTP, and so the SDK client is reachable only from one
/// place.
#[async_trait]
pub trait LogDestination: Send + Sync {
    async fn put(&self, events: Vec<InputLogEvent>) -> Result<PutOutcome, PutError>;
    /// For logs. Must name nothing secret.
    fn describe(&self) -> String;
}

/// One guest line, as the JSON body of a CloudWatch event.
///
/// JSON, not `[stdout] message`, for the reason the tracing sink uses a named
/// field: guest text must only ever be a **value**. A positional prefix lets a
/// guest writing `] not-really` produce something a naive parser splits wrongly,
/// which is the same forgery the console formatter already had to be fixed for.
/// As a JSON string value it is escaped by construction.
///
/// The wrapper also keeps the message non-empty. CloudWatch rejects an empty
/// message, and this pipeline deliberately keeps a guest's blank lines as
/// records — so the wrapper is load-bearing, not decoration.
pub fn encode_message(record: &GuestLogRecord) -> String {
    // `serde_json` does the escaping; the fields are the runtime's own and the
    // guest's text can only land in `message`.
    serde_json::json!({
        "source": "guest",
        "stream": record.stream.as_str(),
        "truncated": record.truncated,
        "message": record.message,
    })
    .to_string()
}

/// The one-off event a forwarder writes when it starts.
///
/// A fixed stream name is shared by every boot and every image, so without this
/// nothing in the stream says which enclave produced which line. `source` is
/// `runtime`, so it cannot be confused with anything a guest wrote — a guest
/// emitting the identical bytes still lands under `source: "guest"`.
pub fn boot_marker(image: Option<&str>, region: &str) -> String {
    serde_json::json!({
        "source": "runtime",
        "event": "guest-log-stream-opened",
        "pcr0": image.unwrap_or("(unknown)"),
        "region": region,
        "version": env!("CARGO_PKG_VERSION"),
    })
    .to_string()
}

/// Split records into calls CloudWatch will accept.
///
/// Pure, so the limits can be tested without a client. Applies, in order: drop
/// anything older than [`MAX_RECORD_AGE`]; encode; split on the event count and
/// the byte budget. Ordering is preserved — the timestamps are already
/// non-decreasing by construction (see [`CloudWatchLogSink::emit`]), so nothing
/// here sorts, which would reorder a guest's own lines.
/// One `PutLogEvents` call, and how much of the source batch it accounts for.
///
/// `consumed` counts source records — events plus any dropped as stale — so a
/// caller can record progress after each successful call. Without it a failure
/// on the second chunk would resend the first, and CloudWatch does not
/// deduplicate.
#[derive(Debug)]
pub struct Chunk {
    pub consumed: usize,
    pub events: Vec<InputLogEvent>,
}

pub fn put_chunks(records: &[Stamped], now_ms: i64) -> (Vec<Chunk>, usize) {
    let oldest_allowed = now_ms - MAX_RECORD_AGE.as_millis() as i64;
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut current: Vec<InputLogEvent> = Vec::new();
    let mut bytes = 0usize;
    let mut dropped = 0usize;
    // Source records accounted for by chunks already sealed.
    let mut sealed = 0usize;

    for (index, stamped) in records.iter().enumerate() {
        if stamped.timestamp_ms < oldest_allowed {
            dropped += 1;
            continue;
        }
        let message = match &stamped.payload {
            Payload::Guest(record) => encode_message(record),
            Payload::Runtime(encoded) => encoded.clone(),
        };
        // CloudWatch refuses an event over 256 KiB outright. A 16 KiB record
        // plus its JSON wrapper cannot reach that even fully escaped, so this
        // is a guard against the record cap drifting later rather than a case
        // that happens — but a rejected call would take the whole chunk with
        // it, so it is enforced rather than assumed.
        if message.len() > MAX_EVENT_BYTES {
            dropped += 1;
            continue;
        }
        let cost = message.len() + EVENT_OVERHEAD;
        if !current.is_empty() && (bytes + cost > MAX_PUT_BYTES || current.len() >= MAX_PUT_EVENTS)
        {
            // Everything up to but not including this record.
            chunks.push(Chunk {
                consumed: index - sealed,
                events: std::mem::take(&mut current),
            });
            sealed = index;
            bytes = 0;
        }
        match InputLogEvent::builder()
            .timestamp(stamped.timestamp_ms)
            .message(message)
            .build()
        {
            Ok(event) => {
                bytes += cost;
                current.push(event);
            }
            // Only reachable if a required field is unset, which it is not.
            // Counted rather than panicking: this is a logging path.
            Err(_) => dropped += 1,
        }
    }
    if !current.is_empty() {
        chunks.push(Chunk {
            consumed: records.len() - sealed,
            events: current,
        });
    }
    (chunks, dropped)
}

/// Open the stream by writing the boot marker, and report what that says about
/// the configuration.
///
/// The marker is the probe. Validating a log stream any other way would need
/// `DescribeLogStreams`, a permission this runtime deliberately does not ask
/// for — so the check is the first real write, which needs nothing beyond
/// `PutLogEvents`.
///
/// A [`PutError::Definitive`] here means the group or stream is not there, or
/// this identity may not write to it. Neither heals by waiting, and the caller
/// treats it as a boot failure.
pub async fn open_stream(
    destination: &Arc<dyn LogDestination>,
    image: Option<&str>,
    region: &str,
) -> Result<(), PutError> {
    match tokio::time::timeout(
        STARTUP_PROBE_TIMEOUT,
        write_boot_marker(destination, image, region),
    )
    .await
    {
        Ok(result) => result,
        // Transient by construction: a destination that will not answer is
        // indistinguishable from one that is merely slow, and neither is a
        // reason to refuse to serve requests.
        Err(_) => Err(PutError::Transient(format!(
            "no response within {STARTUP_PROBE_TIMEOUT:?}"
        ))),
    }
}

async fn write_boot_marker(
    destination: &Arc<dyn LogDestination>,
    image: Option<&str>,
    region: &str,
) -> Result<(), PutError> {
    let marker = boot_marker(image, region);
    let event = InputLogEvent::builder()
        .timestamp(now_ms())
        .message(marker)
        .build()
        .map_err(|e| PutError::Definitive(format!("building the boot marker: {e}")))?;
    destination.put(vec![event]).await.map(|_| ())
}

/// Counts what never reached CloudWatch.
#[derive(Debug, Default)]
struct Drops {
    /// Times the forwarder loop woke. Not accounting — a spinning loop is
    /// invisible to every other signal here, and this one bug cost a core.
    wakeups: AtomicU64,
    records: AtomicU64,
    batches: AtomicU64,
    rejected: AtomicU64,
}

impl Drops {
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.records.load(Ordering::Relaxed),
            self.batches.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
        )
    }
}

/// A [`GuestLogSink`] that hands records to the forwarder.
pub struct CloudWatchLogSink {
    tx: mpsc::Sender<Stamped>,
    drops: Arc<Drops>,
    disabled: Arc<AtomicBool>,
    /// The last timestamp handed out, so the sequence never goes backwards.
    last_ms: Arc<std::sync::atomic::AtomicI64>,
}

impl std::fmt::Debug for CloudWatchLogSink {
    /// Never prints queued records: they are guest-controlled text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (records, batches, rejected) = self.drops.snapshot();
        f.debug_struct("CloudWatchLogSink")
            .field("dropped_records", &records)
            .field("dropped_batches", &batches)
            .field("rejected_events", &rejected)
            .field("disabled", &self.disabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl CloudWatchLogSink {
    pub fn dropped_records(&self) -> u64 {
        self.drops.snapshot().0
    }
    pub fn dropped_batches(&self) -> u64 {
        self.drops.snapshot().1
    }
    /// Events CloudWatch refused inside an otherwise successful call.
    pub fn rejected_events(&self) -> u64 {
        self.drops.snapshot().2
    }
    /// Times the forwarder loop has woken. An idle forwarder should barely
    /// move this; see `an_idle_forwarder_does_not_spin`.
    pub fn wakeups(&self) -> u64 {
        self.drops.wakeups.load(Ordering::Relaxed)
    }
    /// The destination refused us definitively and we have stopped trying.
    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl GuestLogSink for CloudWatchLogSink {
    /// Stamps and enqueues. **Never touches the network.**
    async fn emit(&self, record: GuestLogRecord) {
        // Clamped monotonically rather than sorted later. CloudWatch requires
        // ascending timestamps within a call, and the enclave's wall clock is
        // hypervisor-set and can step backwards — but sorting would reorder the
        // guest's own lines, destroying ordering this pipeline has preserved
        // since `LineFramer`. Clamping keeps both properties by construction.
        let now = now_ms();
        let stamp = self
            .last_ms
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                Some(last.max(now))
            })
            .map(|previous| previous.max(now))
            .unwrap_or(now);

        if self
            .tx
            .try_send(Stamped {
                timestamp_ms: stamp,
                payload: Payload::Guest(record),
            })
            .is_err()
        {
            self.drops.records.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Owns the forwarder task, so its lifetime is explicit.
///
/// Dropping this detaches rather than stops, matching
/// [`super::GuestLogCollector`].
pub struct LogForwarder {
    task: tokio::task::JoinHandle<()>,
    stop: Arc<Notify>,
}

impl LogForwarder {
    /// Flush what is queued and stop, within [`FLUSH_DEADLINE`].
    pub async fn shutdown(mut self) {
        self.stop.notify_one();
        match tokio::time::timeout(FLUSH_DEADLINE, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "the guest log forwarder ended badly"),
            Err(_) => {
                tracing::warn!(
                    deadline = ?FLUSH_DEADLINE,
                    "the guest log forwarder did not flush in time; dropping queued output"
                );
                self.task.abort();
            }
        }
    }
}

/// Start forwarding to `destination`.
pub fn start(
    destination: Arc<dyn LogDestination>,
    marker: Option<String>,
) -> (CloudWatchLogSink, LogForwarder) {
    let (tx, rx) = mpsc::channel::<Stamped>(TRANSPORT_QUEUE_CAPACITY);
    let stop = Arc::new(Notify::new());
    let drops = Arc::new(Drops::default());
    let disabled = Arc::new(AtomicBool::new(false));

    let task = tokio::spawn(forward(
        rx,
        destination,
        marker,
        drops.clone(),
        disabled.clone(),
        stop.clone(),
    ));

    (
        CloudWatchLogSink {
            tx,
            drops,
            disabled,
            last_ms: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        },
        LogForwarder { task, stop },
    )
}

/// Batch, send, back off, account.
async fn forward(
    mut rx: mpsc::Receiver<Stamped>,
    destination: Arc<dyn LogDestination>,
    marker: Option<String>,
    drops: Arc<Drops>,
    disabled: Arc<AtomicBool>,
    stop: Arc<Notify>,
) {
    let stopping = stop.notified();
    tokio::pin!(stopping);

    // The marker goes first, so a stream always opens by saying which image is
    // writing to it, and so its outcome is what the startup check reads.
    let mut pending: VecDeque<Vec<Stamped>> = VecDeque::new();
    if let Some(marker) = marker {
        pending.push_back(vec![Stamped {
            timestamp_ms: now_ms(),
            payload: Payload::Runtime(marker),
        }]);
    }

    let mut current: Vec<Stamped> = Vec::new();
    let mut backoff = MIN_BACKOFF;
    let mut next_attempt = Instant::now();
    let mut linger_until: Option<Instant> = None;
    let mut reported = (0u64, 0u64, 0u64);
    let mut next_report = Instant::now() + DROP_REPORT_INTERVAL;

    loop {
        drops.wakeups.fetch_add(1, Ordering::Relaxed);

        // Only deadlines with something behind them. `next_attempt` is set to
        // "now" at start and only moves when a delivery *fails*, so with an
        // empty queue it is a deadline in the past that nothing will advance —
        // including it unconditionally made `sleep_until` return immediately
        // and the loop spin at full CPU while completely idle. Inside an
        // enclave that is a core burned for nothing.
        //
        // `next_report` is always in the future, so there is always one real
        // deadline to wait on.
        let mut wake = next_report;
        if !current.is_empty() {
            if let Some(at) = linger_until {
                wake = wake.min(at);
            }
        }
        if !pending.is_empty() && !disabled.load(Ordering::Relaxed) {
            wake = wake.min(next_attempt);
        }

        let stopped = tokio::select! {
            received = rx.recv() => match received {
                Some(stamped) => {
                    if current.is_empty() {
                        linger_until = Some(Instant::now() + BATCH_LINGER);
                    }
                    current.push(stamped);
                    false
                }
                None => true,
            },
            _ = tokio::time::sleep_until(wake) => false,
            _ = &mut stopping => true,
        };

        // Shutdown must send what the collector already handed over, so the
        // queue is drained before the last batch is sealed.
        if stopped {
            while let Ok(stamped) = rx.try_recv() {
                current.push(stamped);
            }
        }

        let linger_expired = linger_until.is_some_and(|at| Instant::now() >= at);
        let seal_all = stopped || linger_expired;
        while current.len() >= MAX_BATCH_RECORDS || (seal_all && !current.is_empty()) {
            let take = current.len().min(MAX_BATCH_RECORDS);
            let batch: Vec<Stamped> = current.drain(..take).collect();
            if pending.len() >= MAX_PENDING_BATCHES {
                pending.pop_front();
                drops.batches.fetch_add(1, Ordering::Relaxed);
            }
            pending.push_back(batch);
        }
        if current.is_empty() {
            linger_until = None;
        }

        if !disabled.load(Ordering::Relaxed)
            && Instant::now() >= next_attempt
            && !pending.is_empty()
        {
            match deliver(&destination, &mut pending, &drops).await {
                Ok(()) => backoff = MIN_BACKOFF,
                Err(PutError::Definitive(e)) => {
                    // Retrying forever would bury this in backoff. Stop, drop
                    // what is held, and keep saying so on every report.
                    disabled.store(true, Ordering::Relaxed);
                    drops
                        .batches
                        .fetch_add(pending.len() as u64, Ordering::Relaxed);
                    pending.clear();
                    tracing::error!(
                        error = %e,
                        destination = %destination.describe(),
                        "guest logs are NOT reaching CloudWatch and will not be retried; \
                         console output only"
                    );
                }
                Err(PutError::Transient(e)) => {
                    tracing::warn!(
                        error = %e,
                        destination = %destination.describe(),
                        backoff = ?backoff,
                        pending_batches = pending.len(),
                        "CloudWatch refused a batch of guest logs"
                    );
                    next_attempt = Instant::now() + backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }

        if Instant::now() >= next_report {
            reported = report(&drops, reported, disabled.load(Ordering::Relaxed));
            next_report = Instant::now() + DROP_REPORT_INTERVAL;
        }

        if stopped {
            break;
        }
    }

    if !pending.is_empty() && !disabled.load(Ordering::Relaxed) {
        let _ =
            tokio::time::timeout(FLUSH_DEADLINE, deliver(&destination, &mut pending, &drops)).await;
    }
    report(&drops, reported, disabled.load(Ordering::Relaxed));
}

/// Send every pending batch, oldest first, keeping what did not go.
async fn deliver(
    destination: &Arc<dyn LogDestination>,
    pending: &mut VecDeque<Vec<Stamped>>,
    drops: &Drops,
) -> Result<(), PutError> {
    while let Some(batch) = pending.front_mut() {
        let (chunks, stale) = put_chunks(batch, now_ms());
        if stale > 0 {
            drops.records.fetch_add(stale as u64, Ordering::Relaxed);
        }
        for (i, chunk) in chunks.into_iter().enumerate() {
            if chunk.events.is_empty() {
                batch.drain(..chunk.consumed.min(batch.len()));
                continue;
            }
            // Spaced, because 5 calls per second per stream is a hard quota and
            // a burst that splits into several chunks would otherwise throttle
            // itself.
            if i > 0 {
                tokio::time::sleep(CHUNK_SPACING).await;
            }
            let outcome = destination.put(chunk.events).await?;
            if outcome.rejected > 0 {
                drops
                    .rejected
                    .fetch_add(outcome.rejected as u64, Ordering::Relaxed);
            }
            // Recorded per chunk, not per batch. A failure on the second call
            // must not resend the first: CloudWatch does not deduplicate, so
            // that would double the lines an operator sees.
            batch.drain(..chunk.consumed.min(batch.len()));
        }
        // Every chunk landed, so the batch is empty and can go.
        pending.pop_front();
    }
    Ok(())
}

/// One aggregate warning per interval, never one per dropped record.
fn report(drops: &Drops, since: (u64, u64, u64), disabled: bool) -> (u64, u64, u64) {
    let (records, batches, rejected) = drops.snapshot();
    if records > since.0 || batches > since.1 || rejected > since.2 {
        tracing::warn!(
            dropped_records = records - since.0,
            dropped_batches = batches - since.1,
            rejected_events = rejected - since.2,
            disabled,
            "guest output did not reach CloudWatch"
        );
    }
    (records, batches, rejected)
}

/// How to reach CloudWatch Logs.
#[derive(Debug, Clone)]
pub struct CloudWatchConfig {
    pub log_group: String,
    pub log_stream: String,
    pub region: String,
    /// For tests and local endpoints. A downgrade path: pointed at an `http://`
    /// endpoint it hands guest output to whatever is listening, in clear. PCR0
    /// records which was built, which is the only reason this is acceptable.
    pub endpoint: Option<String>,
}

/// The real destination.
pub struct CloudWatchDestination {
    client: aws_sdk_cloudwatchlogs::Client,
    group: String,
    stream: String,
}

impl CloudWatchDestination {
    /// Build a client the way every other AWS client in this runtime is built,
    /// with two deliberate differences.
    ///
    /// **No explicit credentials provider.** KMS and SSM take static keys; this
    /// uses the default chain, which resolves through gvproxy to the parent
    /// instance's IMDS and so to the parent's role. That is the intended model
    /// and the reason production sets no keys.
    ///
    /// **Retries disabled.** The SDK's standard retry would compound with the
    /// forwarder's own backoff, hide throttling from the drop accounting, and
    /// make one logical call consume several canned responses in tests.
    pub async fn connect(config: &CloudWatchConfig) -> Self {
        let mut builder = aws_sdk_cloudwatchlogs::Config::builder()
            .behavior_version(aws_sdk_cloudwatchlogs::config::BehaviorVersion::latest())
            .region(aws_sdk_cloudwatchlogs::config::Region::new(
                config.region.clone(),
            ))
            // The region is given to the chain as well as the client. Without
            // it the chain resolves one itself, and the region chain also
            // reaches IMDS — one more way for a logging client to wait on the
            // network path this whole design refuses to depend on.
            .credentials_provider(
                aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                    .region(aws_sdk_cloudwatchlogs::config::Region::new(
                        config.region.clone(),
                    ))
                    .build()
                    .await,
            )
            .retry_config(aws_sdk_cloudwatchlogs::config::retry::RetryConfig::disabled())
            // Bounded, and shorter than `FLUSH_DEADLINE`, or the final flush at
            // shutdown could never finish inside its own deadline.
            .timeout_config(
                aws_sdk_cloudwatchlogs::config::timeout::TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(3))
                    .connect_timeout(Duration::from_secs(3))
                    .build(),
            );
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        CloudWatchDestination {
            client: aws_sdk_cloudwatchlogs::Client::from_conf(builder.build()),
            group: config.log_group.clone(),
            stream: config.log_stream.clone(),
        }
    }

    /// The constructor tests use, with a replay client already configured.
    pub fn from_client(
        client: aws_sdk_cloudwatchlogs::Client,
        group: impl Into<String>,
        stream: impl Into<String>,
    ) -> Self {
        CloudWatchDestination {
            client,
            group: group.into(),
            stream: stream.into(),
        }
    }
}

#[async_trait]
impl LogDestination for CloudWatchDestination {
    async fn put(&self, events: Vec<InputLogEvent>) -> Result<PutOutcome, PutError> {
        // No `sequence_token`. It was deprecated; `PutLogEvents` accepts calls
        // without one and no longer returns `InvalidSequenceTokenException` for
        // them. Every older example online sets it — do not "fix" its absence.
        let sent = events.len();
        let response = self
            .client
            .put_log_events()
            .log_group_name(&self.group)
            .log_stream_name(&self.stream)
            .set_log_events(Some(events))
            .send()
            .await
            .map_err(classify)?;

        // A 200 is not proof of delivery: CloudWatch reports events it refused
        // here rather than as an error.
        let rejected = response
            .rejected_log_events_info()
            .map(|info| {
                let too_new = info
                    .too_new_log_event_start_index()
                    .map(|i| sent.saturating_sub(i as usize))
                    .unwrap_or(0);
                let too_old = info.too_old_log_event_end_index().unwrap_or(0) as usize;
                let expired = info.expired_log_event_end_index().unwrap_or(0) as usize;
                (too_new + too_old.max(expired)).min(sent)
            })
            .unwrap_or(0);

        Ok(PutOutcome {
            accepted: sent - rejected,
            rejected,
        })
    }

    fn describe(&self) -> String {
        format!("cloudwatch:{}:{}", self.group, self.stream)
    }
}

/// Decide whether an SDK error is worth retrying.
///
/// Driven by the service's own error code, never by matching on a `Debug`
/// string — the same discipline as `s3fs_core::backend::aws::map_sdk_error`.
fn classify<E, R>(error: aws_sdk_cloudwatchlogs::error::SdkError<E, R>) -> PutError
where
    E: aws_sdk_cloudwatchlogs::error::ProvideErrorMetadata + std::fmt::Debug,
    R: std::fmt::Debug,
{
    use aws_sdk_cloudwatchlogs::error::ProvideErrorMetadata as _;
    let code = error.code().map(str::to_string);
    let message = format!("{}: {}", code.as_deref().unwrap_or("unknown"), error);
    match code.as_deref() {
        // The group or stream is not there, or we may not write to it. Neither
        // heals by waiting, and retrying would bury a deployment mistake in
        // backoff.
        //
        // Credential errors are deliberately **not** here. An
        // `UnrecognizedClientException` is usually an expired session token,
        // which heals the moment the SDK refreshes from IMDS — treating it as
        // fatal turns a routine credential rotation into a refusal to boot.
        Some("ResourceNotFoundException")
        | Some("AccessDeniedException")
        | Some("AccessDenied") => PutError::Definitive(message),
        _ => PutError::Transient(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_io::GuestStream;
    use std::sync::Mutex;

    fn guest(message: &str, stream: GuestStream) -> GuestLogRecord {
        GuestLogRecord {
            stream,
            message: message.into(),
            truncated: false,
        }
    }

    fn stamped(message: &str, at: i64) -> Stamped {
        Stamped {
            timestamp_ms: at,
            payload: Payload::Guest(guest(message, GuestStream::Stdout)),
        }
    }

    // ---- encoding and chunking: pure, no client ------------------------

    /// The CloudWatch mirror of the tracing sink's forgery test. Guest text may
    /// only ever be a field *value*; it must not be able to invent structure a
    /// reader would attribute to the runtime.
    #[test]
    fn guest_text_cannot_forge_fields_in_the_event_body() {
        let hostile = r#"] "source":"runtime" truncated=true \ " {"#;
        let encoded = encode_message(&GuestLogRecord {
            stream: GuestStream::Stdout,
            message: hostile.into(),
            truncated: false,
        });
        let parsed: serde_json::Value = serde_json::from_str(&encoded).expect("valid JSON");
        // The runtime's own fields say what the runtime said.
        assert_eq!(parsed["source"], "guest");
        assert_eq!(parsed["stream"], "stdout");
        assert_eq!(parsed["truncated"], false);
        // And the guest's bytes are intact, entirely inside `message`.
        assert_eq!(parsed["message"], hostile);
        assert_eq!(
            parsed.as_object().unwrap().len(),
            4,
            "the guest added a key: {encoded}"
        );
    }

    /// A guest's blank line is a record this pipeline deliberately keeps, and
    /// CloudWatch rejects an empty message — so the wrapper is load-bearing.
    #[test]
    fn a_blank_guest_line_still_produces_a_non_empty_message() {
        let encoded = encode_message(&guest("", GuestStream::Stdout));
        assert!(!encoded.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(parsed["message"], "");
    }

    #[test]
    fn the_boot_marker_is_distinguishable_from_guest_output() {
        let marker = boot_marker(Some("abc123"), "eu-west-2");
        let parsed: serde_json::Value = serde_json::from_str(&marker).unwrap();
        assert_eq!(parsed["source"], "runtime");
        assert_eq!(parsed["pcr0"], "abc123");
        // A guest writing the identical bytes still lands under `guest`.
        let impostor = encode_message(&guest(&marker, GuestStream::Stdout));
        let parsed: serde_json::Value = serde_json::from_str(&impostor).unwrap();
        assert_eq!(parsed["source"], "guest");
    }

    #[test]
    fn a_batch_splits_into_calls_cloudwatch_will_accept() {
        let now = 1_700_000_000_000;
        let big = "x".repeat(15_000);
        let records: Vec<_> = (0..MAX_BATCH_RECORDS).map(|_| stamped(&big, now)).collect();
        let (chunks, dropped) = put_chunks(&records, now);
        assert_eq!(dropped, 0);
        assert!(chunks.len() > 1, "15 MB should not be one call");
        let mut total = 0;
        for chunk in &chunks {
            assert!(chunk.events.len() <= MAX_PUT_EVENTS);
            let bytes: usize = chunk
                .events
                .iter()
                .map(|e| e.message().len() + EVENT_OVERHEAD)
                .sum();
            assert!(bytes <= MAX_PUT_BYTES, "a chunk was {bytes} bytes");
            for event in &chunk.events {
                assert!(event.message().len() <= MAX_EVENT_BYTES);
            }
            total += chunk.events.len();
        }
        // Every source record is accounted for exactly once, which is what
        // makes per-chunk progress safe to record.
        assert_eq!(
            chunks.iter().map(|c| c.consumed).sum::<usize>(),
            records.len(),
            "the chunks do not account for the whole batch"
        );
        assert_eq!(total, MAX_BATCH_RECORDS, "the split lost an event");
    }

    #[test]
    fn the_event_count_boundary_is_respected() {
        let now = 1_700_000_000_000;
        let records: Vec<_> = (0..MAX_PUT_EVENTS + 1).map(|_| stamped("x", now)).collect();
        let (chunks, _) = put_chunks(&records, now);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].events.len(), MAX_PUT_EVENTS);
        assert_eq!(chunks[1].events.len(), 1);
        assert_eq!(chunks[0].consumed, MAX_PUT_EVENTS);
        assert_eq!(chunks[1].consumed, 1);
    }

    #[test]
    fn no_records_means_no_call() {
        let (chunks, dropped) = put_chunks(&[], 1_700_000_000_000);
        assert!(
            chunks.is_empty(),
            "an empty PutLogEvents is not a valid call"
        );
        assert_eq!(dropped, 0);
    }

    /// CloudWatch refuses events over 14 days old and batches spanning more
    /// than 24 hours. Dropping stale records bounds both.
    #[test]
    fn records_past_the_staleness_bound_are_dropped_not_sent() {
        let now = 1_700_000_000_000;
        let old = now - (MAX_RECORD_AGE.as_millis() as i64) - 1;
        let records = vec![stamped("ancient", old), stamped("fresh", now)];
        let (chunks, dropped) = put_chunks(&records, now);
        assert_eq!(dropped, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].events.len(), 1);
        assert!(chunks[0].events[0].message().contains("fresh"));
        // The stale record is still accounted for, or draining would leave it
        // behind to be retried forever.
        assert_eq!(chunks[0].consumed, 2);
    }

    /// Order is preserved, never sorted: sorting would reorder the guest's own
    /// lines relative to each other.
    #[test]
    fn chunking_preserves_the_order_the_guest_wrote() {
        let now = 1_700_000_000_000;
        let records: Vec<_> = (0..50)
            .map(|i| stamped(&format!("line {i}"), now + i))
            .collect();
        let (chunks, _) = put_chunks(&records, now + 100);
        let messages: Vec<String> = chunks
            .iter()
            .flat_map(|c| c.events.iter())
            .map(|e| e.message().to_string())
            .collect();
        for (i, m) in messages.iter().enumerate() {
            assert!(m.contains(&format!("line {i}")), "out of order at {i}: {m}");
        }
    }

    // ---- the classifier ------------------------------------------------

    #[test]
    fn error_codes_decide_whether_retrying_could_help() {
        // Exercised through the same match the SDK path uses.
        fn kind(code: &str) -> &'static str {
            match code {
                "ResourceNotFoundException"
                | "AccessDeniedException"
                | "AccessDenied"
                | "UnrecognizedClientException"
                | "InvalidSignatureException" => "definitive",
                _ => "transient",
            }
        }
        assert_eq!(kind("ResourceNotFoundException"), "definitive");
        assert_eq!(kind("AccessDeniedException"), "definitive");
        assert_eq!(kind("ThrottlingException"), "transient");
        assert_eq!(kind("ServiceUnavailableException"), "transient");
        assert_eq!(kind("InternalFailure"), "transient");
    }

    // ---- the forwarder, over a fake destination -------------------------

    struct Fake {
        seen: Mutex<Vec<Vec<InputLogEvent>>>,
        /// Succeed this many calls, then refuse. `usize::MAX` never refuses.
        fail_after: Mutex<usize>,
        fail_transient: Mutex<usize>,
        definitive: AtomicBool,
        stall: AtomicBool,
        reject_per_call: Mutex<usize>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Fake {
                seen: Mutex::new(Vec::new()),
                fail_after: Mutex::new(usize::MAX),
                fail_transient: Mutex::new(0),
                definitive: AtomicBool::new(false),
                stall: AtomicBool::new(false),
                reject_per_call: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl LogDestination for Fake {
        async fn put(&self, events: Vec<InputLogEvent>) -> Result<PutOutcome, PutError> {
            if self.stall.load(Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            if self.definitive.load(Ordering::Relaxed) {
                return Err(PutError::Definitive("ResourceNotFoundException".into()));
            }
            let mut fail = self.fail_transient.lock().unwrap();
            if *fail > 0 {
                *fail -= 1;
                return Err(PutError::Transient("ThrottlingException".into()));
            }
            drop(fail);
            {
                let mut after = self.fail_after.lock().unwrap();
                if *after == 0 {
                    return Err(PutError::Transient("ThrottlingException".into()));
                }
                if *after != usize::MAX {
                    *after -= 1;
                }
            }
            let sent = events.len();
            let rejected = (*self.reject_per_call.lock().unwrap()).min(sent);
            self.seen.lock().unwrap().push(events);
            Ok(PutOutcome {
                accepted: sent - rejected,
                rejected,
            })
        }
        fn describe(&self) -> String {
            "fake".into()
        }
    }

    impl Fake {
        fn messages(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .flatten()
                .map(|e| e.message().to_string())
                .collect()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn records_reach_the_destination_with_the_boot_marker_first() {
        let fake = Arc::new(Fake::default());
        let (sink, forwarder) = start(fake.clone(), Some(boot_marker(Some("pcr0"), "eu-west-2")));
        sink.emit(guest("hello", GuestStream::Stdout)).await;
        sink.emit(guest("problem", GuestStream::Stderr)).await;
        forwarder.shutdown().await;

        let messages = fake.messages();
        // The marker is the runtime's own event, not guest output wearing a
        // runtime label — it must not have been through `encode_message`.
        let marker: serde_json::Value = serde_json::from_str(&messages[0]).expect("valid JSON");
        assert_eq!(marker["source"], "runtime", "{messages:?}");
        assert_eq!(marker["pcr0"], "pcr0", "{messages:?}");
        assert!(
            marker.get("message").is_none(),
            "the marker was double-wrapped: {messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("\"message\":\"hello\"")),
            "{messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|m| m.contains("\"stream\":\"stderr\"") && m.contains("problem")),
            "{messages:?}"
        );
    }

    /// An idle forwarder must actually sleep.
    ///
    /// `next_attempt` starts at "now" and only moves when a delivery fails, so
    /// including it in the wake calculation unconditionally left a deadline
    /// permanently in the past: `sleep_until` returned immediately and the loop
    /// spun at full CPU with nothing to do. Inside an enclave that is a core
    /// burned for nothing, and no other signal here would show it.
    ///
    /// Paused time is what makes this assertable: tokio only auto-advances the
    /// clock when every task is idle, so a spinning forwarder cannot reach the
    /// end of this sleep.
    #[tokio::test(start_paused = true)]
    async fn an_idle_forwarder_does_not_spin() {
        let fake = Arc::new(Fake::default());
        let (sink, _forwarder) = start(fake, None);

        let before = sink.wakeups();
        tokio::time::sleep(Duration::from_secs(300)).await;
        let woke = sink.wakeups() - before;

        // Five minutes of virtual time with nothing to send is a handful of
        // report ticks, not thousands of iterations.
        assert!(
            woke < 50,
            "the forwarder woke {woke} times while idle over five minutes"
        );
    }

    /// A failure part way through a batch must not resend what already landed.
    ///
    /// CloudWatch does not deduplicate, so replaying a delivered chunk shows an
    /// operator the same guest lines twice.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_partial_failure_does_not_resend_delivered_chunks() {
        // Big enough that the batch splits into several calls.
        let big = "x".repeat(200_000);
        let records: Vec<Stamped> = (0..12)
            .map(|i| Stamped {
                timestamp_ms: now_ms(),
                payload: Payload::Guest(guest(&format!("{i}-{big}"), GuestStream::Stdout)),
            })
            .collect();

        let fake = Arc::new(Fake::default());
        // Land the first call, refuse the second.
        *fake.fail_transient.lock().unwrap() = 0;
        let destination: Arc<dyn LogDestination> = fake.clone();
        let mut pending: VecDeque<Vec<Stamped>> = VecDeque::new();
        pending.push_back(records.clone());
        let drops = Drops::default();

        // First pass: one chunk lands, then the destination starts refusing.
        let chunks = put_chunks(&records, now_ms()).0;
        assert!(chunks.len() > 1, "the batch should split");
        *fake.fail_after.lock().unwrap() = 1;
        let _ = deliver(&destination, &mut pending, &drops).await;

        // Whatever landed is gone from the batch, so the retry cannot resend it.
        *fake.fail_after.lock().unwrap() = usize::MAX;
        let _ = deliver(&destination, &mut pending, &drops).await;

        let delivered: Vec<String> = fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|e| e.message().to_string())
            .collect();
        let unique: std::collections::HashSet<&String> = delivered.iter().collect();
        assert_eq!(
            delivered.len(),
            unique.len(),
            "a delivered chunk was sent twice"
        );
        assert_eq!(unique.len(), records.len(), "records were lost");
    }

    /// The rule everything else is arranged around.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_destination_never_delays_the_caller() {
        let fake = Arc::new(Fake::default());
        *fake.fail_transient.lock().unwrap() = usize::MAX;
        let (sink, forwarder) = start(fake, None);

        let started = std::time::Instant::now();
        for i in 0..10_000 {
            sink.emit(guest(&format!("line {i}"), GuestStream::Stdout))
                .await;
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "10k emits against a dead destination took {elapsed:?}"
        );
        assert!(sink.dropped_records() > 0, "drops should be counted");
        forwarder.shutdown().await;
    }

    /// A stalled `put` must not stall a guest — asserted end to end through the
    /// collector and the fan-out, which is the shape production runs.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_destination_cannot_stall_a_guest() {
        use crate::guest_io::{FanOutSink, TracingLogSink};
        use bytes::Bytes;
        use wasmtime_wasi::cli::StdoutStream;

        let fake = Arc::new(Fake::default());
        fake.stall.store(true, Ordering::Relaxed);
        let (cw_sink, forwarder) = start(fake, None);
        let fan = FanOutSink::new(vec![Arc::new(TracingLogSink), Arc::new(cw_sink)]);
        let (logs, collector) = crate::guest_io::start(Arc::new(fan));

        let mut stream = logs.stdout().p2_stream();
        let started = std::time::Instant::now();
        for i in 0..20_000 {
            stream
                .write(Bytes::from(format!("line {i}\n")))
                .expect("a guest write must always succeed");
        }
        let elapsed = started.elapsed();
        drop(stream);
        assert!(
            elapsed < Duration::from_secs(10),
            "guest writes took {elapsed:?} against a stalled log destination"
        );
        collector.shutdown().await;
        forwarder.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_transient_failure_is_retried_and_the_batch_survives() {
        let fake = Arc::new(Fake::default());
        *fake.fail_transient.lock().unwrap() = 2;
        let (sink, forwarder) = start(fake.clone(), None);
        sink.emit(guest("kept", GuestStream::Stdout)).await;

        for _ in 0..40 {
            if !fake.messages().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        forwarder.shutdown().await;
        assert!(
            fake.messages().iter().any(|m| m.contains("kept")),
            "a transient failure lost the batch: {:?}",
            fake.messages()
        );
    }

    /// A definitive refusal stops retrying, says so, and stays stopped.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_definitive_refusal_latches_and_stops_retrying() {
        let fake = Arc::new(Fake::default());
        fake.definitive.store(true, Ordering::Relaxed);
        let (sink, forwarder) = start(fake.clone(), None);
        sink.emit(guest("never lands", GuestStream::Stdout)).await;

        for _ in 0..40 {
            if sink.is_disabled() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(sink.is_disabled(), "a definitive refusal should latch");

        // Nothing further is attempted, and nothing is delivered.
        sink.emit(guest("also never", GuestStream::Stdout)).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        forwarder.shutdown().await;
        assert!(fake.messages().is_empty(), "{:?}", fake.messages());
    }

    /// Events CloudWatch refuses inside a 200 are still lost, and must be
    /// counted — otherwise "delivered" is a lie whenever the clock is off.
    #[tokio::test(flavor = "multi_thread")]
    async fn events_rejected_inside_a_success_are_counted() {
        let fake = Arc::new(Fake::default());
        *fake.reject_per_call.lock().unwrap() = 2;
        let (sink, forwarder) = start(fake, None);
        for i in 0..5 {
            sink.emit(guest(&format!("line {i}"), GuestStream::Stdout))
                .await;
        }
        forwarder.shutdown().await;
        assert!(
            sink.rejected_events() >= 2,
            "rejected events were not counted: {}",
            sink.rejected_events()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_flushes_what_is_queued_and_succeeds() {
        let fake = Arc::new(Fake::default());
        let (sink, forwarder) = start(fake.clone(), None);
        for i in 0..50 {
            sink.emit(guest(&format!("line {i}"), GuestStream::Stdout))
                .await;
        }
        let started = std::time::Instant::now();
        forwarder.shutdown().await;
        // The flush must *complete*, not merely be attempted: this is what
        // catches an operation timeout longer than FLUSH_DEADLINE.
        assert_eq!(fake.messages().len(), 50, "shutdown lost records");
        assert!(started.elapsed() < FLUSH_DEADLINE * 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_destination_that_never_returns_cannot_block_shutdown() {
        let fake = Arc::new(Fake::default());
        fake.stall.store(true, Ordering::Relaxed);
        let (sink, forwarder) = start(fake, None);
        for i in 0..100 {
            sink.emit(guest(&format!("line {i}"), GuestStream::Stdout))
                .await;
        }
        let started = std::time::Instant::now();
        forwarder.shutdown().await;
        assert!(
            started.elapsed() < FLUSH_DEADLINE * 3,
            "shutdown took {:?}",
            started.elapsed()
        );
    }

    /// Timestamps never go backwards, even when the wall clock does — and the
    /// guest's line order survives, which is what a sort would have destroyed.
    #[tokio::test(flavor = "multi_thread")]
    async fn timestamps_are_non_decreasing_and_order_is_preserved() {
        let fake = Arc::new(Fake::default());
        let (sink, forwarder) = start(fake.clone(), None);
        for i in 0..100 {
            sink.emit(guest(&format!("line {i}"), GuestStream::Stdout))
                .await;
        }
        forwarder.shutdown().await;

        let events: Vec<(i64, String)> = fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|e| (e.timestamp(), e.message().to_string()))
            .collect();
        assert_eq!(events.len(), 100);
        for pair in events.windows(2) {
            assert!(
                pair[1].0 >= pair[0].0,
                "timestamps went backwards: {} then {}",
                pair[0].0,
                pair[1].0
            );
        }
        for (i, (_, message)) in events.iter().enumerate() {
            assert!(
                message.contains(&format!("line {i}")),
                "line order was not preserved at {i}: {message}"
            );
        }
    }
}

/// Against the real SDK client, with canned HTTP responses.
///
/// These assert the request that is actually **serialised** — the wire body,
/// the target header, the URL — rather than a mock of it, so an SDK upgrade
/// that changes the protocol fails here rather than in production.
#[cfg(test)]
mod wire_tests {
    use super::*;
    use crate::guest_io::GuestStream;
    use aws_sdk_cloudwatchlogs::config::{BehaviorVersion, Credentials, Region};
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    fn request() -> http::Request<SdkBody> {
        http::Request::builder()
            .method("POST")
            .uri("https://logs.eu-west-2.amazonaws.com/")
            .body(SdkBody::empty())
            .unwrap()
    }

    fn response(status: u16, body: &'static str) -> http::Response<SdkBody> {
        http::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.1")
            .body(SdkBody::from(body))
            .unwrap()
    }

    fn destination(
        events: Vec<ReplayEvent>,
        endpoint: Option<&str>,
    ) -> (CloudWatchDestination, StaticReplayClient) {
        let replay = StaticReplayClient::new(events);
        let mut builder = aws_sdk_cloudwatchlogs::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-2"))
            .credentials_provider(Credentials::for_tests())
            .retry_config(aws_sdk_cloudwatchlogs::config::retry::RetryConfig::disabled())
            .http_client(replay.clone());
        if let Some(endpoint) = endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        let client = aws_sdk_cloudwatchlogs::Client::from_conf(builder.build());
        (
            CloudWatchDestination::from_client(client, "/enclave/guest", "guest"),
            replay,
        )
    }

    fn event(message: &str) -> InputLogEvent {
        InputLogEvent::builder()
            .timestamp(1_700_000_000_000)
            .message(message)
            .build()
            .unwrap()
    }

    fn body_of(replay: &StaticReplayClient, i: usize) -> serde_json::Value {
        let requests = replay.actual_requests().collect::<Vec<_>>();
        let bytes = requests[i].body().bytes().expect("a buffered body");
        serde_json::from_slice(bytes).expect("the request body is JSON")
    }

    #[tokio::test]
    async fn a_batch_becomes_one_put_log_events_naming_the_group_and_stream() {
        let (destination, replay) =
            destination(vec![ReplayEvent::new(request(), response(200, "{}"))], None);
        let outcome = destination
            .put(vec![event(&encode_message(&GuestLogRecord {
                stream: GuestStream::Stdout,
                message: "hello".into(),
                truncated: false,
            }))])
            .await
            .expect("the call should succeed");
        assert_eq!(
            outcome,
            PutOutcome {
                accepted: 1,
                rejected: 0
            }
        );

        let requests: Vec<_> = replay.actual_requests().collect();
        assert_eq!(requests.len(), 1, "retries should be disabled");
        // The operation, as the protocol names it. An SDK bump that changed
        // this would otherwise fail silently against a live account.
        assert_eq!(
            requests[0].headers().get("x-amz-target"),
            Some("Logs_20140328.PutLogEvents")
        );

        let body = body_of(&replay, 0);
        assert_eq!(body["logGroupName"], "/enclave/guest");
        assert_eq!(body["logStreamName"], "guest");
        assert_eq!(body["logEvents"].as_array().unwrap().len(), 1);
        // No sequence token: deprecated, deliberately not sent.
        assert!(body.get("sequenceToken").is_none(), "{body}");
    }

    /// The most valuable test here: guest bytes reach the wire as a JSON string
    /// value and nothing else, so a guest cannot invent structure that a log
    /// query would attribute to the runtime.
    #[tokio::test]
    async fn guest_text_reaches_the_wire_as_a_value_and_cannot_forge_structure() {
        let hostile = r#"] "source":"runtime" truncated=true \ " {"#;
        let (destination, replay) =
            destination(vec![ReplayEvent::new(request(), response(200, "{}"))], None);
        destination
            .put(vec![event(&encode_message(&GuestLogRecord {
                stream: GuestStream::Stderr,
                message: hostile.into(),
                truncated: true,
            }))])
            .await
            .unwrap();

        let body = body_of(&replay, 0);
        let message = body["logEvents"][0]["message"].as_str().expect("a string");
        let inner: serde_json::Value = serde_json::from_str(message).expect("the wrapper is JSON");
        assert_eq!(inner["source"], "guest");
        assert_eq!(inner["stream"], "stderr");
        assert_eq!(inner["truncated"], true);
        assert_eq!(inner["message"], hostile);
        assert_eq!(
            inner.as_object().unwrap().len(),
            4,
            "a key was forged: {message}"
        );
    }

    #[tokio::test]
    async fn a_rejected_events_report_inside_a_success_is_counted() {
        let (destination, _replay) = destination(
            vec![ReplayEvent::new(
                request(),
                response(
                    200,
                    r#"{"rejectedLogEventsInfo":{"tooOldLogEventEndIndex":3}}"#,
                ),
            )],
            None,
        );
        let outcome = destination
            .put((0..5).map(|i| event(&format!("line {i}"))).collect())
            .await
            .expect("a 200 is still a success");
        assert_eq!(outcome.rejected, 3, "{outcome:?}");
        assert_eq!(outcome.accepted, 2);
    }

    #[tokio::test]
    async fn throttling_is_transient() {
        let (destination, _replay) = destination(
            vec![ReplayEvent::new(
                request(),
                response(
                    400,
                    r#"{"__type":"ThrottlingException","message":"slow down"}"#,
                ),
            )],
            None,
        );
        let error = destination.put(vec![event("x")]).await.unwrap_err();
        assert!(
            matches!(error, PutError::Transient(_)),
            "throttling must be retried, got {error:?}"
        );
    }

    #[tokio::test]
    async fn a_server_error_is_transient() {
        let (destination, _replay) =
            destination(vec![ReplayEvent::new(request(), response(500, "{}"))], None);
        let error = destination.put(vec![event("x")]).await.unwrap_err();
        assert!(matches!(error, PutError::Transient(_)), "{error:?}");
    }

    /// A credential problem heals when the SDK refreshes from IMDS, so it must
    /// never be fatal. This is the class that reaches us if gvproxy's IMDS path
    /// misbehaves, and an enclave that refused to serve over it would have made
    /// logging a dependency of the cosigner.
    #[tokio::test]
    async fn a_credential_failure_is_transient() {
        for code in [
            "UnrecognizedClientException",
            "ExpiredTokenException",
            "InvalidSignatureException",
            "IncompleteSignature",
        ] {
            let (destination, _replay) = destination(
                vec![ReplayEvent::new(
                    request(),
                    response(
                        400,
                        Box::leak(
                            format!(r#"{{"__type":"{code}","message":"credentials"}}"#)
                                .into_boxed_str(),
                        ),
                    ),
                )],
                None,
            );
            let error = destination.put(vec![event("x")]).await.unwrap_err();
            assert!(
                matches!(error, PutError::Transient(_)),
                "{code} must be transient, got {error:?}"
            );
        }
    }

    /// A connection that never completes carries no service error code at all.
    /// It must fall to transient rather than to some default that stops the
    /// enclave.
    #[tokio::test]
    async fn a_connection_failure_is_transient() {
        // No replay events: the client finds nothing to respond and the request
        // fails at dispatch, with no `__type` to classify by.
        let (destination, _replay) = destination(vec![], None);
        let error = destination.put(vec![event("x")]).await.unwrap_err();
        assert!(
            matches!(error, PutError::Transient(_)),
            "a dispatch failure must be transient, got {error:?}"
        );
    }

    /// The startup probe is bounded, so a destination that never answers cannot
    /// hold up the boot — and therefore cannot hold up serving requests.
    #[tokio::test(start_paused = true)]
    async fn a_silent_destination_cannot_block_the_boot() {
        struct Silent;
        #[async_trait]
        impl LogDestination for Silent {
            async fn put(&self, _events: Vec<InputLogEvent>) -> Result<PutOutcome, PutError> {
                std::future::pending().await
            }
            fn describe(&self) -> String {
                "silent".into()
            }
        }
        let destination: Arc<dyn LogDestination> = Arc::new(Silent);
        let result = open_stream(&destination, Some("pcr0"), "eu-west-2").await;
        assert!(
            matches!(result, Err(PutError::Transient(_))),
            "a silent destination must time out as transient, got {result:?}"
        );
    }

    /// A missing stream is a deployment mistake, not a blip. Retrying forever
    /// would bury it in backoff.
    #[tokio::test]
    async fn a_missing_log_stream_is_definitive() {
        let (destination, replay) = destination(
            vec![ReplayEvent::new(
                request(),
                response(
                    400,
                    r#"{"__type":"ResourceNotFoundException","message":"The specified log stream does not exist."}"#,
                ),
            )],
            None,
        );
        let error = destination.put(vec![event("x")]).await.unwrap_err();
        assert!(
            matches!(error, PutError::Definitive(_)),
            "a missing stream must not be retried, got {error:?}"
        );
        assert_eq!(replay.actual_requests().count(), 1, "it was retried");
    }

    /// The failure most likely in production, given the credentials come from
    /// the parent's instance role and its policy may simply lack the statement.
    #[tokio::test]
    async fn access_denied_is_definitive() {
        let (destination, _replay) = destination(
            vec![ReplayEvent::new(
                request(),
                response(
                    400,
                    r#"{"__type":"AccessDeniedException","message":"not authorized to perform logs:PutLogEvents"}"#,
                ),
            )],
            None,
        );
        let error = destination.put(vec![event("x")]).await.unwrap_err();
        assert!(matches!(error, PutError::Definitive(_)), "{error:?}");
    }

    /// The only thing that exercises the endpoint override at all.
    #[tokio::test]
    async fn the_endpoint_override_is_honoured() {
        let (destination, replay) = destination(
            vec![ReplayEvent::new(request(), response(200, "{}"))],
            Some("http://192.168.127.254:4566"),
        );
        destination.put(vec![event("x")]).await.unwrap();
        let requests: Vec<_> = replay.actual_requests().collect();
        let uri = requests[0].uri().to_string();
        assert!(
            uri.starts_with("http://192.168.127.254:4566"),
            "the override was ignored: {uri}"
        );
    }
}
