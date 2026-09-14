//! Guest stdout and stderr, framed into bounded records and handed to the
//! runtime's own logging pipeline.
//!
//! ```text
//!   guest write ──▶ GuestLogOutput ──▶ bounded mpsc ──▶ GuestLogCollector
//!                   (line framing,      (drop when        (owns the sink)
//!                    truncation)         full)                  │
//!                                                               ▼
//!                                                         GuestLogSink
//!                                                         └── TracingLogSink
//! ```
//!
//! # Guest output is attacker-controlled data
//!
//! Everything that arrives here was chosen by the guest. It is **not** a
//! runtime audit event and must never be read as one. A guest can emit
//! anything it likes, including text shaped exactly like this runtime's own
//! log lines, so the two are kept apart by the tracing *target*
//! ([`GUEST_LOG_TARGET`]) rather than by anything in the message. A filter on
//! that target separates trusted runtime events from untrusted guest output;
//! nothing in the message body is load-bearing.
//!
//! Guest text is never interpolated into an event name or a target, only into
//! a field value, so a guest cannot forge an event that looks like a different
//! kind of event.
//!
//! # Best-effort, and lossy under pressure
//!
//! A guest write must never wait on a log destination — not on this process's
//! collector, not on the parent instance, and not on CloudWatch. So the queue
//! is bounded and **records are dropped when it is full**. The guest sees a
//! successful write either way: logging congestion is a host concern and must
//! not become a guest-visible failure, let alone a stall.
//!
//! What that buys, and what it costs:
//!
//! - The guest cannot make the enclave allocate without bound by writing. Live
//!   memory is capped by the queue ([`LOG_QUEUE_CAPACITY`] records) plus one
//!   partial line per open stream ([`MAX_LOG_RECORD_BYTES`] each).
//! - A stalled or slow sink cannot stall a guest.
//! - There is **no delivery guarantee**. Output is lost when the queue fills,
//!   and output still queued is lost if the enclave stops abruptly. Drops are
//!   counted and reported in aggregate, never one warning per dropped write —
//!   which would hand a guest an amplification primitive against the very log
//!   it is congesting.
//!
//! Delivery beyond the console is a separate concern behind [`GuestLogSink`],
//! and nothing here should be treated as an authenticated record of what a
//! guest did: the content is guest-chosen whatever carries it.

pub mod cloudwatch;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{mpsc, Notify};
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
use wasmtime_wasi::p2::{OutputStream, Pollable, StreamResult};

/// The tracing target every guest-produced event carries.
///
/// The one thing separating untrusted guest output from the runtime's own
/// events. A subscriber can route or drop this target wholesale; a guest
/// cannot change it, because it is never derived from anything the guest
/// wrote.
pub const GUEST_LOG_TARGET: &str = "guest";

/// Records held between the guest and the collector before output is dropped.
///
/// Bounds live memory together with [`MAX_LOG_RECORD_BYTES`]: at most this
/// many records, each at most that large.
pub const LOG_QUEUE_CAPACITY: usize = 1024;

/// Ceiling on one emitted record. A longer line is cut here and marked
/// truncated rather than retained.
pub const MAX_LOG_RECORD_BYTES: usize = 16 * 1024;

/// The permit `check_write` advertises. A guest that respects it writes at
/// most this much per call; one that ignores it is still safe, because what
/// this module *retains* is bounded by [`MAX_LOG_RECORD_BYTES`] regardless of
/// how much arrives at once.
pub const MAX_WRITE_CHUNK_BYTES: usize = 16 * 1024;

/// How long a graceful shutdown will wait for queued records to drain.
///
/// Fixed and short: losing the tail of a log is a nuisance, and an enclave
/// that will not stop is an outage.
const DRAIN_DEADLINE: Duration = Duration::from_secs(2);

/// How often the collector reports dropped output, if any was dropped.
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// Which of the guest's two output streams a record came from.
///
/// Kept distinct all the way to the sink. A guest that writes a diagnostic to
/// stderr and data to stdout is making a distinction, and merging them would
/// destroy it — but note that this says only *which file descriptor* was
/// written to. It is not a severity, and none is inferred from the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestStream {
    Stdout,
    Stderr,
}

impl GuestStream {
    /// The value that appears in the `guest_stream` field.
    pub fn as_str(self) -> &'static str {
        match self {
            GuestStream::Stdout => "stdout",
            GuestStream::Stderr => "stderr",
        }
    }
}

/// One framed line of guest output.
///
/// Deliberately small. Metadata that would need request- or tenant-scope —
/// which tenant wrote this, which request it belonged to — is *not* here: it
/// is not available where the WASI context is built without widening that
/// seam, and inventing a path for it was out of scope for this change. When it
/// arrives it belongs on this struct, filled in by the collector.
///
/// Never carries credentials, tokens, challenges, request bodies or raw
/// configuration, because nothing on this path has access to any of them: the
/// only input is the bytes the guest itself wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLogRecord {
    pub stream: GuestStream,
    /// The line, minus its terminator. Invalid UTF-8 has been replaced
    /// lossily; empty is a legitimate value, because the guest wrote a blank
    /// line and that is worth keeping.
    pub message: String,
    /// The line was longer than [`MAX_LOG_RECORD_BYTES`] and what is here is a
    /// prefix. Explicit, so nothing downstream mistakes a cut line for what
    /// the guest actually wrote.
    pub truncated: bool,
}

/// Where framed guest output finally goes.
///
/// Async, and owned by the collector task — **never** called from a WASI
/// write. That is the whole point of the split: an implementation may take as
/// long as it likes without a guest ever waiting on it.
#[async_trait]
pub trait GuestLogSink: Send + Sync {
    async fn emit(&self, record: GuestLogRecord);
}

/// Emits guest output as structured tracing events under [`GUEST_LOG_TARGET`].
///
/// stderr is emitted at `warn` and stdout at `info`. That is a statement about
/// *which stream was written to*, not about what the text means: severity is
/// never inferred from guest-controlled content, because a guest could then
/// choose its own log level.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingLogSink;

#[async_trait]
impl GuestLogSink for TracingLogSink {
    async fn emit(&self, record: GuestLogRecord) {
        // `guest_message`, not `message`, and recorded as a `&str` rather than
        // through `%`. Both matter, and the enclave console is what showed it:
        //
        // `message` is the field name `tracing` gives an event's own text, so
        // using it put guest bytes *bare and unquoted* at the end of the line,
        // in the structured part, where a guest writing `truncated=true` would
        // render as a field nobody set. A `&str` field is printed quoted and
        // escaped, so guest text can only ever be one field's value —
        // `%` would have formatted it raw again and reopened the same hole.
        //
        // It is still only ever a field *value*: never the event name, never
        // the target.
        match record.stream {
            GuestStream::Stdout => tracing::info!(
                target: GUEST_LOG_TARGET,
                guest_stream = GuestStream::Stdout.as_str(),
                truncated = record.truncated,
                guest_message = record.message.as_str(),
                "guest output"
            ),
            GuestStream::Stderr => tracing::warn!(
                target: GUEST_LOG_TARGET,
                guest_stream = GuestStream::Stderr.as_str(),
                truncated = record.truncated,
                guest_message = record.message.as_str(),
                "guest output"
            ),
        }
    }
}

/// Sends every record to several sinks.
///
/// The console keeps working when a relay is configured. Guest output on the
/// enclave console is often the only thing available while a deployment is
/// being brought up — and the relay is precisely the part that may not work
/// yet — so forwarding is additive rather than a replacement.
///
/// Sinks run in order and a slow one delays the ones after it. That is the
/// collector's own budget to spend: it is already off the guest's path, and
/// none of it reaches a request.
pub struct FanOutSink {
    sinks: Vec<Arc<dyn GuestLogSink>>,
}

impl FanOutSink {
    pub fn new(sinks: Vec<Arc<dyn GuestLogSink>>) -> Self {
        FanOutSink { sinks }
    }
}

impl std::fmt::Debug for FanOutSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FanOutSink")
            .field("sinks", &self.sinks.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl GuestLogSink for FanOutSink {
    async fn emit(&self, record: GuestLogRecord) {
        // Cloned per sink because each takes ownership; a record is one line,
        // capped at `MAX_LOG_RECORD_BYTES`, and there are two sinks.
        for sink in &self.sinks {
            sink.emit(record.clone()).await;
        }
    }
}

/// Output that was lost, counted rather than logged one line at a time.
///
/// Two ways to lose output, and both belong here: a whole record dropped
/// because the queue was full, and the bytes past [`MAX_LOG_RECORD_BYTES`] cut
/// from a line that was too long. `records` counts only the first — a
/// truncated line still arrives, marked — while `bytes` counts what was
/// actually lost either way.
#[derive(Debug, Default)]
struct DropCounters {
    records: AtomicU64,
    bytes: AtomicU64,
}

impl DropCounters {
    fn record(&self, bytes: usize) {
        self.records.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64) {
        (
            self.records.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

/// The handle a [`crate::run::GuestEnvironment`] holds, and the factory every
/// guest instance takes its streams from.
///
/// Cheap to clone. Every stream it hands out feeds the same bounded queue and
/// the same collector, however many instances exist.
#[derive(Clone)]
pub struct GuestLogs {
    tx: mpsc::Sender<GuestLogRecord>,
    drops: Arc<DropCounters>,
}

impl std::fmt::Debug for GuestLogs {
    /// Never prints queued records: they are guest-controlled text, and a
    /// `Debug` that included them would put it in any log line that formatted
    /// a struct holding one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (records, bytes) = self.drops.snapshot();
        f.debug_struct("GuestLogs")
            .field("queue_capacity", &LOG_QUEUE_CAPACITY)
            .field("dropped_records", &records)
            .field("dropped_bytes", &bytes)
            .finish_non_exhaustive()
    }
}

impl GuestLogs {
    /// The guest's stdout, as something [`wasmtime_wasi::WasiCtxBuilder`]
    /// accepts.
    pub fn stdout(&self) -> GuestLogStdio {
        GuestLogStdio {
            stream: GuestStream::Stdout,
            tx: self.tx.clone(),
            drops: self.drops.clone(),
        }
    }

    /// The guest's stderr. `WasiCtxBuilder::stderr` also takes a
    /// [`StdoutStream`]; the name is wasmtime's, and the tagging here is what
    /// keeps the two apart.
    pub fn stderr(&self) -> GuestLogStdio {
        GuestLogStdio {
            stream: GuestStream::Stderr,
            tx: self.tx.clone(),
            drops: self.drops.clone(),
        }
    }

    /// Whole records dropped because the queue was full, since start.
    ///
    /// Does not count truncated lines: those still arrive, carrying
    /// [`GuestLogRecord::truncated`].
    pub fn dropped_records(&self) -> u64 {
        self.drops.snapshot().0
    }

    /// Bytes of guest output lost since start, whether to a full queue or to
    /// the per-record cap.
    pub fn dropped_bytes(&self) -> u64 {
        self.drops.snapshot().1
    }
}

/// Owns the collector task, so its lifetime is explicit rather than resting on
/// a sender that happens to still be alive somewhere.
///
/// Dropping this handle **detaches** the task rather than stopping it: the
/// collector keeps running for as long as any [`GuestLogs`] can still send, so
/// a caller that forgets to shut down loses no output. Only
/// [`GuestLogCollector::shutdown`] drains and stops.
pub struct GuestLogCollector {
    task: tokio::task::JoinHandle<()>,
    stop: Arc<Notify>,
}

impl std::fmt::Debug for GuestLogCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestLogCollector")
            .field("finished", &self.task.is_finished())
            .finish_non_exhaustive()
    }
}

impl GuestLogCollector {
    /// Drain what is queued and stop, within [`DRAIN_DEADLINE`].
    ///
    /// Bounded on purpose. Shutdown must not become dependent on a sink that
    /// has stopped making progress, so a collector that overruns is abandoned
    /// and the fact is logged.
    pub async fn shutdown(mut self) {
        // `notify_one`, not `notify_waiters`: it stores a permit when the task
        // has not yet registered, so a shutdown that races the collector's
        // first poll still stops it instead of waiting out the deadline.
        self.stop.notify_one();
        match tokio::time::timeout(DRAIN_DEADLINE, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "the guest log collector ended badly"),
            Err(_) => {
                tracing::warn!(
                    deadline = ?DRAIN_DEADLINE,
                    "the guest log collector did not drain in time; dropping queued guest output"
                );
                self.task.abort();
            }
        }
    }
}

/// Start the collector and return the handle guests write through.
///
/// Call this **before** any guest can run: the returned [`GuestLogs`] is what
/// builds a guest's streams, so no output can exist before the task that
/// consumes it.
///
/// The task ends when [`GuestLogCollector::shutdown`] is called, or when every
/// [`GuestLogs`] has been dropped — but do not rely on the latter for
/// shutdown, which is exactly why the handle is returned rather than detached.
pub fn start(sink: Arc<dyn GuestLogSink>) -> (GuestLogs, GuestLogCollector) {
    let (tx, mut rx) = mpsc::channel::<GuestLogRecord>(LOG_QUEUE_CAPACITY);
    let stop = Arc::new(Notify::new());
    let drops = Arc::new(DropCounters::default());

    let task = tokio::spawn({
        let drops = drops.clone();
        let stop = stop.clone();
        async move {
            let stopping = stop.notified();
            tokio::pin!(stopping);
            let mut report = tokio::time::interval(DROP_REPORT_INTERVAL);
            report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick completes immediately; nothing has been dropped
            // yet, so let it pass rather than reporting a zero.
            report.tick().await;
            let mut reported = (0u64, 0u64);

            loop {
                // Deliberately *not* `biased`. Polling records first starves the
                // other two branches whenever the queue is never empty —
                // which is exactly the sustained overload the drop report
                // exists to describe, so the report would go silent precisely
                // when it matters. Nothing is lost by letting shutdown win a
                // race: its branch drains the queue explicitly.
                tokio::select! {
                    received = rx.recv() => match received {
                        Some(record) => sink.emit(record).await,
                        // Every sender is gone, so nothing more can arrive.
                        None => break,
                    },
                    _ = report.tick() => {
                        reported = report_drops(&drops, reported);
                    }
                    _ = &mut stopping => {
                        // Whatever is already queued, then stop. Anything a
                        // still-running guest writes after this is dropped,
                        // which is the documented behaviour of a shutdown.
                        while let Ok(record) = rx.try_recv() {
                            sink.emit(record).await;
                        }
                        break;
                    }
                }
            }
            report_drops(&drops, reported);
        }
    });

    (GuestLogs { tx, drops }, GuestLogCollector { task, stop })
}

/// One aggregate warning per interval, never one per dropped write.
///
/// Returns the new high-water mark so the next report covers only what has
/// been dropped since.
fn report_drops(drops: &DropCounters, since: (u64, u64)) -> (u64, u64) {
    let (records, bytes) = drops.snapshot();
    // Either kind of loss is worth reporting: a guest can lose everything it
    // writes to truncation alone without a single record being dropped.
    if records > since.0 || bytes > since.1 {
        tracing::warn!(
            dropped_records = records - since.0,
            lost_bytes = bytes - since.1,
            total_dropped_records = records,
            "guest output was lost: the log queue was full, or lines exceeded the record cap"
        );
    }
    (records, bytes)
}

/// A guest stdio stream, as wasmtime's CLI layer wants it.
///
/// This is the *factory*. `p2_stream` and `async_stream` are called to make a
/// fresh object each time the guest asks for its stdout or stderr, and each of
/// those objects carries its own partial-line buffer — see [`LineFramer`].
#[derive(Clone)]
pub struct GuestLogStdio {
    stream: GuestStream,
    tx: mpsc::Sender<GuestLogRecord>,
    drops: Arc<DropCounters>,
}

impl std::fmt::Debug for GuestLogStdio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestLogStdio")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl GuestLogStdio {
    fn framer(&self) -> LineFramer {
        LineFramer::new(self.stream, self.tx.clone(), self.drops.clone())
    }
}

impl IsTerminal for GuestLogStdio {
    /// Never a terminal. There is no console in an enclave, and a guest told
    /// otherwise may enable colour escapes or line-editing behaviour that
    /// makes its output worse to read and no easier to parse.
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for GuestLogStdio {
    /// Implemented directly rather than through the default
    /// `AsyncWriteStream` adapter: writes here are pure local framing plus a
    /// non-blocking enqueue, so there is no readiness to model and no reason
    /// to pay for an intermediate buffer.
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(GuestLogOutput {
            framer: self.framer(),
        })
    }

    /// Present because the trait requires it. It frames identically, so a host
    /// that reaches for the `AsyncWrite` shape gets the same records.
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(GuestLogWriter {
            framer: self.framer(),
        })
    }
}

/// The `wasi:io/streams` output stream a guest actually writes into.
struct GuestLogOutput {
    framer: LineFramer,
}

#[async_trait]
impl Pollable for GuestLogOutput {
    /// Always ready. There is no destination to wait for — a write frames
    /// locally and enqueues or drops — so a guest never blocks on logging.
    async fn ready(&mut self) {}
}

impl OutputStream for GuestLogOutput {
    /// Constant, and never zero. Returning zero would make a guest poll for
    /// capacity that a full queue will never grant, which is the stall this
    /// design exists to avoid.
    fn check_write(&mut self) -> StreamResult<usize> {
        Ok(MAX_WRITE_CHUNK_BYTES)
    }

    /// Frames and enqueues, and always succeeds.
    ///
    /// A write that is dropped for congestion still reports success: the guest
    /// asked to write to its own stdout, and whether the *host* keeps that is
    /// not something the guest did wrong. Errors are reserved for the stream
    /// being unusable, which this one never is.
    fn write(&mut self, bytes: Bytes) -> StreamResult<()> {
        self.framer.push(&bytes);
        Ok(())
    }

    /// Local framing only.
    ///
    /// Deliberately **not** a flush of the partial line. A guest that writes
    /// `"foo"`, flushes, then writes `"bar\n"` wrote one line, and emitting
    /// `foo` here would split it. There is nothing else to flush: a completed
    /// line is enqueued the moment its terminator arrives, and the tail is
    /// emitted when the stream is dropped.
    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }
}

/// The `AsyncWrite` shape of the same thing.
struct GuestLogWriter {
    framer: LineFramer,
}

impl tokio::io::AsyncWrite for GuestLogWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.framer.push(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.framer.finish();
        std::task::Poll::Ready(Ok(()))
    }
}

/// Turns a byte stream into whole lines, one stream object at a time.
///
/// **Per stream object, deliberately.** `StdoutStream::p2_stream` hands out a
/// fresh object every time the guest asks for its stdout, and a guest may hold
/// several at once. Partial-line state kept in the shared factory would splice
/// two of those together into a line neither of them wrote; keeping it here
/// means an unfinished line belongs to exactly the stream that wrote it, and
/// goes away with it.
///
/// It also keeps the memory bound simple. The only thing retained between
/// writes is one partial line, capped at [`MAX_LOG_RECORD_BYTES`], so a guest
/// writing a gigabyte without a newline costs sixteen kilobytes and a
/// truncation flag.
struct LineFramer {
    stream: GuestStream,
    tx: mpsc::Sender<GuestLogRecord>,
    drops: Arc<DropCounters>,
    /// The line so far, never longer than [`MAX_LOG_RECORD_BYTES`].
    partial: Vec<u8>,
    /// The current line already exceeded the cap: keep the prefix, discard the
    /// rest until a terminator, and mark the record.
    overflowed: bool,
}

impl LineFramer {
    fn new(
        stream: GuestStream,
        tx: mpsc::Sender<GuestLogRecord>,
        drops: Arc<DropCounters>,
    ) -> Self {
        LineFramer {
            stream,
            tx,
            drops,
            partial: Vec::new(),
            overflowed: false,
        }
    }

    /// Absorb a write, emitting a record for every completed line in it.
    fn push(&mut self, mut bytes: &[u8]) {
        while let Some(at) = bytes.iter().position(|&b| b == b'\n') {
            self.extend(&bytes[..at]);
            self.emit();
            bytes = &bytes[at + 1..];
        }
        self.extend(bytes);
    }

    /// Append what still fits, and account for what does not.
    ///
    /// Bytes past the cap are counted as dropped and discarded here rather
    /// than buffered, which is what makes a write of any size cost a bounded
    /// amount of memory.
    fn extend(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let room = MAX_LOG_RECORD_BYTES.saturating_sub(self.partial.len());
        if room == 0 {
            self.overflowed = true;
            self.drops
                .bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            return;
        }
        if bytes.len() > room {
            self.partial.extend_from_slice(&bytes[..room]);
            self.overflowed = true;
            self.drops
                .bytes
                .fetch_add((bytes.len() - room) as u64, Ordering::Relaxed);
        } else {
            self.partial.extend_from_slice(bytes);
        }
    }

    /// Emit the buffered line and start a new one.
    fn emit(&mut self) {
        let mut line = std::mem::take(&mut self.partial);
        let truncated = std::mem::replace(&mut self.overflowed, false);
        // `\r\n` is normalised to `\n`, so a guest built against Windows
        // conventions does not leave a stray carriage return in every record.
        // Only the terminator's own `\r` is removed; one in the middle of a
        // line is the guest's business.
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        // Lossy rather than rejected: invalid UTF-8 is a thing a guest can
        // simply write, and losing the whole line — or worse, panicking — over
        // a stray byte would be a guest-triggered failure.
        let message = String::from_utf8_lossy(&line).into_owned();
        let record = GuestLogRecord {
            stream: self.stream,
            message,
            truncated,
        };
        // `try_send`, never `send`: this is called from a guest write, and
        // awaiting here is exactly the stall this module exists to prevent.
        if let Err(e) = self.tx.try_send(record) {
            let dropped = match e {
                mpsc::error::TrySendError::Full(r) => r,
                mpsc::error::TrySendError::Closed(r) => r,
            };
            self.drops.record(dropped.message.len());
        }
    }

    /// Emit a final unterminated line, if there is one.
    ///
    /// A guest that writes `"done"` and exits without a newline still said
    /// something, and dropping it would make the last thing a failing guest
    /// reported the most likely thing to be lost.
    ///
    /// Emitted when the stream object is dropped, which is when the guest's
    /// stdout resource goes — shortly after the request that wrote it, not at
    /// some later flush. Bounded regardless: one partial line per stream,
    /// capped at [`MAX_LOG_RECORD_BYTES`].
    fn finish(&mut self) {
        if !self.partial.is_empty() || self.overflowed {
            self.emit();
        }
    }
}

impl Drop for LineFramer {
    /// Closing the stream is what ends the last line. There is no explicit
    /// close in `wasi:io/streams`; the resource being dropped is the signal.
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `GuestLogs` whose queue this test owns, so records can be read back
    /// without a collector in the way.
    fn harness(capacity: usize) -> (GuestLogs, mpsc::Receiver<GuestLogRecord>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            GuestLogs {
                tx,
                drops: Arc::new(DropCounters::default()),
            },
            rx,
        )
    }

    /// Everything queued, in order. Takes the stream by value so its `Drop`
    /// runs first — that is what ends an unterminated final line.
    fn drain(
        stream: Box<dyn OutputStream>,
        rx: &mut mpsc::Receiver<GuestLogRecord>,
    ) -> Vec<GuestLogRecord> {
        drop(stream);
        let mut out = Vec::new();
        while let Ok(record) = rx.try_recv() {
            out.push(record);
        }
        out
    }

    fn write(stream: &mut Box<dyn OutputStream>, bytes: &'static [u8]) {
        stream.write(Bytes::from_static(bytes)).expect("write");
    }

    fn messages(records: &[GuestLogRecord]) -> Vec<&str> {
        records.iter().map(|r| r.message.as_str()).collect()
    }

    /// The distinction the whole module exists to preserve. A guest writing a
    /// diagnostic to stderr and data to stdout means two different things, and
    /// a pipeline that merged them would destroy that before anything could
    /// act on it.
    #[test]
    fn stdout_and_stderr_are_tagged_apart() {
        let (logs, mut rx) = harness(8);
        let mut out = logs.stdout().p2_stream();
        let mut err = logs.stderr().p2_stream();
        write(&mut out, b"to stdout\n");
        write(&mut err, b"to stderr\n");
        drop(out);
        drop(err);

        let mut seen: Vec<(GuestStream, String)> = Vec::new();
        while let Ok(r) = rx.try_recv() {
            seen.push((r.stream, r.message));
        }
        assert!(
            seen.contains(&(GuestStream::Stdout, "to stdout".into())),
            "{seen:?}"
        );
        assert!(
            seen.contains(&(GuestStream::Stderr, "to stderr".into())),
            "{seen:?}"
        );
    }

    #[test]
    fn one_write_one_line() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"hello\n");
        let records = drain(s, &mut rx);
        assert_eq!(messages(&records), vec!["hello"]);
        assert!(!records[0].truncated);
    }

    /// A guest is under no obligation to write whole lines. `print!` followed
    /// by `println!` is two writes and one line, and reporting it as two would
    /// misrepresent what the guest said.
    #[test]
    fn a_line_split_across_writes_is_joined() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"one ");
        write(&mut s, b"two ");
        write(&mut s, b"three\n");
        assert_eq!(messages(&drain(s, &mut rx)), vec!["one two three"]);
    }

    #[test]
    fn many_lines_in_one_write() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"a\nb\nc\n");
        assert_eq!(messages(&drain(s, &mut rx)), vec!["a", "b", "c"]);
    }

    /// A blank line is something the guest wrote, and spacing can be the whole
    /// meaning of it. Dropping empties would also silently renumber anything
    /// counting lines.
    #[test]
    fn an_empty_line_is_still_a_record() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"a\n\nb\n");
        assert_eq!(messages(&drain(s, &mut rx)), vec!["a", "", "b"]);
    }

    #[test]
    fn crlf_is_normalised() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"windows\r\nunix\n");
        assert_eq!(messages(&drain(s, &mut rx)), vec!["windows", "unix"]);
    }

    /// Only the terminator's own carriage return is removed. One in the middle
    /// of a line is content, and rewriting content would be lying about what
    /// the guest wrote.
    #[test]
    fn an_interior_carriage_return_is_left_alone() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"a\rb\n");
        assert_eq!(messages(&drain(s, &mut rx)), vec!["a\rb"]);
    }

    /// A guest can write any bytes it likes. Losing the line — or panicking
    /// over it — would hand the guest a way to suppress logging, or worse.
    #[test]
    fn invalid_utf8_is_replaced_not_dropped() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"bad \xff\xfe end\n");
        let records = drain(s, &mut rx);
        assert_eq!(records.len(), 1);
        assert!(records[0].message.starts_with("bad "), "{:?}", records[0]);
        assert!(records[0].message.ends_with(" end"), "{:?}", records[0]);
        assert!(records[0].message.contains('\u{fffd}'), "{:?}", records[0]);
    }

    /// The last thing a failing guest reports is the thing most worth keeping,
    /// and it is exactly the thing with no newline after it.
    #[test]
    fn an_unterminated_line_is_emitted_when_the_stream_closes() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"no newline here");
        assert!(
            rx.try_recv().is_err(),
            "nothing should be emitted before close"
        );
        assert_eq!(messages(&drain(s, &mut rx)), vec!["no newline here"]);
    }

    /// Closing after a clean line must not invent an empty record.
    #[test]
    fn closing_after_a_complete_line_emits_nothing_extra() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"done\n");
        assert_eq!(messages(&drain(s, &mut rx)), vec!["done"]);
    }

    /// Flushing mid-line must not split it. A guest that writes `"foo"`,
    /// flushes, then writes `"bar\n"` wrote one line, and `flush` is not a
    /// statement that the line is over.
    #[test]
    fn flush_does_not_split_a_line() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        write(&mut s, b"foo");
        s.flush().expect("flush");
        assert!(rx.try_recv().is_err(), "flush must not emit a partial line");
        write(&mut s, b"bar\n");
        assert_eq!(messages(&drain(s, &mut rx)), vec!["foobar"]);
    }

    #[test]
    fn an_oversized_line_is_cut_and_marked() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        let huge = vec![b'x'; MAX_LOG_RECORD_BYTES * 3];
        s.write(Bytes::from(huge)).expect("write");
        write(&mut s, b"\ntail\n");
        let records = drain(s, &mut rx);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message.len(), MAX_LOG_RECORD_BYTES);
        assert!(records[0].truncated, "an cut line must say so");
        // The cut ends with the line, so the next one starts clean rather than
        // inheriting the overflow flag.
        assert_eq!(records[1].message, "tail");
        assert!(!records[1].truncated);
    }

    /// The bound that stops a guest turning `println!` into an allocator. A
    /// single enormous write must cost a fixed amount of retained memory, not
    /// a proportional one.
    #[test]
    fn an_oversized_write_does_not_allocate_without_bound() {
        let (tx, _rx) = mpsc::channel(8);
        let mut framer =
            LineFramer::new(GuestStream::Stdout, tx, Arc::new(DropCounters::default()));
        framer.push(&vec![b'x'; 4 * 1024 * 1024]);
        assert!(
            framer.partial.len() <= MAX_LOG_RECORD_BYTES,
            "retained {} bytes for a 4 MiB write",
            framer.partial.len()
        );
        assert!(framer.overflowed);
    }

    /// The requirement that outranks delivery: a guest write returns, whatever
    /// the state of the log queue. A stalled sink is a host problem and must
    /// never become a guest stall or a guest-visible error.
    #[test]
    fn a_full_queue_never_blocks_or_fails_a_guest_write() {
        let (logs, _rx) = harness(1);
        let mut s = logs.stdout().p2_stream();
        for _ in 0..10_000 {
            // Never `Err`, and never awaits: if this test hangs or fails, the
            // design has been broken.
            s.write(Bytes::from_static(b"line\n"))
                .expect("guest write must succeed");
            assert_eq!(s.check_write().expect("permit"), MAX_WRITE_CHUNK_BYTES);
        }
    }

    #[test]
    fn dropped_output_is_counted() {
        let (logs, _rx) = harness(1);
        let mut s = logs.stdout().p2_stream();
        for _ in 0..100 {
            write(&mut s, b"line\n");
        }
        drop(s);
        assert!(
            logs.dropped_records() > 0,
            "a queue of one and a hundred lines must drop something"
        );
        assert!(logs.dropped_bytes() > 0);
    }

    /// Truncated bytes are accounted too, so the drop report reflects how much
    /// output was actually lost rather than only how many records.
    #[test]
    fn truncated_bytes_are_accounted() {
        let (logs, mut rx) = harness(8);
        let mut s = logs.stdout().p2_stream();
        let overshoot = MAX_LOG_RECORD_BYTES * 2;
        s.write(Bytes::from(vec![b'x'; overshoot])).expect("write");
        let _ = drain(s, &mut rx);
        assert_eq!(
            logs.dropped_bytes(),
            (overshoot - MAX_LOG_RECORD_BYTES) as u64
        );
    }

    /// `p2_stream` hands out a fresh object every time a guest asks for its
    /// stdout, and a guest may hold several. Partial-line state kept anywhere
    /// shared would splice two of them into a line neither wrote.
    #[test]
    fn two_streams_do_not_merge_their_partial_lines() {
        let (logs, mut rx) = harness(8);
        let stdio = logs.stdout();
        let mut a = stdio.p2_stream();
        let mut b = stdio.p2_stream();
        write(&mut a, b"aaa");
        write(&mut b, b"bbb");
        write(&mut a, b"AAA\n");
        write(&mut b, b"BBB\n");
        drop(a);
        drop(b);

        let mut seen = Vec::new();
        while let Ok(r) = rx.try_recv() {
            seen.push(r.message);
        }
        assert!(seen.contains(&"aaaAAA".to_string()), "{seen:?}");
        assert!(seen.contains(&"bbbBBB".to_string()), "{seen:?}");
    }

    /// Never a terminal: there is no console in an enclave, and a guest told
    /// otherwise may emit colour escapes that make its output worse to read.
    #[test]
    fn a_guest_stream_is_never_a_terminal() {
        let (logs, _rx) = harness(1);
        assert!(!logs.stdout().is_terminal());
        assert!(!logs.stderr().is_terminal());
    }

    /// The `AsyncWrite` shape must frame identically, or a host reaching for
    /// it would get different records from the same bytes.
    #[tokio::test]
    async fn the_async_write_shape_frames_the_same_way() {
        use tokio::io::AsyncWriteExt;
        let (logs, mut rx) = harness(8);
        let mut w = std::pin::Pin::from(logs.stdout().async_stream());
        w.write_all(b"split ").await.unwrap();
        w.write_all(b"line\nnext\n").await.unwrap();
        w.write_all(b"tail").await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);

        let mut seen = Vec::new();
        while let Ok(r) = rx.try_recv() {
            seen.push(r.message);
        }
        assert_eq!(seen, vec!["split line", "next", "tail"]);
    }

    // ---- the collector ------------------------------------------------

    #[derive(Default)]
    struct MemorySink {
        records: std::sync::Mutex<Vec<GuestLogRecord>>,
    }

    #[async_trait]
    impl GuestLogSink for MemorySink {
        async fn emit(&self, record: GuestLogRecord) {
            self.records.lock().expect("sink poisoned").push(record);
        }
    }

    #[tokio::test]
    async fn the_collector_delivers_to_its_sink() {
        let sink = Arc::new(MemorySink::default());
        let (logs, collector) = start(sink.clone());
        let mut s = logs.stdout().p2_stream();
        s.write(Bytes::from_static(b"through the collector\n"))
            .unwrap();
        drop(s);
        drop(logs);
        collector.shutdown().await;

        let records = sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "through the collector");
        assert_eq!(records[0].stream, GuestStream::Stdout);
    }

    /// Shutdown drains what is already queued rather than discarding it, so a
    /// clean stop does not lose the output that prompted it.
    #[tokio::test]
    async fn shutdown_drains_what_is_already_queued() {
        let sink = Arc::new(MemorySink::default());
        let (logs, collector) = start(sink.clone());
        let mut s = logs.stdout().p2_stream();
        for i in 0..64 {
            s.write(Bytes::from(format!("line {i}\n"))).unwrap();
        }
        drop(s);
        // The handle is still alive, so the queue is not closed — shutdown is
        // what has to drain it.
        collector.shutdown().await;
        assert_eq!(sink.records.lock().unwrap().len(), 64);
    }

    /// A sink that never returns must not hold the enclave open. The deadline
    /// is fixed and short, and overrunning it abandons the collector rather
    /// than the shutdown.
    #[tokio::test]
    async fn a_stalled_sink_cannot_block_shutdown_forever() {
        struct Stalled;
        #[async_trait]
        impl GuestLogSink for Stalled {
            async fn emit(&self, _record: GuestLogRecord) {
                std::future::pending::<()>().await;
            }
        }
        let (logs, collector) = start(Arc::new(Stalled));
        let mut s = logs.stdout().p2_stream();
        s.write(Bytes::from_static(b"never delivered\n")).unwrap();
        drop(s);

        let started = std::time::Instant::now();
        collector.shutdown().await;
        assert!(
            started.elapsed() < DRAIN_DEADLINE * 3,
            "shutdown took {:?}",
            started.elapsed()
        );
    }

    /// The acceptance criterion, stated directly: a sink that never returns
    /// must not slow a guest down. The collector wedges on its first record,
    /// the queue fills behind it, and the guest keeps writing at full speed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_sink_cannot_stall_a_guest() {
        struct Stalled;
        #[async_trait]
        impl GuestLogSink for Stalled {
            async fn emit(&self, _record: GuestLogRecord) {
                std::future::pending::<()>().await;
            }
        }

        let (logs, _collector) = start(Arc::new(Stalled));
        let mut s = logs.stdout().p2_stream();
        // Comfortably more than the queue holds, so most of these are written
        // into a queue that nothing will ever drain.
        let writes = LOG_QUEUE_CAPACITY * 4;
        let started = std::time::Instant::now();
        for i in 0..writes {
            s.write(Bytes::from(format!("line {i}\n")))
                .expect("guest write must succeed");
        }
        let elapsed = started.elapsed();
        drop(s);

        assert!(
            elapsed < Duration::from_secs(5),
            "{writes} writes against a stalled sink took {elapsed:?}"
        );
        assert!(
            logs.dropped_records() > 0,
            "a stalled sink must show up as dropped output, not as a slow guest"
        );
    }

    /// Every sink sees every record, so configuring a relay does not cost the
    /// console.
    #[tokio::test]
    async fn a_fan_out_reaches_every_sink() {
        let a = Arc::new(MemorySink::default());
        let b = Arc::new(MemorySink::default());
        let fan = FanOutSink::new(vec![a.clone(), b.clone()]);
        fan.emit(GuestLogRecord {
            stream: GuestStream::Stderr,
            message: "both".into(),
            truncated: true,
        })
        .await;

        for sink in [&a, &b] {
            let records = sink.records.lock().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].message, "both");
            assert_eq!(records[0].stream, GuestStream::Stderr);
            assert!(records[0].truncated);
        }
    }

    /// Guest text must not be able to forge structure on its own log line.
    ///
    /// Found on a real enclave console, not here: naming the field `message`
    /// collided with the event's own message field and printed guest bytes
    /// bare in the structured part of the line, so a guest could write
    /// `truncated=true` and have it render exactly like a field the runtime
    /// set. The value is quoted and escaped now, and this is what says so.
    #[tokio::test]
    async fn guest_text_cannot_forge_fields_on_its_own_line() {
        use std::sync::Mutex;

        /// Collects what the formatter actually wrote.
        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = Buffer;
            fn make_writer(&'a self) -> Buffer {
                self.clone()
            }
        }

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_target(true)
            .with_ansi(false)
            .compact()
            .finish();

        // Text shaped exactly like the fields the runtime sets beside it.
        let hostile = r#"truncated=true guest_stream="stderr" tenant=someone-else"#;
        tracing::subscriber::with_default(subscriber, || {
            futures::executor::block_on(TracingLogSink.emit(GuestLogRecord {
                stream: GuestStream::Stdout,
                message: hostile.into(),
                truncated: false,
            }));
        });

        let line = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();

        // Everything before `guest_message=` is the runtime's own structure.
        // Nothing the guest wrote may appear in it — that is the whole claim.
        let (structured, value) = line
            .split_once("guest_message=")
            .unwrap_or_else(|| panic!("no guest_message field: {line}"));
        assert!(
            !structured.contains("tenant=someone-else"),
            "guest text reached the structured part of the line: {line}"
        );
        assert!(
            !structured.contains("truncated=true"),
            "the guest overrode a field the runtime set: {line}"
        );
        // The runtime's own values stand, and say what the runtime said.
        assert!(structured.contains("truncated=false"), "{line}");
        assert!(structured.contains(r#"guest_stream="stdout""#), "{line}");
        // The guest's quotes are escaped, so it cannot close the value it is in
        // and open a field of its own after it.
        assert!(
            value.contains("\\\""),
            "guest quotes were not escaped: {line}"
        );
    }

    /// Untrusted guest text and the runtime's own events must be separable by
    /// something a guest cannot influence. The target is that something.
    #[tokio::test]
    async fn guest_output_and_runtime_events_carry_different_targets() {
        use std::sync::Mutex;
        use tracing_subscriber::layer::SubscriberExt as _;

        #[derive(Clone, Default)]
        struct Spy(Arc<Mutex<Vec<(String, String)>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Spy {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.0.lock().unwrap().push((
                    event.metadata().target().to_string(),
                    event.metadata().name().to_string(),
                ));
            }
        }

        let spy = Spy::default();
        let subscriber = tracing_subscriber::registry().with(spy.clone());
        let seen = tracing::subscriber::with_default(subscriber, || {
            tracing::info!("a runtime event");
            futures::executor::block_on(TracingLogSink.emit(GuestLogRecord {
                stream: GuestStream::Stderr,
                // Guest text shaped exactly like a runtime log line. It must
                // not become one.
                message: "a runtime event".into(),
                truncated: false,
            }));
            spy.0.lock().unwrap().clone()
        });

        let guest: Vec<_> = seen.iter().filter(|(t, _)| t == GUEST_LOG_TARGET).collect();
        let runtime: Vec<_> = seen.iter().filter(|(t, _)| t != GUEST_LOG_TARGET).collect();
        assert_eq!(guest.len(), 1, "{seen:?}");
        assert_eq!(runtime.len(), 1, "{seen:?}");
        // Guest text never reaches the event name, so it cannot impersonate a
        // differently-shaped event however it is spelled.
        assert_ne!(guest[0].1, "a runtime event");
    }
}
