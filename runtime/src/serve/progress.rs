//! Evidence that a call is still doing something.
//!
//! The epoch watchdog gives a guest a fixed budget of wall clock and traps it
//! when the budget runs out. That is right for a request/response call, where
//! taking longer than the timeout means something is wrong. It is wrong for a
//! long-lived stream, where taking a long time is the *point* — a signing
//! session may be open for minutes and be healthy throughout.
//!
//! Two things must stay true at once: a stream doing real work lives, and a
//! guest spinning in a loop still dies. The distinguishing fact is not elapsed
//! time but whether bytes moved, so that is what this measures.
//!
//! # Why a guest cannot fake it
//!
//! Neither counter is under the guest's control:
//!
//! - the **request** counter is fed by bytes hyper delivered from the client,
//!   so it advances only when the peer actually sends;
//! - the **response** counter is fed by bytes hyper pulled *out* of the
//!   outgoing body, so it advances only when the client actually reads. A guest
//!   writing into a buffer nobody drains moves it exactly once, because the
//!   channel behind it holds two chunks and then stops being polled.
//!
//! So "made progress" means the guest and its peer are still talking, which is
//! the only thing worth keeping a tenant's slot open for.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame};

/// Bytes moved on one call, and what the watchdog saw last time it looked.
#[derive(Debug, Default)]
pub struct StreamProgress {
    /// Both directions together. They are never reported apart, and a stream
    /// that is only receiving is as alive as one that is only sending.
    bytes: AtomicU64,
    /// Written only by [`StreamProgress::still_working`]. Not a count of
    /// anything — it exists to be compared with `bytes` one epoch later.
    last_seen: AtomicU64,
    /// Whether the response head has gone out.
    ///
    /// This is what decides how patient the watchdog may be, and the reason is
    /// a race the module doc on `watchdog` spells out. Until the head is set,
    /// `await_head` is holding a `tokio::time::timeout` that will `abort` the
    /// task — and abort needs an await point, which a spinning guest never
    /// reaches. The epoch has to win that race, so before the head there is no
    /// patience at all: the first silent expiry ends the call, exactly as it
    /// did before any of this existed.
    ///
    /// Once the head is out that timeout is gone — nothing will abort the call
    /// — so silence can be judged properly instead of instantly.
    head_sent: AtomicBool,
    /// Consecutive expiries that saw nothing move.
    ///
    /// One silent observation is not evidence of a runaway. The response
    /// counter advances when hyper *drains* the body, which is a different
    /// moment from the guest's epoch check, so a busy machine can leave a
    /// perfectly healthy stream looking idle for one tick. Requiring several
    /// in a row is what separates "the reader is behind" from "nothing is
    /// happening", and it costs a runaway only the strikes it takes to die.
    strikes: AtomicU32,
}

impl StreamProgress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count bytes that crossed the boundary in either direction.
    pub fn record(&self, bytes: usize) {
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Start a new call on a store that may have served others.
    ///
    /// A pooled instance keeps its counters between requests, and a fresh call
    /// must not inherit the last one's progress — it would be handed a free
    /// extension it did not earn.
    pub fn reset(&self) {
        self.bytes.store(0, Ordering::Relaxed);
        self.last_seen.store(0, Ordering::Relaxed);
        self.strikes.store(0, Ordering::Relaxed);
        self.head_sent.store(false, Ordering::Relaxed);
    }

    /// The guest has set a response; `await_head` is no longer watching.
    pub fn head_sent(&self) {
        self.head_sent.store(true, Ordering::Relaxed);
    }

    /// Should this call be allowed to keep running?
    ///
    /// **Not idempotent.** Asking *is* the observation: it records what it saw
    /// so the next call compares against this moment, and it counts the strike.
    /// Only the epoch callback may call it, and only once per expiry.
    ///
    /// Traffic clears the record. `limit` consecutive silent expiries is what
    /// it takes to be judged a runaway, which bounds how long one can burn a
    /// worker after its budget ran out — independent of how generous that
    /// budget was.
    pub fn still_working(&self, limit: u32) -> bool {
        let now = self.bytes.load(Ordering::Relaxed);
        if self.last_seen.swap(now, Ordering::Relaxed) != now {
            self.strikes.store(0, Ordering::Relaxed);
            return true;
        }
        // Before the head, the epoch is the only thing that can stop this
        // guest and it must do so now — see `head_sent`.
        if !self.head_sent.load(Ordering::Relaxed) {
            return false;
        }
        self.strikes.fetch_add(1, Ordering::Relaxed) + 1 < limit
    }
}

/// A body that reports what passes through it and changes nothing else.
///
/// Deliberately not a place for policy: it does not cap, delay or inspect. The
/// runtime holds both the request body before it becomes a guest resource and
/// the response body after it stops being one, so wrapping at those two points
/// observes the whole call without a fork of `wasmtime-wasi-http`.
pub struct Counting<B> {
    inner: B,
    progress: std::sync::Arc<StreamProgress>,
}

impl<B> Counting<B> {
    pub fn new(inner: B, progress: std::sync::Arc<StreamProgress>) -> Self {
        Counting { inner, progress }
    }
}

impl<B> Body for Counting<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled {
            if let Some(data) = frame.data_ref() {
                this.progress.record(data.len());
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    #[tokio::test]
    async fn a_counting_body_reports_exactly_what_passed_through() {
        let progress = std::sync::Arc::new(StreamProgress::new());
        let body = Counting::new(
            Full::new(Bytes::from_static(b"twelve bytes")),
            progress.clone(),
        );
        let collected = body.collect().await.expect("collecting").to_bytes();
        assert_eq!(collected.len(), 12);
        assert!(
            progress.still_working(2),
            "twelve bytes moved and went unreported"
        );
    }

    /// The property the watchdog rests on: silence reads as silence, but only
    /// once it has been silent long enough to mean something.
    #[test]
    fn sustained_silence_is_what_ends_a_call() {
        let progress = StreamProgress::new();
        progress.head_sent();
        // One quiet tick is tolerated: the reader may simply be behind.
        assert!(progress.still_working(3), "one quiet tick ended the call");
        assert!(progress.still_working(3), "two quiet ticks ended the call");
        assert!(!progress.still_working(3), "silence never ended the call");
    }

    /// Traffic clears the record, so a stream that pauses and resumes is not
    /// carrying strikes from an earlier lull.
    #[test]
    fn moving_bytes_forgives_earlier_silence() {
        let progress = StreamProgress::new();
        progress.head_sent();
        assert!(progress.still_working(2), "the first quiet tick");
        progress.record(1);
        assert!(
            progress.still_working(2),
            "traffic did not clear the strike"
        );
        assert!(progress.still_working(2), "the strike count was not reset");
    }

    /// Before the head there is no patience: the epoch must beat `await_head`.
    #[test]
    fn a_guest_that_has_not_answered_yet_gets_no_grace() {
        let progress = StreamProgress::new();
        assert!(
            !progress.still_working(8),
            "a silent guest was given grace it could not be aborted out of"
        );
    }

    /// A pooled instance must not hand its next request a free extension.
    #[test]
    fn a_reset_forgets_what_the_last_call_moved() {
        let progress = StreamProgress::new();
        progress.record(4096);
        progress.reset();
        // A limit of one makes the very first silent observation decisive,
        // which is the sharpest way to ask "did anything carry over?".
        assert!(
            !progress.still_working(1),
            "the previous call's bytes counted for this one"
        );
    }
}
