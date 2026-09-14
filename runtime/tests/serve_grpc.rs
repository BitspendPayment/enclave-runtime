//! Bidirectional gRPC streaming, through the runtime, to a Wasm guest.
//!
//! The claim under test is not "a body streams" — `serve_guest` already pins
//! that — but that **both** directions are open at once: the guest answers
//! while the client is still sending, and the client sends more after reading
//! an answer. A runtime that buffered either half would pass a naive echo test
//! and fail every one of these.
//!
//! These drive `ServeHandle::handle` directly rather than over a socket. That
//! is not a shortcut: it is the only way to hold the request body open and feed
//! it one frame at a time while reading the response, which is exactly the
//! interleaving being asserted. `serve_h2` covers the wire.
//!
//! ```console
//! $ (cd examples/guest-grpc && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test serve_grpc -- --include-ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use enclave_runtime::{GuestEnvironment, HostClock, ServeHandle};
use http_body_util::BodyExt;
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::{Config, Fs, MasterSecret};
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;

/// One gRPC frame on its way to the guest, or the error that ended the body.
type ClientFrame =
    Result<hyper::body::Frame<Bytes>, wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>;
/// The request body the test keeps feeding, one frame at a time.
type OpenBody = http_body_util::StreamBody<tokio_stream::wrappers::ReceiverStream<ClientFrame>>;

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/guest-grpc/target/wasm32-wasip2/release/guest-grpc.wasm")
}

const SIGN: &str = "/enclave.cosign.v1.SigningSession/Sign";
const REFUSE: &str = "/enclave.cosign.v1.SigningSession/Refuse";
const SPIN: &str = "/enclave.cosign.v1.SigningSession/Spin";
const FIREHOSE: &str = "/enclave.cosign.v1.SigningSession/Firehose";

// --- the wire format, host side --------------------------------------------
//
// Deliberately written out rather than shared with the guest: a test that
// encodes with the same code the guest decodes with proves the two agree with
// themselves, not that either speaks gRPC.

fn frame(message: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + message.len());
    out.put_u8(0);
    out.put_u32(message.len() as u32);
    out.put_slice(message);
    out.freeze()
}

/// Protobuf for `ClientMsg { session_id, seq, kind, payload }`, by hand.
fn client_msg(session: &str, seq: u64, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    // field 1, wire type 2 (length-delimited)
    buf.put_u8(0x0a);
    buf.put_u8(session.len() as u8);
    buf.put_slice(session.as_bytes());
    // field 2, wire type 0 (varint)
    buf.put_u8(0x10);
    let mut n = seq;
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            buf.put_u8(byte);
            break;
        }
        buf.put_u8(byte | 0x80);
    }
    // field 3, wire type 0: Kind::Round
    buf.put_u8(0x18);
    buf.put_u8(2);
    // field 4, wire type 2
    buf.put_u8(0x22);
    buf.put_u8(payload.len() as u8);
    buf.put_slice(payload);
    frame(&buf.freeze())
}

/// Pull `payload` (field 4) out of a `ServerMsg`, which is all these assert on.
fn server_payload(message: &[u8]) -> Vec<u8> {
    let mut i = 0usize;
    while i < message.len() {
        let tag = message[i];
        i += 1;
        match tag {
            // field 1 / 4, length-delimited
            0x0a | 0x22 => {
                let len = message[i] as usize;
                i += 1;
                let value = message[i..i + len].to_vec();
                i += len;
                if tag == 0x22 {
                    return value;
                }
            }
            // varint fields
            0x10 | 0x18 => {
                while message[i] & 0x80 != 0 {
                    i += 1;
                }
                i += 1;
            }
            _ => break,
        }
    }
    Vec::new()
}

/// Reassembles gRPC frames from however the response arrives.
#[derive(Default)]
struct Deframer {
    buffer: BytesMut,
}

impl Deframer {
    fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    fn next(&mut self) -> Option<Bytes> {
        if self.buffer.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes(self.buffer[1..5].try_into().unwrap()) as usize;
        if self.buffer.len() < 5 + len {
            return None;
        }
        let _ = self.buffer.split_to(5);
        Some(self.buffer.split_to(len).freeze())
    }
}

// --- harness ----------------------------------------------------------------

async fn grpc_handle() -> ServeHandle {
    let backend = Arc::new(MemoryBackend::new());
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([3u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the filesystem");

    let (logs, _collector) =
        enclave_runtime::guest_io::start(Arc::new(enclave_runtime::TracingLogSink));
    let guest = GuestEnvironment::new(
        fs,
        Box::new(HostClock),
        Arc::new(nitro_nsm::fake::FakeNsm::new()),
        &[],
        &[],
        logs,
    )
    .expect("guest environment");

    let bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-grpc && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });

    let engine = ServeHandle::engine_with_watchdog().expect("engine");
    ServeHandle::new(&engine, &bytes, guest).expect("preparing the guest")
}

/// A request whose body the test keeps feeding.
///
/// This is what makes the interleaving observable: the call is made with the
/// request body still open, so anything the guest answers is an answer given
/// *before* the client finished asking.
fn open_request(
    path: &str,
) -> (
    hyper::Request<OpenBody>,
    tokio::sync::mpsc::Sender<ClientFrame>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let body = http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://enclave.test{path}"))
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(body)
        .expect("well-formed request");
    (req, tx)
}

async fn send(tx: &tokio::sync::mpsc::Sender<ClientFrame>, bytes: Bytes) {
    tx.send(Ok(hyper::body::Frame::data(bytes)))
        .await
        .expect("the guest stopped reading");
}

// --- the tests --------------------------------------------------------------

/// **The property this whole change exists for.**
///
/// The guest answers while the request body is still open, and the client
/// sends its next message only after reading that answer. Neither side could
/// make progress if the runtime buffered the other, so the exchange completing
/// at all is the proof.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn both_directions_make_progress_at_once() {
    let handle = grpc_handle().await;
    let (req, tx) = open_request(SIGN);

    let response = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("the guest answered");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc+proto")
    );

    let mut body = response.into_body();
    let mut deframer = Deframer::default();

    for seq in 0..4u64 {
        // Ask.
        send(
            &tx,
            client_msg("s-1", seq, format!("round-{seq}").as_bytes()),
        )
        .await;

        // And read the answer before asking again. If the runtime were holding
        // the request body until it completed, this would block forever.
        let answer = loop {
            if let Some(message) = deframer.next() {
                break message;
            }
            let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
                .await
                .expect("the guest did not answer while the request was still open")
                .expect("the body ended early")
                .expect("a frame");
            if let Some(data) = frame.data_ref() {
                deframer.push(data);
            }
        };
        assert_eq!(
            server_payload(&answer),
            format!("round-{seq}").into_bytes(),
            "the guest answered the wrong message"
        );
    }

    // Half-close: an orderly end, and the trailers say so.
    drop(tx);
    let mut status = None;
    while let Some(Ok(frame)) = body.frame().await {
        if let Some(trailers) = frame.trailers_ref() {
            status = trailers.get("grpc-status").cloned();
        }
    }
    assert_eq!(
        status.as_ref().and_then(|v| v.to_str().ok()),
        Some("0"),
        "a half-closed stream should end OK"
    );
}

/// A stream stays healthy far past the head timeout.
///
/// The client paces itself at 200ms a message for well over a second, against
/// a runtime configured to give a response head 400ms. Nothing here is
/// unhealthy — every message is answered — and until the watchdog learned to
/// ask whether bytes were moving rather than how long the call had run, this
/// was the case it could not tell from a runaway.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_stream_outlives_the_request_timeout() {
    let handle = grpc_handle().await.with_timeout(Duration::from_millis(400));
    let (req, tx) = open_request(SIGN);

    let response = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("the guest answered");
    let mut body = response.into_body();
    let mut deframer = Deframer::default();

    let started = std::time::Instant::now();
    for seq in 0..8u64 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        send(&tx, client_msg("slow", seq, b"tick")).await;
        let answer = loop {
            if let Some(message) = deframer.next() {
                break message;
            }
            let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
                .await
                .unwrap_or_else(|_| panic!("the stream stalled at message {seq}"))
                .expect("the stream was cut short")
                .expect("a frame");
            if let Some(data) = frame.data_ref() {
                deframer.push(data);
            }
        };
        assert_eq!(server_payload(&answer), b"tick".to_vec());
    }
    let ran_for = started.elapsed();
    assert!(
        ran_for > Duration::from_millis(400),
        "the stream did not outlast the timeout, so it proves nothing: {ran_for:?}"
    );
}

/// And the guarantee that keeps the one above safe.
///
/// `Spin` answers once and then burns CPU without touching either body. It has
/// no progress to show, so the epoch must still end it — otherwise "a stream
/// may run long" would have quietly become "anything may run forever".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_spinning_stream_is_still_interrupted() {
    let handle = grpc_handle().await.with_timeout(Duration::from_secs(1));
    let (req, tx) = open_request(SPIN);

    let response = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("the head is set before the guest starts spinning");
    let mut body = response.into_body();

    send(&tx, client_msg("spin", 0, b"go")).await;

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                return true;
            }
        }
        true
    })
    .await;
    let took = started.elapsed();

    assert!(
        outcome.is_ok(),
        "a spinning guest was never interrupted: {took:?}"
    );
    assert!(
        took < Duration::from_secs(25),
        "the spinning guest was not stopped promptly: {took:?}"
    );
}

/// A non-zero gRPC status arrives in the trailers, not the head.
///
/// This is the shape of every gRPC failure: HTTP 200, and the real answer at
/// the end. A client that read only the head would call this a success.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_refusal_arrives_as_grpc_status_trailers() {
    let handle = grpc_handle().await;
    let (req, tx) = open_request(REFUSE);

    let response = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("the guest answered");
    assert_eq!(
        response.status(),
        200,
        "gRPC reports failure in trailers, never in the status line"
    );

    let mut body = response.into_body();
    send(&tx, client_msg("refused", 0, b"please sign")).await;
    drop(tx);

    let mut status = None;
    let mut message = None;
    while let Some(Ok(frame)) = body.frame().await {
        if let Some(trailers) = frame.trailers_ref() {
            status = trailers.get("grpc-status").cloned();
            message = trailers.get("grpc-message").cloned();
        }
    }
    assert_eq!(
        status.as_ref().and_then(|v| v.to_str().ok()),
        Some("7"),
        "the refusal did not reach the client as PERMISSION_DENIED"
    );
    assert!(
        message
            .as_ref()
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .contains("not authorized to sign"),
        "the refusal carried no reason: {message:?}"
    );
}

/// A guest writing to a client that is not reading stops, rather than growing.
///
/// `Firehose` queues 64 KiB-sized messages and never reads. The host's outgoing
/// body holds a couple of chunks and then simply stops polling, so what bounds
/// this is backpressure rather than any limit the guest was asked to respect.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_guest_cannot_outrun_a_client_that_is_not_reading() {
    let handle = grpc_handle().await;
    let (req, _tx) = open_request(FIREHOSE);

    let response = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("the guest answered");
    let mut body = response.into_body();

    // Read one frame, then stop for long enough that an unbounded guest would
    // have produced everything it had.
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("the first frame never arrived")
        .expect("the body ended early")
        .expect("a frame");
    assert!(first.data_ref().is_some(), "expected a data frame first");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Then drain the rest. What matters is that it completes: the guest was
    // still there to finish, which it could not be if it had run ahead and
    // died, and the sleep above did not lose anything.
    let mut frames = 1usize;
    while let Some(Ok(frame)) = body.frame().await {
        if frame.data_ref().is_some() {
            frames += 1;
        }
    }
    assert_eq!(
        frames, 64,
        "the guest lost or duplicated frames while the client was not reading"
    );
}

/// A tenanted handle, so two clients can be told apart.
async fn tenanted() -> ServeHandle {
    let handle = grpc_handle().await;
    let tenancy = enclave_runtime::Tenancy::new(enclave_runtime::PoolLimits::default());
    handle.with_tenancy(Arc::new(tenancy))
}

/// **The cost of a long stream, stated as a test.**
///
/// One active guest handler per tenant is the isolation model, not a limit to
/// be raised: a tenant's SQLite database is only safe because exactly one of
/// their requests is ever in flight. A stream is a request, so an open stream
/// occupies that tenant's slot for its whole life and their next request waits.
///
/// The half that makes it acceptable is the second assertion: another tenant
/// has nothing to queue on and proceeds immediately.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn an_open_stream_holds_its_own_tenant_and_no_other() {
    let handle = Arc::new(tenanted().await);
    let alice = [0xaa; 16];
    let bob = [0xbb; 16];

    let (req, tx) = open_request(SIGN);
    let response = handle
        .handle(Scheme::Http, req, Some(&alice))
        .await
        .expect("alice's stream opened");
    let mut body = response.into_body();

    // Alice's stream is open and answering.
    send(&tx, client_msg("alice", 0, b"hello")).await;
    let mut deframer = Deframer::default();
    loop {
        if deframer.next().is_some() {
            break;
        }
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("alice's stream stalled")
            .expect("alice's stream ended")
            .expect("a frame");
        if let Some(data) = frame.data_ref() {
            deframer.push(data);
        }
    }

    // Alice's *second* request waits behind her stream.
    let (blocked, _blocked_tx) = open_request(SIGN);
    let alice_again = handle.clone();
    let waiting = tokio::spawn(async move {
        alice_again
            .handle(Scheme::Http, blocked, Some(&[0xaa; 16]))
            .await
            .map(|_| ())
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !waiting.is_finished(),
        "alice's second request ran while her stream was still open"
    );

    // Bob has nothing to queue on.
    let (bobs, bobs_tx) = open_request(SIGN);
    let bobs_response = tokio::time::timeout(
        Duration::from_secs(5),
        handle.handle(Scheme::Http, bobs, Some(&bob)),
    )
    .await
    .expect("bob waited behind alice, which is the bug this asserts against")
    .expect("bob's stream opened");
    assert_eq!(bobs_response.status(), 200);
    drop(bobs_tx);

    // And when alice's stream ends, her queued request proceeds.
    drop(tx);
    while body.frame().await.is_some() {}
    assert!(
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .is_ok(),
        "alice's tenant was never released when her stream ended"
    );
}

/// A stream abandoned mid-flight frees its tenant, and leaves nothing poisoned.
///
/// Dropping the response body is what a client disconnecting looks like from
/// in here. The guest task is aborted, its instance goes with it, and the next
/// request for that tenant gets a fresh one — which it must, because the
/// interrupted store cannot be re-entered.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn an_abandoned_stream_frees_its_tenant() {
    let handle = tenanted().await;
    let carol = [0xcc; 16];

    {
        let (req, tx) = open_request(SIGN);
        let response = handle
            .handle(Scheme::Http, req, Some(&carol))
            .await
            .expect("carol's stream opened");
        send(&tx, client_msg("carol", 0, b"hi")).await;
        // Both ends dropped without half-closing: the client vanished.
        drop(response);
        drop(tx);
    }

    // The tenant must be usable again, promptly.
    let (again, again_tx) = open_request(SIGN);
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        handle.handle(Scheme::Http, again, Some(&carol)),
    )
    .await
    .expect("the tenant was never released after the stream was abandoned")
    .expect("carol's next stream opened");
    assert_eq!(response.status(), 200);

    let mut body = response.into_body();
    let mut deframer = Deframer::default();
    send(&again_tx, client_msg("carol", 1, b"again")).await;
    let answer = loop {
        if let Some(message) = deframer.next() {
            break message;
        }
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("the reused tenant never answered")
            .expect("the stream ended early")
            .expect("a frame");
        if let Some(data) = frame.data_ref() {
            deframer.push(data);
        }
    };
    assert_eq!(
        server_payload(&answer),
        b"again".to_vec(),
        "the tenant came back but its instance was not usable"
    );
}

/// Read a stream to its end and return the `grpc-status` it finished with.
async fn status_after_half_close(path: &str, partial: &[u8]) -> (Option<String>, Option<String>) {
    let handle = grpc_handle().await;
    let (req, tx) = open_request(path);
    let response = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("the guest answered");
    let mut body = response.into_body();

    send(&tx, Bytes::copy_from_slice(partial)).await;
    // Half-close with those bytes stranded: at the HTTP layer this is a clean
    // end, which is exactly why the gRPC status has to disagree.
    drop(tx);

    let (mut status, mut message) = (None, None);
    while let Some(Ok(frame)) = body.frame().await {
        if let Some(trailers) = frame.trailers_ref() {
            status = trailers
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            message = trailers
                .get("grpc-message")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
        }
    }
    (status, message)
}

/// **A truncated header must not read as success.**
///
/// Four bytes is less than the five-byte prefix, so the guest never saw a
/// length at all. Answering `grpc-status: 0` would tell the client its message
/// had been received when nothing had been.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_stream_ending_on_a_truncated_header_is_not_a_success() {
    let (status, message) = status_after_half_close(SIGN, &[0u8, 0, 0, 0]).await;
    assert_eq!(
        status.as_deref(),
        Some("3"),
        "a stream cut off inside its header reported success"
    );
    assert!(
        message.unwrap_or_default().contains("part-way through"),
        "the refusal did not say what was wrong"
    );
}

/// And the subtler shape: a complete header whose payload never finished.
///
/// The guest read a length of ten and got four bytes. It has been waiting for
/// the rest, and the rest is never coming.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_stream_ending_on_a_truncated_payload_is_not_a_success() {
    let mut partial = vec![0u8];
    partial.extend_from_slice(&10u32.to_be_bytes());
    partial.extend_from_slice(b"four");

    let (status, message) = status_after_half_close(SIGN, &partial).await;
    assert_eq!(
        status.as_deref(),
        Some("3"),
        "a stream cut off inside its payload reported success"
    );
    assert!(message.unwrap_or_default().contains("part-way through"));
}

/// The control: a stream that ends between messages still ends cleanly.
///
/// Without this the two tests above would pass on a guest that simply always
/// refused, which would be a different bug wearing the same trailers.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_stream_ending_between_messages_is_still_a_success() {
    let (status, _) = status_after_half_close(SIGN, &client_msg("whole", 0, b"complete")).await;
    assert_eq!(
        status.as_deref(),
        Some("0"),
        "a cleanly framed stream was reported as truncated"
    );
}

/// **The case the epoch watchdog cannot see.**
///
/// The client opens a stream and then says nothing. The guest is blocked in a
/// host call waiting for a frame, so no wasm executes, so no epoch check is
/// ever reached — the epoch could wait forever and never fire. Meanwhile the
/// stream holds its tenant's only slot.
///
/// A wall clock is the instrument here, and it works for the same reason the
/// epoch does not: a guest parked in a host call *is* at an await point, so an
/// abort reaches it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_silent_stream_is_ended_at_its_deadline_and_frees_its_tenant() {
    let handle = tenanted()
        .await
        .with_max_interaction(Duration::from_millis(400));
    let quiet = [0xd0; 16];

    let (req, tx) = open_request(SIGN);
    let response = handle
        .handle(Scheme::Http, req, Some(&quiet))
        .await
        .expect("the stream opened");
    let mut body = response.into_body();

    // Not one frame, ever. The sender is held so the request body stays open —
    // this is a client that connected and then went quiet, not one that left.
    let started = std::time::Instant::now();
    let ended = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                break;
            }
        }
    })
    .await;
    let took = started.elapsed();

    assert!(
        ended.is_ok(),
        "a silent stream was never ended: still running after {took:?}"
    );
    assert!(
        took >= Duration::from_millis(400),
        "the stream ended before its deadline, so this proves nothing: {took:?}"
    );

    // And the tenant is usable again — which is the point of ending it.
    let (again, again_tx) = open_request(SIGN);
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        handle.handle(Scheme::Http, again, Some(&quiet)),
    )
    .await
    .expect("the deadline did not free the tenant")
    .expect("the tenant's next interaction opened");
    assert_eq!(response.status(), 200);
    drop(again_tx);
    drop(tx);
}

/// The other half: a stream that *is* talking runs past the same deadline
/// without being touched, because the deadline bounds neglect rather than
/// duration.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_busy_stream_is_not_ended_by_the_head_timeout() {
    let handle = grpc_handle()
        .await
        .with_timeout(Duration::from_millis(300))
        .with_max_interaction(Duration::from_secs(30));
    let (req, tx) = open_request(SIGN);

    let response = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("the stream opened");
    let mut body = response.into_body();
    let mut deframer = Deframer::default();

    let started = std::time::Instant::now();
    for seq in 0..5u64 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        send(&tx, client_msg("busy", seq, b"tick")).await;
        loop {
            if deframer.next().is_some() {
                break;
            }
            let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
                .await
                .unwrap_or_else(|_| panic!("the stream stalled at message {seq}"))
                .expect("the stream was cut short")
                .expect("a frame");
            if let Some(data) = frame.data_ref() {
                deframer.push(data);
            }
        }
    }
    assert!(
        started.elapsed() > Duration::from_millis(300),
        "the exchange finished inside the head timeout, so it proves nothing"
    );
}
