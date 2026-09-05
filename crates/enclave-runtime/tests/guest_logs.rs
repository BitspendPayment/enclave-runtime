//! Guest stdout and stderr, end to end: a real component writing real bytes,
//! observed through a test sink rather than by scraping a terminal.
//!
//! The unit tests in `guest_io` cover the framing rules directly. What only an
//! integration test can show is that a guest's `write` actually arrives here —
//! that the WASI streams are wired to this pipeline at all, and that nothing
//! between the guest and the sink reorders, merges or loses what it wrote.
//!
//! Records are read from an in-memory [`GuestLogSink`] and never from
//! formatted output. A test that grepped a terminal would pass just as well
//! with the old `inherit_stdio`, which is exactly the arrangement this change
//! removed.
//!
//! Ignored by default because it needs the guest component built first:
//!
//! ```console
//! $ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test guest_logs -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use enclave_runtime::guest_io::{GuestLogRecord, GuestLogSink, GuestStream};
use enclave_runtime::{GuestEnvironment, HostClock, ServeHandle};
use http_body_util::{BodyExt, Full};
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::{Config, Fs, MasterSecret};
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

/// Keeps every record, in arrival order.
#[derive(Default)]
struct MemorySink {
    records: Mutex<Vec<GuestLogRecord>>,
}

#[async_trait::async_trait]
impl GuestLogSink for MemorySink {
    async fn emit(&self, record: GuestLogRecord) {
        self.records.lock().expect("sink poisoned").push(record);
    }
}

impl MemorySink {
    fn len(&self) -> usize {
        self.records.lock().expect("sink poisoned").len()
    }

    fn messages(&self, stream: GuestStream) -> Vec<String> {
        self.records
            .lock()
            .expect("sink poisoned")
            .iter()
            .filter(|r| r.stream == stream)
            .map(|r| r.message.clone())
            .collect()
    }
}

async fn handle_with(sink: Arc<MemorySink>) -> (ServeHandle, enclave_runtime::GuestLogCollector) {
    let backend = Arc::new(MemoryBackend::new());
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([7u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the memory-backed filesystem");

    // Started before the handle exists, so there is no window in which a guest
    // could write with nothing consuming it.
    let (logs, collector) = enclave_runtime::guest_io::start(sink);
    let guest = GuestEnvironment::new(
        fs,
        Box::new(HostClock),
        Arc::new(nitro_nsm::fake::FakeNsm::new()),
        &[],
        &[],
        logs,
    )
    .expect("building the guest environment");

    let bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-http && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });
    let engine = ServeHandle::engine_with_watchdog().expect("engine");
    let handle = ServeHandle::new(&engine, &bytes, guest).expect("preparing the guest");
    (handle, collector)
}

/// Records a guest wrote per request: five lines on stdout, one on stderr.
const PER_REQUEST: usize = 6;

/// Wait for asynchronous delivery, with a bound.
///
/// A guest's last unterminated line is emitted when its stream is dropped, and
/// the stream lives in the dispatch task rather than in this one — so the final
/// request's tail arrives shortly *after* the response body has been read.
/// Waiting for it is not papering over a race: eventual delivery is what this
/// pipeline promises, and asserting before it could only ever be flaky.
async fn settle(sink: &MemorySink, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while sink.len() < expected && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// The return type is what drives inference here; an inline cast does not.
fn empty_body() -> HyperOutgoingBody {
    Full::new(Bytes::new())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

async fn get(handle: &ServeHandle, path: &str) -> u16 {
    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://enclave.test{path}"))
        .body(empty_body())
        .expect("well-formed request");
    let resp = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("guest handled the request");
    let status = resp.status().as_u16();
    // Drained, so the guest's instance is finished with before the records are
    // read: the last unterminated line is emitted when its stream drops.
    let _ = resp.into_body().collect().await.expect("collecting body");
    status
}

/// The whole point, in one test: bytes a guest wrote reach the runtime's sink,
/// framed into lines, tagged with the stream they came from.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_guest_write_arrives_as_a_framed_record() {
    let sink = Arc::new(MemorySink::default());
    let (handle, collector) = handle_with(sink.clone()).await;
    assert_eq!(get(&handle, "/log").await, 200);

    // Ends the instance and drains the queue, so what follows is everything
    // the guest produced and not a snapshot part way through.
    drop(handle);
    settle(&sink, PER_REQUEST).await;
    collector.shutdown().await;

    let out = sink.messages(GuestStream::Stdout);
    let err = sink.messages(GuestStream::Stderr);

    // Two `write_all`s, one line: the runtime joined them.
    assert!(out.contains(&"first line".to_string()), "stdout: {out:?}");
    // A blank line the guest wrote is a record the runtime kept.
    assert!(out.contains(&String::new()), "stdout: {out:?}");
    // CRLF normalised, with no stray carriage return left behind.
    assert!(out.contains(&"windows".to_string()), "stdout: {out:?}");
    // Bytes that are not UTF-8 neither trapped the guest nor lost the line.
    assert!(
        out.iter()
            .any(|m| m.starts_with("invalid ") && m.ends_with(" bytes") && m.contains('\u{fffd}')),
        "stdout: {out:?}"
    );
    // The final line had no terminator and was emitted when the stream closed.
    assert!(
        out.contains(&"no trailing newline".to_string()),
        "stdout: {out:?}"
    );

    // The distinction that must survive the whole path.
    assert_eq!(err, vec!["on stderr".to_string()], "stderr: {err:?}");
    assert!(
        !out.contains(&"on stderr".to_string()),
        "stderr leaked into stdout: {out:?}"
    );
}

/// Nothing the guest writes goes anywhere but the sink. If any of this had
/// still been inherited, these records would be on the test's own stdout and
/// the sink would be short.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn no_guest_output_escapes_to_the_hosts_own_streams() {
    let sink = Arc::new(MemorySink::default());
    let (handle, collector) = handle_with(sink.clone()).await;
    for _ in 0..3 {
        assert_eq!(get(&handle, "/log").await, 200);
    }
    drop(handle);
    settle(&sink, 3 * PER_REQUEST).await;
    collector.shutdown().await;

    // Six per request: five stdout lines and one stderr.
    let out = sink.messages(GuestStream::Stdout);
    let err = sink.messages(GuestStream::Stderr);
    assert_eq!(err.len(), 3, "stderr: {err:?}");
    assert_eq!(out.len(), 15, "stdout: {out:?}");
}

/// Each request is a fresh instance with fresh streams, so an unterminated
/// line from one request must not be joined to the next one's first line.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn one_requests_partial_line_does_not_join_the_next() {
    let sink = Arc::new(MemorySink::default());
    let (handle, collector) = handle_with(sink.clone()).await;
    assert_eq!(get(&handle, "/log").await, 200);
    assert_eq!(get(&handle, "/log").await, 200);
    drop(handle);
    settle(&sink, 2 * PER_REQUEST).await;
    collector.shutdown().await;

    let out = sink.messages(GuestStream::Stdout);
    assert_eq!(
        out.iter().filter(|m| *m == "no trailing newline").count(),
        2,
        "each request's tail must stand alone: {out:?}"
    );
    assert!(
        !out.iter().any(|m| m.contains("no trailing newlinefirst")),
        "two requests' output was spliced: {out:?}"
    );
}
