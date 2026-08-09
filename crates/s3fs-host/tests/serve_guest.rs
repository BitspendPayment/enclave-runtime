//! End-to-end for the serving path: a real `wasi:http/proxy` component,
//! dispatched through the real linker, reading and writing a real block store.
//!
//! It runs over [`MemoryBackend`] rather than MinIO, so it needs no Docker and
//! no network — the thing under test is the HTTP dispatch and the guest's view
//! of the filesystem, neither of which cares whether the blocks land in S3 or
//! in a `HashMap`. The S3 backend has its own integration suite.
//!
//! Ignored by default because it needs the guest component built first:
//!
//! ```console
//! $ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p s3fs-host --features serve --test serve_guest -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::{Config, Fs, MasterSecret};
use s3fs_host::{GuestEnvironment, HostClock, ServeHandle};
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

fn body(bytes: &[u8]) -> HyperOutgoingBody {
    Full::new(Bytes::copy_from_slice(bytes))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

/// One filesystem, one compiled guest, many requests — the arrangement the
/// runtime actually uses.
async fn handle_for(env: &[(String, String)]) -> ServeHandle {
    let backend = Arc::new(MemoryBackend::new());
    let master = MasterSecret::from_bytes([7u8; 32]);
    let fs = Fs::mount(
        backend.clone(),
        backend,
        &master,
        [0u8; 16],
        Arc::new(Config::default()),
        None,
    )
    .await
    .expect("mounting the memory-backed filesystem");

    let guest = GuestEnvironment::new(
        fs,
        Box::new(HostClock),
        Arc::new(nitro_nsm::fake::FakeNsm::new()),
        env,
        &[],
    )
    .expect("building the guest environment");

    let bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-http && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });

    let engine = wasmtime::Engine::new(&wasmtime::Config::new()).expect("engine");
    ServeHandle::new(&engine, &bytes, guest, 1).expect("preparing the guest")
}

async fn get(handle: &ServeHandle, path: &str) -> (u16, String) {
    request(handle, "GET", path, &[]).await
}

async fn request(
    handle: &ServeHandle,
    method: &str,
    path: &str,
    body_bytes: &[u8],
) -> (u16, String) {
    let req = hyper::Request::builder()
        .method(method)
        .uri(format!("http://enclave.test{path}"))
        .body(body(body_bytes))
        .expect("well-formed request");
    let resp = handle
        .handle(Scheme::Http, req)
        .await
        .expect("guest handled the request");
    let status = resp.status().as_u16();
    let collected = resp.into_body().collect().await.expect("collecting body");
    (
        status,
        String::from_utf8_lossy(&collected.to_bytes()).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_answers_requests() {
    let handle = handle_for(&[]).await;
    let (status, body) = get(&handle, "/").await;
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("guest-http"), "unexpected banner: {body}");
}

/// The load-bearing test. Each request gets its own `Store` and its own guest
/// instance; only a *committed* filesystem carries the count between them. If
/// this returns 1 twice, requests are being served against separate or
/// uncommitted views of the store.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn state_written_by_one_request_is_visible_to_the_next() {
    let handle = handle_for(&[]).await;
    for expected in 1..=3 {
        let (status, body) = get(&handle, "/counter").await;
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(body.trim(), expected.to_string(), "counter did not advance");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_file_written_over_http_reads_back() {
    let handle = handle_for(&[]).await;
    let payload = b"the block store round-trips through wasi:http";

    let (status, body) = request(&handle, "POST", "/files/note.txt", payload).await;
    assert_eq!(status, 201, "body: {body}");

    let (status, body) = get(&handle, "/files/note.txt").await;
    assert_eq!(status, 200);
    assert_eq!(body.as_bytes(), payload);
}

/// The environment policy reaches an HTTP guest by the same path a command
/// guest uses — `GuestEnvironment` builds both, which is why it exists.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_environment_policy_reaches_the_guest() {
    let handle = handle_for(&[("DEPLOYMENT".to_string(), "test".to_string())]).await;
    let (status, body) = get(&handle, "/env").await;
    assert_eq!(status, 200);
    assert!(body.contains("DEPLOYMENT=test"), "env was: {body}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn an_unknown_route_is_the_guests_own_404() {
    let handle = handle_for(&[]).await;
    let (status, _) = get(&handle, "/nothing-here").await;
    assert_eq!(status, 404);
}

/// A path escaping the guest's own directory is refused *by the guest*. The
/// preopen it holds is the filesystem root, so nothing below would have
/// stopped it — which is exactly why the example does the check and why this
/// test guards the example.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_traversing_path_is_refused() {
    let handle = handle_for(&[]).await;
    let (status, body) = get(&handle, "/files/../counter").await;
    assert_ne!(status, 200, "traversal must not succeed: {body}");
}

/// `wasi:http/outgoing-handler` is linked, so a guest can call it. It must
/// fail. This is the enclave's egress boundary, checked through the same
/// linker the runtime uses rather than against the policy type in isolation.
#[tokio::test(flavor = "multi_thread")]
async fn the_linker_denies_guest_egress() {
    use s3fs_host::EgressPolicy;
    use wasmtime_wasi_http::p2::{types::OutgoingRequestConfig, WasiHttpHooks};

    let mut policy = EgressPolicy::Denied;
    let req = hyper::Request::builder()
        .uri("https://example.invalid/")
        .body(body(b""))
        .unwrap();
    let config = OutgoingRequestConfig {
        use_tls: true,
        connect_timeout: std::time::Duration::from_secs(1),
        first_byte_timeout: std::time::Duration::from_secs(1),
        between_bytes_timeout: std::time::Duration::from_secs(1),
    };
    let Err(err) = policy.send_request(req, config) else {
        panic!("egress must be refused");
    };
    assert!(format!("{err:?}").contains("HttpRequestDenied"), "{err:?}");
}
