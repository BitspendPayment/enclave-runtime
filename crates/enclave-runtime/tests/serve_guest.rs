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
//! $ cargo test -p enclave-runtime --test serve_guest -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
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

fn body(bytes: &[u8]) -> HyperOutgoingBody {
    Full::new(Bytes::copy_from_slice(bytes))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

/// One filesystem, one compiled guest, many requests — the arrangement the
/// runtime actually uses.
async fn handle_for(env: &[(String, String)]) -> ServeHandle {
    handle_for_with(env, 1).await
}

/// A handle over a filesystem that already exists, at a chosen concurrency.
///
/// Separated so a test can build a *second* handle over the first one's
/// storage — the only way to ask what survives a restart — and so the
/// per-client tests can raise the limit. Tenancy only means anything above 1:
/// the limit is a global admission cap, and at 1 every client still queues
/// behind every other whatever the per-client locks say.
async fn handle_over_with(
    fs: Arc<Fs>,
    env: &[(String, String)],
    concurrency: usize,
) -> ServeHandle {
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

    let engine = ServeHandle::engine_with_watchdog().expect("engine");
    ServeHandle::new(&engine, &bytes, guest, concurrency).expect("preparing the guest")
}

/// A runtime filesystem plus a handle, at a chosen concurrency.
async fn handle_for_with(env: &[(String, String)], concurrency: usize) -> ServeHandle {
    let backend = Arc::new(MemoryBackend::new());
    // `create`, not `mount`: mounting stopped formatting an empty store when
    // the boot machine landed, because a store that answers "nothing" is now a
    // refusal rather than an invitation to make a fresh filesystem.
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([7u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the memory-backed filesystem");
    handle_over_with(fs, env, concurrency).await
}

async fn get_as(handle: &ServeHandle, path: &str, tenant: Option<&[u8; 16]>) -> (u16, String) {
    request_as(handle, "GET", path, &[], tenant).await
}

async fn request_as(
    handle: &ServeHandle,
    method: &str,
    path: &str,
    body_bytes: &[u8],
    tenant: Option<&[u8; 16]>,
) -> (u16, String) {
    let req = hyper::Request::builder()
        .method(method)
        .uri(format!("http://enclave.test{path}"))
        .body(body(body_bytes))
        .expect("well-formed request");
    let resp = handle
        .handle(Scheme::Http, req, tenant)
        .await
        .expect("guest handled the request");
    let status = resp.status().as_u16();
    let collected = resp.into_body().collect().await.expect("collecting body");
    (
        status,
        String::from_utf8_lossy(&collected.to_bytes()).into_owned(),
    )
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
        .handle(Scheme::Http, req, None)
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
    use enclave_runtime::EgressPolicy;
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

/// A guest that never returns and never answers.
///
/// Without a watchdog this is not a slow request, it is a permanent one: the
/// `oneshot::Sender` lives in the `Store`, the `Store` was moved into the
/// spawned task, so `receiver.await` can never resolve, the concurrency permit
/// is never released, and at the default of one request in flight the server
/// is finished for the life of the process.
///
/// The assertions are ordered accordingly — the second one is the point. The
/// first only shows the request gave up; the second shows the *server* did not.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_hung_guest_does_not_wedge_the_server() {
    let handle = handle_for(&[])
        .await
        .with_timeout(std::time::Duration::from_secs(3));

    let req = hyper::Request::builder()
        .method("GET")
        .uri("http://enclave.test/hang")
        .body(body(b""))
        .expect("well-formed request");

    // Belt and braces: if the watchdog regresses this fails rather than hanging
    // the whole suite, which is what it would do otherwise.
    let hung = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        handle.handle(Scheme::Http, req, None),
    )
    .await
    .expect("the watchdog did not fire; the request hung");

    // Either mechanism is a correct outcome and which one fires depends on
    // where the guest is stuck: spinning wasm is trapped by the epoch, a guest
    // parked in a host call is abandoned by the timeout. Asserting on one would
    // make this a test of the message rather than of the guarantee.
    hung.expect_err("a guest that never answers must not succeed");

    // The permit was released and the guest instance is gone, so the next
    // request is served normally. This is the assertion that matters.
    let (status, body) = get(&handle, "/").await;
    assert_eq!(
        status, 200,
        "the server was wedged by the hung request: {body}"
    );
}

// ---------------------------------------------------------------------------
// One instance per request. No two requests share one.
// ---------------------------------------------------------------------------

/// The isolation invariant, stated as a test.
///
/// `/memory` increments a counter held in the guest's linear memory and written
/// nowhere. A fresh instance has fresh memory, so it can only ever answer `1`.
/// Any other answer means two requests reached the same instance — and with
/// one instance behind two clients, the `Store` boundary that separates them
/// has moved from the runtime into guest code, where a single bug confuses two
/// clients instead of one.
///
/// This is the test that fails if anyone reintroduces a shared instance. It
/// sends enough requests to mean it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn no_two_requests_share_an_instance() {
    let handle = handle_for(&[]).await;
    for n in 1..=200 {
        let (status, body) = get(&handle, "/memory").await;
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(
            body.trim(),
            "1",
            "request {n} reached an instance a previous request had already used"
        );
    }
}

/// The guest is built before the listener binds, not on the first request. A
/// guest that will not instantiate should stop the enclave rather than serving
/// 500s while looking healthy.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_is_proved_to_instantiate_at_startup() {
    let handle = handle_for(&[]).await;
    handle
        .verify_instantiates()
        .await
        .expect("the guest instantiates");

    // And keeps nothing: the check must not leave an instance behind for a
    // request to inherit.
    let (_, body) = get(&handle, "/memory").await;
    assert_eq!(
        body.trim(),
        "1",
        "the startup check left an instance behind"
    );
}

/// A trap dies with its request. There is no instance to poison and nothing to
/// rebuild, so the next request is simply unaffected — which is the property
/// that a shared instance could not offer at any price.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_trap_dies_with_its_request() {
    let handle = handle_for(&[])
        .await
        .with_timeout(std::time::Duration::from_secs(3));

    // `/hang` spins until the epoch traps it.
    let req = hyper::Request::builder()
        .method("GET")
        .uri("http://enclave.test/hang")
        .body(body(b""))
        .expect("well-formed request");
    let wedged = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        handle.handle(Scheme::Http, req, None),
    )
    .await
    .expect("the watchdog did not fire");
    assert!(wedged.is_err(), "a wedged guest was reported as success");

    let (status, body) = get(&handle, "/memory").await;
    assert_eq!(status, 200, "the service did not recover: {body}");
    assert_eq!(body.trim(), "1");
}

// ---------------------------------------------------------------------------
// The client identity the guest is told about.
// ---------------------------------------------------------------------------

/// A tenant id, as the gate would have resolved one.
///
/// These tests exercise what happens *after* authentication — isolation,
/// warmth, concurrency — so they take the tenant as given. That the tenant can
/// only come from a verified assertion is the gate's own business, and
/// `auth::gate` tests it directly.
fn identity(name: &str) -> [u8; 16] {
    let full = nitro_attestation::sha256(name.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

async fn whoami(handle: &ServeHandle, tenant: Option<&[u8; 16]>, forged: Option<&str>) -> String {
    let mut builder = hyper::Request::builder()
        .method("GET")
        .uri("http://enclave.test/whoami");
    if let Some(value) = forged {
        // Three copies, because one survivor is all a forgery needs and
        // `append` would leave exactly that.
        builder = builder
            .header("x-enclave-client", value)
            .header("x-enclave-client", value)
            .header("x-enclave-client", value);
    }
    let req = builder.body(body(b"")).expect("well-formed request");
    let resp = handle
        .handle(Scheme::Http, req, tenant)
        .await
        .expect("guest handled the request");
    let collected = resp.into_body().collect().await.expect("collecting body");
    String::from_utf8_lossy(&collected.to_bytes())
        .trim()
        .to_string()
}

/// The runtime's word reaches the guest.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_is_told_which_tenant_is_calling() {
    let handle = handle_for(&[]).await;
    let id = identity("a-client");
    assert_eq!(whoami(&handle, Some(&id), None).await, hex::encode(id));
}

/// The forgery. A client sending the header itself must not be believed, and
/// sending it three times must not leave one behind — the guest's
/// `fields.get()` returns a list, so a survivor at `[0]` would be the
/// attacker's.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_client_cannot_forge_its_own_tenant() {
    let handle = handle_for(&[]).await;
    let real = identity("the-real-client");
    let stolen = hex::encode(identity("someone-else"));

    assert_eq!(
        whoami(&handle, Some(&real), Some(&stolen)).await,
        hex::encode(real),
        "a client-supplied header was believed"
    );
}

/// And the shorter route to the same forgery: no identity at all, so the
/// client's own header must be removed rather than passed through.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn an_unauthenticated_request_reaches_the_guest_as_anonymous() {
    let handle = handle_for(&[]).await;
    let stolen = hex::encode(identity("someone-else"));

    assert_eq!(
        whoami(&handle, None, Some(&stolen)).await,
        "(anonymous)",
        "an unauthenticated client forged an identity"
    );
}

// ---------------------------------------------------------------------------
// A filesystem per client.
// ---------------------------------------------------------------------------

/// A handle that gives every authenticated client their own directory of the
/// one shared filesystem.
async fn tenanted(concurrency: usize) -> ServeHandle {
    let handle = handle_for_with(&[], concurrency).await;
    let tenancy = enclave_runtime::Tenancy::new(enclave_runtime::PoolLimits::default());
    handle.with_tenancy(Arc::new(tenancy))
}

/// A client's own directory persists between their requests, and the warm
/// instance means their in-memory state does too.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_client_keeps_their_own_directory_and_instance() {
    let handle = tenanted(4).await;
    let client = identity("a-client");

    for expected in 1..=3 {
        let (status, body) = get_as(&handle, "/counter", Some(&client)).await;
        assert_eq!(status, 200, "body: {body}");
        assert_eq!(body.trim(), expected.to_string(), "the directory reset");
    }
    // And the instance was kept, which a fresh one could never show.
    for expected in 1..=3 {
        let (_, body) = get_as(&handle, "/memory", Some(&client)).await;
        assert_eq!(
            body.trim(),
            expected.to_string(),
            "the instance was rebuilt"
        );
    }
}

/// **The isolation property.** Two clients write the same path and neither
/// sees the other's value — because `/` means a different directory to each of
/// them, and the resolver will not let either name the other's.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn two_clients_never_see_each_others_data() {
    let handle = tenanted(4).await;
    let alice = identity("alice");
    let bob = identity("bob");

    request_as(
        &handle,
        "POST",
        "/files/secret.txt",
        b"alice's",
        Some(&alice),
    )
    .await;
    request_as(&handle, "POST", "/files/secret.txt", b"bob's", Some(&bob)).await;

    let (_, seen_by_alice) = get_as(&handle, "/files/secret.txt", Some(&alice)).await;
    let (_, seen_by_bob) = get_as(&handle, "/files/secret.txt", Some(&bob)).await;
    assert_eq!(seen_by_alice, "alice's");
    assert_eq!(seen_by_bob, "bob's", "one client read another's file");

    // Their counters are independent too: same path, two directories.
    let (_, a) = get_as(&handle, "/counter", Some(&alice)).await;
    let (_, b) = get_as(&handle, "/counter", Some(&bob)).await;
    assert_eq!(a.trim(), "1");
    assert_eq!(b.trim(), "1", "a shared counter means a shared view");
}

/// And no shared linear memory either — the `Store` boundary, not guest code.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn two_clients_never_share_an_instance() {
    let handle = tenanted(4).await;
    let alice = identity("alice");
    let bob = identity("bob");

    for _ in 0..5 {
        get_as(&handle, "/memory", Some(&alice)).await;
    }
    let (_, bobs_first) = get_as(&handle, "/memory", Some(&bob)).await;
    assert_eq!(
        bobs_first.trim(),
        "1",
        "a second client landed in the first client's instance"
    );
}

/// An anonymous caller occupies no slot, so anyone who can open a socket
/// cannot fill the pool and evict every real client's mount.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn an_anonymous_caller_gets_no_tenant() {
    let handle = tenanted(4).await;
    for _ in 0..3 {
        let (status, body) = get_as(&handle, "/memory", None).await;
        assert_eq!(status, 200);
        assert_eq!(body.trim(), "1", "an anonymous caller kept an instance");
    }
}

/// A trap takes down one client's instance and touches nobody else — the whole
/// argument for the per-client boundary, as a test.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_trap_is_contained_to_one_client() {
    let handle = tenanted(4)
        .await
        .with_timeout(std::time::Duration::from_secs(3));

    let alice = identity("alice");
    let bob = identity("bob");

    // Bob builds up instance state.
    for _ in 0..3 {
        get_as(&handle, "/memory", Some(&bob)).await;
    }

    // Alice wedges hers.
    let req = hyper::Request::builder()
        .method("GET")
        .uri("http://enclave.test/hang")
        .body(body(b""))
        .expect("well-formed request");
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        handle.handle(Scheme::Http, req, Some(&alice)),
    )
    .await
    .expect("the watchdog did not fire");

    // Alice's instance was rebuilt; Bob's was never touched.
    let (status, alices) = get_as(&handle, "/memory", Some(&alice)).await;
    assert_eq!(status, 200, "alice's tenant did not recover: {alices}");
    assert_eq!(alices.trim(), "1", "a trapped instance was reused");

    let (_, bobs) = get_as(&handle, "/memory", Some(&bob)).await;
    assert_eq!(
        bobs.trim(),
        "4",
        "another client's trap reset bob's instance"
    );
}

/// Their data survives too: a trap discards the poisoned instance and nothing
/// else. The filesystem is shared and was never in question.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_trap_keeps_the_clients_data() {
    let handle = tenanted(4)
        .await
        .with_timeout(std::time::Duration::from_secs(3));
    let alice = identity("alice");

    let (_, before) = get_as(&handle, "/counter", Some(&alice)).await;
    assert_eq!(before.trim(), "1");

    let req = hyper::Request::builder()
        .method("GET")
        .uri("http://enclave.test/hang")
        .body(body(b""))
        .expect("well-formed request");
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        handle.handle(Scheme::Http, req, Some(&alice)),
    )
    .await
    .expect("the watchdog did not fire");

    let (_, after) = get_as(&handle, "/counter", Some(&alice)).await;
    assert_eq!(
        after.trim(),
        "2",
        "the client's directory was lost after a trap"
    );
}

/// The concurrency property, and the reason the whole design exists: two
/// clients run at the same time. `/hang` holds Alice's tenant until the epoch
/// traps it; Bob must be served long before that.
///
/// Note what this does *not* do: abort the hung task and walk away.
/// `tokio::abort` needs an await point and spinning wasm never reaches one, so
/// only the epoch can stop it — and the epoch ticker is itself a task on this
/// runtime, which stops being polled once the test returns. Aborting and
/// leaving therefore hangs at shutdown instead of failing. The test waits for
/// the trap it knows is coming.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn one_client_does_not_wait_for_another() {
    let handle = Arc::new(
        tenanted(4)
            .await
            .with_timeout(std::time::Duration::from_secs(3)),
    );
    let alice = identity("alice");
    let bob = identity("bob");

    // Warm Bob first, so the assertion below measures contention rather than
    // the cost of a cold mount.
    assert_eq!(get_as(&handle, "/counter", Some(&bob)).await.0, 200);

    let hung = {
        let handle = handle.clone();
        tokio::task::spawn(async move {
            let req = hyper::Request::builder()
                .method("GET")
                .uri("http://enclave.test/hang")
                .body(body(b""))
                .expect("well-formed request");
            let _ = handle.handle(Scheme::Http, req, Some(&alice)).await;
        })
    };

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // Alice spins until the epoch traps her at ~2.5s. Queued behind her, Bob
    // could not possibly answer inside 1.5s.
    let served = tokio::time::timeout(
        std::time::Duration::from_millis(1_500),
        get_as(&handle, "/counter", Some(&bob)),
    )
    .await
    .expect("bob waited on alice's request; clients are not running concurrently");
    assert_eq!(served.0, 200);
    assert_eq!(served.1.trim(), "2", "bob's own filesystem did not advance");

    // Let the epoch trap Alice, so nothing is left spinning at shutdown.
    tokio::time::timeout(std::time::Duration::from_secs(30), hung)
        .await
        .expect("the epoch never trapped the hung guest")
        .expect("the hung task panicked");
}

/// **Separation is the runtime's, not the guest's.**
///
/// `/escape/<path>` opens whatever it is given with no validation at all — a
/// guest that is actively not helping. Everything below must still be refused,
/// and refused by the capability layer: absolute paths restart at the tenant's
/// own root, `..` stops there, and no number of either walks out.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_tenant_cannot_escape_its_directory_even_with_a_hostile_guest() {
    let handle = tenanted(4).await;
    let alice = identity("alice");
    let bob = identity("bob");

    // Bob has something worth stealing, at a path Alice can name exactly.
    request_as(&handle, "POST", "/files/secret.txt", b"bob's", Some(&bob)).await;
    let bob_id = hex::encode(bob);

    for attempt in [
        format!("/tenants/{bob_id}/http-example/secret.txt"),
        format!("../{bob_id}/http-example/secret.txt"),
        format!("../../tenants/{bob_id}/http-example/secret.txt"),
        "../../../../../../etc/passwd".to_string(),
    ] {
        let (status, body) = get_as(&handle, &format!("/escape/{attempt}"), Some(&alice)).await;
        assert_eq!(status, 404, "{attempt} was not refused: {body}");
        assert!(
            !body.contains("read 5 bytes"),
            "{attempt} reached another tenant's file: {body}"
        );
    }

    // And the same unvalidated route reads Alice's *own* file, so the refusals
    // above are the scope working and not simply a broken code path.
    request_as(&handle, "POST", "/files/mine.txt", b"alice's", Some(&alice)).await;
    let (status, body) = get_as(&handle, "/escape//http-example/mine.txt", Some(&alice)).await;
    assert_eq!(status, 200, "a tenant could not read its own file: {body}");
}
