//! The harness a guest author gets, used the way they would use it.
//!
//! Every test here is what a separate repository — one whose component this
//! runtime will serve — would write against `enclave_runtime::testing`. If any
//! of it needs knowledge that lives only in this repository, the harness is not
//! finished.
//!
//! ```console
//! $ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test harness -- --ignored
//! ```

use enclave_runtime::testing::Enclave;

fn guest() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm");
    std::fs::read(path).expect("build examples/guest-http for wasm32-wasip2")
}

/// An FCM-shaped registration token, as a client would present.
const DEVICE: &str = "harness-device:APA91bEnclaveRuntimeTestHarness0123456789";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_guest_author_can_stand_up_an_enclave_and_sign_a_request() {
    let enclave = Enclave::builder(guest()).start().await.unwrap();

    let alice = enclave.enrol().await.unwrap();
    let (status, body) = enclave.signed(&alice, "GET", "/counter", "").await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.trim(), "1");

    // And the gate is real: the same route without an assertion is refused.
    let (status, _, _) = enclave.request("GET", "/counter", &[], "").await.unwrap();
    assert_eq!(
        status, 401,
        "the harness served a guest without an assertion"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn two_passkeys_are_two_tenants() {
    let enclave = Enclave::builder(guest()).start().await.unwrap();
    let alice = enclave.enrol().await.unwrap();
    let bob = enclave.enrol().await.unwrap();
    assert_ne!(alice.tenant(), bob.tenant());

    enclave
        .signed(&alice, "POST", "/files/who.txt", "alice")
        .await
        .unwrap();
    enclave
        .signed(&bob, "POST", "/files/who.txt", "bob")
        .await
        .unwrap();

    let (_, seen_by_alice) = enclave
        .signed(&alice, "GET", "/files/who.txt", "")
        .await
        .unwrap();
    let (_, seen_by_bob) = enclave
        .signed(&bob, "GET", "/files/who.txt", "")
        .await
        .unwrap();
    assert_eq!(seen_by_alice.trim(), "alice");
    assert_eq!(seen_by_bob.trim(), "bob", "one tenant read another's file");
}

/// What a guest author most needs to see: work scheduled by one interaction
/// ran later, and woke its owner, with nothing signed at the moment it did.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_task_that_finishes_wakes_its_owner() {
    let enclave = Enclave::builder(guest())
        .background_tasks()
        .notify()
        .start()
        .await
        .unwrap();

    let alice = enclave.enrol().await.unwrap();
    let (status, body) = enclave
        .signed(&alice, "POST", "/devices", DEVICE)
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");

    let (status, body) = enclave
        .signed(&alice, "POST", "/tasks/job", "work")
        .await
        .unwrap();
    assert_eq!(status, 202, "{body}");

    let wake = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if let Some(wake) = enclave.wakes().into_iter().next() {
                return wake;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the finished task never woke anybody");

    assert_eq!(wake.category, "task-done");
    assert_eq!(wake.reference.as_deref(), Some("job"));
    assert_eq!(wake.token, DEVICE);
}

/// The measurements a client would pin, available before it connects.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_harness_says_what_a_client_would_have_to_pin() {
    let bytes = guest();
    let enclave = Enclave::builder(bytes.clone()).start().await.unwrap();

    assert_eq!(
        enclave.pcr16(),
        nitro_attestation::guest_pcr(&bytes),
        "the harness disagrees with the verifier about the guest"
    );
    assert!(!enclave.trust_root().is_empty());
    assert!(enclave.url().starts_with("https://127.0.0.1:"));
}
