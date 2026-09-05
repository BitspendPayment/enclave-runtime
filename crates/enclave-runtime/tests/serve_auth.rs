//! The rule, over a real socket: **no assertion, no guest.**
//!
//! `serve_guest.rs` tests what happens once a tenant has been resolved.
//! `auth::gate` tests the verification itself. This is the join between them —
//! a real listener, a real TLS handshake, the real dispatch — because the
//! interesting failure is not in either half but in the wiring: a gate that
//! verifies perfectly and is never consulted protects nothing.
//!
//! ```console
//! $ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test serve_auth -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use enclave_runtime::{
    AuthEndpoints, ChallengeStore, FilesystemCredentials, Gate, GuestEnvironment, HostClock,
    PoolLimits, ServeConfig, SoftwareAuthenticator, Tenancy, TlsIdentity,
};
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::{Config, Fs, MasterSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RP_ID: &str = "enclave.test";
const ORIGIN: &str = "https://enclave.test";
/// Two, so a test can enrol two tenants. A token is single-use by design, and
/// there is deliberately no way to mint one over the wire.
const TOKENS: [&str; 2] = ["an-invite-code-long-enough", "a-second-invite-code-long"];

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

struct Harness {
    addr: std::net::SocketAddr,
}

async fn start() -> Harness {
    let backend = Arc::new(MemoryBackend::new());
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([9u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("filesystem");

    let bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-http && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });

    let entropy: Arc<dyn nitro_nsm::Nsm> = Arc::new(nitro_nsm::fake::FakeNsm::new());
    let credentials = Arc::new(FilesystemCredentials::new(fs.clone()));
    let gate = Arc::new(Gate::new(
        enclave_runtime::build_relying_party(RP_ID, ORIGIN).expect("relying party"),
        ChallengeStore::new(std::time::Duration::from_secs(60), 256),
        credentials.clone(),
        64 * 1024,
    ));
    let auth = Arc::new(AuthEndpoints::new(
        gate.clone(),
        credentials,
        fs.clone(),
        entropy.clone(),
    ));
    for token in TOKENS {
        auth.enrollment().seed(token).await.expect("seeding");
    }

    // Detached deliberately: the collector runs for as long as this
    // environment can send, which is what a test wants. Production drains it
    // explicitly instead.
    let (logs, _collector) =
        enclave_runtime::guest_io::start(std::sync::Arc::new(enclave_runtime::TracingLogSink));
    let guest = GuestEnvironment::new(fs, Box::new(HostClock), entropy, &[], &[], logs)
        .expect("guest environment");
    let tls = TlsIdentity::self_signed(&[RP_ID.to_string()]).expect("tls identity");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let _ = enclave_runtime::serve_component(
            &bytes,
            guest,
            ServeConfig {
                addr,
                certificate: Some(enclave_runtime::CertificateSlot::fixed(Arc::new(tls))),
                acme: None,
                attestation: None,
                request_timeout: std::time::Duration::from_secs(30),
                tenancy: Some(Arc::new(Tenancy::new(PoolLimits::default()))),
                authentication: Some((auth, gate)),
            },
        )
        .await;
    });

    for _ in 0..400 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Harness { addr };
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the server never came up on {addr}");
}

/// One request over TLS, with whatever headers the caller wants.
/// A distinct nonce per request, base64url and unpadded.
///
/// Distinct rather than random: these tests need only that no two requests
/// share one. A real client uses a CSPRNG.
fn fresh_nonce() -> String {
    use base64::Engine as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut nonce = vec![0x5au8; 20];
    nonce[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

async fn https(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String) {
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(RP_ID).unwrap();

    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut stream = connector.connect(name, socket).await.expect("handshake");

    // Every request carries a nonce, whether or not the deployment attests —
    // this harness runs with `attestation: None` and must still send one, which
    // is the point of that rule: a client behaves the same either way.
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {RP_ID}\r\nConnection: close\r\n\
         x-enclave-nonce: {}\r\nContent-Length: {}\r\n",
        fresh_nonce(),
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).await.expect("write");

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let rest = &raw[split + 4..];
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    (status, String::from_utf8_lossy(&body).to_string())
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(end) = rest.windows(2).position(|w| w == b"\r\n") {
        let header = String::from_utf8_lossy(&rest[..end]);
        let Ok(size) = usize::from_str_radix(header.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        rest = &rest[end + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
    out
}

async fn post_json(
    addr: std::net::SocketAddr,
    path: &str,
    value: serde_json::Value,
) -> (u16, serde_json::Value) {
    let (status, body) = https(
        addr,
        "POST",
        path,
        &[("content-type", "application/json".into())],
        &value.to_string(),
    )
    .await;
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

/// Register a passkey and return it, ready to sign for requests.
async fn enrol(addr: std::net::SocketAddr, token: &str) -> SoftwareAuthenticator {
    let auth = SoftwareAuthenticator::new(RP_ID);
    let (status, options) = post_json(
        addr,
        "/auth/register/options",
        serde_json::json!({ "enrollment_token": token }),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    let challenge = options["options"]["publicKey"]["challenge"]
        .as_str()
        .expect("a challenge");
    let (status, body) = post_json(
        addr,
        "/auth/register/verify",
        serde_json::json!({
            "registration_id": options["registration_id"],
            "credential": auth.register(challenge, ORIGIN),
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    auth
}

/// A signed request: ask for a challenge bound to it, then send it.
async fn signed(
    addr: std::net::SocketAddr,
    auth: &SoftwareAuthenticator,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String) {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    let (status, options) = post_json(
        addr,
        "/auth/request/options",
        serde_json::json!({
            "credential_id": b64.encode(auth.credential_id()),
            "method": method,
            "path": path_only,
            "query": query,
            "body_sha256": b64.encode(nitro_attestation::sha256(body.as_bytes())),
        }),
    )
    .await;
    assert_eq!(status, 200, "{options}");

    let challenge = options["options"]["publicKey"]["challenge"]
        .as_str()
        .expect("a challenge");
    let assertion = auth.assert(challenge, ORIGIN);
    https(
        addr,
        method,
        path,
        &[
            (
                "x-webauthn-challenge-id",
                options["challenge_id"].as_str().unwrap().to_string(),
            ),
            ("x-webauthn-assertion", b64.encode(assertion.to_string())),
        ],
        body,
    )
    .await
}

/// **The rule.** Nothing reaches the guest without an assertion.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_is_unreachable_without_an_assertion() {
    let h = start().await;
    for path in ["/", "/counter", "/whoami", "/files/x", "/nothing-here"] {
        let (status, body) = https(h.addr, "GET", path, &[], "").await;
        assert_eq!(status, 401, "{path} reached the guest: {body}");
        // Not the guest's own 404, and not its banner: the guest was never
        // called at all.
        assert!(!body.contains("guest-http"), "{path} was served: {body}");
        assert!(!body.contains("no route for"), "{path} reached the guest");
    }
}

/// And with one, it works — so the refusals above mean something.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_signed_request_reaches_the_guest() {
    let h = start().await;
    let auth = enrol(h.addr, TOKENS[0]).await;

    let (status, body) = signed(h.addr, &auth, "GET", "/counter", "").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.trim(), "1");

    // A second, separately signed request continues the same tenant.
    let (status, body) = signed(h.addr, &auth, "GET", "/counter", "").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.trim(), "2", "the tenant did not persist");
}

/// The guest is told which tenant, and the assertion decided it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_is_told_the_resolved_tenant() {
    let h = start().await;
    let alice = enrol(h.addr, TOKENS[0]).await;

    let (status, seen) = signed(h.addr, &alice, "GET", "/whoami", "").await;
    assert_eq!(status, 200);
    assert_eq!(seen.trim().len(), 32, "expected a hex tenant id: {seen}");
    assert_ne!(seen.trim(), "(anonymous)");
}

/// **The substitution, over a real socket.** An approval for one body must not
/// authorize another.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn an_assertion_cannot_be_moved_to_another_request() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h = start().await;
    let auth = enrol(h.addr, TOKENS[0]).await;

    // A challenge bound to writing "approved".
    let (_, options) = post_json(
        h.addr,
        "/auth/request/options",
        serde_json::json!({
            "credential_id": b64.encode(auth.credential_id()),
            "method": "POST",
            "path": "/files/note.txt",
            "body_sha256": b64.encode(nitro_attestation::sha256(b"approved")),
        }),
    )
    .await;
    let assertion = auth.assert(
        options["options"]["publicKey"]["challenge"]
            .as_str()
            .unwrap(),
        ORIGIN,
    );
    let headers = [
        (
            "x-webauthn-challenge-id",
            options["challenge_id"].as_str().unwrap().to_string(),
        ),
        ("x-webauthn-assertion", b64.encode(assertion.to_string())),
    ];

    // Sent with a different body.
    let (status, body) = https(h.addr, "POST", "/files/note.txt", &headers, "substituted").await;
    assert_eq!(status, 401, "a substituted body was authorized: {body}");
    // And the file was never written, so the guest genuinely was not called.
    let (status, _) = signed(h.addr, &auth, "GET", "/files/note.txt", "").await;
    assert_eq!(status, 404, "the substituted body reached the filesystem");
}

/// One approval, one request. A captured assertion is worthless afterwards.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn an_assertion_cannot_be_replayed() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h = start().await;
    let auth = enrol(h.addr, TOKENS[0]).await;

    let (_, options) = post_json(
        h.addr,
        "/auth/request/options",
        serde_json::json!({
            "credential_id": b64.encode(auth.credential_id()),
            "method": "GET",
            "path": "/counter",
            "body_sha256": b64.encode(nitro_attestation::sha256(b"")),
        }),
    )
    .await;
    let assertion = auth.assert(
        options["options"]["publicKey"]["challenge"]
            .as_str()
            .unwrap(),
        ORIGIN,
    );
    let headers = [
        (
            "x-webauthn-challenge-id",
            options["challenge_id"].as_str().unwrap().to_string(),
        ),
        ("x-webauthn-assertion", b64.encode(assertion.to_string())),
    ];

    assert_eq!(https(h.addr, "GET", "/counter", &headers, "").await.0, 200);
    let (status, _) = https(h.addr, "GET", "/counter", &headers, "").await;
    assert_eq!(status, 401, "an assertion authorized a second request");
}

/// Two passkeys, two tenants, and neither can see the other's data — the whole
/// arrangement, over the wire, from enrollment to storage.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn two_passkeys_are_two_tenants() {
    let h = start().await;
    let alice = enrol(h.addr, TOKENS[0]).await;
    let bob = enrol(h.addr, TOKENS[1]).await;

    let (_, alice_id) = signed(h.addr, &alice, "GET", "/whoami", "").await;
    let (_, bob_id) = signed(h.addr, &bob, "GET", "/whoami", "").await;
    assert_ne!(
        alice_id.trim(),
        bob_id.trim(),
        "two passkeys resolved to one tenant"
    );

    // The same path, written by each, holds each one's own value.
    assert_eq!(
        signed(h.addr, &alice, "POST", "/files/secret.txt", "alice's")
            .await
            .0,
        201
    );
    assert_eq!(
        signed(h.addr, &bob, "POST", "/files/secret.txt", "bob's")
            .await
            .0,
        201
    );
    let (_, seen_by_alice) = signed(h.addr, &alice, "GET", "/files/secret.txt", "").await;
    let (_, seen_by_bob) = signed(h.addr, &bob, "GET", "/files/secret.txt", "").await;
    assert_eq!(seen_by_alice, "alice's");
    assert_eq!(seen_by_bob, "bob's", "one tenant read another's file");
}

/// A token is spent by the registration it starts, whether or not that
/// registration finishes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn an_enrollment_token_is_spent_once() {
    let h = start().await;
    let _ = enrol(h.addr, TOKENS[0]).await;
    let (status, _) = post_json(
        h.addr,
        "/auth/register/options",
        serde_json::json!({ "enrollment_token": TOKENS[0] }),
    )
    .await;
    assert_eq!(status, 403, "a spent enrollment token registered again");
}

/// `/auth/*` answers without an assertion — it has to, or nobody could ever
/// get one — and it performs no cosigner action.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn auth_routes_answer_without_an_assertion() {
    let h = start().await;
    let (status, _) = post_json(
        h.addr,
        "/auth/register/options",
        serde_json::json!({ "enrollment_token": "wrong-but-long-enough-token" }),
    )
    .await;
    // Refused on its merits, not for lack of an assertion.
    assert_eq!(status, 403);

    let (status, _) = post_json(h.addr, "/auth/nonsense", serde_json::json!({})).await;
    assert_eq!(status, 404);
}

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _s: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The `passkey-client` binary, against a real server — the same path the QEMU
/// harness takes.
///
/// Worth its own test because the harness cannot be run here (`/dev/vsock` is
/// absent) and a helper that only works in theory would fail at the one moment
/// nobody is watching.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built and the passkey-client binary"]
async fn the_passkey_client_binary_drives_the_gate() {
    let h = start().await;
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/passkey-client");
    if !exe.exists() {
        eprintln!(
            "skipping: build it with\n  cargo build --release -p enclave-runtime \\\n    --features testing --bin passkey-client"
        );
        return;
    }
    let state = std::env::temp_dir().join(format!("passkey-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&state);

    let run = |args: Vec<String>| {
        let exe = exe.clone();
        let state = state.clone();
        let url = format!("https://127.0.0.1:{}", h.addr.port());
        async move {
            tokio::task::spawn_blocking(move || {
                let out = std::process::Command::new(&exe)
                    .args(["--url", &url, "--state", state.to_str().unwrap()])
                    .args(&args)
                    .output()
                    .expect("running passkey-client");
                (
                    out.status.success(),
                    String::from_utf8_lossy(&out.stdout).to_string(),
                    String::from_utf8_lossy(&out.stderr).to_string(),
                )
            })
            .await
            .unwrap()
        }
    };

    let (ok, _, err) = run(vec![
        "enrol".into(),
        "--token".into(),
        TOKENS[0].to_string(),
    ])
    .await;
    assert!(ok, "enrol failed: {err}");

    let (ok, body, err) = run(vec!["get".into(), "--path".into(), "/counter".into()]).await;
    assert!(
        ok,
        "a signed request failed: stdout={body:?} stderr={err:?}"
    );
    assert_eq!(body.trim(), "1", "unexpected body: {body}");

    // And the substitution the harness checks: refused, and nothing written.
    let (_, out, _) = run(vec![
        "substitute".into(),
        "--path".into(),
        "/files/e2e.txt".into(),
        "--approved".into(),
        "approved".into(),
        "--sent".into(),
        "substituted".into(),
    ])
    .await;
    assert!(
        out.starts_with("401"),
        "a substituted body was authorized: {out}"
    );
    let (ok, _, _) = run(vec!["get".into(), "--path".into(), "/files/e2e.txt".into()]).await;
    assert!(!ok, "the substituted body reached the filesystem");

    let _ = std::fs::remove_file(&state);
}
