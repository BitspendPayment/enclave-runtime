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

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

/// An NSM that signs for real, echoing back whatever it was asked to bind.
///
/// The auth exchange is now the only place the runtime attests, and it is the
/// exchange a client uses to identify the enclave before approving anything —
/// so this harness has to produce documents that verify, not canned bytes.
///
/// Its registers behave like the device's: 0–15 locked from the start, 16 free
/// until the harness measures the guest into it, and documents list only the
/// locked ones. So PCR16 is in a document here for the reason it is in a real
/// one — the guest was measured and the register locked.
#[derive(Debug)]
struct SigningNsm {
    chain: nitro_attestation::testing::TestChain,
    pcrs: std::sync::Mutex<Vec<nitro_nsm::Pcr>>,
    /// Counted, so successive draws differ. A device that returned the same
    /// bytes every time would mint one tenant id for every passkey, which is
    /// the isolation property quietly inverted.
    draws: std::sync::atomic::AtomicU64,
}

/// What `SigningNsm` reports as PCR0, and what a client here pins.
const PCR0: [u8; 48] = [0x5a; 48];

impl SigningNsm {
    fn new() -> Self {
        SigningNsm {
            chain: nitro_attestation::testing::TestChain::new().expect("test chain"),
            pcrs: std::sync::Mutex::new(
                (0..32)
                    .map(|i| nitro_nsm::Pcr {
                        locked: i < 16,
                        value: if i == 0 {
                            PCR0.to_vec()
                        } else {
                            nitro_nsm::PCR_ZERO.to_vec()
                        },
                    })
                    .collect(),
            ),
            draws: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl nitro_nsm::Nsm for SigningNsm {
    fn get_random(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        let draw = self.draws.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8)
                .wrapping_mul(7)
                .wrapping_add(3)
                .wrapping_add(draw as u8);
        }
        Ok(())
    }
    fn attest(&self, request: &nitro_nsm::AttestationRequest) -> anyhow::Result<Vec<u8>> {
        let pcrs = self
            .pcrs
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, pcr)| pcr.locked)
            .map(|(index, pcr)| (index as u32, pcr.value.clone()))
            .collect();
        self.chain
            .document_with_pcrs(request.user_data.clone(), request.nonce.clone(), pcrs)
    }
    fn describe_pcr(&self, index: u16) -> anyhow::Result<nitro_nsm::Pcr> {
        self.pcrs
            .lock()
            .unwrap()
            .get(index as usize)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))
    }
    fn extend_pcr(&self, index: u16, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.value = nitro_nsm::pcr_extend(&pcr.value, data);
        Ok(pcr.value.clone())
    }
    fn lock_pcr(&self, index: u16) -> anyhow::Result<()> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.locked = true;
        Ok(())
    }
    fn describe(&self) -> String {
        "signing test NSM".into()
    }
}

struct Harness {
    addr: std::net::SocketAddr,
    nsm: Arc<SigningNsm>,
    guest_bytes: Vec<u8>,
}

async fn start() -> Harness {
    start_with_background(false).await
}

async fn start_with_background(background: bool) -> Harness {
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
    let bytes_for_harness = bytes.clone();

    let nsm = Arc::new(SigningNsm::new());
    // As `main` does, before anything could attest: the documents this server
    // produces carry PCR16 because the guest it serves was measured into it.
    enclave_runtime::measure_guest(nsm.as_ref(), &bytes).expect("measuring the guest");
    let entropy: Arc<dyn nitro_nsm::Nsm> = nsm.clone();
    let credentials = Arc::new(FilesystemCredentials::new(fs.clone()));
    let gate = Arc::new(Gate::new(
        enclave_runtime::build_relying_party(RP_ID, ORIGIN).expect("relying party"),
        ChallengeStore::new(std::time::Duration::from_secs(60), 256),
        credentials.clone(),
        enclave_runtime::TokenStore::new(
            std::time::Duration::from_secs(60),
            enclave_runtime::DEFAULT_TOKEN_CAPACITY,
        ),
    ));
    let auth = Arc::new(AuthEndpoints::new(
        gate.clone(),
        credentials,
        fs.clone(),
        entropy.clone(),
    ));

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

    let nsm_for_server: Arc<dyn nitro_nsm::Nsm> = nsm.clone();
    tokio::spawn(async move {
        let _ = enclave_runtime::serve_component(
            &bytes,
            guest,
            ServeConfig {
                background_tasks: background.then(Default::default),
                addr,
                certificate: Some(enclave_runtime::CertificateSlot::fixed(Arc::new(tls))),
                acme: None,
                attestation: Some(nsm_for_server),
                request_timeout: std::time::Duration::from_secs(30),
                max_interaction: std::time::Duration::from_secs(300),
                tenancy: Some(Arc::new(Tenancy::new(PoolLimits::default()))),
                authentication: Some((auth, gate)),
            },
        )
        .await;
    });

    for _ in 0..400 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Harness {
                addr,
                nsm,
                guest_bytes: bytes_for_harness,
            };
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
fn raw_nonce() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1_000);
    let mut nonce = vec![0x5au8; 20];
    nonce[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    nonce
}

fn fresh_nonce() -> String {
    use base64::Engine as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut nonce = vec![0x5au8; 20];
    nonce[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// Like [`https`], but returns the response head and the certificate this
/// connection presented — which is what an attestation binds.
async fn https_full(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    nonce: &[u8],
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String, Vec<u8>) {
    use base64::Engine as _;
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

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {RP_ID}\r\nConnection: close\r\n\
         x-enclave-nonce: {}\r\nContent-Length: {}\r\n",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
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
    let presented = {
        let (_, conn) = stream.get_ref();
        conn.peer_certificates()
            .and_then(|c| c.first().cloned())
            .expect("server certificate")
            .to_vec()
    };
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
    (status, head, presented)
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

    // Every request carries a nonce, whether or not the response it gets back
    // is attested — the runtime attests `/auth/` exchanges and nothing else, and
    // a client behaves the same either way.
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
async fn enrol(addr: std::net::SocketAddr) -> SoftwareAuthenticator {
    let auth = SoftwareAuthenticator::new(RP_ID);
    let (status, options) = post_json(addr, "/auth/register/options", serde_json::json!({})).await;
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
/// Walk the whole flow: challenge, assertion, token, interaction.
///
/// Three trips, and they have to be three: a passkey is a challenge-response,
/// so the assertion cannot exist until the challenge has been answered, and the
/// token cannot exist until the assertion has been checked.
async fn signed(
    addr: std::net::SocketAddr,
    auth: &SoftwareAuthenticator,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String) {
    let token = token_for(addr, auth, method, path).await;
    https(
        addr,
        method,
        path,
        &[("authorization", format!("Bearer {token}"))],
        body,
    )
    .await
}

/// Trips one and two, returning the token they produce.
async fn token_for(
    addr: std::net::SocketAddr,
    auth: &SoftwareAuthenticator,
    method: &str,
    path: &str,
) -> String {
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
        }),
    )
    .await;
    assert_eq!(status, 200, "{options}");

    let challenge = options["options"]["publicKey"]["challenge"]
        .as_str()
        .expect("a challenge");
    let assertion = auth.assert(challenge, ORIGIN);

    let (status, granted) = post_json(
        addr,
        "/auth/request/verify",
        serde_json::json!({
            "challenge_id": options["challenge_id"].as_str().expect("a challenge id"),
            "assertion": b64.encode(assertion.to_string()),
        }),
    )
    .await;
    assert_eq!(status, 200, "{granted}");
    granted["token"].as_str().expect("a token").to_string()
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
    let auth = enrol(h.addr).await;

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
    let alice = enrol(h.addr).await;

    let (status, seen) = signed(h.addr, &alice, "GET", "/whoami", "").await;
    assert_eq!(status, 200);
    assert_eq!(seen.trim().len(), 32, "expected a hex tenant id: {seen}");
    assert_ne!(seen.trim(), "(anonymous)");
}

/// **The substitution, over a real socket.** An approval for one body must not
/// **What the approval still names: the interaction.**
///
/// A token issued for one route cannot be spent on another, so an approval to
/// write one file is not an approval to write a different one.
///
/// What it deliberately no longer names is the *body* — see
/// `a_token_does_not_bind_the_body` in the gate's own tests. That is the trade
/// this model makes, and it is written down rather than left to be discovered.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_token_cannot_be_moved_to_another_interaction() {
    let h = start().await;
    let auth = enrol(h.addr).await;

    // Approved for writing one file.
    let token = token_for(h.addr, &auth, "POST", "/files/approved.txt").await;

    // Spent on another.
    let (status, body) = https(
        h.addr,
        "POST",
        "/files/substituted.txt",
        &[("authorization", format!("Bearer {token}"))],
        "substituted",
    )
    .await;
    assert_eq!(status, 401, "a token was moved to another route: {body}");

    // And the guest genuinely was not called.
    let (status, _) = signed(h.addr, &auth, "GET", "/files/substituted.txt", "").await;
    assert_eq!(
        status, 404,
        "the substituted request reached the filesystem"
    );
}

/// **One approval, one interaction.** A captured token is worthless afterwards.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_token_cannot_be_replayed() {
    let h = start().await;
    let auth = enrol(h.addr).await;
    let token = token_for(h.addr, &auth, "GET", "/counter").await;
    let headers = [("authorization", format!("Bearer {token}"))];

    assert_eq!(https(h.addr, "GET", "/counter", &headers, "").await.0, 200);
    let (status, _) = https(h.addr, "GET", "/counter", &headers, "").await;
    assert_eq!(status, 401, "a spent token was accepted a second time");
}

/// Two passkeys, two tenants, and neither can see the other's data — the whole
/// arrangement, over the wire, from enrollment to storage.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn two_passkeys_are_two_tenants() {
    let h = start().await;
    let alice = enrol(h.addr).await;
    let bob = enrol(h.addr).await;

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

/// `/auth/*` answers without an assertion — it has to, or nobody could ever
/// get one — and it performs no cosigner action.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn auth_routes_answer_without_an_assertion() {
    let h = start().await;
    let (status, _) = post_json(h.addr, "/auth/register/options", serde_json::json!({})).await;
    // Answered on its merits, not refused for lack of an assertion: this is the
    // one route that must work before any credential exists.
    assert_eq!(status, 200);

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

/// Where the real client binary is, or `None` when it has not been built.
///
/// Prints the build line and returns `None` rather than failing, because a
/// suite that cannot find it has nothing to say about the client — but a
/// *silent* skip reports green for a test that never ran, so it says so.
fn client_binary() -> Option<PathBuf> {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/passkey-client");
    if exe.exists() {
        return Some(exe);
    }
    eprintln!(
        "skipping: build it with\n  cargo build --release -p enclave-runtime \\\n    --features testing --bin passkey-client"
    );
    None
}

/// A passkey file of this test's own.
///
/// Tagged, not just keyed on the process id: these tests share one process, and
/// one state file between them would mean one test's credential answering
/// another's challenges.
fn client_state(tag: &str) -> PathBuf {
    let state = std::env::temp_dir().join(format!("passkey-{}-{tag}.json", std::process::id()));
    let _ = std::fs::remove_file(&state);
    state
}

/// One invocation of the real client, as a subprocess, against this harness.
///
/// Every call is a fresh process that re-reads its passkey, re-runs the whole
/// three-trip ceremony, and re-checks the attestation — which is what a shell
/// script driving this binary does, and the reason it is worth spawning rather
/// than calling in-process.
async fn client(h: &Harness, state: &std::path::Path, args: Vec<String>) -> (bool, String, String) {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/passkey-client");
    let state = state.to_path_buf();
    let pcr16 = hex::encode(nitro_attestation::guest_pcr(&h.guest_bytes));
    let url = format!("https://127.0.0.1:{}", h.addr.port());
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new(&exe)
            .args(["--url", &url, "--state", state.to_str().unwrap()])
            // The harness signs with a `TestChain`, which roots at itself
            // rather than AWS. The chain is still verified — this only says
            // "do not require the AWS root", which is the whole difference
            // between this and production.
            .arg("--allow-untrusted-root")
            // And which enclave, which the client insists on knowing in both
            // halves: `SigningNsm` reports PCR0, and PCR16 holds the guest the
            // harness measured into it.
            .args(["--pcr0", &hex::encode(PCR0)])
            .args(["--pcr16", &pcr16])
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
    if client_binary().is_none() {
        return;
    }
    let state = client_state("gate");
    let run = |args: Vec<String>| client(&h, &state, args);

    let (ok, _, err) = run(vec!["enrol".into()]).await;
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
        "--approved".into(),
        "/files/approved.txt".into(),
        "--sent".into(),
        "/files/substituted.txt".into(),
        "--body".into(),
        "substituted".into(),
    ])
    .await;
    assert!(
        out.starts_with("401"),
        "a token was spent on a route it was not approved for: {out}"
    );
    let (ok, _, _) = run(vec![
        "get".into(),
        "--path".into(),
        "/files/substituted.txt".into(),
    ])
    .await;
    assert!(!ok, "the substituted request reached the filesystem");

    let _ = std::fs::remove_file(&state);
}

/// **Standing authority: one ceremony, and work that runs after it.**
///
/// Everything else in this file is request and response — the client signs, the
/// guest answers, and the approval is spent by the time the connection closes.
/// Background work is the one place that shape does not hold: the assertion
/// authorises an enqueue, and what it authorised runs later, with nobody there
/// to sign anything at the moment it does.
///
/// `scheduled_work_requires_authentication_and_runs_for_its_owner` makes that
/// claim with the in-process authenticator. This one makes it with the real
/// binary, out of process, which is the thing a person actually holds — and
/// because every poll below is a fresh process that re-reads its passkey, the
/// credential surviving between invocations is part of what is under test.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built and the passkey-client binary"]
async fn the_passkey_client_binary_schedules_work_that_later_runs_for_it() {
    let h = start_with_background(true).await;
    if client_binary().is_none() {
        return;
    }
    let state = client_state("tasks");
    let run = |args: Vec<String>| client(&h, &state, args);

    let (ok, _, err) = run(vec!["enrol".into()]).await;
    assert!(ok, "enrol failed: {err}");

    // The approval is spent here, on this route, and never again.
    let (ok, out, err) = run(vec![
        "post".into(),
        "--path".into(),
        "/tasks/client-job".into(),
        "--body".into(),
        "client work".into(),
    ])
    .await;
    assert!(ok, "the enqueue was refused: stdout={out:?} stderr={err:?}");

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let (ok, body, err) = run(vec![
                "get".into(),
                "--path".into(),
                "/tasks/client-job".into(),
            ])
            .await;
            assert!(ok, "the task record became unreadable: {err}");
            let record: serde_json::Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| panic!("not a task record: {e}: {body}"));
            match record["status"].as_str() {
                Some("completed") => {
                    // The work that was actually asked for, not merely a
                    // terminal state.
                    assert_eq!(record["result"], serde_json::json!(b"client work".to_vec()));
                    break;
                }
                Some("failed") => panic!("the scheduled task failed: {body}"),
                _ => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            }
        }
    })
    .await
    .expect("the work a signed interaction scheduled never ran");

    let _ = std::fs::remove_file(&state);
}

/// **The exchange a client uses to identify the enclave.**
///
/// `/auth/request/options` is the first trip of three, and the one that goes
/// out on a connection nothing has vouched for yet — so its response is the one
/// that has to carry a document. A client checks it *before* asking a person to
/// approve anything, and then pins the certificate it named for the two trips
/// that follow.
///
/// This is why there is no separate probe route: the round trip was needed
/// anyway.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_challenge_exchange_is_attested_and_binds_its_connection() {
    use base64::Engine as _;
    let h = start().await;
    let auth = enrol(h.addr).await;

    let nonce = raw_nonce();
    let (status, head, presented) = https_full(
        h.addr,
        "POST",
        "/auth/request/options",
        &nonce,
        &[("content-type", "application/json".to_string())],
        &serde_json::json!({
            "credential_id": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(auth.credential_id()),
            "method": "GET",
            "path": "/counter",
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, 200, "{head}");

    let document = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .expect("the challenge exchange carried no attestation");
    let cose = base64::engine::general_purpose::STANDARD
        .decode(document)
        .expect("the document is base64");

    nitro_attestation::verify(
        &cose,
        &nitro_attestation::VerifyOptions {
            trust_root: h.nsm.chain.root_der().to_vec(),
            now: std::time::SystemTime::now(),
            allow_untrusted_root: false,
        },
    )
    .expect("the document verifies")
    .expect(
        &nitro_attestation::Expectations {
            nonce: Some(nonce.clone()),
            user_data: Some(
                nitro_attestation::AttestationHashes::new(&presented, &h.guest_bytes).serialize(),
            ),
            ..Default::default()
        },
        std::time::SystemTime::now(),
    )
    .expect("the document must bind this connection's certificate and this nonce");
}

/// And the interaction itself is *not* attested, deliberately.
///
/// A second document would establish nothing the first has not: the client
/// pinned the certificate the challenge exchange named, and TLS proves the peer
/// holds its private key. What it would cost is an NSM signature per
/// interaction, on a device that is the runtime's throughput ceiling.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_guest_response_is_not_attested() {
    let h = start().await;
    let auth = enrol(h.addr).await;
    let token = token_for(h.addr, &auth, "GET", "/counter").await;

    let nonce = raw_nonce();
    let (status, head, _) = https_full(
        h.addr,
        "GET",
        "/counter",
        &nonce,
        &[("authorization", format!("Bearer {token}"))],
        "",
    )
    .await;
    assert_eq!(status, 200, "{head}");
    assert!(
        !head.to_ascii_lowercase().contains("x-enclave-attestation:"),
        "a guest response carried a document:\n{head}"
    );
}

// Multi-threaded like every other test in this file. With background work
// enabled the scheduler runs the guest on one runtime while this test polls it
// over a socket on the same one; on a current-thread runtime those share a
// single thread, which is a latent flake rather than a design.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires built guest-http component"]
async fn scheduled_work_requires_authentication_and_runs_for_its_owner() {
    let h = start_with_background(true).await;
    assert_eq!(
        https(h.addr, "POST", "/tasks/job", &[], "unapproved")
            .await
            .0,
        401
    );
    let alice = enrol(h.addr).await;
    let bob = enrol(h.addr).await;
    assert_eq!(
        signed(h.addr, &alice, "POST", "/tasks/job", "alice work")
            .await
            .0,
        202
    );
    assert_eq!(signed(h.addr, &bob, "GET", "/tasks/job", "").await.0, 404);
    assert_eq!(
        signed(h.addr, &bob, "DELETE", "/tasks/job", "").await.0,
        400
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let (status, body) = signed(h.addr, &alice, "GET", "/tasks/job", "").await;
            assert_eq!(status, 200, "{body}");
            let record: serde_json::Value = serde_json::from_str(&body).unwrap();
            if record["status"] == "completed" {
                assert_eq!(record["result"], serde_json::json!(b"alice work".to_vec()));
                break;
            }
            assert_ne!(record["status"], "failed", "{body}");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("scheduled task did not finish");
}
