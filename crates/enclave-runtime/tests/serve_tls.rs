//! The property this milestone exists for, end to end.
//!
//! A client opens a real TLS connection, asks for an attestation document
//! quoting a nonce it chose, verifies the document with the real verifier, and
//! checks that its `user_data` binds **the certificate it just saw in the
//! handshake**. If that holds, the connection terminates in the enclave that
//! signed the document — not in a proxy in front of it.
//!
//! The NSM here is a local fake, but it is not a stub: it produces a genuine
//! P-384 chain and a genuine ES384 COSE_Sign1 over a payload built from the
//! request it was given. The chain is pinned as the trust root and verified
//! against — `allow_untrusted_root` is off — so the verifier does the same
//! work it does in production. What the fake cannot supply is AWS's signing
//! key, so what these tests do *not* establish is that a real NSM's documents
//! chain to the real root. Only hardware shows that; the QEMU harness covers
//! the real device short of the AWS signature.
//!
//! ```console
//! $ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test serve_tls -- --include-ignored
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use enclave_runtime::{GuestEnvironment, HostClock, ServeConfig, TlsIdentity};
use nitro_attestation::testing::TestChain;
use nitro_attestation::{AttestationHashes, Expectations, VerifyOptions};
use nitro_nsm::{AttestationRequest, Nsm};
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::{Config, Fs, MasterSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

/// An NSM that signs for real, echoing back whatever it was asked to bind.
///
/// A fake returning a canned document would let the endpoint pass while
/// binding the wrong certificate — precisely the bug these tests exist to
/// catch — so this builds the payload from the request.
#[derive(Debug)]
struct SigningNsm {
    chain: TestChain,
    pcr0: [u8; 48],
    last: Mutex<Option<AttestationRequest>>,
}

impl SigningNsm {
    fn new() -> Self {
        SigningNsm {
            chain: TestChain::new().expect("test chain"),
            pcr0: [0x5a; 48],
            last: Mutex::new(None),
        }
    }
}

impl Nsm for SigningNsm {
    fn get_random(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        Ok(())
    }

    fn attest(&self, request: &AttestationRequest) -> anyhow::Result<Vec<u8>> {
        *self.last.lock().unwrap() = Some(request.clone());
        self.chain
            .document(request.user_data.clone(), request.nonce.clone(), self.pcr0)
    }

    fn describe_pcr(&self, index: u16) -> anyhow::Result<nitro_nsm::Pcr> {
        Ok(nitro_nsm::Pcr {
            locked: index < 3,
            value: if index == 0 {
                self.pcr0.to_vec()
            } else {
                nitro_nsm::PCR_ZERO.to_vec()
            },
        })
    }

    fn extend_pcr(&self, _index: u16, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("this fake does not model PCR extension")
    }

    fn lock_pcr(&self, _index: u16) -> anyhow::Result<()> {
        anyhow::bail!("this fake does not model PCR locking")
    }

    fn describe(&self) -> String {
        "signing test NSM".into()
    }
}

struct Harness {
    addr: std::net::SocketAddr,
    nsm: Arc<SigningNsm>,
    certificate_der: Vec<u8>,
    guest_bytes: Vec<u8>,
}

/// Start the real [`enclave_runtime::serve_component`] on an ephemeral port.
/// Like [`start`], but serving from a slot the caller keeps — so a test can
/// replace the certificate while a connection is open.
async fn start_with_slot() -> (Harness, enclave_runtime::CertificateSlot) {
    let slot = enclave_runtime::CertificateSlot::empty();
    let harness = start_inner(Some(slot.clone())).await;
    (harness, slot)
}

async fn start() -> Harness {
    start_inner(None).await
}

async fn start_inner(slot: Option<enclave_runtime::CertificateSlot>) -> Harness {
    let backend = Arc::new(MemoryBackend::new());
    // `create`, not `mount`: an empty store is a refusal since the boot
    // machine landed, not an invitation to format one.
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([9u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the filesystem");

    let nsm = Arc::new(SigningNsm::new());
    let guest_bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-http && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });

    // Detached deliberately: the collector runs for as long as this
    // environment can send, which is what a test wants. Production drains it
    // explicitly instead.
    let (logs, _collector) =
        enclave_runtime::guest_io::start(std::sync::Arc::new(enclave_runtime::TracingLogSink));
    let guest = GuestEnvironment::new(fs, Box::new(HostClock), nsm.clone(), &[], &[], logs)
        .expect("guest environment");
    let identity =
        Arc::new(TlsIdentity::self_signed(&["enclave.test".to_string()]).expect("tls identity"));
    let certificate_der = identity.certificate_der.clone();
    // A caller that wants to replace the certificate later serves from its own
    // slot; everyone else gets one that never changes.
    let certificate = match &slot {
        Some(slot) => {
            slot.set(identity);
            Some(slot.clone())
        }
        None => Some(enclave_runtime::CertificateSlot::fixed(identity)),
    };

    // Bind first so the test knows the port before the server owns it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let bytes = guest_bytes.clone();
    let nsm_for_server = nsm.clone();
    tokio::spawn(async move {
        let _ = enclave_runtime::serve_component(
            &bytes,
            guest,
            ServeConfig {
                addr,
                certificate,
                acme: None,
                attestation: Some(nsm_for_server),
                request_timeout: std::time::Duration::from_secs(30),
                max_interaction: std::time::Duration::from_secs(300),
                tenancy: None,
                // These tests are about the attestation binding, which is
                // reached under `/enclave/` and never passes the gate.
                authentication: None,
            },
        )
        .await;
    });

    // Compiling the guest takes a moment and several tests start servers at
    // once. Wait properly, and say so on failure rather than leaving every
    // assertion below to fail on a refused connection.
    let mut ready = false;
    for _ in 0..400 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ready, "the server never came up on {addr}");

    Harness {
        addr,
        nsm,
        certificate_der,
        guest_bytes,
    }
}

/// A nonce, as a client is required to send one.
///
/// Distinct per call rather than random: what these tests need is that no two
/// requests share one, so a document cannot pass for another request's. A real
/// client must use a CSPRNG.
fn fresh_nonce() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut nonce = vec![0xa5u8; 20];
    nonce[..8].copy_from_slice(&n.to_be_bytes());
    nonce
}

fn nonce_header(nonce: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// A TLS request, returning the status, body, and the certificate the server
/// presented — which is the whole point. Sends a fresh nonce, which every
/// request must now carry.
async fn https(addr: std::net::SocketAddr, path: &str) -> (u16, String, Vec<u8>) {
    let (status, _, body, certificate) = https_full(addr, path, &fresh_nonce()).await;
    (status, body, certificate)
}

/// The same, plus the response head — which is where the per-response
/// attestation lives, and which `https` discards.
async fn https_full(
    addr: std::net::SocketAddr,
    path: &str,
    nonce: &[u8],
) -> (u16, String, String, Vec<u8>) {
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();

    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut stream = connector.connect(name, socket).await.expect("handshake");

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: enclave.test\r\nx-enclave-nonce: {}\r\n\
         Connection: close\r\n\r\n",
        nonce_header(nonce)
    );
    stream.write_all(request.as_bytes()).await.expect("write");

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;

    let certificate = {
        let (_, conn) = stream.get_ref();
        conn.peer_certificates()
            .and_then(|c| c.first().cloned())
            .expect("server certificate")
            .to_vec()
    };

    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let head = String::from_utf8_lossy(&response[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let raw = &response[split + 4..];
    // A guest response carries no content-length — the body streams out of the
    // component — so hyper chunks it.
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(raw)
    } else {
        raw.to_vec()
    };
    (
        status,
        head,
        String::from_utf8_lossy(&body).to_string(),
        certificate,
    )
}

/// The attestation document from a response head, decoded.
fn document_from(head: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let line = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))?;
    let value = line.split_once(':')?.1.trim();
    base64::engine::general_purpose::STANDARD.decode(value).ok()
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

/// The guest keeps working over TLS, and never sees the runtime's paths.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_serves_everything_else() {
    let harness = start().await;

    let (status, body, _) = https(harness.addr, "/counter").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.trim(), "1");

    let (status, body, _) = https(harness.addr, "/counter").await;
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "2", "state must persist across TLS requests");
}

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Trust comes from the attestation binding, which these tests check
        // explicitly; PKI has nothing to say about a certificate born inside
        // an enclave ten milliseconds ago.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Per-response attestation
// ---------------------------------------------------------------------------

/// A request with no nonce is refused before anything runs — and the guest is
/// the witness: `/counter` increments only when the guest is invoked.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_request_without_a_nonce_never_reaches_the_guest() {
    let harness = start().await;

    let (_, before, _) = https(harness.addr, "/counter").await;

    // The same request, minus the nonce.
    let (status, head, body, _) = https_full(harness.addr, "/counter", b"").await;
    assert_eq!(status, 400, "body: {body}");
    assert!(body.contains("x-enclave-nonce"), "body: {body}");
    assert!(
        document_from(&head).is_none(),
        "a refusal with no nonce has nothing to bind, so it must carry no document"
    );

    let (_, after, _) = https(harness.addr, "/counter").await;
    assert_eq!(
        after.trim().parse::<u32>().unwrap(),
        before.trim().parse::<u32>().unwrap() + 1,
        "the unnonced request reached the guest"
    );
}

/// The guest cannot own the header. It sets a forged one on `/whoami`-style
/// routes and the client must still see exactly one, the runtime's.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_cannot_forge_the_proof() {
    let harness = start().await;
    let nonce = fresh_nonce();
    let (status, head, _, _) = https_full(harness.addr, "/forge-attestation", &nonce).await;
    assert_eq!(status, 200);

    // None, not one. The runtime does not attest a guest response — a caller
    // has already identified the enclave on the `/auth/` exchange and pinned
    // its certificate — so there is no document of its own to overwrite the
    // guest's with. The header is taken away instead.
    //
    // This is the check that keeps the header runtime-owned. It used to hold
    // as a side effect of attesting everything; now it is deliberate, and
    // failing it means a guest can hand a client a document under the
    // runtime's name.
    let copies = head
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))
        .count();
    assert_eq!(copies, 0, "the guest's copies survived:\n{head}");
}

/// A TLS connection the caller keeps, so it can ask twice.
///
/// [`https_full`] sends `Connection: close` and reads to EOF, which is right
/// for a single request but makes "the same connection" impossible to express:
/// the socket is gone before the next line of the test runs. Renewal is only
/// interesting *while a connection is open*, so that case needs this.
struct KeptConnection {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    /// The leaf from this connection's own handshake, captured once.
    presented: Vec<u8>,
}

impl KeptConnection {
    async fn open(addr: std::net::SocketAddr) -> Self {
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();
        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let stream = connector.connect(name, socket).await.expect("handshake");
        let presented = {
            let (_, conn) = stream.get_ref();
            conn.peer_certificates()
                .and_then(|c| c.first().cloned())
                .expect("server certificate")
                .to_vec()
        };
        KeptConnection { stream, presented }
    }

    /// One request, keep-alive, and the head of its response.
    ///
    /// Reads exactly one response rather than to EOF, so the connection is
    /// still usable afterwards.
    async fn request(&mut self, path: &str, nonce: &[u8]) -> String {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: enclave.test\r\nx-enclave-nonce: {}\r\n\r\n",
            nonce_header(nonce)
        );
        self.stream
            .write_all(request.as_bytes())
            .await
            .expect("write");

        let mut buf = Vec::new();
        let split = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await.expect("read");
            assert!(n > 0, "the connection closed before a response arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..split]).to_string();

        // Drain this response's body so the next request starts clean. Both
        // framings appear here: runtime endpoints send a length, guest
        // responses are chunked.
        let lower = head.to_ascii_lowercase();
        let mut body = buf[split + 4..].to_vec();
        if lower.contains("transfer-encoding: chunked") {
            while !body.ends_with(b"0\r\n\r\n") {
                let mut chunk = [0u8; 4096];
                let n = self.stream.read(&mut chunk).await.expect("read body");
                assert!(n > 0, "the connection closed mid-body");
                body.extend_from_slice(&chunk[..n]);
            }
        } else {
            let want = lower
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while body.len() < want {
                let mut chunk = [0u8; 4096];
                let n = self.stream.read(&mut chunk).await.expect("read body");
                assert!(n > 0, "the connection closed mid-body");
                body.extend_from_slice(&chunk[..n]);
            }
        }
        head
    }
}

/// A connection keeps the certificate it was served, across a renewal.
///
/// This is what the whole per-connection design is for, and the case a
/// globally-read certificate gets wrong: while connection A is open the slot is
/// replaced, so a runtime that read "the current certificate" at response time
/// would tell A about a certificate A was never served — and A's client, which
/// compares against its own handshake, would read that as an interceptor.
///
/// The case that matters is A's **second** request, sent on the connection it
/// already had once the slot has moved on. A fresh connection after a renewal
/// proves nothing: it handshakes under the new certificate and is told about
/// the new certificate, which a runtime reading one global value gets right by
/// accident. Only a connection that outlives the replacement can catch it.
///
/// Driven over `/auth/request/options` because that is where the runtime
/// attests now — the exchange a client uses to identify the enclave before
/// approving anything. This harness configures no gate, so the route itself
/// answers 404; the document on it is what the test is for, and it is attached
/// before the request is routed.
///
/// `#[ignore]`d like its neighbours: [`start_with_slot`] builds the real
/// server, which needs the guest component built first.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the guest component; see the module docs"]
async fn a_connection_keeps_the_certificate_it_was_served_across_a_renewal() {
    let (harness, slot) = start_with_slot().await;
    let original = harness.certificate_der.clone();

    // A opens and STAYS OPEN for the rest of the test.
    let mut a = KeptConnection::open(harness.addr).await;
    assert_eq!(a.presented, original, "A was served the original");
    let nonce_a1 = fresh_nonce();
    let head_a1 = a.request("/auth/request/options", &nonce_a1).await;

    // The renewal, with A still connected. Everything that handshakes after
    // this gets the new certificate; A must not.
    let renewed = Arc::new(
        TlsIdentity::self_signed(&["enclave.test".to_string()]).expect("a renewed identity"),
    );
    assert_ne!(renewed.certificate_der, original);
    slot.set(renewed.clone());

    // The point of the whole test: A asks again, on the same connection, after
    // the slot has moved on.
    let nonce_a2 = fresh_nonce();
    let head_a2 = a.request("/auth/request/options", &nonce_a2).await;

    // B, served under the new certificate.
    let nonce_b = fresh_nonce();
    let (_, head_b, _, presented_b) =
        https_full(harness.addr, "/auth/request/options", &nonce_b).await;
    assert_eq!(
        presented_b, renewed.certificate_der,
        "B should have been served the renewed certificate"
    );

    let options = VerifyOptions {
        trust_root: harness.nsm.chain.root_der().to_vec(),
        now: SystemTime::now(),
        allow_untrusted_root: false,
    };
    let check = |head: &str, nonce: &[u8], presented: &[u8]| {
        let document = document_from(head).expect("a document");
        nitro_attestation::verify(&document, &options)
            .expect("verifies")
            .expect(
                &Expectations {
                    nonce: Some(nonce.to_vec()),
                    user_data: Some(
                        AttestationHashes::new(presented, &harness.guest_bytes).serialize(),
                    ),
                    ..Default::default()
                },
                SystemTime::now(),
            )
    };

    // Each document names the certificate its own connection was served.
    check(&head_a1, &nonce_a1, &original).expect("A's document must bind A's certificate");
    check(&head_b, &nonce_b, &renewed.certificate_der)
        .expect("B's document must bind the renewed certificate");

    // The assertion the earlier shape could not make: A's *post-renewal*
    // document still names the certificate A handshook with. A runtime reading
    // "the current certificate" here would name the renewed one instead, and
    // A's client — comparing against its own handshake — would read that as an
    // interceptor sitting in front of the enclave.
    check(&head_a2, &nonce_a2, &original)
        .expect("A's second document must still bind the certificate A was served");
    assert!(
        check(&head_a2, &nonce_a2, &renewed.certificate_der).is_err(),
        "A was told about the renewed certificate it was never served"
    );

    // And the first document is not retroactively about the new certificate.
    assert!(
        check(&head_a1, &nonce_a1, &renewed.certificate_der).is_err(),
        "A's document named a certificate A was never served"
    );
}

/// The proof must not cost streaming. The document binds the nonce and the
/// connection's certificate — nothing the guest produces — so it is generated
/// before the guest is invoked, and the head goes out the moment the guest
/// sets it.
///
/// `/trickle` sends three chunks with a pause between them. If the runtime
/// buffered the response, or waited for the body to finish before writing the
/// head, the head would not arrive until every chunk had.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_document_does_not_wait_for_the_body() {
    let harness = start().await;
    let nonce = fresh_nonce();

    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();
    let socket = tokio::net::TcpStream::connect(harness.addr)
        .await
        .expect("connect");
    let mut stream = connector.connect(name, socket).await.expect("handshake");

    let request = format!(
        "GET /trickle HTTP/1.1\r\nHost: enclave.test\r\nx-enclave-nonce: {}\r\n\
         Connection: close\r\n\r\n",
        nonce_header(&nonce)
    );
    let started = std::time::Instant::now();
    stream.write_all(request.as_bytes()).await.expect("write");

    // Read only as far as the end of the head, so the timing below measures
    // when the head arrived rather than when the whole response did.
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await.expect("read");
        assert!(n == 1, "the connection closed before the head was complete");
        raw.push(byte[0]);
    }
    let head_at = started.elapsed();
    let head = String::from_utf8_lossy(&raw).to_string();

    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest).await;
    let body_at = started.elapsed();
    let body = String::from_utf8_lossy(&dechunk(&rest)).to_string();

    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "a streamed body must not be given a content-length: {head}"
    );
    assert_eq!(body, "chunk-0\nchunk-1\nchunk-2\n", "{head}");

    // The guest pauses 150ms before each of the last two chunks, so a
    // buffering runtime could not have produced the head in under 300ms.
    assert!(
        body_at >= Duration::from_millis(250),
        "the guest did not actually pause; the timing below proves nothing"
    );
    assert!(
        head_at < body_at / 2,
        "the head waited for the body: head at {head_at:?}, body at {body_at:?}"
    );
}
