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

use enclave_runtime::{GuestEnvironment, HostClock, ServeConfig, TlsIdentity};
use nitro_attestation::testing::TestChain;
use nitro_attestation::{AttestationHashes, Expectations, Trust, VerifyOptions};
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
async fn start() -> Harness {
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

    let guest = GuestEnvironment::new(fs, Box::new(HostClock), nsm.clone(), &[], &[])
        .expect("guest environment");
    let tls = TlsIdentity::self_signed(&["enclave.test".to_string()]).expect("tls identity");
    let certificate_der = tls.certificate_der.clone();

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
                concurrency: 1,
                tls: Some(tls),
                acme: None,
                attestation: Some(nsm_for_server),
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

/// A TLS request, returning the status, body, and the certificate the server
/// presented — which is the whole point.
async fn https(addr: std::net::SocketAddr, path: &str) -> (u16, String, Vec<u8>) {
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

    let request = format!("GET {path} HTTP/1.1\r\nHost: enclave.test\r\nConnection: close\r\n\r\n");
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
        String::from_utf8_lossy(&body).to_string(),
        certificate,
    )
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

fn decode(body: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .expect("body is base64")
}

/// The end-to-end claim: the certificate serving this connection is the one
/// the enclave attested. Everything else here supports this test.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_attested_certificate_is_the_one_serving_the_connection() {
    let harness = start().await;
    let nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a";

    let (status, body, presented) = https(
        harness.addr,
        &format!("/enclave/attestation?nonce={}", hex::encode(nonce)),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let verified = nitro_attestation::verify(
        &decode(&body),
        &VerifyOptions {
            trust_root: harness.nsm.chain.root_der().to_vec(),
            now: std::time::SystemTime::now(),
            allow_untrusted_root: false,
        },
    )
    .expect("document verifies");
    // The chain really validates: the test root is pinned, not waved through.
    assert_eq!(verified.trust, Trust::ChainVerified);

    // The binding, checked the way a client checks it: hash the certificate
    // this connection presented and require the document to name it.
    let expected = AttestationHashes::new(&presented, &harness.guest_bytes);
    verified
        .expect(
            &Expectations {
                nonce: Some(nonce.to_vec()),
                user_data: Some(expected.serialize()),
                pcrs: [(0u32, harness.nsm.pcr0.to_vec())].into(),
                max_age: Some(std::time::Duration::from_secs(60)),
            },
            std::time::SystemTime::now(),
        )
        .expect("the attested certificate must be the one that served us");

    assert_eq!(
        presented, harness.certificate_der,
        "the handshake must present the identity the runtime built"
    );
}

/// A client that saw a *different* certificate must not be satisfied — the
/// case where something terminates TLS in between.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_substituted_certificate_breaks_the_binding() {
    let harness = start().await;
    let nonce = b"\x11\x22\x33\x44\x55\x66\x77\x88";

    let (_, body, _) = https(
        harness.addr,
        &format!("/enclave/attestation?nonce={}", hex::encode(nonce)),
    )
    .await;
    let verified = nitro_attestation::verify(
        &decode(&body),
        &VerifyOptions {
            trust_root: harness.nsm.chain.root_der().to_vec(),
            now: std::time::SystemTime::now(),
            allow_untrusted_root: false,
        },
    )
    .unwrap();

    let impostor = TlsIdentity::self_signed(&["enclave.test".to_string()]).unwrap();
    let wrong = AttestationHashes::new(&impostor.certificate_der, &harness.guest_bytes);
    let err = verified
        .expect(
            &Expectations {
                user_data: Some(wrong.serialize()),
                ..Default::default()
            },
            std::time::SystemTime::now(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("user_data mismatch"), "{err:#}");
}

/// Every request gets a document bound to its own nonce, so a captured one
/// cannot be replayed against a later challenge.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn each_request_gets_a_document_for_its_own_nonce() {
    let harness = start().await;

    let (_, first, _) = https(harness.addr, "/enclave/attestation?nonce=aaaaaaaaaaaaaaaa").await;
    let (_, second, _) = https(harness.addr, "/enclave/attestation?nonce=bbbbbbbbbbbbbbbb").await;
    assert_ne!(first, second, "documents must differ by nonce");

    let options = || VerifyOptions {
        trust_root: harness.nsm.chain.root_der().to_vec(),
        now: std::time::SystemTime::now(),
        allow_untrusted_root: false,
    };
    let a = nitro_attestation::verify(&decode(&first), &options()).unwrap();
    let b = nitro_attestation::verify(&decode(&second), &options()).unwrap();
    assert_eq!(
        a.document.nonce.as_deref(),
        Some(&hex::decode("aaaaaaaaaaaaaaaa").unwrap()[..])
    );
    assert_eq!(
        b.document.nonce.as_deref(),
        Some(&hex::decode("bbbbbbbbbbbbbbbb").unwrap()[..])
    );

    // And the earlier document must not satisfy the later challenge.
    assert!(a
        .expect(
            &Expectations {
                nonce: Some(hex::decode("bbbbbbbbbbbbbbbb").unwrap()),
                ..Default::default()
            },
            std::time::SystemTime::now()
        )
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn an_unnonced_request_is_refused() {
    let harness = start().await;
    let (status, body, _) = https(harness.addr, "/enclave/attestation").await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("fresh"), "{body}");
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

    // `/enclave/…` belongs to the runtime. The guest answers 404 for unknown
    // routes, so a 404 here would mean the request reached it.
    let (status, body, _) = https(harness.addr, "/enclave/nonsense").await;
    assert_eq!(status, 404);
    assert!(
        body.contains("runtime endpoint"),
        "the runtime must answer under /enclave/, not the guest: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn config_reports_the_same_binding_the_document_carries() {
    let harness = start().await;
    let (status, body, presented) = https(harness.addr, "/enclave/config").await;
    assert_eq!(status, 200);

    let hashes = AttestationHashes::new(&presented, &harness.guest_bytes);
    assert!(
        body.contains(&hex::encode(hashes.tls_certificate)),
        "{body}"
    );
    assert!(body.contains(&hex::encode(hashes.guest)), "{body}");
    assert!(body.contains(&hex::encode(harness.nsm.pcr0)), "{body}");
}

/// The runtime asks the device to bind the certificate and the guest, not
/// something it made up.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_runtime_binds_the_certificate_it_actually_serves() {
    let harness = start().await;
    let _ = https(harness.addr, "/enclave/attestation?nonce=0011223344556677").await;

    let request = harness.nsm.last.lock().unwrap().clone().expect("asked");
    let expected = AttestationHashes::new(&harness.certificate_der, &harness.guest_bytes);
    assert_eq!(
        request.user_data.as_deref(),
        Some(&expected.serialize()[..])
    );
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
