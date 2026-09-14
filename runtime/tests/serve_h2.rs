//! HTTP/2 on the wire, and HTTP/1.1 still on it beside.
//!
//! gRPC is HTTP/2 and nothing else, so a bidirectional stream to a guest needs
//! the listener to negotiate `h2`. What this suite pins is that it does, that
//! it does so without a configuration knob, and — the part that matters more —
//! that every client which never heard of h2 is untouched. The protocol is
//! chosen per connection from ALPN, so the two are not alternatives.
//!
//! ```console
//! $ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test serve_h2 -- --include-ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use enclave_runtime::{GuestEnvironment, HostClock, ServeConfig, TlsIdentity};
use http_body_util::{BodyExt, Full};
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::{Config, Fs, MasterSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

/// Every request carries one, whether or not the deployment attests.
fn nonce_header() -> String {
    use base64::Engine as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut nonce = vec![0xc3u8; 20];
    nonce[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
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

/// The runtime on an ephemeral port, TLS on, attestation off.
///
/// Attestation is off deliberately: what this suite is about is the transport,
/// and a document on every response would only add a signature to each
/// assertion below without changing what any of them prove.
async fn start() -> std::net::SocketAddr {
    let backend = Arc::new(MemoryBackend::new());
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([5u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the filesystem");

    let bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-http && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });

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

    let identity =
        Arc::new(TlsIdentity::self_signed(&["enclave.test".to_string()]).expect("tls identity"));

    // Bind first so the test knows the port before the server owns it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        let _ = enclave_runtime::serve_component(
            &bytes,
            guest,
            ServeConfig {
                background_tasks: None,
                notify: None,
                addr,
                certificate: Some(enclave_runtime::CertificateSlot::fixed(identity)),
                acme: None,
                attestation: None,
                request_timeout: std::time::Duration::from_secs(30),
                max_interaction: std::time::Duration::from_secs(300),
                tenancy: None,
                authentication: None,
            },
        )
        .await;
    });

    let mut ready = false;
    for _ in 0..400 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ready, "the server never came up on {addr}");
    addr
}

/// A TLS connection offering exactly `alpn`, and what the server chose.
async fn connect(
    addr: std::net::SocketAddr,
    alpn: &[&[u8]],
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    Option<Vec<u8>>,
) {
    let mut config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();
    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let stream = connector.connect(name, socket).await.expect("handshake");
    let chosen = {
        let (_, conn) = stream.get_ref();
        conn.alpn_protocol().map(|p| p.to_vec())
    };
    (stream, chosen)
}

/// A client that asks for h2 is given h2.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn alpn_negotiates_h2_when_the_client_asks_for_it() {
    let addr = start().await;
    let (_stream, chosen) = connect(addr, &[b"h2"]).await;
    assert_eq!(
        chosen.as_deref(),
        Some(&b"h2"[..]),
        "a gRPC client offers only h2 and would have nothing to speak"
    );
}

/// And a client that asks for HTTP/1.1 is still given HTTP/1.1.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn alpn_still_offers_http11() {
    let addr = start().await;
    let (_stream, chosen) = connect(addr, &[b"http/1.1"]).await;
    assert_eq!(chosen.as_deref(), Some(&b"http/1.1"[..]));
}

/// **The regression test for the whole transport change.**
///
/// A client that never heard of ALPN sends no extension at all, and rustls
/// skips the negotiation entirely. Nothing about adding h2 may reach it: this
/// is a byte-for-byte HTTP/1.1 exchange of the kind every other suite makes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_client_that_never_heard_of_alpn_is_unaffected() {
    let addr = start().await;
    let (mut stream, chosen) = connect(addr, &[]).await;
    assert_eq!(chosen, None, "no ALPN offered, so none should be selected");

    let request = format!(
        "GET /counter HTTP/1.1\r\nHost: enclave.test\r\nx-enclave-nonce: {}\r\n\
         Connection: close\r\n\r\n",
        nonce_header()
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "an ordinary HTTP/1.1 client stopped working: {text}"
    );
}

/// A request completes over h2, end to end, through the real guest.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_request_completes_over_h2() {
    let addr = start().await;
    let (stream, chosen) = connect(addr, &[b"h2"]).await;
    assert_eq!(chosen.as_deref(), Some(&b"h2"[..]));

    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("GET")
        .uri("https://enclave.test/counter")
        .header("x-enclave-nonce", nonce_header())
        .body(Full::new(bytes::Bytes::new()))
        .expect("well-formed request");

    let resp = sender.send_request(req).await.expect("h2 request");
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(
        String::from_utf8_lossy(&body).trim(),
        "1",
        "the guest answered something else over h2"
    );
}
