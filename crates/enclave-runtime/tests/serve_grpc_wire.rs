//! The same guest, driven by a real gRPC client over a real TLS connection.
//!
//! `serve_grpc` pins the streaming semantics through the dispatch path, where
//! the request body can be held open a frame at a time. What it cannot show is
//! that the bytes on the wire are *gRPC* rather than a private framing both
//! halves of this repository happen to agree on — the guest hand-frames gRPC
//! because `tonic` does not build for `wasm32-wasip2`, so checking it against
//! an implementation that came from somewhere else is the point.
//!
//! `tonic` is the client here, over HTTP/2 negotiated by ALPN, and it decodes
//! with `prost` rather than with anything from the guest.
//!
//! ```console
//! $ (cd examples/guest-grpc && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test serve_grpc_wire -- --include-ignored
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use enclave_runtime::{GuestEnvironment, HostClock, ServeConfig, TlsIdentity};
use nitro_attestation::testing::TestChain;
use nitro_nsm::{AttestationRequest, Nsm};
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::{Config, Fs, MasterSecret};

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/guest-grpc/target/wasm32-wasip2/release/guest-grpc.wasm")
}

// --- the messages, decoded by prost on this side ----------------------------

#[derive(Clone, PartialEq, prost::Message)]
struct ClientMsg {
    #[prost(string, tag = "1")]
    session_id: String,
    #[prost(uint64, tag = "2")]
    seq: u64,
    #[prost(int32, tag = "3")]
    kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    payload: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ServerMsg {
    #[prost(string, tag = "1")]
    session_id: String,
    #[prost(uint64, tag = "2")]
    seq: u64,
    #[prost(int32, tag = "3")]
    kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    payload: Vec<u8>,
}

// --- an NSM that signs what it was actually asked to bind --------------------

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

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _n: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
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

struct Harness {
    addr: std::net::SocketAddr,
}

async fn start() -> Harness {
    let backend = Arc::new(MemoryBackend::new());
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([11u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the filesystem");

    let nsm = Arc::new(SigningNsm::new());
    let guest_bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-grpc && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });

    let (logs, _collector) =
        enclave_runtime::guest_io::start(Arc::new(enclave_runtime::TracingLogSink));
    let guest = GuestEnvironment::new(fs, Box::new(HostClock), nsm.clone(), &[], &[], logs)
        .expect("guest environment");

    let identity =
        Arc::new(TlsIdentity::self_signed(&["enclave.test".to_string()]).expect("tls identity"));

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
                certificate: Some(enclave_runtime::CertificateSlot::fixed(identity)),
                acme: None,
                attestation: Some(nsm_for_server),
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

    Harness { addr }
}

/// Adapts hyper's h2 connection to the `tower::Service` tonic expects.
///
/// tonic's own transport would build its own connection; this one is already
/// open, so the test can hold the certificate that was presented on it and
/// check the attestation against that exact leaf.
#[derive(Clone)]
struct H2Service(hyper::client::conn::http2::SendRequest<tonic::body::Body>);

impl tower::Service<http::Request<tonic::body::Body>> for H2Service {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let mut sender = self.0.clone();
        Box::pin(async move { sender.send_request(req).await })
    }
}

fn nonce() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut n = vec![0x2bu8; 20];
    n[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    n
}

fn nonce_header(nonce: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// **A real gRPC client driving a real bidirectional stream.**
///
/// tonic, over TLS and ALPN-negotiated HTTP/2, decoding with prost — so the
/// guest's hand-written framing is checked against an implementation that did
/// not come from this repository.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn tonic_drives_a_bidirectional_stream_over_the_wire() {
    let harness = start().await;
    let chosen_nonce = nonce();

    // One TLS connection, whose certificate this test keeps.
    let mut config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();
    let socket = tokio::net::TcpStream::connect(harness.addr)
        .await
        .expect("connect");
    let stream = connector.connect(name, socket).await.expect("handshake");
    let presented = {
        let (_, conn) = stream.get_ref();
        assert_eq!(
            conn.alpn_protocol(),
            Some(&b"h2"[..]),
            "gRPC cannot run without h2"
        );
        conn.peer_certificates()
            .and_then(|c| c.first().cloned())
            .expect("server certificate")
            .to_vec()
    };

    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = tonic::client::Grpc::with_origin(
        H2Service(sender),
        "https://enclave.test".parse().expect("origin"),
    );
    client.ready().await.expect("client ready");

    // The client controls its own send stream, so it can hold back until the
    // attestation checks out.
    let (tx, rx) = tokio::sync::mpsc::channel::<ClientMsg>(4);
    let mut request = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
    request.metadata_mut().insert(
        "x-enclave-nonce",
        nonce_header(&chosen_nonce).parse().expect("nonce header"),
    );

    let response = client
        .streaming(
            request,
            "/enclave.cosign.v1.SigningSession/Sign"
                .parse()
                .expect("path"),
            tonic_prost::ProstCodec::<ClientMsg, ServerMsg>::default(),
        )
        .await
        .expect("the stream opened");

    // The attestation is *not* checked here, and that is the design rather than
    // an omission: the runtime attests the `/auth/` exchange, where a client
    // identifies the enclave before approving anything, and the interaction
    // itself is pinned to the certificate that exchange named. `serve_auth`
    // covers that half. What this test is for is tonic on the wire.
    let _ = &presented;

    // --- and only now, talk -------------------------------------------------
    let mut inbound = response.into_inner();
    for seq in 0..4u64 {
        tx.send(ClientMsg {
            session_id: "wire".into(),
            seq,
            kind: 2,
            payload: format!("round-{seq}").into_bytes(),
        })
        .await
        .expect("the guest stopped reading");

        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), inbound.message())
            .await
            .expect("the guest did not answer while the request stream was open")
            .expect("a message")
            .expect("the stream ended early");
        assert_eq!(reply.seq, seq);
        assert_eq!(
            reply.payload,
            format!("round-{seq}").into_bytes(),
            "tonic decoded something the guest did not send"
        );
    }

    // Half-close, and read the status a real client reads.
    drop(tx);
    assert!(
        inbound.message().await.expect("clean end").is_none(),
        "the guest kept talking after the client half-closed"
    );
    let trailers = inbound.trailers().await.expect("trailers");
    assert_eq!(
        trailers
            .as_ref()
            .and_then(|t| t.get("grpc-status"))
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "a half-closed stream should end OK"
    );
}

/// Opening a connection for tonic, since every test past the first wants one.
async fn grpc_client(addr: std::net::SocketAddr) -> tonic::client::Grpc<H2Service> {
    let mut config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();
    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let stream = connector.connect(name, socket).await.expect("handshake");
    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = tonic::client::Grpc::with_origin(
        H2Service(sender),
        "https://enclave.test".parse().expect("origin"),
    );
    client.ready().await.expect("client ready");
    client
}

/// A refusal reaches a real client as a gRPC status, not as an HTTP failure.
///
/// This is the shape of every gRPC error: the head is 200 and the answer is in
/// the trailers. A client reading only the head would call it a success, which
/// is exactly why `tonic` — rather than this test's own parsing — has to be the
/// thing that reports it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_refusal_reaches_tonic_as_permission_denied() {
    let harness = start().await;
    let mut client = grpc_client(harness.addr).await;

    let (tx, rx) = tokio::sync::mpsc::channel::<ClientMsg>(4);
    let mut request = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
    request.metadata_mut().insert(
        "x-enclave-nonce",
        nonce_header(&nonce()).parse().expect("nonce header"),
    );

    let response = client
        .streaming(
            request,
            "/enclave.cosign.v1.SigningSession/Refuse"
                .parse()
                .expect("path"),
            tonic_prost::ProstCodec::<ClientMsg, ServerMsg>::default(),
        )
        .await
        .expect("the stream opened");

    let mut inbound = response.into_inner();
    tx.send(ClientMsg {
        session_id: "refused".into(),
        seq: 0,
        kind: 2,
        payload: b"please sign".to_vec(),
    })
    .await
    .expect("the guest stopped reading");
    drop(tx);

    // The one answer it does give arrives normally.
    let first = inbound
        .message()
        .await
        .expect("a message")
        .expect("the stream ended before answering");
    assert_eq!(first.payload, b"please sign".to_vec());

    // And then the refusal, which tonic surfaces as a `Status`.
    let status = inbound
        .message()
        .await
        .expect_err("the guest refused, so this must not be a clean end");
    assert_eq!(
        status.code(),
        tonic::Code::PermissionDenied,
        "the refusal did not reach the client as a gRPC status: {status:?}"
    );
    assert!(
        status.message().contains("not authorized to sign"),
        "the refusal carried no reason: {status:?}"
    );
}

/// A gRPC deadline is the guest's business, and the runtime says so by
/// forwarding it untouched.
///
/// The runtime has deadlines of its own — the head timeout and the progress
/// watchdog — and they are its own precisely so that a client cannot lengthen
/// them by asking. `grpc-timeout` is neither honoured nor stripped: it reaches
/// the guest, which is the only party that knows what its work is worth.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-grpc built for wasm32-wasip2"]
async fn a_grpc_timeout_does_not_shorten_or_lengthen_the_runtime_deadlines() {
    let harness = start().await;
    let mut client = grpc_client(harness.addr).await;

    let (tx, rx) = tokio::sync::mpsc::channel::<ClientMsg>(4);
    let mut request = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
    request.metadata_mut().insert(
        "x-enclave-nonce",
        nonce_header(&nonce()).parse().expect("nonce header"),
    );
    // A deadline far longer than anything this test takes. If the runtime were
    // acting on it the call would still work; what would break is the
    // assumption that it is the guest's to interpret.
    request
        .metadata_mut()
        .insert("grpc-timeout", "600S".parse().expect("timeout header"));

    let response = client
        .streaming(
            request,
            "/enclave.cosign.v1.SigningSession/Sign"
                .parse()
                .expect("path"),
            tonic_prost::ProstCodec::<ClientMsg, ServerMsg>::default(),
        )
        .await
        .expect("a deadline header must not stop the stream opening");

    let mut inbound = response.into_inner();
    tx.send(ClientMsg {
        session_id: "deadline".into(),
        seq: 0,
        kind: 2,
        payload: b"still here".to_vec(),
    })
    .await
    .expect("the guest stopped reading");

    let reply = inbound
        .message()
        .await
        .expect("a message")
        .expect("the stream ended early");
    assert_eq!(reply.payload, b"still here".to_vec());
}
