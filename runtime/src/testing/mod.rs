//! A whole enclave, in process, for people writing guests.
//!
//! The runtime's own integration tests each stood up their own listener, their
//! own signing NSM and their own hand-rolled HTTPS client. That was tolerable
//! while the only guests lived in this repository. It is not tolerable as the
//! way a *separate* project — one whose component this runtime will actually
//! serve — finds out whether its guest works, because it would have to
//! reimplement all of it before writing a single assertion.
//!
//! So this is that harness, exported:
//!
//! ```no_run
//! # async fn f() -> anyhow::Result<()> {
//! use enclave_runtime::testing::Enclave;
//!
//! let enclave = Enclave::builder(std::fs::read("cosigner.wasm")?)
//!     .background_tasks()
//!     .notify()
//!     .start()
//!     .await?;
//!
//! let alice = enclave.enrol().await?;
//! let (status, body) = enclave.signed(&alice, "POST", "/sign", "payload").await?;
//! # Ok(()) }
//! ```
//!
//! Everything below the guest is real: a real TLS handshake, a real WebAuthn
//! ceremony, real interaction tokens scoped to one route, real tenant
//! isolation, the real task scheduler, and attestation documents that verify
//! against a chain this harness mints.
//!
//! # What it is not
//!
//! **The NSM is a test chain, not hardware.** Documents from here verify only
//! against [`Enclave::trust_root`], which nothing outside this process has any
//! reason to trust. A client that accepts them under production settings has a
//! bug this harness cannot find.
//!
//! **PCR0 is a constant**, not a measurement of a real image, and the master
//! key is static rather than released by KMS against an attestation. Those two
//! are the whole of what an enclave buys, and neither is exercised here — the
//! QEMU harness in `deploy/qemu-nitro/` covers as much of them as an emulator
//! can, and real hardware covers the rest.
//!
//! Behind the `testing` feature, like [`crate::SoftwareAuthenticator`], because
//! it mints assertions and signs attestations. Nothing here may reach an image.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::SoftwareAuthenticator;

mod cosign;
mod nsm;
mod stub;

pub use cosign::CosigningNsm;
pub use nsm::SigningNsm;

/// The relying party this harness serves as.
pub const RP_ID: &str = "enclave.test";
/// The origin its assertions claim.
pub const ORIGIN: &str = "https://enclave.test";

/// What `SigningNsm` reports as PCR0. A constant, and honest about it: nothing
/// measured this.
pub const PCR0: [u8; 48] = [0x5a; 48];

/// One wake signal the guest raised, as it reached the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wake {
    pub category: String,
    pub reference: Option<String>,
    pub token: String,
}

/// A registered passkey, ready to sign for requests.
pub struct Credential {
    authenticator: SoftwareAuthenticator,
    tenant: String,
}

impl Credential {
    /// The tenant this passkey resolved to, hex encoded.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn credential_id(&self) -> &[u8] {
        self.authenticator.credential_id()
    }
}

/// How to build one.
pub struct EnclaveBuilder {
    guest: Vec<u8>,
    background_tasks: bool,
    notify: bool,
}

impl EnclaveBuilder {
    /// Let the guest schedule durable work. Requires a `run-task` export.
    pub fn background_tasks(mut self) -> Self {
        self.background_tasks = true;
        self
    }

    /// Let the guest enrol devices and raise wake signals.
    ///
    /// The harness stands up a stub in place of Firebase and records what the
    /// runtime sent — see [`Enclave::wakes`]. The transport, the signed OAuth
    /// assertion and the error handling are the real ones; only the far end is
    /// not Google.
    pub fn notify(mut self) -> Self {
        self.notify = true;
        self
    }

    pub async fn start(self) -> Result<Enclave> {
        Enclave::start(self).await
    }
}

/// A running enclave.
pub struct Enclave {
    addr: SocketAddr,
    nsm: Arc<SigningNsm>,
    guest: Vec<u8>,
    fcm: Option<Arc<stub::Fcm>>,
}

impl Enclave {
    pub fn builder(guest: impl Into<Vec<u8>>) -> EnclaveBuilder {
        EnclaveBuilder {
            guest: guest.into(),
            background_tasks: false,
            notify: false,
        }
    }

    async fn start(builder: EnclaveBuilder) -> Result<Enclave> {
        use crate::{
            AuthEndpoints, ChallengeStore, FilesystemCredentials, Gate, GuestEnvironment,
            HostClock, PoolLimits, ServeConfig, Tenancy, TlsIdentity,
        };
        use s3fs_core::backend::memory::MemoryBackend;
        use s3fs_core::{Config, Fs, MasterSecret};

        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([9u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .context("creating the harness filesystem")?;

        let nsm = Arc::new(SigningNsm::new()?);
        // As `main` does, before anything could attest: the documents this
        // enclave produces carry PCR16 because the guest was measured into it.
        crate::measure_guest(nsm.as_ref(), &builder.guest).context("measuring the guest")?;
        let entropy: Arc<dyn nitro_nsm::Nsm> = nsm.clone();

        let credentials = Arc::new(FilesystemCredentials::new(fs.clone()));
        let gate = Arc::new(Gate::new(
            crate::build_relying_party(RP_ID, ORIGIN, &[])?,
            ChallengeStore::new(std::time::Duration::from_secs(60), 256),
            credentials.clone(),
            crate::TokenStore::new(
                std::time::Duration::from_secs(60),
                crate::DEFAULT_TOKEN_CAPACITY,
            ),
        ));
        let auth = Arc::new(AuthEndpoints::new(
            gate.clone(),
            credentials,
            fs.clone(),
            entropy.clone(),
        ));

        // Detached: the collector runs as long as this environment can send,
        // which is what a harness wants. Production drains it explicitly.
        let (logs, _collector) = crate::guest_io::start(Arc::new(crate::TracingLogSink));
        let guest_env = GuestEnvironment::new(fs, Box::new(HostClock), entropy, &[], &[], logs)
            .context("building the guest environment")?;

        let fcm = if builder.notify {
            Some(stub::Fcm::start().await?)
        } else {
            None
        };
        let notify = match &fcm {
            Some(stub) => Some(stub.config()?),
            None => None,
        };

        let tls = TlsIdentity::self_signed(&[RP_ID.to_string()])?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener);

        let bytes = builder.guest.clone();
        let attestation: Arc<dyn nitro_nsm::Nsm> = nsm.clone();
        tokio::spawn(async move {
            let _ = crate::serve_component(
                &bytes,
                guest_env,
                ServeConfig {
                    notify,
                    background_tasks: builder.background_tasks.then(Default::default),
                    addr,
                    certificate: Some(crate::CertificateSlot::fixed(Arc::new(tls))),
                    acme: None,
                    attestation: Some(attestation),
                    request_timeout: std::time::Duration::from_secs(30),
                    max_interaction: std::time::Duration::from_secs(300),
                    tenancy: Some(Arc::new(Tenancy::new(PoolLimits::default()))),
                    authentication: Some((auth, gate)),
                    egress: Default::default(),
                },
            )
            .await;
        });

        for _ in 0..400 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return Ok(Enclave {
                    addr,
                    nsm,
                    guest: builder.guest,
                    fcm,
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        anyhow::bail!("the harness never came up on {addr}")
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    /// The root a client must trust to verify this enclave's documents.
    ///
    /// Nothing outside this process has any reason to, which is the point: a
    /// client that verifies against its production roots will refuse these, and
    /// should.
    pub fn trust_root(&self) -> Vec<u8> {
        self.nsm.trust_root()
    }

    pub fn pcr0(&self) -> [u8; 48] {
        PCR0
    }

    /// What the guest measured to, as a key policy would pin it.
    pub fn pcr16(&self) -> [u8; 48] {
        nitro_attestation::guest_pcr(&self.guest)
    }

    /// Every wake signal the guest raised, in order.
    ///
    /// Empty unless the builder asked for [`EnclaveBuilder::notify`].
    pub fn wakes(&self) -> Vec<Wake> {
        self.fcm.as_ref().map(|f| f.wakes()).unwrap_or_default()
    }

    /// Register a passkey, and with it a new tenant.
    pub async fn enrol(&self) -> Result<Credential> {
        let authenticator = SoftwareAuthenticator::new(RP_ID);
        let (status, options) = self
            .post_json("/auth/register/options", serde_json::json!({}))
            .await?;
        anyhow::ensure!(status == 200, "registration was refused: {options}");
        let challenge = options["options"]["publicKey"]["challenge"]
            .as_str()
            .context("registration options carry no challenge")?;
        let (status, body) = self
            .post_json(
                "/auth/register/verify",
                serde_json::json!({
                    "registration_id": options["registration_id"],
                    "credential": authenticator.register(challenge, ORIGIN),
                }),
            )
            .await?;
        anyhow::ensure!(status == 200, "registration was refused: {body}");
        Ok(Credential {
            tenant: body["tenant_id"]
                .as_str()
                .context("no tenant id")?
                .to_string(),
            authenticator,
        })
    }

    /// A signed request: ask for a challenge bound to it, sign, then send it.
    ///
    /// Three round trips, because a passkey is a challenge and a response and
    /// the approval names this exact method and path.
    pub async fn signed(
        &self,
        credential: &Credential,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<(u16, String)> {
        let token = self.token_for(credential, method, path).await?;
        let (status, _, body) = self
            .request(
                method,
                path,
                &[("authorization", format!("Bearer {token}"))],
                body,
            )
            .await?;
        Ok((status, body))
    }

    async fn token_for(&self, credential: &Credential, method: &str, path: &str) -> Result<String> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (path_only, query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        let (status, options) = self
            .post_json(
                "/auth/request/options",
                serde_json::json!({
                    "credential_id": b64.encode(credential.credential_id()),
                    "method": method,
                    "path": path_only,
                    "query": query,
                }),
            )
            .await?;
        anyhow::ensure!(status == 200, "no challenge was issued: {options}");

        let challenge = options["options"]["publicKey"]["challenge"]
            .as_str()
            .context("challenge options carry no challenge")?;
        let assertion = credential.authenticator.assert(challenge, ORIGIN);
        let (status, body) = self
            .post_json(
                "/auth/request/verify",
                serde_json::json!({
                    "challenge_id": options["challenge_id"],
                    "assertion": b64.encode(assertion.to_string().as_bytes()),
                }),
            )
            .await?;
        anyhow::ensure!(status == 200, "the assertion was refused: {body}");
        body["token"]
            .as_str()
            .map(str::to_string)
            .context("no token in the response")
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<(u16, serde_json::Value)> {
        let (status, _, text) = self
            .request(
                "POST",
                path,
                &[("content-type", "application/json".to_string())],
                &body.to_string(),
            )
            .await?;
        Ok((
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        ))
    }

    /// One HTTPS request, returning status, headers and body.
    ///
    /// The certificate is accepted without checking, and that is correct here:
    /// nothing vouches for a self-signed harness certificate, and what a real
    /// client checks instead is that the attestation document names the
    /// certificate it was served — which [`Enclave::trust_root`] makes possible.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: &str,
    ) -> Result<(u16, String, String)> {
        use base64::Engine as _;

        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(RP_ID)?;
        let socket = tokio::net::TcpStream::connect(self.addr).await?;
        let mut stream = connector.connect(name, socket).await?;

        let mut nonce = vec![0u8; 20];
        getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("nonce: {e}"))?;
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {RP_ID}\r\nConnection: close\r\n\
             x-enclave-nonce: {}\r\nContent-Length: {}\r\n",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&nonce),
            body.len()
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);
        stream.write_all(request.as_bytes()).await?;

        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw).await;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .context("no header terminator in the response")?;
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .context("no status line")?
            .parse()?;
        let rest = &raw[split + 4..];
        let body = if head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            dechunk(rest)
        } else {
            rest.to_vec()
        };
        Ok((status, head, String::from_utf8_lossy(&body).to_string()))
    }
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(end) = rest.windows(2).position(|w| w == b"\r\n") {
        let Ok(size) = usize::from_str_radix(String::from_utf8_lossy(&rest[..end]).trim(), 16)
        else {
            break;
        };
        if size == 0 {
            break;
        }
        let start = end + 2;
        if start + size > rest.len() {
            break;
        }
        out.extend_from_slice(&rest[start..start + size]);
        rest = &rest[(start + size + 2).min(rest.len())..];
    }
    out
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
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
