//! `nitro-attest` — check that an HTTPS endpoint is the enclave you think.
//!
//! ```console
//! $ nitro-attest --url https://enclave.example/enclave/attestation \
//!       --pcr0 8cac35ce… --guest ./guest.wasm
//! ```
//!
//! The check that matters is the last one, and it is the reason this tool
//! exists rather than `curl | openssl`:
//!
//! 1. Open a TLS connection and keep the certificate the server presented.
//! 2. Ask for an attestation document, quoting a freshly generated nonce.
//! 3. Verify the document's signature and its chain to the AWS Nitro root.
//! 4. Check the document's `user_data` contains **the hash of that same
//!    certificate**.
//!
//! Step 4 is what ties the connection to the enclave. Without it, a valid
//! attestation document proves only that *an* enclave exists somewhere; a
//! proxy could fetch a real document from a real enclave and serve it over its
//! own TLS session. With it, the only party who could have produced this
//! document is the one holding the private key for the connection in hand.
//!
//! PKI is deliberately not what establishes trust here. The certificate is
//! accepted whatever a public CA thinks of it, because the attestation is the
//! stronger statement — it says which *code* terminates the connection, which
//! no CA can attest to. A Let's Encrypt certificate still helps browsers,
//! which cannot check attestations; this tool does not need it.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use clap::Parser;
use nitro_attestation::{
    AttestationHashes, Expectations, Trust, VerifyOptions, AWS_NITRO_ROOT_G1_PEM,
};

#[derive(Parser, Debug)]
#[command(version, about = "Verify an AWS Nitro Enclaves attestation document")]
struct Cli {
    /// Attestation endpoint to query, e.g.
    /// `https://enclave.example/enclave/attestation`.
    #[arg(long, conflicts_with = "document")]
    url: Option<String>,

    /// Read a document from a file instead of fetching one. Base64 or raw
    /// COSE_Sign1; the encoding is detected.
    #[arg(long, conflicts_with = "url")]
    document: Option<std::path::PathBuf>,

    /// Required PCR0, hex. Pins which enclave image is running.
    #[arg(long)]
    pcr0: Option<String>,

    /// Guest component to check against the document's second hash.
    #[arg(long)]
    guest: Option<std::path::PathBuf>,

    /// Trust root, PEM or DER. Defaults to the embedded AWS Nitro root.
    #[arg(long)]
    trust_root: Option<std::path::PathBuf>,

    /// Accept a document that does not chain to the AWS root.
    ///
    /// For the QEMU harness, which signs with a key it generated. The result
    /// is reported as self-signed and proves nothing about AWS hardware.
    #[arg(long)]
    allow_untrusted_root: bool,

    /// Reject a document older than this many seconds.
    #[arg(long, default_value_t = 300)]
    max_age: u64,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("FAIL: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // 20 bytes, the nitriding convention, and enough that an attacker cannot
    // have a matching document ready.
    let nonce = random_nonce()?;

    let (document, server_certificate) = match (&cli.url, &cli.document) {
        (Some(url), _) => {
            let fetched = fetch(url, &nonce)?;
            (fetched.document, Some(fetched.certificate))
        }
        (_, Some(path)) => {
            let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            (decode_document(&raw)?, None)
        }
        _ => bail!("pass --url or --document"),
    };

    let trust_root = match &cli.trust_root {
        Some(path) => std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        None => AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(),
    };

    let now = SystemTime::now();
    let verified = nitro_attestation::verify(
        &document,
        &VerifyOptions {
            trust_root,
            now,
            allow_untrusted_root: cli.allow_untrusted_root,
        },
    )?;

    let mut expectations = Expectations {
        max_age: Some(Duration::from_secs(cli.max_age)),
        ..Default::default()
    };
    if cli.url.is_some() {
        // Only meaningful for a document we fetched: a file has no nonce we
        // chose, so demanding one would fail every time.
        expectations.nonce = Some(nonce.clone());
    }
    if let Some(pcr0) = &cli.pcr0 {
        expectations.pcr0 = Some(hex::decode(pcr0.trim()).context("--pcr0 is not hex")?);
    }
    verified.expect(&expectations, now)?;

    let document = &verified.document;
    println!("module     {}", document.module_id);
    println!(
        "PCR0       {}",
        document.pcr0_hex().unwrap_or_else(|| "(absent)".into())
    );
    println!("timestamp  {:?}", document.timestamp());
    match verified.trust {
        Trust::ChainVerified => println!("chain      verified to the AWS Nitro root"),
        Trust::SelfSigned => println!("chain      SELF-SIGNED — proves nothing about AWS hardware"),
    }

    check_binding(
        document.user_data.as_deref(),
        server_certificate.as_deref(),
        &cli,
    )?;

    println!("\nOK");
    Ok(())
}

/// The step that ties the TLS session to the attested code.
fn check_binding(
    user_data: Option<&[u8]>,
    server_certificate: Option<&[u8]>,
    cli: &Cli,
) -> Result<()> {
    let Some(user_data) = user_data else {
        if server_certificate.is_some() {
            bail!(
                "document carries no user_data, so the TLS certificate is not bound to it \
                 and this connection could be terminated by anyone"
            );
        }
        println!("user_data  (absent)");
        return Ok(());
    };

    let hashes = AttestationHashes::parse(user_data).context(
        "document's user_data is not the expected two-hash layout, so the TLS binding \
         cannot be checked",
    )?;
    println!("tls hash   {}", hex::encode(hashes.tls_certificate));
    println!("guest hash {}", hex::encode(hashes.guest));

    if let Some(der) = server_certificate {
        let presented = nitro_attestation::sha256(der);
        if presented != hashes.tls_certificate {
            bail!(
                "the certificate this connection presented ({}) is not the one the enclave \
                 attested ({}) — something is terminating TLS in between",
                hex::encode(presented),
                hex::encode(hashes.tls_certificate)
            );
        }
        println!("binding    the attested certificate is the one serving this connection");
    }

    if let Some(path) = &cli.guest {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let digest = nitro_attestation::sha256(&bytes);
        if digest != hashes.guest {
            bail!(
                "the enclave is serving a different guest: attested {}, local file {}",
                hex::encode(hashes.guest),
                hex::encode(digest)
            );
        }
        println!("guest      matches {}", path.display());
    }

    Ok(())
}

fn random_nonce() -> Result<Vec<u8>> {
    use aws_lc_rs::rand::SecureRandom;
    let mut nonce = vec![0u8; 20];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|e| anyhow::anyhow!("generating a nonce: {e}"))?;
    Ok(nonce)
}

fn decode_document(raw: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine;
    let text = std::str::from_utf8(raw).unwrap_or("").trim();
    if !text.is_empty()
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'+'
                || b == b'/'
                || b == b'='
                || b.is_ascii_whitespace()
        })
    {
        let compact: String = text.split_whitespace().collect();
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&compact) {
            return Ok(bytes);
        }
    }
    Ok(raw.to_vec())
}

struct Fetched {
    document: Vec<u8>,
    /// DER of the certificate the server presented.
    certificate: Vec<u8>,
}

/// GET the endpoint over TLS, keeping the certificate it presented.
fn fetch(url: &str, nonce: &[u8]) -> Result<Fetched> {
    let (host, port, path) = split_url(url)?;

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::AcceptAnyServerCert))
        .with_no_client_auth();

    let server_name = rustls_pki_types::ServerName::try_from(host.clone())
        .with_context(|| format!("{host:?} is not a valid server name"))?;
    let mut client = rustls::ClientConnection::new(Arc::new(config), server_name)
        .context("starting the TLS session")?;
    let mut socket = TcpStream::connect((host.as_str(), port))
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let mut tls = rustls::Stream::new(&mut client, &mut socket);

    let separator = if path.contains('?') { '&' } else { '?' };
    let request = format!(
        "GET {path}{separator}nonce={} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         User-Agent: nitro-attest\r\n\r\n",
        hex::encode(nonce)
    );
    tls.write_all(request.as_bytes())
        .context("sending the request")?;

    let mut response = Vec::new();
    match tls.read_to_end(&mut response) {
        Ok(_) => {}
        // Servers commonly drop the connection rather than closing TLS
        // cleanly. That is not a failure if the response already arrived.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !response.is_empty() => {}
        Err(e) => return Err(e).context("reading the response"),
    }

    let certificate = client
        .peer_certificates()
        .and_then(|c| c.first().cloned())
        .context("the server presented no certificate")?
        .to_vec();

    let (status, body) = split_response(&response)?;
    if status != 200 {
        bail!(
            "endpoint answered HTTP {status}: {}",
            String::from_utf8_lossy(&body).trim()
        );
    }

    Ok(Fetched {
        document: decode_document(&body)?,
        certificate,
    })
}

fn split_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .context("--url must start with https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("invalid port")?),
        None => (authority.to_string(), 443u16),
    };
    Ok((host, port, path.to_string()))
}

fn split_response(response: &[u8]) -> Result<(u16, Vec<u8>)> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("response has no header terminator")?;
    let head = String::from_utf8_lossy(&response[..split]);
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .context("response has no status code")?;

    let body = &response[split + 4..];
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

/// Decode `Transfer-Encoding: chunked`.
///
/// Not optional. A guest response has no `content-length` — the body streams
/// out of the component as it is produced — so hyper chunks it, and an
/// attestation endpoint sitting on the same server may be reached the same
/// way. A client that ignored this would read chunk framing as content.
fn dechunk(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("chunked body ended without a chunk header")?;
        let header = std::str::from_utf8(&rest[..end]).context("chunk header is not UTF-8")?;
        let size = usize::from_str_radix(header.split(';').next().unwrap_or("").trim(), 16)
            .context("chunk size is not hex")?;
        rest = &rest[end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            bail!("chunked body is truncated");
        }
        out.extend_from_slice(&rest[..size]);
        // Skip the chunk's trailing CRLF.
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
    Ok(out)
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    /// Accepts any server certificate.
    ///
    /// Not an oversight and not a shortcut. Trust here comes from the
    /// attestation document, which binds this certificate's hash to a specific
    /// enclave image — a strictly stronger statement than any CA makes, and
    /// one that holds even for a self-signed certificate. The caller checks
    /// that binding; if it does not hold, the connection is rejected there.
    ///
    /// This is safe *only* because that check is not optional in this tool.
    #[derive(Debug)]
    pub struct AcceptAnyServerCert;

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
