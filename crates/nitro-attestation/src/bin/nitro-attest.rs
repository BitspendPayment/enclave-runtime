//! `nitro-attest` — check that an HTTPS endpoint is the enclave you think.
//!
//! ```console
//! $ nitro-attest --url https://enclave.example --pcr0 8cac35ce… \
//!       --guest ./guest.wasm
//! ```
//!
//! The check that matters is the last one, and it is the reason this tool
//! exists rather than `curl | openssl`:
//!
//! 1. Open a TLS connection and keep the certificate the server presented.
//! 2. Make an ordinary request, quoting a freshly generated nonce in
//!    `x-enclave-nonce`. Every response carries a document in
//!    `x-enclave-attestation`; there is no separate attestation endpoint.
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
//!
//! ## Which code: two measurements
//!
//! PCR0 measures the runtime image, and the guest is not in it. The runtime
//! fetches the guest at boot, extends PCR16 with its hash and locks the
//! register before it can obtain a key. So `--pcr0` says which runtime,
//! `--guest` or `--pcr16` says which application, and neither says both.
//!
//! ```console
//! $ nitro-attest --measure ./guest.wasm
//! {"sha256": "…", "PCR16": "…"}
//! ```
//!
//! prints the PCR16 to pin for a component, computed by the same function this
//! tool verifies with — so the value in a key policy and the value a client
//! checks cannot disagree.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::Parser;
use nitro_attestation::{
    AttestationHashes, Expectations, Trust, Verified, VerifyOptions, AWS_NITRO_ROOT_G1_PEM,
};

/// The request header carrying the client's nonce, base64url without padding.
const NONCE_HEADER: &str = "x-enclave-nonce";
/// The response header carrying the document, base64.
const ATTESTATION_HEADER: &str = "x-enclave-attestation";

#[derive(Parser, Debug)]
#[command(version, about = "Verify an AWS Nitro Enclaves attestation document")]
struct Cli {
    /// URL to request, e.g. `https://enclave.example`. The path defaults to
    /// `/auth/`.
    ///
    /// Not every route carries a document: the runtime attests its `/auth/`
    /// exchanges, which is where a client identifies the enclave before
    /// approving anything, and leaves guest responses alone — a caller has
    /// already pinned the certificate by then. `/auth/` needs no credential and
    /// reaches no guest; it answers 404 or 405, and is attested either way.
    #[arg(long, conflicts_with = "document")]
    url: Option<String>,

    /// Read a document from a file instead of fetching one. Base64 or raw
    /// COSE_Sign1; the encoding is detected.
    #[arg(long, conflicts_with = "url")]
    document: Option<std::path::PathBuf>,

    /// DER of the certificate the connection that produced `--document` was
    /// served. Without it a document read from a file proves nothing about any
    /// connection, because there is no connection in hand to bind it to.
    #[arg(long, requires = "document")]
    peer_certificate: Option<std::path::PathBuf>,

    /// The nonce that request sent, hex. Only for `--document`: a fetched
    /// document is checked against a nonce this tool generated itself.
    #[arg(long, requires = "document")]
    nonce: Option<String>,

    /// Required PCR0, hex. Pins which runtime image is running. Required for
    /// verification unless `--unsigned-emulator`.
    #[arg(long, required_unless_present_any = ["measure", "unsigned_emulator"])]
    pcr0: Option<String>,

    /// Required PCR16, hex. Pins which guest component the runtime measured
    /// before it could obtain a key. `--guest` computes it from the component.
    /// Required for verification unless `--guest` or `--unsigned-emulator`.
    #[arg(long, required_unless_present_any = ["measure", "guest", "unsigned_emulator"])]
    pcr16: Option<String>,

    /// Guest component to check against: the PCR16 it measures to, and the
    /// document's second hash.
    #[arg(long)]
    guest: Option<std::path::PathBuf>,

    /// Print the PCR16 an enclave serving this component attests, and exit.
    ///
    /// That is the value a KMS key policy pins beside PCR0, and the value a
    /// client pins with `--pcr16`.
    #[arg(long, value_name = "COMPONENT", conflicts_with_all = ["url", "document"])]
    measure: Option<std::path::PathBuf>,

    /// Trust root, PEM or DER. Defaults to the embedded AWS Nitro root.
    #[arg(long)]
    trust_root: Option<std::path::PathBuf>,

    /// Accept a document that does not chain to the AWS root, reporting the
    /// result as self-signed.
    #[arg(long)]
    allow_untrusted_root: bool,

    /// Check the document's *contents* without verifying any signature.
    ///
    /// Only one producer needs this and it is not a real enclave: QEMU's
    /// emulated NSM does not sign its documents at all — its source says
    /// "we don't actually sign the data, so we use -1 as the 'alg' value".
    /// There is no signature to check and no chain to follow, so nothing here
    /// says the document came from an enclave, or from AWS, or from anything
    /// other than whoever answered the connection.
    ///
    /// What it still checks is what the *runtime* put in: the nonce, the PCRs,
    /// and whether user_data binds the certificate this connection was
    /// served. Those are our code's job and worth testing. The signature is
    /// AWS hardware's job and cannot be tested here.
    #[arg(long)]
    unsigned_emulator: bool,

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

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn verification_requires_both_measurements_before_reading_or_connecting() {
        for source in [
            ["--url", "https://example.test"],
            ["--document", "proof.cose"],
        ] {
            for pins in [
                vec![],
                vec!["--pcr0", "ab"],
                vec!["--pcr16", "cd"],
                vec!["--guest", "guest.wasm"],
            ] {
                let mut args = vec!["nitro-attest"];
                args.extend(source);
                args.extend(pins);
                assert_eq!(
                    Cli::try_parse_from(args).unwrap_err().kind(),
                    clap::error::ErrorKind::MissingRequiredArgument
                );
            }
            for guest in [["--pcr16", "cd"], ["--guest", "guest.wasm"]] {
                let mut args = vec!["nitro-attest"];
                args.extend(source);
                args.extend(["--pcr0", "ab"]);
                args.extend(guest);
                Cli::try_parse_from(args).unwrap();
            }
        }
    }

    #[test]
    fn measurement_and_explicit_emulator_mode_need_no_pins() {
        Cli::try_parse_from(["nitro-attest", "--measure", "guest.wasm"]).unwrap();
        Cli::try_parse_from([
            "nitro-attest",
            "--url",
            "https://example.test",
            "--unsigned-emulator",
        ])
        .unwrap();
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if let Some(path) = &cli.measure {
        let component =
            std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        println!(
            "{{\"sha256\": \"{}\", \"PCR16\": \"{}\"}}",
            hex::encode(nitro_attestation::sha256(&component)),
            hex::encode(nitro_attestation::guest_pcr(&component))
        );
        return Ok(());
    }

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
            let certificate = match &cli.peer_certificate {
                Some(path) => Some(
                    std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
                ),
                None => None,
            };
            (decode_document(&raw)?, certificate)
        }
        _ => bail!("pass --url, --document, or --measure"),
    };

    let guest = match &cli.guest {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
        }
        None => None,
    };
    let pcr16 = expected_guest_register(cli.pcr16.as_deref(), guest.as_deref())?;

    let trust_root = match &cli.trust_root {
        Some(path) => std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        None => AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(),
    };

    let now = SystemTime::now();
    let verified = if cli.unsigned_emulator {
        eprintln!(
            "WARNING: --unsigned-emulator: no signature and no chain were checked. \
             Nothing here says who produced this document."
        );
        Verified {
            document: nitro_attestation::parse(&document)?,
            trust: Trust::Unsigned,
        }
    } else {
        nitro_attestation::verify(
            &document,
            &VerifyOptions {
                trust_root,
                now,
                allow_untrusted_root: cli.allow_untrusted_root,
            },
        )?
    };

    let mut expectations = Expectations {
        max_age: Some(Duration::from_secs(cli.max_age)),
        ..Default::default()
    };
    match (&cli.url, &cli.nonce) {
        // A document we fetched must quote the nonce this process generated.
        (Some(_), _) => expectations.nonce = Some(nonce.clone()),
        // A document from a file can only be held to a nonce the caller says
        // its request sent. Without one there is nothing to compare, and the
        // document could be any age the clock allows.
        (None, Some(hex)) => {
            expectations.nonce = Some(hex::decode(hex.trim()).context("--nonce is not hex")?)
        }
        (None, None) => {}
    }
    if let Some(pcr0) = &cli.pcr0 {
        expectations = expectations.pcr0(hex::decode(pcr0.trim()).context("--pcr0 is not hex")?);
    }
    if let Some(pcr16) = pcr16 {
        expectations = expectations.pcr(nitro_attestation::PCR_GUEST, pcr16);
    }
    verified.expect(&expectations, now)?;

    let document = &verified.document;
    println!("module     {}", document.module_id);
    println!(
        "PCR0       {}",
        document.pcr0_hex().unwrap_or_else(|| "(absent)".into())
    );
    println!(
        "PCR16      {}",
        document
            .pcr(nitro_attestation::PCR_GUEST)
            .map(hex::encode)
            .unwrap_or_else(|| "(absent: no guest was measured)".into())
    );
    println!("timestamp  {:?}", document.timestamp());
    match verified.trust {
        Trust::ChainVerified => println!("chain      verified to the AWS Nitro root"),
        Trust::SelfSigned => println!("chain      SELF-SIGNED — proves nothing about AWS hardware"),
        Trust::Unsigned => println!("chain      UNSIGNED — nothing verified; contents only"),
    }

    check_binding(
        document.user_data.as_deref(),
        server_certificate.as_deref(),
        cli.guest.as_deref().zip(guest.as_deref()),
    )?;

    println!("\nOK");
    Ok(())
}

/// The PCR16 to require: from `--pcr16`, from `--guest`, or from both when they
/// name the same guest.
fn expected_guest_register(
    pinned: Option<&str>,
    component: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    let measured = component.map(|c| nitro_attestation::guest_pcr(c).to_vec());
    let Some(pinned) = pinned else {
        return Ok(measured);
    };
    let pinned = hex::decode(pinned.trim()).context("--pcr16 is not hex")?;
    if let Some(measured) = measured {
        if measured != pinned {
            bail!(
                "--pcr16 and --guest name different guests: the component measures to {}",
                hex::encode(&measured)
            );
        }
    }
    Ok(Some(pinned))
}

/// The step that ties the TLS session to the attested code.
fn check_binding(
    user_data: Option<&[u8]>,
    server_certificate: Option<&[u8]>,
    guest: Option<(&Path, &[u8])>,
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

    if let Some((path, bytes)) = guest {
        let digest = nitro_attestation::sha256(bytes);
        if digest != hashes.guest {
            bail!(
                "the enclave is serving a different guest: attested {}, local file {}",
                hex::encode(hashes.guest),
                hex::encode(digest)
            );
        }
        println!(
            "guest      matches {} (PCR16 and user_data)",
            path.display()
        );
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

    // Named explicitly: `builder()` resolves the provider from rustls's
    // compiled-in features and panics when more than one is present.
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .context("selecting TLS protocol versions")?
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

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\n{}: {}\r\nConnection: close\r\n\
         User-Agent: nitro-attest\r\n\r\n",
        NONCE_HEADER,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
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

    let (status, head, body) = split_response(&response)?;

    // The document rides on the response, whatever the response says. A
    // refusal is attested too — a client that only trusted 200s could be
    // steered by an unattested 401 into believing the enclave was down.
    let encoded = head
        .lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with(&format!("{ATTESTATION_HEADER}:"))
        })
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .with_context(|| {
            format!(
                "no {ATTESTATION_HEADER} header on the HTTP {status} response — \
                 attestation is disabled, or something else is answering: {}",
                String::from_utf8_lossy(&body).trim()
            )
        })?;

    Ok(Fetched {
        document: decode_document(encoded.as_bytes())?,
        certificate,
    })
}

fn split_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .context("--url must start with https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        // The probe: attested, needs no credential, reaches no guest. What
        // comes back is a refusal, and the document on it is the point.
        None => (rest, "/auth/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("invalid port")?),
        None => (authority.to_string(), 443u16),
    };
    Ok((host, port, path.to_string()))
}

fn split_response(response: &[u8]) -> Result<(u16, String, Vec<u8>)> {
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
    Ok((status, head.to_string(), body))
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
