//! `passkey-client` — drive the enclave's WebAuthn gate from a script.
//!
//! ```console
//! $ passkey-client --url https://127.0.0.1:8443 enrol --token <invite>
//! $ passkey-client --url https://127.0.0.1:8443 get --path /counter
//! ```
//!
//! A phone cannot be driven from a shell script, and the QEMU harness serves a
//! self-signed certificate that no platform authenticator would attest against
//! anyway. So this is the client half in software: it registers a P-256 passkey
//! and then, for each request, asks for a challenge bound to that exact request
//! and signs it — the same two round trips a real app makes, producing the same
//! bytes.
//!
//! It is a *client*, not a bypass. Everything it sends goes through the same
//! gate as anything else, and the enclave cannot tell the difference — which is
//! the point: if the harness can reach the guest with this, the gate is wired
//! up, and if it cannot without it, the gate is doing its job.
//!
//! The credential is kept in a file between invocations so a script can enrol
//! once and then make several signed requests, the way a session on a phone
//! would.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use enclave_runtime::SoftwareAuthenticator;

#[derive(Parser, Debug)]
#[command(
    about = "Register a software passkey and make signed requests",
    version
)]
struct Cli {
    /// Base URL, e.g. `https://127.0.0.1:8443`.
    #[arg(long)]
    url: String,

    /// Where the passkey is kept between invocations.
    #[arg(long, default_value = "/tmp/passkey-client.json")]
    state: PathBuf,

    /// The relying-party id the enclave was configured with.
    #[arg(long, default_value = "enclave.test")]
    rp_id: String,

    /// The origin assertions must claim. Defaults to `https://<rp-id>`.
    #[arg(long)]
    origin: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Register a new passkey against an enrollment token.
    Enrol {
        #[arg(long)]
        token: String,
    },
    /// A signed GET.
    Get {
        #[arg(long)]
        path: String,
    },
    /// A signed POST.
    Post {
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "")]
        body: String,
    },
    /// Send an assertion issued for one request against a different one.
    ///
    /// The harness uses this to show that a substituted body is refused — the
    /// property the whole binding exists for, and one no ordinary client can
    /// exercise.
    Substitute {
        #[arg(long)]
        path: String,
        /// The body the assertion was issued for.
        #[arg(long)]
        approved: String,
        /// The body actually sent.
        #[arg(long)]
        sent: String,
    },
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let origin = cli
        .origin
        .clone()
        .unwrap_or_else(|| format!("https://{}", cli.rp_id));

    match &cli.command {
        Command::Enrol { token } => {
            let authenticator = SoftwareAuthenticator::new(&cli.rp_id);
            enrol(&cli, &origin, &authenticator, token)?;
            save(&cli, &authenticator)?;
            println!("enrolled");
        }
        Command::Get { path } => {
            let authenticator = load(&cli)?;
            let (status, body) = signed(&cli, &origin, &authenticator, "GET", path, "", None)?;
            save(&cli, &authenticator)?;
            print!("{body}");
            std::process::exit(if (200..300).contains(&status) { 0 } else { 1 });
        }
        Command::Post { path, body } => {
            let authenticator = load(&cli)?;
            let (status, response) =
                signed(&cli, &origin, &authenticator, "POST", path, body, None)?;
            save(&cli, &authenticator)?;
            print!("{response}");
            std::process::exit(if (200..300).contains(&status) { 0 } else { 1 });
        }
        Command::Substitute {
            path,
            approved,
            sent,
        } => {
            let authenticator = load(&cli)?;
            let (status, response) = signed(
                &cli,
                &origin,
                &authenticator,
                "POST",
                path,
                sent,
                Some(approved),
            )?;
            save(&cli, &authenticator)?;
            println!("{status}");
            print!("{response}");
        }
    }
    Ok(())
}

/// Just enough of the authenticator to rebuild it next time.
#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    credential_id: String,
    key_pkcs8: String,
    /// Carried between invocations so the counter keeps rising. A real
    /// authenticator holds this in its own hardware; a shell script invoking a
    /// fresh process per request has to write it down.
    counter: u32,
}

impl Saved {
    fn of(a: &SoftwareAuthenticator) -> Self {
        Saved {
            credential_id: b64().encode(a.credential_id()),
            key_pkcs8: b64().encode(a.private_key_pkcs8()),
            counter: a.counter(),
        }
    }
}

fn load(cli: &Cli) -> Result<SoftwareAuthenticator> {
    let raw = std::fs::read(&cli.state)
        .with_context(|| format!("reading {} — run `enrol` first", cli.state.display()))?;
    let saved: Saved = serde_json::from_slice(&raw).context("parsing saved passkey")?;
    SoftwareAuthenticator::restore(
        &cli.rp_id,
        &b64().decode(saved.credential_id)?,
        &b64().decode(saved.key_pkcs8)?,
        saved.counter,
    )
}

/// Write the passkey back, so the next invocation continues its counter.
fn save(cli: &Cli, a: &SoftwareAuthenticator) -> Result<()> {
    std::fs::write(&cli.state, serde_json::to_vec(&Saved::of(a))?)
        .with_context(|| format!("writing {}", cli.state.display()))
}

fn enrol(cli: &Cli, origin: &str, a: &SoftwareAuthenticator, token: &str) -> Result<()> {
    let options = post_json(
        cli,
        "/auth/register/options",
        &serde_json::json!({ "enrollment_token": token }),
    )?;
    let challenge = options["options"]["publicKey"]["challenge"]
        .as_str()
        .context("registration options carry no challenge")?;
    let verified = post_json(
        cli,
        "/auth/register/verify",
        &serde_json::json!({
            "registration_id": options["registration_id"],
            "credential": a.register(challenge, origin),
        }),
    )?;
    if verified["tenant_id"].as_str().is_none() {
        bail!("registration was refused: {verified}");
    }
    Ok(())
}

/// Ask for a challenge bound to a request, sign it, and send the request.
///
/// `approved_body` exists only so the harness can bind an assertion to one body
/// and send another.
fn signed(
    cli: &Cli,
    origin: &str,
    a: &SoftwareAuthenticator,
    method: &str,
    path: &str,
    body: &str,
    approved_body: Option<&str>,
) -> Result<(u16, String)> {
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let bound_to = approved_body.unwrap_or(body);
    let options = post_json(
        cli,
        "/auth/request/options",
        &serde_json::json!({
            "credential_id": b64().encode(a.credential_id()),
            "method": method,
            "path": path_only,
            "query": query,
            "body_sha256": b64().encode(nitro_attestation::sha256(bound_to.as_bytes())),
        }),
    )?;
    let challenge = options["options"]["publicKey"]["challenge"]
        .as_str()
        .context("challenge options carry no challenge")?;
    let assertion = a.assert(challenge, origin);

    request(
        cli,
        method,
        path,
        &[
            (
                "x-webauthn-challenge-id",
                options["challenge_id"]
                    .as_str()
                    .context("no challenge id")?
                    .to_string(),
            ),
            ("x-webauthn-assertion", b64().encode(assertion.to_string())),
        ],
        body,
    )
}

fn post_json(cli: &Cli, path: &str, value: &serde_json::Value) -> Result<serde_json::Value> {
    let (_, body) = request(
        cli,
        "POST",
        path,
        &[("content-type", "application/json".to_string())],
        &value.to_string(),
    )?;
    serde_json::from_str(&body).with_context(|| format!("{path} did not answer JSON: {body}"))
}

/// One HTTPS request, accepting whatever certificate is presented.
///
/// The certificate is not what establishes trust here — the attestation is, and
/// `nitro-attest` is the tool that checks it. This one is about the gate.
fn request(
    cli: &Cli,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> Result<(u16, String)> {
    let authority = cli
        .url
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();

    let name = rustls::pki_types::ServerName::try_from(cli.rp_id.clone())?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), name)?;
    let mut socket =
        TcpStream::connect(&authority).with_context(|| format!("connecting to {authority}"))?;
    let mut tls = rustls::Stream::new(&mut connection, &mut socket);

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        cli.rp_id,
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    tls.write_all(request.as_bytes())?;

    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("no response headers")?;
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
    Ok((status, String::from_utf8_lossy(&body).to_string()))
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
