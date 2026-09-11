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
//! # The order of a signed request
//!
//! ```text
//!   1. POST /auth/request/options   ── carries the body hash, no approval
//!   2. check that response's document against this connection   ◀── refuse here
//!      and remember the certificate it was served under
//!   3. ask the authenticator to sign            (a person is prompted)
//!   4. open the operation's connection, complete the handshake, and check it
//!      presents that same certificate          ◀── refuse *before* sending
//!   5. only then send the operation
//! ```
//!
//! Step 2 is why there is no separate probe route. Verifying a connection means
//! receiving a response on it, so *something* has to go first on a connection
//! nothing has vouched for — and the challenge request is the right thing to
//! send: it carries the operation's hash but no approval, so a party that
//! intercepted it learns what is intended and holds nothing it can act on. The
//! round trip was needed anyway.
//!
//! Step 2 comes before step 3 deliberately. A person should not be asked to
//! approve an operation for a party nobody has identified yet.
//!
//! Step 4 needs no second attestation document, and that is the point. The
//! document from step 2 binds a certificate; TLS proves the peer holds that
//! certificate's *private key*, which the certificate itself — being public —
//! does not. So "the same certificate" and "the same enclave" are the same
//! statement, and checking it costs a comparison rather than a signature.
//!
//! It is checked after the handshake and before a byte is written, so a changed
//! far end means the operation is never sent. Nothing is retried on a fresh
//! connection: the assertion is bound to this exact body and is single-use, so
//! a retry would risk executing twice for the sake of reaching a party that has
//! just failed to be the one approved.
//!
//! This rests on the runtime refusing session resumption — see `serve::tls`. A
//! resumed session need present no certificate at all, and pinning against one
//! the client had cached would be checking its own memory.
//!
//! What none of this establishes: the document is generated before the request
//! is routed, so it says nothing about the response body and does not show the
//! guest ran. Signature and chain are `nitro-attest`'s to check, and need a
//! trust root this client is not given.
//!
//! The credential is kept in a file between invocations so a script can enrol
//! once and then make several signed requests, the way a session on a phone
//! would.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
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

    /// Write each response's proof into this directory: `document.b64`, the
    /// `certificate.der` this connection was served, and the `nonce.hex` the
    /// request sent. Three files is what `nitro-attest --document
    /// --peer-certificate --nonce` needs to check the binding for a request
    /// this client signed — which it cannot make for itself.
    #[arg(long)]
    dump_proof: Option<PathBuf>,

    /// Required PCR0, hex. Pins which runtime image is answering.
    ///
    /// The hypervisor measures this from the image and locks it, so nothing
    /// running inside can choose it — which is what makes it the measurement
    /// the other one rests on. It does not cover the guest, which is not in the
    /// image. Required unless `--unsigned-emulator`.
    #[arg(long)]
    pcr0: Option<String>,

    /// Required PCR16, hex. Pins which guest the runtime is running.
    ///
    /// The runtime extends this register with the guest's hash and locks it
    /// before it can obtain a key, so it is the measurement that says which
    /// application holds your data. It says that only beside `--pcr0`, because
    /// the runtime is what writes it. Required — or `--guest` — unless
    /// `--unsigned-emulator`.
    #[arg(long)]
    pcr16: Option<String>,

    /// The guest component itself. Computes the PCR16 to require, and checks
    /// the document's second hash as well.
    ///
    /// Never a substitute for `--pcr0`, for the same reason `--pcr16` is not:
    /// both halves of what it checks are written by the runtime being attested.
    #[arg(long)]
    guest: Option<PathBuf>,

    /// Trust root, PEM or DER. Defaults to the embedded AWS Nitro root.
    #[arg(long)]
    trust_root: Option<PathBuf>,

    /// Accept a document that does not chain to the AWS root.
    #[arg(long)]
    allow_untrusted_root: bool,

    /// Reject a document older than this many seconds.
    #[arg(long, default_value_t = 300)]
    max_age: u64,

    /// Check the document's contents without verifying any signature.
    ///
    /// Only one producer needs this and it is not a real enclave: QEMU's
    /// emulated NSM does not sign at all. With this on, **nothing establishes
    /// who produced the document** — the nonce and certificate binding are
    /// still checked, and they are this runtime's work, but the signature is
    /// AWS hardware's and there is none to check.
    ///
    /// Never use it against anything you are trusting with a key.
    #[arg(long)]
    unsigned_emulator: bool,

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
    /// Spend a token issued for one route against a different one.
    ///
    /// The harness uses this to show that an approval names an interaction and
    /// cannot be moved off it — one no ordinary client can exercise, because a
    /// client has no reason to build a request its own approval does not match.
    ///
    /// Note what this deliberately no longer demonstrates: a substituted
    /// *body*. A token commits to no bytes, so sending different ones at the
    /// approved route is not a refusal and there would be nothing to show.
    Substitute {
        /// The route the token is issued for.
        #[arg(long)]
        approved: String,
        /// The route it is actually spent on.
        #[arg(long)]
        sent: String,
        #[arg(long, default_value = "")]
        body: String,
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
            approved,
            sent,
            body,
        } => {
            let authenticator = load(&cli)?;
            let (status, response) = signed(
                &cli,
                &origin,
                &authenticator,
                "POST",
                sent,
                body,
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
    let (options, opened_on) = post_json(
        cli,
        "/auth/register/options",
        &serde_json::json!({ "enrollment_token": token }),
        None,
    )?;
    let opened_on = opened_on.expect("an unpinned exchange is always checked");
    let challenge = options["options"]["publicKey"]["challenge"]
        .as_str()
        .context("registration options carry no challenge")?;
    let (verified, _) = post_json(
        cli,
        "/auth/register/verify",
        &serde_json::json!({
            "registration_id": options["registration_id"],
            "credential": a.register(challenge, origin),
        }),
        // The credential being registered is as worth protecting as an
        // assertion, and for the same reason.
        Some(&opened_on.certificate),
    )?;
    if verified["tenant_id"].as_str().is_none() {
        bail!("registration was refused: {verified}");
    }
    Ok(())
}

/// Ask for a challenge bound to a request, sign it, and send the request.
///
/// `approved_route` exists only so the harness can take a token for one route
/// and spend it on another.
fn signed(
    cli: &Cli,
    origin: &str,
    a: &SoftwareAuthenticator,
    method: &str,
    path: &str,
    body: &str,
    approved_route: Option<&str>,
) -> Result<(u16, String)> {
    // The route the approval is *for*, which is normally the one being asked.
    let approved = approved_route.unwrap_or(path);
    let (approved_path, approved_query) = match approved.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (approved, None),
    };
    // The challenge request is the one that goes first on a connection nothing
    // has vouched for yet, and it is chosen for that: it carries the operation's
    // hash but no approval, so a party that intercepted it would learn what is
    // intended and hold nothing it could act on.
    //
    // Its response is attested like any other, which is what makes a separate
    // probe route unnecessary — the round trip was going to happen anyway.
    let (options, opened_on) = post_json(
        cli,
        "/auth/request/options",
        &serde_json::json!({
            "credential_id": b64().encode(a.credential_id()),
            "method": method,
            "path": approved_path,
            "query": approved_query,
        }),
        // Nothing to pin to yet: this is the exchange that establishes it, and
        // it is chosen to go first precisely because it carries no approval.
        None,
    )?;
    let opened_on = opened_on.expect("an unpinned exchange is always checked");

    // Only now, with the far end identified, is it reasonable to ask a person
    // to approve anything. `post_json` has already refused if the exchange
    // could not be tied to this connection, so reaching here means it was.
    let challenge = options["options"]["publicKey"]["challenge"]
        .as_str()
        .with_context(|| format!("challenge options carry no challenge: {options}"))?;
    let assertion = a.assert(challenge, origin);

    // Trip two: hand the assertion back and take a token for the interaction.
    // The token is what the interaction presents, so this is where the passkey
    // ceremony ends and nothing after it needs the authenticator again — which
    // is the whole point when the interaction is a stream with no single
    // request to hang an assertion on.
    let (granted, _) = post_json(
        cli,
        "/auth/request/verify",
        &serde_json::json!({
            "challenge_id": options["challenge_id"]
                .as_str()
                .context("no challenge id")?,
            "assertion": b64().encode(assertion.to_string()),
        }),
        // Checked after the handshake and *before* the assertion is written, so
        // a changed far end means the credential is never sent.
        Some(&opened_on.certificate),
    )?;
    let token = granted["token"]
        .as_str()
        .context("the runtime issued no token")?;

    // Trip three, pinned to the certificate the challenge exchange identified.
    // The pin is checked after the handshake and *before* a byte goes out, so a
    // changed far end means the interaction is never sent rather than sent and
    // regretted.
    //
    // Nothing is retried on a fresh connection. The token is good once, so a
    // retry would reach a party that has just failed to be the one approved,
    // holding an approval that may already have been spent.
    let (status, response, _) = request(
        cli,
        method,
        path,
        &[("authorization", format!("Bearer {token}"))],
        body,
        Some(&opened_on.certificate),
    )?;

    Ok((status, response))
}

/// A JSON POST, optionally to a connection that must present `pinned`.
///
/// The pin matters most on the exchange that carries the assertion. That
/// exchange used to open an unpinned connection, which meant the credential
/// went out to whoever answered: an interceptor could take it, redeem it at the
/// real enclave, and keep the token. Checking the response afterwards proves
/// only that the theft succeeded.
fn post_json(
    cli: &Cli,
    path: &str,
    value: &serde_json::Value,
    pinned: Option<&[u8]>,
) -> Result<(serde_json::Value, Option<ConnectionProof>)> {
    let (_, body, proof) = request(
        cli,
        "POST",
        path,
        &[("content-type", "application/json".to_string())],
        &value.to_string(),
        pinned,
    )?;
    let value = serde_json::from_str(&body)
        .with_context(|| format!("{path} did not answer JSON: {body}"))?;
    Ok((value, proof))
}

/// One HTTPS request, accepting whatever certificate is presented.
///
/// The certificate is not what establishes trust — nothing vouches for it, and
/// nothing needs to. The attestation does, by naming the certificate this
/// connection presented, which is checked here before the response is returned.
/// What is *not* checked here is the signature and the chain: that needs a
/// trust root and expected measurements this client is not given, and
/// `nitro-attest` is the tool for it.
fn request(
    cli: &Cli,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
    // The certificate this connection must present, once one is known. `None`
    // on the exchange that establishes it — there is nothing to pin to yet,
    // which is why that exchange carries no approval.
    pinned: Option<&[u8]>,
) -> Result<(u16, String, Option<ConnectionProof>)> {
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

    // Driven to completion here rather than left to the first write, because
    // what the far end presents has to be known *before* anything is sent to
    // it. TLS proves the peer holds the private key for the certificate it
    // shows; the certificate itself is public and proves nothing on its own.
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .context("completing the TLS handshake")?;
    }
    let presented = connection
        .peer_certificates()
        .and_then(|c| c.first())
        .context("the server presented no certificate")?
        .to_vec();

    // The operation goes nowhere if this is not the enclave the approval was
    // given to. Checked before a byte is written, so a changed far end means
    // the request is never sent rather than sent and regretted.
    if let Some(expected) = pinned {
        anyhow::ensure!(
            presented == expected,
            "this connection presents a different certificate than the one the \
             approval was given to; the operation was not sent"
        );
    }

    let mut tls = rustls::Stream::new(&mut connection, &mut socket);

    // Every request carries a nonce. The runtime refuses without one whether or
    // not it attests, so a client that omits it reaches nothing.
    let nonce = fresh_nonce();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
         x-enclave-nonce: {}\r\nContent-Length: {}\r\n",
        cli.rp_id,
        encode_nonce(&nonce),
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

    // On a pinned connection there is nothing left to establish: the far end
    // presented the certificate the approval was given to, and TLS proved it
    // holds the private key. The runtime does not attest these responses for
    // exactly that reason, so there is no document here to read.
    //
    // On an unpinned one there is everything to establish, and it is checked
    // before the body is even looked at. A response this client cannot tie to
    // the enclave on the other end is not a response it will act on, and a
    // deployment with attestation off is one it will not talk to — nothing to
    // check means nothing it can promise.
    let proof = match pinned {
        // A pinned response carries no document by design — the runtime attests
        // the `/auth/` exchange and leaves the rest alone — so there is nothing
        // here to check and nothing to dump. Dumping unconditionally used to
        // fail *after* the interaction had already run.
        Some(_) => None,
        None => Some(
            connection_proof(&head, &nonce, &presented, &TrustConfig::from(cli)?)
                .with_context(|| format!("{method} {path} could not be tied to this connection"))?,
        ),
    };

    // Only the attested exchange has a proof worth keeping, and it is the one a
    // verifier needs: the document, the certificate it binds, and the nonce it
    // quotes. The interaction that follows is covered by the pin.
    if proof.is_some() {
        if let Some(dir) = &cli.dump_proof {
            dump_proof(dir, &head, &nonce, &connection)?;
        }
    }

    let rest = &raw[split + 4..];
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    Ok((status, String::from_utf8_lossy(&body).to_string(), proof))
}

/// A fresh nonce for one request.
///
/// From the OS, because a nonce a third party can predict is not a nonce — and
/// this one is checked: the document that comes back must quote it, or the
/// response is refused before its body is read.
fn fresh_nonce() -> [u8; 20] {
    let mut nonce = [0u8; 20];
    getrandom::fill(&mut nonce).expect("the OS has entropy");
    nonce
}

fn encode_nonce(nonce: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// The three things a verifier needs and cannot recover after the fact: what
/// the enclave signed, which certificate this connection was actually served,
/// and which nonce was asked for.
/// What one response proves about the connection it arrived on.
///
/// The document is generated before the request is routed, so it says nothing
/// about the body below it and nothing about whether the guest ran. What it
/// does say is that *this* enclave terminated *this* connection, just now —
/// and that is the claim the operation depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionProof {
    /// The leaf this connection presented, which the document was checked to
    /// name. Kept whole rather than hashed because the next connection is
    /// pinned against it, and TLS compares certificates rather than digests.
    certificate: Vec<u8>,
    guest: [u8; 32],
}

/// Verify a response's attestation against the connection it arrived on.
///
/// Everything, in the order it has to happen:
///
/// - the **signature and certificate chain**, so the document came from a real
///   Nitro enclave and not from whoever answered the socket;
/// - its **age**, so it was made now rather than captured earlier;
/// - the **nonce**, so it was made for this caller and not replayed from
///   somebody else's exchange;
/// - the **certificate** it binds, against the one this connection actually
///   presented, so the enclave that signed it is the party on the other end
///   rather than one being relayed by something in between;
/// - and, when given, **PCR0** and the guest hash — *which* enclave and *which*
///   application, not merely that it is some enclave.
///
/// The chain check is what the other four rest on. Without it a party that
/// terminated TLS could mint a document naming its own certificate and quoting
/// the nonce, and every remaining check would pass.
fn connection_proof(
    head: &str,
    nonce: &[u8],
    presented: &[u8],
    trust: &TrustConfig,
) -> Result<ConnectionProof> {
    let encoded = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .context("the response carried no x-enclave-attestation header")?;
    let cose = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("the attestation header is not base64")?;

    let now = std::time::SystemTime::now();
    let verified = if trust.unsigned_emulator {
        nitro_attestation::Verified {
            document: nitro_attestation::parse(&cose).context("parsing the document")?,
            trust: nitro_attestation::Trust::Unsigned,
        }
    } else {
        nitro_attestation::verify(
            &cose,
            &nitro_attestation::VerifyOptions {
                trust_root: trust.root.clone(),
                now,
                allow_untrusted_root: trust.allow_untrusted_root,
            },
        )
        .context("the document did not verify")?
    };

    // What the runtime binds: the leaf this connection was served, and the
    // guest component behind it. The certificate half is checked always; the
    // guest half only when the caller supplied the component to check against.
    let hashes = nitro_attestation::AttestationHashes::parse(
        verified
            .document
            .user_data
            .as_deref()
            .context("the document binds no user_data")?,
    )
    .context("the document's user_data is not the runtime's binding")?;
    anyhow::ensure!(
        hashes.tls_certificate == nitro_attestation::sha256(presented),
        "the document binds a certificate this connection was never served: \
         the enclave that signed it is not the party answering here"
    );

    let mut expectations = nitro_attestation::Expectations {
        nonce: Some(nonce.to_vec()),
        max_age: Some(trust.max_age),
        ..Default::default()
    };
    if let Some(pcr0) = &trust.pcr0 {
        expectations = expectations.pcr0(pcr0.clone());
    }
    // Missing from the document is a refusal, not a skipped check: a runtime
    // that never locked the register attests no guest at all.
    if let Some(pcr16) = &trust.pcr16 {
        expectations = expectations.pcr(nitro_attestation::PCR_GUEST, pcr16.clone());
    }
    if let Some(guest) = &trust.guest {
        expectations.user_data =
            Some(nitro_attestation::AttestationHashes::new(presented, guest).serialize());
    }
    verified
        .expect(&expectations, now)
        .context("the document did not meet expectations")?;

    Ok(ConnectionProof {
        certificate: presented.to_vec(),
        guest: hashes.guest,
    })
}

/// What the client requires of a document before it acts on the response.
struct TrustConfig {
    root: Vec<u8>,
    allow_untrusted_root: bool,
    unsigned_emulator: bool,
    max_age: std::time::Duration,
    pcr0: Option<Vec<u8>>,
    /// The guest register to require, from `--pcr16` or computed from
    /// `--guest`.
    pcr16: Option<Vec<u8>>,
    guest: Option<Vec<u8>>,
}

impl TrustConfig {
    fn from(cli: &Cli) -> Result<Self> {
        // A verified chain says "a genuine Nitro enclave". It does not say
        // *which* one, and an attacker who can run their own gets a document
        // that passes every other check here.
        //
        // **Two measurements close that, and neither stands in for the other.**
        // PCR0 is measured by the hypervisor from the image and locked, so no
        // software inside the enclave can choose it — but the image no longer
        // contains the guest. PCR16 is the guest, extended and locked by the
        // runtime before it could obtain a key — but because the runtime writes
        // it, an enclave running an attacker's runtime can claim your guest's
        // value while running nothing of the kind. PCR0 says the runtime that
        // wrote PCR16 is yours; PCR16 says which application it loaded.
        //
        // `--guest` is how most callers supply PCR16, and it checks the
        // document's guest hash as well. Both halves of that come from the
        // runtime, so it is never a substitute for `--pcr0`.
        //
        // `--unsigned-emulator` is the one exception, and an explicit one: QEMU
        // has no stable PCR0 to pin, and nothing there is signed anyway.
        let guest = match &cli.guest {
            Some(path) => {
                Some(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
            }
            None => None,
        };
        let measured = guest
            .as_deref()
            .map(|component| nitro_attestation::guest_pcr(component).to_vec());
        let pcr16 = match (&cli.pcr16, measured) {
            (Some(pinned), measured) => {
                let pinned = hex::decode(pinned.trim()).context("--pcr16 is not hex")?;
                if let Some(measured) = measured {
                    anyhow::ensure!(
                        measured == pinned,
                        "--pcr16 and --guest name different guests: the component measures \
                         to {}",
                        hex::encode(&measured)
                    );
                }
                Some(pinned)
            }
            (None, measured) => measured,
        };

        if !cli.unsigned_emulator {
            if cli.pcr0.is_none() {
                bail!(
                    "refusing to talk to an unidentified enclave: pass --pcr0, which is the \
                     measurement the hypervisor takes of the image and the only one an \
                     attacker's own enclave cannot claim. --guest and --pcr16 are required \
                     alongside it, not instead of it: the runtime being attested is what \
                     writes them. Against QEMU, pass --unsigned-emulator."
                );
            }
            if pcr16.is_none() {
                bail!(
                    "refusing to talk to an enclave whose guest is unidentified: pass --pcr16, \
                     or --guest with the component itself. PCR0 measures the runtime image, \
                     and the guest is not in it — the runtime loads it at boot, measures it \
                     into PCR16 and locks that register before it can obtain a key. PCR16 is \
                     the measurement that says which application holds your data."
                );
            }
        }
        Ok(TrustConfig {
            root: match &cli.trust_root {
                Some(path) => {
                    std::fs::read(path).with_context(|| format!("reading {}", path.display()))?
                }
                None => nitro_attestation::AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(),
            },
            allow_untrusted_root: cli.allow_untrusted_root,
            unsigned_emulator: cli.unsigned_emulator,
            max_age: std::time::Duration::from_secs(cli.max_age),
            pcr0: match &cli.pcr0 {
                Some(hex) => Some(hex::decode(hex.trim()).context("--pcr0 is not hex")?),
                None => None,
            },
            pcr16,
            guest,
        })
    }
}

fn dump_proof(
    dir: &Path,
    head: &str,
    nonce: &[u8],
    connection: &rustls::ClientConnection,
) -> Result<()> {
    let document = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .context("the response carried no x-enclave-attestation header")?;
    let certificate = connection
        .peer_certificates()
        .and_then(|c| c.first())
        .context("the server presented no certificate")?;

    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(dir.join("document.b64"), document)?;
    std::fs::write(dir.join("certificate.der"), certificate.as_ref())?;
    std::fs::write(dir.join("nonce.hex"), hex::encode(nonce))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use nitro_attestation::testing::TestChain;
    use nitro_attestation::AttestationHashes;

    /// What a client requires, pointed at a test chain rather than AWS.
    ///
    /// `allow_untrusted_root` stays **false**: it does not mean "this root is
    /// not AWS", it means "accept a document that chains to nothing I pinned",
    /// which would make every test below vacuous. Pinning the test chain's own
    /// root is what keeps the chain check real.
    fn trust(chain: &TestChain) -> TrustConfig {
        TrustConfig {
            root: chain.root_der().to_vec(),
            allow_untrusted_root: false,
            unsigned_emulator: false,
            max_age: std::time::Duration::from_secs(300),
            pcr0: None,
            pcr16: None,
            guest: None,
        }
    }

    const GUEST: &[u8] = b"a-guest";

    /// The registers an enclave running [`GUEST`] has locked: its image, and
    /// the guest it measured.
    fn registers() -> std::collections::BTreeMap<u32, Vec<u8>> {
        [
            (0u32, vec![0x5a; 48]),
            (
                nitro_attestation::PCR_GUEST,
                nitro_attestation::guest_pcr(GUEST).to_vec(),
            ),
        ]
        .into()
    }

    /// A response head carrying a document built for `cert` and `nonce`.
    fn head_for(chain: &TestChain, cert: &[u8], nonce: &[u8]) -> String {
        head_with(chain, cert, nonce, registers())
    }

    /// The same, listing exactly the registers given.
    fn head_with(
        chain: &TestChain,
        cert: &[u8],
        nonce: &[u8],
        pcrs: std::collections::BTreeMap<u32, Vec<u8>>,
    ) -> String {
        let user_data = AttestationHashes::new(cert, GUEST).serialize();
        let cose = chain
            .document_with_pcrs(Some(user_data), Some(nonce.to_vec()), pcrs)
            .expect("a document");
        format!(
            "HTTP/1.1 200 OK\r\nx-enclave-attestation: {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(cose)
        )
    }

    #[test]
    fn a_document_for_this_connection_and_this_nonce_is_accepted() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf-this-connection-presented";
        let nonce = [7u8; 20];
        let proof = connection_proof(
            &head_for(&chain, cert, &nonce),
            &nonce,
            cert,
            &trust(&chain),
        )
        .expect("the document names this certificate and quotes this nonce");
        assert_eq!(proof.certificate, cert.to_vec());
    }

    /// **The forgery.** A document nobody signed, naming the forger's own
    /// certificate and quoting the nonce it was just sent.
    ///
    /// Every check except the chain passes: the nonce matches, and the
    /// certificate it binds really is the one this connection presented —
    /// because the forger chose both. Only verifying the signature and the
    /// chain catches it, which is why parsing the document was never enough.
    #[test]
    fn a_document_that_nobody_signed_is_refused() {
        let forger = TestChain::new().expect("the forger's own chain");
        let honest = TestChain::new().expect("the enclave's chain");
        let cert = b"the-forgers-leaf";
        let nonce = [7u8; 20];

        // Signed by a chain the client does not trust.
        let err = connection_proof(
            &head_for(&forger, cert, &nonce),
            &nonce,
            cert,
            &trust(&honest),
        )
        .expect_err("a document from an untrusted chain was accepted");
        assert!(
            format!("{err:#}").contains("did not verify"),
            "the refusal did not name the reason: {err:#}"
        );
    }

    /// **The relay.** A genuine document from the real enclave, replayed by
    /// something that terminated TLS itself.
    #[test]
    fn a_document_naming_another_certificate_is_refused() {
        let chain = TestChain::new().expect("chain");
        let nonce = [7u8; 20];
        let head = head_for(&chain, b"the-real-enclaves-leaf", &nonce);
        let err = connection_proof(&head, &nonce, b"the-interceptors-leaf", &trust(&chain))
            .expect_err("a relayed document was accepted");
        assert!(
            format!("{err:#}").contains("never served"),
            "the refusal did not name the reason: {err:#}"
        );
    }

    /// **The replay.** A document made earlier, for an earlier request.
    #[test]
    fn a_document_quoting_another_nonce_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let head = head_for(&chain, cert, &[1u8; 20]);
        assert!(
            connection_proof(&head, &[2u8; 20], cert, &trust(&chain)).is_err(),
            "a document made for another request was accepted"
        );
    }

    /// A document older than the client will accept.
    #[test]
    fn a_stale_document_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [4u8; 20];
        let mut trust = trust(&chain);
        trust.max_age = std::time::Duration::from_nanos(1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(
            connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust).is_err(),
            "a document older than the client's window was accepted"
        );
    }

    /// The wrong image, caught by PCR0 when the caller pins one.
    #[test]
    fn a_document_from_another_image_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [5u8; 20];
        let mut trust = trust(&chain);
        trust.pcr0 = Some(vec![0xff; 48]);
        assert!(
            connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust).is_err(),
            "a document from an unexpected image was accepted"
        );
    }

    /// Fail closed: a deployment that does not attest is one this client will
    /// not act on, because there is nothing for it to check.
    #[test]
    fn a_response_without_a_document_is_refused() {
        let chain = TestChain::new().expect("chain");
        let err = connection_proof("HTTP/1.1 200 OK\r\n", &[0u8; 20], b"leaf", &trust(&chain))
            .expect_err("an unattested response was accepted");
        assert!(
            format!("{err:#}").contains("no x-enclave-attestation"),
            "{err:#}"
        );
    }

    /// The continuity check, which is what pins the interaction's connection.
    #[test]
    fn two_exchanges_on_different_certificates_do_not_match() {
        let chain = TestChain::new().expect("chain");
        let nonce = [3u8; 20];
        let t = trust(&chain);

        let opened = connection_proof(
            &head_for(&chain, b"leaf-one", &nonce),
            &nonce,
            b"leaf-one",
            &t,
        )
        .expect("the first exchange");
        let answered = connection_proof(
            &head_for(&chain, b"leaf-two", &nonce),
            &nonce,
            b"leaf-two",
            &t,
        )
        .expect("the second exchange");
        assert_ne!(
            opened.certificate, answered.certificate,
            "a changed certificate must be visible, or the pin cannot fire"
        );

        let again = connection_proof(
            &head_for(&chain, b"leaf-one", &nonce),
            &nonce,
            b"leaf-one",
            &t,
        )
        .expect("the same enclave again");
        assert_eq!(opened.certificate, again.certificate);
    }

    /// **A chain alone is not an identity.**
    ///
    /// Verifying the signature says a genuine Nitro enclave answered. It does
    /// not say whose. Refusing to run without measurements is what stops the
    /// default from reading as more safety than it gives.
    #[test]
    fn a_client_refuses_to_run_without_expected_measurements() {
        let cli = Cli::parse_from([
            "passkey-client",
            "--url",
            "https://e.test",
            "get",
            "--path",
            "/",
        ]);
        let err = match TrustConfig::from(&cli) {
            Err(e) => e,
            Ok(_) => panic!("an unidentified enclave was accepted"),
        };
        assert!(
            format!("{err:#}").contains("unidentified enclave"),
            "{err:#}"
        );
    }

    fn cli_with(flags: &[&str]) -> Cli {
        let mut args = vec!["passkey-client", "--url", "https://e.test"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["get", "--path", "/"]);
        Cli::parse_from(args)
    }

    fn guest_file(name: &str, bytes: &[u8]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("passkey-client-{}-{name}.wasm", std::process::id()));
        std::fs::write(&path, bytes).expect("writing a guest file");
        path
    }

    fn refusal(cli: &Cli) -> String {
        match TrustConfig::from(cli) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("an unidentified enclave was accepted"),
        }
    }

    /// **`--guest` alone is not an identity.**
    ///
    /// It yields a PCR16 and a `user_data` guest hash, and the runtime being
    /// attested writes both — so an attacker running their own runtime signs a
    /// genuine document claiming whatever guest you asked for. Only PCR0,
    /// measured by the hypervisor and locked, says whose runtime wrote them.
    #[test]
    fn a_guest_alone_is_not_an_identity() {
        let text = refusal(&cli_with(&["--guest", "/dev/null"]));
        assert!(text.contains("--pcr0"), "{text}");
    }

    /// **PCR0 alone no longer identifies the guest.** The image does not
    /// contain it, so a client pinning only the runtime would accept that
    /// runtime serving any application at all.
    #[test]
    fn pinning_the_runtime_alone_does_not_identify_the_guest() {
        let text = refusal(&cli_with(&["--pcr0", &"ab".repeat(48)]));
        assert!(text.contains("PCR16"), "{text}");
    }

    #[test]
    fn pinning_both_measurements_identifies_the_enclave() {
        let trust = TrustConfig::from(&cli_with(&[
            "--pcr0",
            &"ab".repeat(48),
            "--pcr16",
            &"cd".repeat(48),
        ]))
        .expect("both measurements were not accepted");
        assert_eq!(trust.pcr16, Some(vec![0xcd; 48]));
    }

    /// The component itself is the usual way to supply PCR16, and it becomes
    /// exactly the value the runtime would have locked.
    #[test]
    fn a_guest_file_becomes_the_register_it_measures_to() {
        let path = guest_file("measured", GUEST);
        let trust = TrustConfig::from(&cli_with(&[
            "--pcr0",
            &"ab".repeat(48),
            "--guest",
            path.to_str().unwrap(),
        ]));
        let _ = std::fs::remove_file(&path);

        let trust = trust.expect("a guest file was not accepted");
        assert_eq!(
            trust.pcr16,
            Some(nitro_attestation::guest_pcr(GUEST).to_vec())
        );
        assert_eq!(trust.guest.as_deref(), Some(GUEST));
    }

    #[test]
    fn a_pcr16_and_a_guest_file_that_disagree_are_refused() {
        let path = guest_file("disagreeing", GUEST);
        let cli = cli_with(&[
            "--pcr0",
            &"ab".repeat(48),
            "--pcr16",
            &"00".repeat(48),
            "--guest",
            path.to_str().unwrap(),
        ]);
        let text = refusal(&cli);
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("different guests"), "{text}");
    }

    /// **Another guest**, behind the right runtime.
    #[test]
    fn a_document_from_another_guest_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [6u8; 20];
        let mut trust = trust(&chain);
        trust.pcr0 = Some(vec![0x5a; 48]);
        trust.pcr16 = Some(nitro_attestation::guest_pcr(b"the approved guest").to_vec());
        let err = connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust)
            .expect_err("a document for another guest was accepted");
        assert!(format!("{err:#}").contains("PCR16 mismatch"), "{err:#}");
    }

    /// **No guest at all.** A runtime that never locked the register attests
    /// documents without it, and a client pinning a guest refuses that rather
    /// than skipping the check.
    #[test]
    fn a_document_that_measured_no_guest_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [7u8; 20];
        let mut trust = trust(&chain);
        trust.pcr16 = Some(nitro_attestation::guest_pcr(GUEST).to_vec());
        let head = head_with(&chain, cert, &nonce, [(0u32, vec![0x5a; 48])].into());
        let err = connection_proof(&head, &nonce, cert, &trust)
            .expect_err("a document with no guest register was accepted");
        assert!(format!("{err:#}").contains("no PCR16"), "{err:#}");
    }

    #[test]
    fn a_document_for_the_pinned_runtime_and_guest_is_accepted() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [8u8; 20];
        let mut trust = trust(&chain);
        trust.pcr0 = Some(vec![0x5a; 48]);
        trust.pcr16 = Some(nitro_attestation::guest_pcr(GUEST).to_vec());
        trust.guest = Some(GUEST.to_vec());
        connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust)
            .expect("the pinned runtime and guest were refused");
    }

    /// The exception is explicit, and only for the one producer that needs it.
    #[test]
    fn the_emulator_exception_must_be_asked_for_by_name() {
        let trust =
            TrustConfig::from(&cli_with(&["--unsigned-emulator"])).expect("the emulator exception");
        assert!(trust.unsigned_emulator);
        assert!(
            trust.pcr0.is_none() && trust.pcr16.is_none(),
            "the exception should not invent a measurement"
        );
    }
}
