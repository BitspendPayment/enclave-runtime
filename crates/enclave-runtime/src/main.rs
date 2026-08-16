//! `enclave-runtime` — run a Wasm guest against the Merkle-anchored
//! filesystem, inside an AWS Nitro Enclave.
//!
//! An enclave has no shell, no config file, and no operator to type flags at
//! it. It gets whatever the enclave image baked in, so **every setting reads
//! from an environment variable**, with a matching flag that wins if present.
//! `ENV` lines in the image's Dockerfile are the deployment configuration; the
//! flags exist so the same binary stays drivable by hand while developing.
//!
//! The guest component is loaded from a known path — `/enclave/guest.wasm` by
//! default — because it ships *inside* the enclave image. That is what puts it
//! under PCR0, and it is the whole argument for the design: the KMS key policy
//! that releases the filesystem key then attests to exactly which code will
//! read the data, not merely to the runtime that loads it. Streaming the guest
//! in over vsock would leave a valid attestation proving something much
//! weaker.
//!
//! Argument parsing over [`enclave_runtime`], which is the same crate: the
//! library half is everything below this file, and lives beside it rather than
//! inside it so integration tests can reach it.
//!
//! What is *not* here yet is KMS key release. The master secret still comes
//! from configuration, which is a development seam — a key in an environment
//! variable is visible to the parent instance, exactly the party an enclave
//! exists to exclude. Replacing it is a new
//! [`enclave_runtime::MasterKeySource`] implementation and nothing else.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use enclave_runtime::{
    open_clock, open_entropy, read_component, run_component, serve_component, AcmeConfig,
    ClockSource, GuestEnvPolicy, GuestEnvironment, MasterKeySource, MountConfig, NetworkConfig,
    NetworkMode, RandomSource, ReceiptTrust, ServeConfig, StaticKey, TlsIdentity, TlsMode,
    DEFAULT_GVFORWARDER, DEFAULT_NSM_DEVICE, DEFAULT_PTP_DEVICE, EXIT_RUNTIME_FAILURE,
};

/// Where the guest lives inside the enclave image.
const DEFAULT_GUEST_PATH: &str = "/enclave/guest.wasm";

/// Whether the guest is run to completion or serves requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Command,
    Serve,
}

fn parse_mode(s: &str) -> Result<Mode, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "command" | "run" => Ok(Mode::Command),
        "serve" | "http" => Ok(Mode::Serve),
        other => Err(format!("unknown mode {other:?}; expected command or serve")),
    }
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Run a Wasm guest against a Merkle-anchored S3 filesystem",
    long_about = None
)]
struct Cli {
    /// Guest component to run. Ships inside the enclave image, so its hash is
    /// covered by PCR0 along with this binary.
    #[arg(long, env = "S3FS_GUEST_PATH", default_value = DEFAULT_GUEST_PATH)]
    guest_path: PathBuf,

    /// Bucket holding the data slabs.
    #[arg(long, env = "S3FS_BUCKET")]
    bucket: String,

    /// Bucket holding the signed root records. Defaults to `--bucket`.
    ///
    /// These should differ in production: the roots bucket carries Object Lock
    /// COMPLIANCE retention and is the entire rollback guarantee, while the
    /// data bucket stays unlocked so dead copy-on-write blocks stay
    /// reclaimable.
    #[arg(long, env = "S3FS_ROOTS_BUCKET")]
    roots_bucket: Option<String>,

    /// 32-byte master secret, hex encoded. Every other key derives from it.
    #[arg(long, env = "S3FS_MASTER_KEY")]
    master_key: String,

    /// Filesystem identifier, 32 hex characters — the key-derivation salt, so
    /// two filesystems under one master secret stay independent.
    ///
    /// Supplied rather than read from the store: the keys that verify a root
    /// record derive from it, so taking it from the store would mean trusting
    /// the store to say which key checks its own signature.
    #[arg(
        long,
        env = "S3FS_ID",
        default_value = "00000000000000000000000000000000"
    )]
    fs_id: String,

    /// Refuse to mount a root record older than this sequence number.
    ///
    /// The only defence against a store that hides newer roots at a cold
    /// mount. Everything else about rollback is closed cryptographically; this
    /// one needs a number from outside the store.
    #[arg(long, env = "S3FS_MIN_ROOT_SEQ")]
    min_root_seq: Option<u64>,

    /// Path the guest sees as its preopen root.
    #[arg(long, env = "S3FS_MOUNT_PATH", default_value = "/")]
    mount_path: String,

    /// Key prefix inside both buckets.
    #[arg(long, env = "S3FS_BUCKET_PREFIX", default_value = "")]
    bucket_prefix: String,

    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    region: String,

    /// Endpoint override, e.g. a local MinIO or the parent's vsock proxy.
    #[arg(long, env = "S3FS_ENDPOINT")]
    endpoint: Option<String>,

    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    access_key_id: Option<String>,

    #[arg(long, env = "AWS_SECRET_ACCESS_KEY")]
    secret_access_key: Option<String>,

    #[arg(long, env = "AWS_SESSION_TOKEN")]
    session_token: Option<String>,

    /// Path-style addressing, required by MinIO and many S3-compatibles.
    #[arg(long, env = "S3FS_FORCE_PATH_STYLE", value_parser = enclave_runtime::parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    force_path_style: bool,

    /// Skip the `HeadBucket` startup probe.
    #[arg(long, env = "S3FS_SKIP_BUCKET_PROBE", value_parser = enclave_runtime::parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    skip_bucket_probe: bool,

    /// Give the guest nothing but what `--guest-env` names.
    ///
    /// **Use this when running outside an enclave.** Inheritance is right for
    /// an enclave image, where the environment is curated deployment
    /// configuration; it is wrong on a developer's machine, where it forwards
    /// that machine's whole environment to the guest. The denylist below
    /// withholds this runtime's own credentials, not a `GITHUB_TOKEN` or an
    /// `SSH_AUTH_SOCK`.
    ///
    /// By default it inherits this process's environment minus anything under
    /// `AWS_` or `S3FS_`, which is where the credentials and this runtime's
    /// own configuration live.
    #[arg(long, env = "S3FS_NO_INHERIT_ENV", value_parser = enclave_runtime::parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    no_inherit_env: bool,

    /// Extra variable for the guest, as `NAME` (inherit that one by name) or
    /// `NAME=VALUE`. Applied after inheritance, so it overrides — including
    /// for names that are otherwise withheld. Repeatable, or comma-separated.
    ///
    /// Paired with `--no-inherit-env` this is the explicit model: the guest
    /// gets exactly what is named here and nothing else.
    #[arg(
        long = "guest-env",
        env = "S3FS_GUEST_ENV",
        value_delimiter = ',',
        value_name = "NAME[=VALUE]"
    )]
    guest_env: Vec<String>,

    /// Where the guest's wall-clock time comes from.
    ///
    /// `ptp` reads the Nitro PTP hardware clock and refuses to start without
    /// it. `host` uses the system clock, which inside an enclave is whatever
    /// the hypervisor last set — fine for development, untrusted in
    /// production. `auto` prefers PTP and warns when it falls back.
    ///
    /// An enclave image should set this to `ptp`.
    #[arg(long, env = "S3FS_CLOCK_SOURCE", default_value = "auto",
          value_parser = ClockSource::parse)]
    clock_source: ClockSource,

    /// PTP character device to read.
    #[arg(long, env = "S3FS_PTP_DEVICE", default_value = DEFAULT_PTP_DEVICE)]
    ptp_device: PathBuf,

    /// Where the guest's random bytes come from.
    ///
    /// `nsm` reads the Nitro Security Module and refuses to start without it.
    /// `host` uses the kernel, which inside an enclave is NSM-seeded but says
    /// nothing about it. `auto` prefers NSM and reports a fallback as an error,
    /// because every key the guest generates afterwards rests on the answer.
    ///
    /// An enclave image should set this to `nsm`.
    #[arg(long, env = "S3FS_RANDOM_SOURCE", default_value = "auto",
          value_parser = RandomSource::parse)]
    random_source: RandomSource,

    /// NSM character device to read.
    #[arg(long, env = "S3FS_NSM_DEVICE", default_value = DEFAULT_NSM_DEVICE)]
    nsm_device: PathBuf,

    /// How a state-origin receipt must be trusted.
    ///
    /// `required` demands a signature chaining to the AWS Nitro root.
    /// `unsigned-emulator` reads the contents without checking anything,
    /// because QEMU's emulated NSM does not sign — and because the image's
    /// environment is measured, PCR0 tells a client which of the two an
    /// enclave was built with. A production image never sets it.
    #[arg(long, env = "S3FS_RECEIPT_TRUST", default_value = "required",
          value_parser = ReceiptTrust::parse)]
    receipt_trust: ReceiptTrust,

    /// Seconds a guest may take to produce a response head before the request
    /// is abandoned.
    ///
    /// A guest that neither returns nor answers otherwise hangs forever, and
    /// with one request in flight at a time that is the whole server. Baked
    /// into the image like every other setting, so PCR0 covers it.
    #[arg(long, env = "S3FS_REQUEST_TIMEOUT_SECS", default_value_t = 30)]
    request_timeout_secs: u64,

    /// Whether a guest instance lives one request or many.
    ///
    /// `request` is a handler: fresh memory each time, so nothing survives but
    /// what reached the filesystem. `session` is a process — it keeps its
    /// memory, and that memory is outside everything the store guarantees.
    /// Baked into the image, so PCR0 says which model an enclave runs.
    #[arg(long, env = "S3FS_GUEST_LIFETIME", default_value = "request",
          value_parser = enclave_runtime::GuestLifetime::parse)]
    guest_lifetime: enclave_runtime::GuestLifetime,

    /// Authorise a successor enclave image, by PCR0, then exit.
    ///
    /// Run against the *outgoing* image. It extends PCR31 with the successor's
    /// PCR0 — irreversibly, for this enclave's life — and attests, so the
    /// resulting receipt proves both who wrote it and that they had committed
    /// to this specific successor before doing so.
    #[arg(long, env = "S3FS_AUTHORISE_SUCCESSOR", value_name = "PCR0_HEX")]
    authorise_successor: Option<String>,

    /// Report on the configured clock and entropy source and exit, without
    /// mounting or running anything. For diagnosing a deployment, and the only
    /// thing the emulator harness needs — it touches no storage.
    #[arg(long, alias = "clock-check")]
    self_check: bool,

    /// What kind of guest this is.
    ///
    /// `command` runs a `wasi:cli/command` guest once and exits with its code.
    /// `serve` expects a `wasi:http/proxy` guest and answers HTTP until
    /// stopped. The two are different component worlds, so a guest built for
    /// one will not instantiate under the other.
    #[arg(long, env = "S3FS_MODE", default_value = "command",
          value_parser = parse_mode)]
    mode: Mode,

    /// Address to serve on in `serve` mode.
    ///
    /// Binds every interface by default because inside an enclave the only
    /// interface is the one the parent's proxy reaches, and binding loopback
    /// there would answer nobody.
    #[arg(long, env = "S3FS_HTTP_LISTEN", default_value = "0.0.0.0:8080")]
    http_listen: SocketAddr,

    /// Requests allowed inside the guest at once.
    ///
    /// One by default. The filesystem is safe to share, but a guest is not
    /// necessarily safe to run twice over the same data — SQLite on WASI has
    /// to hold `locking_mode=EXCLUSIVE`, because WASI has no `fcntl` and so no
    /// file locking. Raise it for a guest that keeps no cross-request state.
    #[arg(long, env = "S3FS_HTTP_CONCURRENCY", default_value_t = 1)]
    http_concurrency: usize,

    /// Where the serving certificate comes from.
    ///
    /// `self-signed` generates one at startup, inside the enclave. Browsers
    /// reject it; a client verifying attestation does not care, because the
    /// document binds the certificate to a specific enclave image — a stronger
    /// statement than any CA makes.
    ///
    /// `acme` obtains a browser-trusted certificate from Let's Encrypt over
    /// TLS-ALPN-01, on the same port. It needs `--acme-domain` and outbound
    /// network.
    ///
    /// `off` serves plaintext. Inside an enclave that hands every request to
    /// the parent instance, which is the party this design excludes.
    #[arg(long, env = "S3FS_TLS", default_value = "self-signed",
          value_parser = TlsMode::parse)]
    tls: TlsMode,

    /// Domain to put in the certificate. Repeatable; required for `--tls acme`.
    #[arg(long = "tls-domain", env = "S3FS_TLS_DOMAINS", value_delimiter = ',')]
    tls_domains: Vec<String>,

    /// Contact address registered with the ACME provider, for expiry notices.
    #[arg(
        long = "acme-contact",
        env = "S3FS_ACME_CONTACTS",
        value_delimiter = ','
    )]
    acme_contacts: Vec<String>,

    /// ACME directory URL. Defaults to Let's Encrypt production.
    ///
    /// Point it at staging while setting a deployment up. Production allows
    /// five duplicate certificates per week per domain, and an enclave that
    /// keeps re-issuing will exhaust that and be unable to serve.
    #[arg(long, env = "S3FS_ACME_DIRECTORY")]
    acme_directory: Option<String>,

    /// How the enclave reaches the network.
    ///
    /// `gvproxy` runs the tap forwarder against the parent's gvproxy, which is
    /// the only way an enclave gets an interface at all — it has no NIC, only
    /// vsock. Without it nothing that speaks TCP works: not S3, not ACME, not
    /// even DNS.
    ///
    /// `none` assumes the network is already there, which is true everywhere
    /// except inside an enclave.
    ///
    /// An enclave image should set this to `gvproxy`.
    #[arg(long, env = "S3FS_NETWORK", default_value = "none",
          value_parser = NetworkMode::parse)]
    network: NetworkMode,

    /// The tap forwarder binary, shipped inside the enclave image.
    #[arg(long, env = "S3FS_GVFORWARDER", default_value = DEFAULT_GVFORWARDER)]
    gvforwarder: PathBuf,

    /// Serve `/enclave/attestation` and `/enclave/config`.
    ///
    /// On by default: an enclave nobody can verify is an enclave for nothing.
    /// Turning it off is for running the same image outside one, where the NSM
    /// is absent and startup would otherwise fail.
    #[arg(long, env = "S3FS_ATTESTATION", value_parser = enclave_runtime::parse_bool_flag,
          num_args = 0..=1, default_value_t = true, default_missing_value = "true")]
    attestation: bool,

    /// Arguments passed to the guest.
    #[arg(last = true)]
    guest_args: Vec<String>,
}

impl Cli {
    fn mount_config(&self) -> Result<MountConfig> {
        Ok(MountConfig {
            bucket: self.bucket.clone(),
            roots_bucket: self.roots_bucket.clone(),
            region: self.region.clone(),
            endpoint: self.endpoint.clone(),
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            force_path_style: self.force_path_style,
            bucket_prefix: self.bucket_prefix.clone(),
            mount_path: self.mount_path.clone(),
            fs_id: enclave_runtime::parse_fs_id(&self.fs_id)?,
            min_root_seq: self.min_root_seq,
            skip_bucket_probe: self.skip_bucket_probe,
            request_timeout: Duration::from_secs(30),
        })
    }

    fn env_policy(&self) -> GuestEnvPolicy {
        if self.no_inherit_env {
            GuestEnvPolicy::explicit_only(self.guest_env.clone())
        } else {
            GuestEnvPolicy {
                inherit: true,
                explicit: self.guest_env.clone(),
            }
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();

    match run().await {
        Ok(outcome) => {
            if outcome.is_success() {
                tracing::info!("guest exited successfully");
            } else {
                tracing::warn!(exit_code = outcome.exit_code(), "guest exited non-zero");
            }
            exit_code(outcome.exit_code())
        }
        Err(e) => {
            // A failure before the guest ever started: the filesystem would
            // not mount, or the component would not compile. Distinct from a
            // guest crash, because the responses differ — an integrity or
            // rollback failure here is a security event, not a bug in the
            // guest.
            tracing::error!(
                error = format!("{e:#}"),
                "runtime failed to start the guest"
            );
            exit_code(EXIT_RUNTIME_FAILURE)
        }
    }
}

async fn run() -> Result<enclave_runtime::GuestOutcome> {
    let cli = Cli::parse();

    let clock = open_clock(cli.clock_source, &cli.ptp_device)?;
    let entropy = open_entropy(cli.random_source, &cli.nsm_device)?;
    if cli.self_check {
        clock_check(clock.as_ref())?;
        println!();
        entropy_check(entropy.as_ref())?;
        return Ok(enclave_runtime::GuestOutcome::Success);
    }

    // Before anything that needs a socket. Mounting reaches S3, so a runtime
    // that mounted first would fail with an S3 error that says nothing about
    // the real cause.
    let _network = enclave_runtime::bring_up(&NetworkConfig {
        mode: cli.network,
        gvforwarder: cli.gvforwarder.clone(),
        ..Default::default()
    })?;

    let keys = StaticKey::from_hex(&cli.master_key)?;
    tracing::info!(
        key_source = keys.describe(),
        guest = %cli.guest_path.display(),
        "starting"
    );

    let mount_config = cli.mount_config()?;
    let backends = enclave_runtime::connect(&mount_config).await?;

    // Authorising a successor is not a way to start serving: it extends a PCR
    // irreversibly and writes a receipt, then stops. Doing it in the same
    // process that goes on to serve would mean an enclave running with a
    // register it changed halfway through its own life.
    if let Some(successor) = &cli.authorise_successor {
        let pcr0 = hex::decode(successor.trim())
            .map_err(|_| anyhow::anyhow!("--authorise-successor is not hex"))?;
        enclave_runtime::authorise_successor(&backends, &mount_config, &entropy, &keys, &pcr0)
            .await?;
        return Ok(enclave_runtime::GuestOutcome::Success);
    }

    // Decide whether this enclave is entitled to the state it is about to
    // load, before it loads any of it.
    let booted = enclave_runtime::boot(
        &backends,
        &mount_config,
        &enclave_runtime::BootConfig {
            trust: cli.receipt_trust,
        },
        &entropy,
        &keys,
    )
    .await?;

    tracing::info!(
        mode = ?booted.mode,
        pcr0 = %hex::encode(&booted.pcr0),
        state_root = %hex::encode(booted.state_root),
        "state origin established"
    );

    let mounted = booted.mounted;
    let fs = mounted.fs.clone();

    // Read the guest before building the environment so a missing component —
    // the likeliest misconfiguration inside an image — fails immediately and
    // names the path it looked at.
    let component = read_component(&cli.guest_path)?;

    let env = cli.env_policy().build()?;

    match cli.mode {
        Mode::Command => {
            tracing::info!(
                variables = env.len(),
                args = cli.guest_args.len(),
                "running guest"
            );
            run_component(fs, clock, entropy, &component, &env, &cli.guest_args).await
        }
        Mode::Serve => {
            let (tls, acme) = match cli.tls {
                TlsMode::Off => (None, None),
                TlsMode::SelfSigned => (Some(TlsIdentity::self_signed(&cli.tls_domains)?), None),
                TlsMode::Acme => {
                    let acme = enclave_runtime::serve::acme::start(
                        &AcmeConfig {
                            domains: cli.tls_domains.clone(),
                            contacts: cli.acme_contacts.clone(),
                            directory: cli.acme_directory.clone(),
                            prefix: mounted.bucket_prefix.clone(),
                        },
                        mounted.data.clone(),
                        mounted.keys.clone(),
                    )?;
                    (None, Some(acme))
                }
            };
            tracing::info!(
                variables = env.len(),
                listen = %cli.http_listen,
                tls = ?cli.tls,
                "serving guest"
            );

            let attestation = cli.attestation.then(|| entropy.clone());
            let guest = GuestEnvironment::new(fs, clock, entropy, &env, &cli.guest_args)?;
            serve_component(
                &component,
                guest,
                ServeConfig {
                    addr: cli.http_listen,
                    concurrency: cli.http_concurrency,
                    tls,
                    acme,
                    attestation,
                    request_timeout: Duration::from_secs(cli.request_timeout_secs),
                    lifetime: cli.guest_lifetime,
                },
            )
            .await?;
            // `serve_component` only returns on error; reaching here means the
            // accept loop stopped, which is not a guest exit.
            Ok(enclave_runtime::GuestOutcome::Failed)
        }
    }
}

/// Print what the configured clock actually reports.
///
/// The delta against `CLOCK_REALTIME` is the interesting column: a PTP clock
/// disciplined by an external source and a host clock set by the hypervisor
/// have no reason to agree, and how far apart they are is exactly what this
/// feature exists to expose.
fn clock_check(clock: &dyn enclave_runtime::TrustedClock) -> Result<()> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    println!("clock source: {}", clock.describe());
    println!("resolution:   {:?}", clock.resolution());
    println!();
    println!(
        "  {:<26} {:>16} {:>12}",
        "reading", "vs CLOCK_REALTIME", "read time"
    );

    let mut previous: Option<Duration> = None;
    for _ in 0..5 {
        let started = Instant::now();
        let now = clock.now()?;
        let read_time = started.elapsed();
        let realtime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("host clock before the epoch");

        // Signed skew, in milliseconds.
        let skew_ms = now.as_secs_f64() * 1e3 - realtime.as_secs_f64() * 1e3;

        if let Some(prev) = previous {
            if now < prev {
                anyhow::bail!("clock went backwards: {:?} then {:?}", prev, now);
            }
        }
        previous = Some(now);

        println!(
            "  {:<26} {:>13.3} ms {:>9.1} us",
            format!("{}.{:09}", now.as_secs(), now.subsec_nanos()),
            skew_ms,
            read_time.as_secs_f64() * 1e6
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    println!();
    println!("clock advanced monotonically across 5 readings");
    Ok(())
}

fn exit_code(code: i32) -> std::process::ExitCode {
    // `ExitCode` is a byte; a guest exit code outside that range would wrap
    // silently, so clamp it to something a parent can read unambiguously.
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();
}

/// Report on the entropy source, and apply the crude checks that catch a
/// device returning constants.
///
/// These prove nothing about randomness quality — no cheap test can — but they
/// do catch the failure modes that actually occur: a stub that returns zeros, a
/// buffer never written, a device answering the same block every time. That is
/// exactly how an emulator or a misconfigured driver misbehaves.
fn entropy_check(source: &dyn enclave_runtime::Nsm) -> Result<()> {
    use std::time::Instant;

    println!("entropy source: {}", source.describe());

    let mut first = [0u8; 64];
    let started = Instant::now();
    source.get_random(&mut first)?;
    let first_read = started.elapsed();

    let mut second = [0u8; 64];
    source.get_random(&mut second)?;

    if first.iter().all(|&b| b == 0) {
        anyhow::bail!("entropy source returned all zeros");
    }
    if first.iter().all(|&b| b == first[0]) {
        anyhow::bail!("entropy source returned a constant byte {:#04x}", first[0]);
    }
    if first == second {
        anyhow::bail!("two draws returned identical bytes; the source is not advancing");
    }

    // A byte histogram over a larger sample. Not a randomness test — with 4096
    // samples over 256 buckets the mean is 16, and anything above ~80 in one
    // bucket is a stuck source rather than bad luck.
    let mut bulk = vec![0u8; 4096];
    let bulk_started = Instant::now();
    source.get_random(&mut bulk)?;
    let bulk_read = bulk_started.elapsed();

    let mut histogram = [0u32; 256];
    for &b in &bulk {
        histogram[b as usize] += 1;
    }
    let peak = histogram.iter().copied().max().unwrap_or(0);
    let empty = histogram.iter().filter(|&&c| c == 0).count();
    if peak > 80 {
        anyhow::bail!("byte histogram peaks at {peak} of 4096; the source looks stuck");
    }

    println!(
        "  sample:      {}",
        first[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );
    println!("  histogram:   peak {peak}, {empty} of 256 values unseen (mean 16)");
    println!(
        "  read cost:   {:.1} us for 64 bytes, {:.1} us for 4096",
        first_read.as_secs_f64() * 1e6,
        bulk_read.as_secs_f64() * 1e6
    );
    println!();
    println!("entropy source produced varying, non-constant bytes");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn cli_from(args: &[&str]) -> Cli {
        let mut full = vec!["enclave-runtime"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).expect("parse")
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_guest_path_defaults_to_the_image_location() {
        let cli = cli_from(&["--bucket", "b", "--master-key", &"aa".repeat(32)]);
        assert_eq!(cli.guest_path, PathBuf::from(DEFAULT_GUEST_PATH));
    }

    #[test]
    fn a_flag_overrides_the_environment_default() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-path",
            "/tmp/other.wasm",
        ]);
        assert_eq!(cli.guest_path, PathBuf::from("/tmp/other.wasm"));
    }

    /// The explicit model, which is what `--no-inherit-env` leaves you with:
    /// the guest gets exactly what is named and nothing else. This was
    /// `s3fs-runner`'s whole reason to exist before it was deleted, so it is
    /// tested here rather than assumed.
    #[test]
    fn named_variables_reach_the_guest_when_nothing_is_inherited() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--no-inherit-env",
            "--guest-env",
            "LOG_LEVEL=debug",
        ]);
        assert_eq!(
            cli.env_policy().build().unwrap(),
            vec![("LOG_LEVEL".to_string(), "debug".to_string())]
        );
    }

    /// Repeatable *and* comma-separated, because inside an enclave the setting
    /// arrives as one `S3FS_GUEST_ENV` string and there is nowhere to repeat a
    /// flag from.
    #[test]
    fn guest_env_accepts_a_comma_separated_list() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--no-inherit-env",
            "--guest-env",
            "A=1,B=2",
        ]);
        let env = cli.env_policy().build().unwrap();
        assert_eq!(
            env,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "2".to_string())
            ]
        );
    }

    #[test]
    fn the_bucket_and_master_key_are_required() {
        assert!(Cli::try_parse_from(["enclave-runtime"]).is_err());
        assert!(Cli::try_parse_from(["enclave-runtime", "--bucket", "b"]).is_err());
    }

    #[test]
    fn guest_arguments_come_after_a_separator() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--",
            "arg1",
            "--not-our-flag",
        ]);
        assert_eq!(cli.guest_args, vec!["arg1", "--not-our-flag"]);
    }

    /// The default is inheritance, because a guest that needs configuration
    /// should get it without every variable being enumerated.
    #[test]
    fn the_environment_is_inherited_by_default() {
        let cli = cli_from(&["--bucket", "b", "--master-key", &"aa".repeat(32)]);
        assert!(cli.env_policy().inherit);
    }

    #[test]
    fn no_inherit_env_switches_to_allowlist_only() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--no-inherit-env",
            "--guest-env",
            "RUST_LOG=debug",
        ]);
        let policy = cli.env_policy();
        assert!(!policy.inherit);
        assert_eq!(policy.explicit, vec!["RUST_LOG=debug"]);
    }

    #[test]
    fn an_invalid_filesystem_id_is_rejected_before_anything_is_opened() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--fs-id",
            "not-hex",
        ]);
        assert!(cli.mount_config().is_err());
    }

    #[test]
    fn mount_config_carries_the_settings_through() {
        let cli = cli_from(&[
            "--bucket",
            "data",
            "--roots-bucket",
            "roots",
            "--master-key",
            &"aa".repeat(32),
            "--bucket-prefix",
            "tenant",
            "--min-root-seq",
            "42",
            "--force-path-style",
        ]);
        let cfg = cli.mount_config().unwrap();
        assert_eq!(cfg.bucket, "data");
        assert_eq!(cfg.roots_bucket.as_deref(), Some("roots"));
        assert_eq!(cfg.bucket_prefix, "tenant");
        assert_eq!(cfg.min_root_seq, Some(42));
        assert!(cfg.force_path_style);
    }

    /// `ExitCode` is a byte. A guest exit code outside that range must not
    /// wrap into something a parent would read as success.
    #[test]
    fn out_of_range_exit_codes_do_not_wrap_to_success() {
        assert_eq!(
            format!("{:?}", exit_code(256)),
            format!("{:?}", exit_code(1))
        );
        assert_eq!(
            format!("{:?}", exit_code(-1)),
            format!("{:?}", exit_code(1))
        );
        assert_ne!(
            format!("{:?}", exit_code(256)),
            format!("{:?}", exit_code(0))
        );
    }
}
