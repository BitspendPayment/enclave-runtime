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
//! The master secret comes from `--master-key-source`, which has no default:
//! `kms` mints it inside the enclave and lets KMS release it only against an
//! attestation whose PCR0 matches the key policy, and `static` takes it from
//! configuration for development and for the QEMU harness. Supplying a
//! plaintext key under `kms` is refused rather than ignored — a key in an
//! environment variable is visible to the parent instance, exactly the party
//! an enclave exists to exclude.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use enclave_runtime::{
    open_clock, open_entropy, read_component, serve_component, AcmeConfig, ClockSource,
    GuestEnvPolicy, GuestEnvironment, MasterKeySource, MountConfig, NetworkConfig, NetworkMode,
    RandomSource, ReceiptTrust, ServeConfig, TlsMode, DEFAULT_GVFORWARDER, DEFAULT_NSM_DEVICE,
    DEFAULT_PTP_DEVICE, EXIT_RUNTIME_FAILURE,
};

/// Where the guest lives inside the enclave image.
const DEFAULT_GUEST_PATH: &str = "/enclave/guest.wasm";

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

    /// Where the master secret comes from.
    ///
    /// `kms` mints it inside the enclave and lets KMS release it only against
    /// an attestation whose PCR0 matches the key policy — so a wrong image
    /// gets no key at all, rather than a refused mount. `static` takes it from
    /// `--master-key` and stores it unsealed; it exists for development and
    /// for the QEMU harness, whose emulated NSM cannot produce a document KMS
    /// would accept.
    ///
    /// No default. This is the one setting that should never be inherited by
    /// omission, and because the image environment is measured, PCR0 records
    /// which of the two an enclave was built with.
    #[arg(long, env = "S3FS_MASTER_KEY_SOURCE",
          value_parser = enclave_runtime::MasterKeySourceKind::parse)]
    master_key_source: enclave_runtime::MasterKeySourceKind,

    /// 32-byte master secret, hex encoded. **`--master-key-source=static` only.**
    ///
    /// Supplying it under `kms` is refused rather than ignored: a key from
    /// configuration is a key the parent instance holds, which is precisely
    /// what KMS release exists to prevent.
    #[arg(long, env = "S3FS_MASTER_KEY")]
    master_key: Option<String>,

    /// The customer master key that releases this filesystem's secret. Its
    /// policy — `kms:RecipientAttestation:PCR0` — is the security control.
    #[arg(long, env = "S3FS_KMS_KEY_ID")]
    kms_key_id: Option<String>,

    /// SSM parameter holding the KMS ciphertext, and nothing else.
    #[arg(long, env = "S3FS_MASTER_KEY_PARAMETER")]
    master_key_parameter: Option<String>,

    /// Deployment name, mixed into the KMS encryption context alongside the
    /// filesystem id — so a staging enclave cannot open a production
    /// filesystem even when pointed at the same parameter.
    #[arg(long, env = "S3FS_ENVIRONMENT", default_value = "production")]
    environment: String,

    /// Endpoint overrides for KMS and SSM, separate from `--endpoint`.
    ///
    /// S3's override points at MinIO in development; a MinIO endpoint is not a
    /// KMS endpoint, and reusing it would fail in a way that reads like a
    /// credentials problem.
    #[arg(long, env = "S3FS_KMS_ENDPOINT")]
    kms_endpoint: Option<String>,

    #[arg(long, env = "S3FS_SSM_ENDPOINT")]
    ssm_endpoint: Option<String>,

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

    /// Seconds one S3 request may take, before the SDK's retries.
    ///
    /// Its own setting rather than a reuse of `--request-timeout-secs`, which
    /// bounds how long a *guest* may take: tuning how long a guest may think
    /// should not silently change how long a slab read may take, and the two
    /// have no reason to move together.
    ///
    /// It has to be a setting at all because an enclave has no shell. Thirty
    /// seconds is a guess, and a slow endpoint or a large slab is exactly the
    /// case where a guess is wrong — with the symptom being a mount that never
    /// returns rather than an error that names S3.
    #[arg(long, env = "S3FS_S3_TIMEOUT_SECS", default_value_t = 30)]
    s3_timeout_secs: u64,

    #[arg(long, env = "S3FS_GUEST_LOG_GROUP")]
    guest_log_group: Option<String>,

    /// The stream within `--guest-log-group`. Required alongside it.
    #[arg(long, env = "S3FS_GUEST_LOG_STREAM")]
    guest_log_stream: Option<String>,

    /// Point the CloudWatch client somewhere else. For tests.
    ///
    /// A downgrade path, and worth naming as one: aimed at an `http://`
    /// endpoint it hands guest output to whatever is listening, in clear. That
    /// is tolerable only because this is baked into the image, so PCR0 records
    /// which was built.
    #[arg(long, env = "S3FS_GUEST_LOG_ENDPOINT")]
    guest_log_endpoint: Option<String>,

    /// Clients kept warm at once.
    ///
    /// A warm client costs a wasm linear memory and nothing else — the
    /// filesystem and its block cache are shared — so this bounds instance
    /// memory rather than cache memory. Past it, the least recently used idle
    /// client is dropped; one serving a request is never evicted.
    #[arg(long, env = "S3FS_MAX_TENANTS", default_value_t = 64)]
    max_tenants: usize,

    /// Seconds a mounted client may sit idle before it is dropped.
    #[arg(long, env = "S3FS_TENANT_IDLE_SECS", default_value_t = 900)]
    tenant_idle_secs: u64,

    /// Requests one client's instance serves before it is rebuilt.
    ///
    /// Wasm linear memory never shrinks, so an instance that lived forever
    /// would only grow. Rebuilding costs ~24 µs and keeps the mount, which is
    /// the part that costs S3 round trips.
    #[arg(long, env = "S3FS_MAX_REQUESTS_PER_INSTANCE", default_value_t = 10_000)]
    max_requests_per_instance: u64,

    /// The WebAuthn relying-party id — the domain passkeys are scoped to.
    ///
    /// Setting it, with `--webauthn-origin`, is what turns authentication on:
    /// **every request that could reach the guest then needs a fresh assertion
    /// bound to exactly that request.** Left unset the runtime serves the guest
    /// to anyone who can open a connection, which is a development and QEMU
    /// arrangement and is warned about at startup.
    ///
    /// Must match the domain the app is scoped to, and production needs
    /// browser-trusted TLS on it — see `--tls acme`. Baked into the image, so
    /// PCR0 records which relying party an enclave will accept assertions for.
    #[arg(long, env = "S3FS_WEBAUTHN_RP_ID")]
    webauthn_rp_id: Option<String>,

    /// The exact origin assertions must claim, e.g. `https://cosigner.example.com`.
    ///
    /// Compared exactly, not by suffix: a page on another origin must not be
    /// able to borrow a user's passkey for this one.
    #[arg(long, env = "S3FS_WEBAUTHN_ORIGIN")]
    webauthn_origin: Option<String>,

    /// Seconds a challenge is good for.
    ///
    /// Long enough for a person to look at a prompt and present a finger,
    /// short enough that a captured assertion is stale before it can be used.
    #[arg(long, env = "S3FS_CHALLENGE_TTL_SECS", default_value_t = 60)]
    challenge_ttl_secs: u64,

    /// Seconds an interaction token is good for before it is spent.
    ///
    /// This bounds the time to *start* an interaction — a person who approves
    /// something and then puts their phone down should not find the approval
    /// still live later. It is not how long an interaction may run.
    #[arg(long, env = "S3FS_INTERACTION_TOKEN_TTL_SECS", default_value_t = 60)]
    interaction_token_ttl_secs: u64,

    /// Seconds an interaction may run once started.
    ///
    /// The other half of the distinction: a stream holds its tenant's single
    /// slot for its whole life, so this is what bounds how long that tenant's
    /// next request waits. Enforced by wall clock, because a guest parked in a
    /// host call executes no wasm and the epoch cannot see it.
    #[arg(long, env = "S3FS_MAX_INTERACTION_SECS", default_value_t = 300)]
    max_interaction_secs: u64,

    /// Single-use enrollment tokens, seeded at boot if not already there.
    /// Repeatable, or comma-separated.
    ///
    /// It authorizes **creating a tenant** and nothing else: it cannot reach
    /// an existing tenant's data, approve a transaction, or add a passkey to
    /// somebody else's account. That matters because inside an enclave this
    /// value reaches the runtime through the parent instance — the party the
    /// enclave exists to exclude. A parent that steals it can make a tenant of
    /// its own; it still cannot read anyone else's.
    #[arg(
        long = "enrollment-token",
        env = "S3FS_ENROLLMENT_TOKEN",
        value_delimiter = ','
    )]
    enrollment_tokens: Vec<String>,

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

    /// Address to serve on in `serve` mode.
    ///
    /// Binds every interface by default because inside an enclave the only
    /// interface is the one the parent's proxy reaches, and binding loopback
    /// there would answer nobody.
    #[arg(long, env = "S3FS_HTTP_LISTEN", default_value = "0.0.0.0:8080")]
    http_listen: SocketAddr,

    /// Where the serving certificate comes from.
    ///
    /// `acme`, the default, obtains one from Let's Encrypt over TLS-ALPN-01 on
    /// the same port. It needs `--tls-domain` and outbound network. The key is
    /// generated inside the enclave and never leaves it; what the CA signs is
    /// what every response's attestation document binds.
    ///
    /// `off` serves plaintext. Inside an enclave that hands every request to
    /// the parent instance, which is the party this design excludes.
    ///
    /// There is deliberately no self-signed mode at all: a certificate an
    /// operator can mint is one they can mint for an impostor too, and it buys
    /// nothing the attestation binding does not already give. A deployment with
    /// no public CA points `--acme-directory` at a private one instead.
    #[arg(long, env = "S3FS_TLS", default_value = "acme",
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

    /// PEM trust root for the ACME directory's own HTTPS certificate.
    ///
    /// **Only in a `testing` build.** A real CA serves its API under a
    /// publicly-trusted certificate and needs nothing here; a test CA like
    /// Pebble does not, so the QEMU harness supplies its root. A production
    /// enclave has no such flag, because one that took issuance orders from a
    /// CA of the operator's choosing would be a different trust model than the
    /// one this image claims.
    #[cfg(any(test, feature = "testing"))]
    #[arg(long, env = "S3FS_ACME_CA")]
    acme_ca: Option<PathBuf>,

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

    /// Arguments passed to the guest.
    #[arg(last = true)]
    guest_args: Vec<String>,
}

impl Cli {
    /// Where guest output goes, beyond the console.
    ///
    /// A group without a stream is refused here rather than at the first write:
    /// it needs no I/O to know it is wrong, and the same discipline as
    /// `--webauthn-rp-id`/`--webauthn-origin`. Everything that *does* need the
    /// network is decided at startup instead, where a transient failure can be
    /// told apart from a mistake.
    fn guest_log_config(&self) -> Result<Option<enclave_runtime::CloudWatchConfig>> {
        // Empty means off, not malformed. The image environment is layered —
        // the QEMU image inherits production's and overrides what it cannot
        // use — and setting a variable to "" is how that layer says "not this
        // one". Treating it as a typo would make the override impossible.
        let group = self
            .guest_log_group
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty());
        let stream = self
            .guest_log_stream
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (group, stream) {
            (None, None) => Ok(None),
            (Some(group), Some(stream)) => Ok(Some(enclave_runtime::CloudWatchConfig {
                log_group: group.to_string(),
                log_stream: stream.to_string(),
                region: self.region.clone(),
                endpoint: self.guest_log_endpoint.clone(),
            })),
            _ => anyhow::bail!(
                "--guest-log-group and --guest-log-stream must be given together. \
                 This runtime holds `logs:PutLogEvents` and nothing more, so it cannot \
                 create a stream it was not told the name of."
            ),
        }
    }

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
            request_timeout: Duration::from_secs(self.s3_timeout_secs),
        })
    }

    fn master_key_config(&self) -> Result<enclave_runtime::MasterKeyConfig> {
        Ok(enclave_runtime::MasterKeyConfig {
            kind: self.master_key_source,
            master_key: self.master_key.clone(),
            kms_key_id: self.kms_key_id.clone(),
            parameter: self.master_key_parameter.clone(),
            environment: self.environment.clone(),
            fs_id: enclave_runtime::parse_fs_id(&self.fs_id)?,
            region: self.region.clone(),
            kms_endpoint: self.kms_endpoint.clone(),
            ssm_endpoint: self.ssm_endpoint.clone(),
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
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

    let keys = enclave_runtime::open_key_source(&cli.master_key_config()?, entropy.clone())?;
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

    /// The ACME directory's trust root, if this build can have one.
    ///
    /// Two definitions rather than a runtime branch: a production binary has no
    /// `--acme-ca` field to read, so the public roots are not something a
    /// deployment can talk it out of.
    #[cfg(any(test, feature = "testing"))]
    fn acme_directory_ca(cli: &Cli) -> anyhow::Result<Option<Vec<u8>>> {
        match &cli.acme_ca {
            Some(path) => Ok(Some(anyhow::Context::with_context(
                std::fs::read(path),
                || format!("reading the ACME directory trust root {}", path.display()),
            )?)),
            None => Ok(None),
        }
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn acme_directory_ca(_cli: &Cli) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    // One certificate source, or none. There is no third: a certificate the
    // runtime minted for itself would be one an operator could mint too.
    let acme = match cli.tls {
        TlsMode::Off => None,
        TlsMode::Acme => Some(enclave_runtime::serve::acme::start(
            &AcmeConfig {
                domains: cli.tls_domains.clone(),
                contacts: cli.acme_contacts.clone(),
                directory: cli.acme_directory.clone(),
                directory_ca: acme_directory_ca(&cli)?,
                prefix: mounted.bucket_prefix.clone(),
            },
            mounted.data.clone(),
            mounted.keys.clone(),
        )?),
    };
    tracing::info!(
        variables = env.len(),
        listen = %cli.http_listen,
        tls = ?cli.tls,
        "serving guest"
    );

    // Not a choice. An enclave nobody can verify is an enclave for nothing, and
    // a flag that turns verification off is a flag that can be turned off by
    // whoever starts the process — which inside an enclave is the party the
    // enclave exists to exclude.
    let attestation = Some(entropy.clone());

    // Per-client views of the one filesystem. Each client's guest sees
    // its own directory as `/`; the mount, the block cache and the
    // transaction stream are shared, so a client costs a directory
    // rather than a mount.
    //
    // A client is serialised against itself and nobody else, so two
    // clients can execute guest code at the same time. A guest is
    // written for that; it is not a deployment decision.
    let tenancy = {
        let limits = enclave_runtime::PoolLimits {
            max_tenants: cli.max_tenants,
            idle_timeout: Duration::from_secs(cli.tenant_idle_secs),
            max_requests_per_instance: cli.max_requests_per_instance,
        };
        tracing::info!(
            max_tenants = limits.max_tenants,
            "serving each client its own directory of the filesystem"
        );
        Some(std::sync::Arc::new(enclave_runtime::Tenancy::new(limits)))
    };

    // WebAuthn, when the deployment named a relying party. Both the
    // id and the origin or neither: a gate with no origin to compare
    // against would accept assertions from any page that could reach
    // it.
    let authentication = match (&cli.webauthn_rp_id, &cli.webauthn_origin) {
        (Some(rp_id), Some(origin)) => {
            let credentials =
                std::sync::Arc::new(enclave_runtime::FilesystemCredentials::new(fs.clone()));
            let gate = std::sync::Arc::new(enclave_runtime::Gate::new(
                enclave_runtime::build_relying_party(rp_id, origin)?,
                enclave_runtime::ChallengeStore::new(
                    Duration::from_secs(cli.challenge_ttl_secs),
                    enclave_runtime::DEFAULT_CAPACITY,
                ),
                credentials.clone(),
                enclave_runtime::TokenStore::new(
                    Duration::from_secs(cli.interaction_token_ttl_secs),
                    enclave_runtime::DEFAULT_TOKEN_CAPACITY,
                ),
            ));
            let auth = std::sync::Arc::new(enclave_runtime::AuthEndpoints::new(
                gate.clone(),
                credentials,
                fs.clone(),
                entropy.clone(),
            ));
            for token in &cli.enrollment_tokens {
                auth.enrollment().seed(token).await?;
            }
            if !cli.enrollment_tokens.is_empty() {
                tracing::info!(
                    tokens = cli.enrollment_tokens.len(),
                    "enrollment tokens are available"
                );
            }
            tracing::info!(rp_id, origin, "requiring a passkey assertion per request");
            Some((auth, gate))
        }
        (None, None) => None,
        _ => anyhow::bail!(
            "--webauthn-rp-id and --webauthn-origin must be given together. A gate \
             with no origin to compare against would accept an assertion from any \
             page that could reach it."
        ),
    };

    // The console always, and CloudWatch alongside it when configured.
    // Additive on purpose: the console is often the only thing working
    // while a deployment is being brought up, and the destination that
    // needs the network is exactly the part that may not be.
    //
    // TracingLogSink first, so console output is never queued behind
    // the network sink.
    let mut sinks: Vec<std::sync::Arc<dyn enclave_runtime::GuestLogSink>> =
        vec![std::sync::Arc::new(enclave_runtime::TracingLogSink)];
    let mut log_forwarder = None;

    if let Some(config) = cli.guest_log_config()? {
        // Which image is writing to this stream. A fixed stream name is
        // shared by every boot and every image, so without this nothing
        // in it says which enclave produced which line.
        let image = attestation
            .as_ref()
            .and_then(|nsm| match nsm.describe_pcr(0) {
                Ok(pcr) => Some(hex::encode(pcr.value)),
                Err(e) => {
                    tracing::warn!(error = %e, "could not read PCR0 for the guest log stream");
                    None
                }
            });

        // Bounded, like everything else on this path. Building the
        // client resolves a credential provider, and that reaches IMDS
        // through gvproxy — a path this deployment has not verified. A
        // logging client must never be what decides whether the enclave
        // binds its listener.
        let destination: Option<std::sync::Arc<dyn enclave_runtime::LogDestination>> =
            match tokio::time::timeout(
                enclave_runtime::STARTUP_PROBE_TIMEOUT,
                enclave_runtime::CloudWatchDestination::connect(&config),
            )
            .await
            {
                Ok(destination) => Some(std::sync::Arc::new(destination)),
                Err(_) => {
                    tracing::error!(
                        timeout = ?enclave_runtime::STARTUP_PROBE_TIMEOUT,
                        log_group = %config.log_group,
                        "could not build a CloudWatch client in time; guest output \
                         stays on the console only. Check that the enclave can reach \
                         IMDS through gvproxy."
                    );
                    None
                }
            };

        // The boot marker is the probe. A definitive refusal — the
        // stream is not there, or this identity may not write to it —
        // stops the boot: it is a deployment mistake, and discovering
        // it only from a console line that was meant to be shipped off
        // the box would mean running blind indefinitely. Anything
        // transient does not stop the boot, because CloudWatch having a
        // bad day must not be a cosigner outage.
        if let Some(destination) = destination {
            // Carried to the forwarder when the probe did not manage to
            // write it, so a stream that recovers still ends up saying
            // which image is writing to it. `None` once it is written.
            let mut marker = None;
            match enclave_runtime::open_guest_log_stream(
                &destination,
                image.as_deref(),
                &config.region,
            )
            .await
            {
                Ok(()) => tracing::info!(
                    log_group = %config.log_group,
                    log_stream = %config.log_stream,
                    image = image.as_deref().unwrap_or("(unknown)"),
                    "guest output is going to CloudWatch"
                ),
                Err(enclave_runtime::PutError::Definitive(e)) => anyhow::bail!(
                    "guest logging is configured for {}/{} but that destination refused \
                 us: {e}. The log group and stream must exist and this enclave's \
                 credentials must carry logs:PutLogEvents for them. Leave \
                 --guest-log-group unset for console-only logging.",
                    config.log_group,
                    config.log_stream,
                ),
                Err(enclave_runtime::PutError::Transient(e)) => {
                    tracing::warn!(
                        error = %e,
                        log_group = %config.log_group,
                        "could not reach CloudWatch at startup; guest logs will retry"
                    );
                    marker = Some(enclave_runtime::guest_log_boot_marker(
                        image.as_deref(),
                        &config.region,
                    ));
                }
            }

            let (sink, forwarder) = enclave_runtime::start_guest_log_forwarder(destination, marker);
            sinks.push(std::sync::Arc::new(sink));
            log_forwarder = Some(forwarder);
        }
    }

    // Before the listener binds, so no request can produce guest output
    // before there is a task consuming it. Held for the server's
    // lifetime and drained explicitly below.
    let (guest_logs, log_collector) = enclave_runtime::guest_io::start(std::sync::Arc::new(
        enclave_runtime::FanOutSink::new(sinks),
    ));

    let guest = GuestEnvironment::new(fs, clock, entropy, &env, &cli.guest_args, guest_logs)?;
    let served = serve_component(
        &component,
        guest,
        ServeConfig {
            addr: cli.http_listen,
            certificate: None,
            acme,
            attestation,
            request_timeout: Duration::from_secs(cli.request_timeout_secs),
            max_interaction: Duration::from_secs(cli.max_interaction_secs),
            tenancy,
            authentication,
        },
    )
    .await;
    // Drained whether the accept loop stopped cleanly or failed, and
    // on a bounded deadline — a log that will not flush must not be
    // what keeps an enclave from stopping.
    log_collector.shutdown().await;
    // After the collector, so records it was still holding reach the
    // forwarder before the forwarder is asked to flush. Both deadlines
    // are bounded; neither can hold the enclave open.
    if let Some(forwarder) = log_forwarder {
        forwarder.shutdown().await;
    }
    served?;
    // `serve_component` only returns on error; reaching here means the
    // accept loop stopped, which is not a guest exit.
    Ok(enclave_runtime::GuestOutcome::Failed)
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
        // Targets are shown, and that is not cosmetic. The console carries the
        // runtime's own events *and* whatever a guest chose to write, and the
        // target is the one thing separating them that a guest cannot
        // influence — see `enclave_runtime::guest_io`. Guest lines say
        // `guest`; everything else names a module in this runtime. Hiding it
        // was right when every line was the runtime's own; it stopped being
        // right when untrusted text started sharing the same console.
        //
        // `RUST_LOG=guest=warn` filters guest output independently either way,
        // but an operator reading the console should not have to know that to
        // tell which lines are trustworthy.
        .with_target(true)
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

    /// The minimum a parse needs, so a test can say only what it is about.
    ///
    /// `--master-key-source` is here because it has no default and never
    /// should: an enclave's key handling is not something to inherit by
    /// omission. Tests that care which source is chosen pass their own.
    fn cli_from(args: &[&str]) -> Cli {
        let mut full = vec!["enclave-runtime", "--master-key-source", "static"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).expect("parse")
    }

    /// The S3 timeout is its own setting, and reaches the mount config. It
    /// used to be hardcoded here *and* ignored by the backend, so neither half
    /// of the path worked.
    #[test]
    fn the_s3_timeout_is_configurable_and_separate_from_the_guest_one() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--s3-timeout-secs",
            "9",
            "--request-timeout-secs",
            "45",
        ]);
        assert_eq!(
            cli.mount_config().expect("valid").request_timeout,
            Duration::from_secs(9)
        );
        // Changing the guest deadline must not move the S3 one.
        assert_eq!(cli.request_timeout_secs, 45);
    }

    /// Console-only is the default, and takes no client and no credentials.
    #[test]
    fn guest_logging_is_console_only_unless_configured() {
        let cli = cli_from(&["--bucket", "b", "--master-key", &"aa".repeat(32)]);
        assert!(cli.guest_log_config().expect("valid").is_none());
    }

    /// An empty setting means off, not malformed.
    ///
    /// The image environment is layered: the QEMU image inherits production's
    /// and sets what it cannot use to "". Treating that as a typo made the
    /// harness enclave refuse to boot, which is how this rule was learned.
    #[test]
    fn an_empty_setting_turns_guest_logging_off() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-log-group",
            "",
            "--guest-log-stream",
            "",
        ]);
        assert!(
            cli.guest_log_config()
                .expect("empty is off, not an error")
                .is_none(),
            "an empty group should mean console-only"
        );
    }

    /// Half a destination is a typo, and knowable without touching the network.
    #[test]
    fn a_log_group_without_a_stream_is_refused() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-log-group",
            "/enclave/guest",
        ]);
        let error = cli.guest_log_config().unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("--guest-log-stream"), "{message}");

        // And the other way round.
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-log-stream",
            "guest",
        ]);
        assert!(cli.guest_log_config().is_err());
    }

    #[test]
    fn a_configured_destination_carries_the_settings_through() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--region",
            "eu-west-2",
            "--guest-log-group",
            "/enclave/guest",
            "--guest-log-stream",
            "guest",
            "--guest-log-endpoint",
            "http://127.0.0.1:4566",
        ]);
        let config = cli.guest_log_config().expect("valid").expect("configured");
        assert_eq!(config.log_group, "/enclave/guest");
        assert_eq!(config.log_stream, "guest");
        assert_eq!(config.region, "eu-west-2");
        assert_eq!(config.endpoint.as_deref(), Some("http://127.0.0.1:4566"));
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
    fn the_bucket_and_key_source_are_required() {
        assert!(Cli::try_parse_from(["enclave-runtime"]).is_err());
        assert!(Cli::try_parse_from(["enclave-runtime", "--bucket", "b"]).is_err());
        // A bucket without a key source is not enough: there is no default,
        // and picking one would mean guessing at how the enclave gets its key.
        assert!(Cli::try_parse_from([
            "enclave-runtime",
            "--bucket",
            "b",
            "--master-key",
            &"ab".repeat(32),
        ])
        .is_err());
    }

    fn key_config(args: &[&str]) -> Result<enclave_runtime::MasterKeyConfig> {
        let mut full = vec!["--bucket", "b"];
        full.extend_from_slice(args);
        Cli::try_parse_from(std::iter::once("enclave-runtime").chain(full.iter().copied()))
            .expect("parse")
            .master_key_config()
    }

    fn source_error(args: &[&str]) -> String {
        let config = key_config(args).expect("config");
        let nsm = std::sync::Arc::new(nitro_nsm::fake::FakeNsm::new());
        format!(
            "{:#}",
            enclave_runtime::open_key_source(&config, nsm)
                .expect_err("this combination must be refused")
        )
    }

    /// The refusal that matters most. A production image that still carried
    /// `S3FS_MASTER_KEY` would work perfectly — quietly taking its key from
    /// the parent instance, which is the whole thing KMS release prevents.
    #[test]
    fn a_plaintext_key_is_refused_under_kms() {
        let err = source_error(&[
            "--master-key-source",
            "kms",
            "--kms-key-id",
            "arn:aws:kms:eu-west-2:1:key/a",
            "--master-key-parameter",
            "/p",
            "--master-key",
            &"ab".repeat(32),
        ]);
        assert!(err.contains("refused"), "unexpected error: {err}");
    }

    /// The mirror image: KMS settings under `static` mean one of the two is
    /// not what was meant, and there is no safe way to guess which.
    #[test]
    fn kms_settings_are_refused_under_static() {
        let err = source_error(&[
            "--master-key-source",
            "static",
            "--master-key",
            &"ab".repeat(32),
            "--kms-key-id",
            "arn:aws:kms:eu-west-2:1:key/a",
        ]);
        assert!(err.contains("alongside KMS settings"), "unexpected: {err}");
    }

    #[test]
    fn each_source_names_the_setting_it_is_missing() {
        assert!(source_error(&["--master-key-source", "static"]).contains("--master-key"));
        assert!(source_error(&["--master-key-source", "kms"]).contains("--kms-key-id"));
        assert!(source_error(&[
            "--master-key-source",
            "kms",
            "--kms-key-id",
            "arn:aws:kms:eu-west-2:1:key/a",
        ])
        .contains("--master-key-parameter"));
    }

    /// Warm clients are bounded by default. Each costs a wasm linear memory,
    /// so an unbounded pool is an enclave that dies of memory exhaustion under
    /// the load it was built for.
    #[test]
    fn the_warm_client_count_is_bounded_by_default() {
        let cli = cli_from(&["--bucket", "b"]);
        assert_eq!(cli.max_tenants, 64);
        assert!(cli.tenant_idle_secs > 0, "idle tenants are never reclaimed");
    }

    /// The encryption context is built from the filesystem id and the
    /// environment, so it is the same at mint and at open by construction.
    #[test]
    fn the_key_config_carries_the_encryption_context_inputs() {
        let config = key_config(&[
            "--master-key-source",
            "kms",
            "--fs-id",
            &"cd".repeat(16),
            "--environment",
            "staging",
        ])
        .expect("config");
        assert_eq!(config.environment, "staging");
        assert_eq!(config.fs_id, [0xcd; 16]);
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
