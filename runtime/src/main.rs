//! `enclave-runtime` — run a Wasm guest against the Merkle-anchored
//! filesystem, inside an AWS Nitro Enclave.
//!
//! An enclave has no shell, no config file, and no operator to type flags at
//! it. It gets whatever the enclave image baked in, so **every setting reads
//! from an environment variable**, with a matching flag that wins if present.
//! `ENV` lines in the image's Dockerfile are the deployment configuration; the
//! flags exist so the same binary stays drivable by hand while developing.
//!
//! The guest component is **not** in the image. The runtime fetches it at boot
//! from `--guest-object`, a key in the roots bucket, then measures it into PCR16
//! and locks that register before it asks KMS for anything — see
//! [`enclave_runtime::guest`]. PCR0 covers the runtime and *where* the guest
//! comes from; PCR16 covers *what* arrived. A key policy pinning both releases
//! the filesystem key to exactly this runtime running exactly this guest, so an
//! attestation still says which code will read the data — and changing the
//! guest is a policy edit rather than an image rebuild.
//!
//! Argument parsing over [`enclave_runtime`], which is the same crate: the
//! library half is everything below this file, and lives beside it rather than
//! inside it so integration tests can reach it.
//!
//! The master secret comes from `--master-key-source`, which has no default:
//! `kms` mints it inside the enclave and lets KMS release it only against an
//! attestation whose PCR0 and PCR16 match the key policy, and `static` takes it from
//! configuration for development and for the QEMU harness. Supplying a
//! plaintext key under `kms` is refused rather than ignored — a key in an
//! environment variable is visible to the parent instance, exactly the party
//! an enclave exists to exclude.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;
use enclave_runtime::{
    open_clock, open_entropy, serve_component, AcmeConfig, ClockSource, GuestEnvPolicy,
    GuestEnvironment, GuestSource, MasterKeySource, MountConfig, NetworkConfig, NetworkMode,
    RandomSource, ReceiptTrust, ServeConfig, TlsMode, DEFAULT_GVFORWARDER, DEFAULT_NSM_DEVICE,
    DEFAULT_PTP_DEVICE, EXIT_RUNTIME_FAILURE,
};

/// Where the FCM credential comes from, once the settings have been checked.
enum FcmCredential {
    /// Already parsed, because it was supplied literally and parsing it needed
    /// nothing but the bytes.
    Account(Box<enclave_runtime::ServiceAccount>),
    /// A name to resolve against SSM, once there is a network.
    Parameter(String),
}

/// Notification settings, as far as they can be decided without I/O.
struct NotifySettings {
    project_id: String,
    credential: FcmCredential,
    endpoint: Option<String>,
}

/// Read a parameter, decrypting a SecureString if that is what it is.
///
/// Its own small client rather than the one `keys` builds: that one is
/// configured from a `MasterKeyConfig` and exists to fetch a KMS ciphertext,
/// and threading an unrelated credential through it would tie two things
/// together that have no reason to change at the same time.
async fn read_ssm_parameter(cli: &Cli, name: &str) -> Result<String> {
    use aws_sdk_ssm::config::{BehaviorVersion, Credentials, Region};

    let region = Region::new(cli.region.clone());
    let mut builder = aws_sdk_ssm::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(region.clone())
        // Bounded, because this runs before the listener binds. A parameter
        // store that accepts a connection and then says nothing would mean an
        // enclave that never serves at all.
        .timeout_config(
            aws_sdk_ssm::config::timeout::TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(3))
                .build(),
        );
    if let Some(endpoint) = &cli.ssm_endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    // Static credentials when they were configured, and the default chain
    // otherwise — which inside an enclave reaches the parent's instance role
    // through gvproxy. Naming one is not optional: `Config::builder()` starts
    // empty and resolves neither on its own, so leaving this out is not a
    // default, it is no credentials at all.
    builder = match (
        cli.access_key_id.as_deref(),
        cli.secret_access_key.as_deref(),
    ) {
        (Some(akid), Some(sak)) => builder.credentials_provider(Credentials::new(
            akid,
            sak,
            cli.session_token.clone(),
            None,
            "s3fs-static",
        )),
        _ => builder.credentials_provider(
            aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                .region(region)
                .build()
                .await,
        ),
    };
    let client = aws_sdk_ssm::Client::from_conf(builder.build());
    let response = client
        .get_parameter()
        .name(name)
        .with_decryption(true)
        .send()
        .await
        .with_context(|| format!("reading SSM parameter {name}"))?;
    response
        .parameter()
        .and_then(|p| p.value())
        .map(str::to_string)
        .with_context(|| format!("SSM parameter {name} has no value"))
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Run a Wasm guest against a Merkle-anchored S3 filesystem",
    long_about = None
)]
struct Cli {
    /// Enable durable background tasks. Requires authentication and a guest
    /// exporting run-task from enclave:tasks/background@0.1.0.
    #[arg(long, env = "S3FS_BACKGROUND_TASKS", default_value = "false", value_parser = enclave_runtime::parse_bool_flag, action = clap::ArgAction::Set)]
    background_tasks: bool,
    #[arg(long, env = "S3FS_BACKGROUND_CONCURRENCY", default_value_t = 1)]
    background_concurrency: usize,
    #[arg(long, env = "S3FS_BACKGROUND_TIMEOUT_SECS", default_value_t = 30)]
    background_timeout_secs: u64,
    #[arg(long, env = "S3FS_BACKGROUND_MAX_RECORDS", default_value_t = 1024)]
    background_max_records: usize,
    #[arg(long, env = "S3FS_BACKGROUND_PER_TENANT", default_value_t = 64)]
    background_per_tenant: usize,

    /// Guest component to run, as a key in the roots bucket. What an enclave
    /// image uses.
    ///
    /// Fetched at boot, measured into PCR16 and locked before any key is asked
    /// for. The key is baked into the image, so PCR0 covers where the guest
    /// comes from; PCR16 covers what arrived. The object itself need not be
    /// trusted: a substituted one measures to a different PCR16, which a key
    /// policy pinning the approved guest releases nothing to.
    #[arg(long, env = "S3FS_GUEST_OBJECT")]
    guest_object: Option<String>,

    /// Guest component to run, from a local file. For development and tests,
    /// and measured exactly as an object is. Give this or `--guest-object`.
    #[arg(long, env = "S3FS_GUEST_PATH")]
    guest_path: Option<PathBuf>,

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
    /// an attestation whose PCR0 and PCR16 match the key policy — so a wrong
    /// image or a wrong guest gets no key at all, rather than a refused mount.
    /// `static` takes it from `--master-key` and stores it unsealed; it exists
    /// for development and for the QEMU harness, whose emulated NSM cannot
    /// produce a document KMS would accept.
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
    /// policy — `kms:RecipientAttestation:PCR0` and `:PCR16`, on both
    /// `GenerateDataKey` and `Decrypt` — is the security control.
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

    /// The Firebase project wake signals are sent for.
    ///
    /// Empty means notifications are off — the same layering rule the guest
    /// log settings follow, so an image can carry the setting and a deployment
    /// can blank it.
    #[arg(long, env = "S3FS_FCM_PROJECT_ID")]
    fcm_project_id: Option<String>,

    /// The service-account JSON itself. Development and local runs.
    ///
    /// Inside an enclave this arrives through the parent instance, which is the
    /// party the enclave excludes. What a stolen credential buys is the ability
    /// to ring doorbells: wake signals carry no data, and reading any of it
    /// still needs a key KMS releases only to a matching PCR0/PCR16.
    #[arg(long, env = "S3FS_FCM_SERVICE_ACCOUNT")]
    fcm_service_account: Option<String>,

    /// An SSM parameter holding that JSON. The production source.
    ///
    /// Keeps the secret out of the measured image and out of the launch
    /// invocation, and lets it rotate without moving PCR0.
    #[arg(long, env = "S3FS_FCM_SERVICE_ACCOUNT_PARAMETER")]
    fcm_service_account_parameter: Option<String>,

    /// Point the FCM client somewhere else. For tests and the emulator.
    ///
    /// A downgrade path: an `http://` endpoint hands wake signals to whatever
    /// is listening. PCR0 records which image was built, which is the only
    /// reason this is acceptable.
    #[arg(long, env = "S3FS_FCM_ENDPOINT")]
    fcm_endpoint: Option<String>,

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

    /// Re-sign attestation documents with a certificate chain minted at boot.
    ///
    /// **Only in a `testing` build, and only useful under an emulator.** QEMU's
    /// NSM produces documents with genuine contents — the real PCR0 of the
    /// image, the PCR16 the runtime measured — inside an envelope it does not
    /// sign: its source says *"we don't actually sign the data, so we use -1 as
    /// the 'alg' value"*, and -1 is not a COSE algorithm. A client meeting one
    /// has to pass `--unsigned-emulator`, which skips the signature, the chain
    /// and the validity windows entirely.
    ///
    /// With this set, the runtime asks the device for a document and re-signs
    /// that same payload, so a client pins the reported root and runs every
    /// check it would run against hardware. It proves nothing about *who*
    /// produced a document — the key is minted inside an image its operator
    /// controls — which is why a production binary has no such flag.
    #[cfg(any(test, feature = "testing"))]
    #[arg(long, env = "S3FS_COSIGN_ATTESTATIONS", value_parser = enclave_runtime::parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    cosign_attestations: bool,

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
    /// Everything about notifications that can be decided without a network.
    ///
    /// The literal credential is parsed here, key and all: a malformed service
    /// account must fail at boot rather than the first time somebody is waiting
    /// to be woken, and proving it parses needs nothing but the bytes.
    fn notify_settings(&self) -> Result<Option<NotifySettings>> {
        let set = |value: &Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let project = set(&self.fcm_project_id);
        let literal = set(&self.fcm_service_account);
        let parameter = set(&self.fcm_service_account_parameter);

        // Empty means off, not malformed.
        if project.is_none() && literal.is_none() && parameter.is_none() {
            return Ok(None);
        }
        anyhow::ensure!(
            !(literal.is_some() && parameter.is_some()),
            "--fcm-service-account and --fcm-service-account-parameter are alternatives. \
             Refused rather than resolved by precedence: a deployment that set both has \
             one of them wrong, and guessing which would be the wrong help."
        );
        let Some(project_id) = project else {
            anyhow::bail!(
                "an FCM credential was given without --fcm-project-id, so there is no \
                 project to send for"
            );
        };
        let credential = match (literal, parameter) {
            (Some(json), _) => FcmCredential::Account(Box::new(
                enclave_runtime::ServiceAccount::parse(&json).context("--fcm-service-account")?,
            )),
            (_, Some(name)) => FcmCredential::Parameter(name),
            (None, None) => anyhow::bail!(
                "--fcm-project-id was set without a service account, so nothing can be sent"
            ),
        };
        Ok(Some(NotifySettings {
            project_id,
            credential,
            endpoint: set(&self.fcm_endpoint),
        }))
    }

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

    /// Where the guest comes from: exactly one of the two settings.
    ///
    /// An empty setting counts as unset, for the layering reason
    /// `guest_log_config` gives.
    fn guest_source(&self) -> Result<GuestSource> {
        let object = self
            .guest_object
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty());
        let path = self
            .guest_path
            .as_ref()
            .filter(|path| !path.as_os_str().is_empty());
        match (object, path) {
            (Some(key), None) => Ok(GuestSource::Object {
                key: key.to_string(),
            }),
            (None, Some(path)) => Ok(GuestSource::Path(path.clone())),
            (None, None) => anyhow::bail!(
                "no guest to run: set --guest-object, a key in the roots bucket, or outside \
                 an enclave --guest-path"
            ),
            (Some(_), Some(_)) => anyhow::bail!(
                "--guest-object and --guest-path are both set. They name two guests, and \
                 there is no safe way to guess which was meant."
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

    /// Wrap the device so its documents carry a signature, if this build can.
    ///
    /// Two definitions rather than a runtime branch, for the reason `--acme-ca`
    /// has two: a production binary has no flag to read, so no deployment can
    /// talk it into signing attestations with a key it minted itself.
    #[cfg(any(test, feature = "testing"))]
    fn cosign(
        cli: &Cli,
        entropy: std::sync::Arc<dyn nitro_nsm::Nsm>,
    ) -> Result<std::sync::Arc<dyn nitro_nsm::Nsm>> {
        use base64::Engine as _;

        if !cli.cosign_attestations {
            return Ok(entropy);
        }
        let cosigning = enclave_runtime::testing::CosigningNsm::wrap(entropy)?;
        // At `warn`, and printed in full. A client cannot check anything
        // without this value, and it is minted fresh at every boot — so it has
        // to leave by the one channel the parent already reads, and it has to
        // stand out from the boot log around it.
        tracing::warn!(
            trust_root = %base64::engine::general_purpose::STANDARD.encode(cosigning.trust_root()),
            "attestation documents are signed with a chain minted at boot, not by Nitro \
             hardware; a client must pin the root below, and it means only that this image \
             produced the document"
        );
        Ok(std::sync::Arc::new(cosigning))
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn cosign(
        _cli: &Cli,
        entropy: std::sync::Arc<dyn nitro_nsm::Nsm>,
    ) -> Result<std::sync::Arc<dyn nitro_nsm::Nsm>> {
        Ok(entropy)
    }

    let entropy = cosign(&cli, entropy)?;

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
    // Resolved before anything touches the network, so a runtime given no
    // guest, or two, says so rather than failing somewhere later.
    let guest_source = cli.guest_source()?;
    tracing::info!(
        key_source = keys.describe(),
        guest = %guest_source,
        "starting"
    );

    let mount_config = cli.mount_config()?;
    let backends = enclave_runtime::connect(&mount_config).await?;

    // The guest, before anything asks for a key. KMS releases the key against
    // an attestation carrying PCR16, so PCR16 has to be final by then: measured,
    // and locked so nothing can extend it afterwards. These same bytes are what
    // get compiled and served below, so what was measured is what runs.
    let component = enclave_runtime::fetch_guest(&guest_source, &backends.roots).await?;
    let guest_pcr = enclave_runtime::measure_guest(entropy.as_ref(), &component)?;
    tracing::info!(
        guest = %guest_source,
        guest_sha256 = %hex::encode(nitro_attestation::sha256(&component)),
        pcr16 = %hex::encode(guest_pcr),
        "guest measured into PCR16 and locked"
    );

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
        pcr0 = %hex::encode(booted.pair.pcr0),
        pcr16 = %hex::encode(booted.pair.pcr16),
        state_root = %hex::encode(booted.state_root),
        "state origin established"
    );

    let mounted = booted.mounted;
    let fs = mounted.fs.clone();

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
            tracing::info!(
                rp_id,
                origin,
                "registration is open to anyone; requiring a passkey assertion per request"
            );
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

    // Resolved before the listener binds, so a credential that cannot be
    // fetched is a boot failure rather than a surprise on the first wake.
    let notify = match cli.notify_settings()? {
        None => None,
        Some(settings) => {
            let service_account = match settings.credential {
                FcmCredential::Account(account) => *account,
                FcmCredential::Parameter(name) => {
                    let json = read_ssm_parameter(&cli, &name).await?;
                    enclave_runtime::ServiceAccount::parse(&json).with_context(|| {
                        format!("the FCM service account in SSM parameter {name}")
                    })?
                }
            };
            tracing::info!(
                project = %settings.project_id,
                "notifications are enabled; wake signals carry no content"
            );
            Some(enclave_runtime::NotifyConfig {
                project_id: settings.project_id,
                service_account,
                endpoint: settings.endpoint,
            })
        }
    };

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
            notify,
            background_tasks: cli
                .background_tasks
                .then(|| enclave_runtime::tasks::TaskLimits {
                    concurrency: cli.background_concurrency,
                    timeout: Duration::from_secs(cli.background_timeout_secs),
                    max_records: cli.background_max_records,
                    per_tenant: cli.background_per_tenant,
                }),
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
    fn notifications_are_off_unless_configured() {
        let cli = cli_from(&["--bucket", "b", "--master-key", &"aa".repeat(32)]);
        assert!(cli.notify_settings().expect("valid").is_none());
    }

    fn account_json() -> String {
        serde_json::json!({
            "type": "service_account",
            "project_id": "enclave-test",
            "private_key_id": "kid-1",
            "private_key": include_str!("notify/testdata/service-account-key.pem"),
            "client_email": "wake@enclave-test.iam.gserviceaccount.com",
        })
        .to_string()
    }

    /// An image carries the setting; a deployment blanks it. Empty is off, not
    /// malformed — the same rule the guest log settings follow.
    #[test]
    fn an_empty_setting_turns_notifications_off() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--fcm-project-id",
            "",
            "--fcm-service-account",
            "",
        ]);
        assert!(cli.notify_settings().expect("valid").is_none());
    }

    #[test]
    fn a_literal_service_account_is_parsed_at_startup_rather_than_on_first_use() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--fcm-project-id",
            "enclave-test",
            "--fcm-service-account",
            &account_json(),
        ]);
        let settings = cli.notify_settings().expect("valid").expect("configured");
        assert_eq!(settings.project_id, "enclave-test");
        assert!(matches!(settings.credential, FcmCredential::Account(_)));

        // And a broken one fails here, not later.
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--fcm-project-id",
            "enclave-test",
            "--fcm-service-account",
            "{\"type\":\"service_account\"}",
        ]);
        assert!(cli.notify_settings().is_err());
    }

    /// Refused rather than resolved by precedence: a deployment that set both
    /// has one of them wrong, and guessing which is the wrong kind of help.
    #[test]
    fn two_credential_sources_are_refused_rather_than_ranked() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--fcm-project-id",
            "p",
            "--fcm-service-account",
            &account_json(),
            "--fcm-service-account-parameter",
            "/prod/fcm",
        ]);
        assert!(cli.notify_settings().is_err());
    }

    #[test]
    fn a_half_configured_notifier_is_refused_without_touching_the_network() {
        let project_only = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--fcm-project-id",
            "p",
        ]);
        assert!(project_only.notify_settings().is_err());

        let credential_only = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--fcm-service-account-parameter",
            "/prod/fcm",
        ]);
        assert!(credential_only.notify_settings().is_err());
    }

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

    /// There is no default guest. The image used to carry one at a fixed path;
    /// it carries a key in the roots bucket instead, and a runtime given
    /// neither says what is missing rather than guessing.
    #[test]
    fn a_guest_source_is_required() {
        let cli = cli_from(&["--bucket", "b", "--master-key", &"aa".repeat(32)]);
        let err = cli.guest_source().unwrap_err();
        assert!(format!("{err:#}").contains("--guest-object"), "{err:#}");
    }

    #[test]
    fn a_guest_object_is_a_key_in_the_roots_bucket() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-object",
            "guest/guest.wasm",
        ]);
        assert_eq!(
            cli.guest_source().unwrap(),
            GuestSource::Object {
                key: "guest/guest.wasm".into()
            }
        );
    }

    #[test]
    fn a_guest_path_is_for_local_runs() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-path",
            "/tmp/other.wasm",
        ]);
        assert_eq!(
            cli.guest_source().unwrap(),
            GuestSource::Path(PathBuf::from("/tmp/other.wasm"))
        );
    }

    #[test]
    fn two_guest_sources_are_refused() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-object",
            "guest/guest.wasm",
            "--guest-path",
            "/tmp/other.wasm",
        ]);
        assert!(cli.guest_source().is_err());
    }

    /// The image environment is layered, and "" is how a layer says "not this
    /// one" — the same rule as the guest log settings.
    #[test]
    fn an_empty_guest_setting_counts_as_unset() {
        let cli = cli_from(&[
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32),
            "--guest-object",
            "",
            "--guest-path",
            "/tmp/other.wasm",
        ]);
        assert_eq!(
            cli.guest_source().unwrap(),
            GuestSource::Path(PathBuf::from("/tmp/other.wasm"))
        );
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
