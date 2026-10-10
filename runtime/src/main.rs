//! `enclave-runtime` — run a Wasm guest over its tenants' ZFS datasets, inside an AWS Nitro
//! Enclave.
//!
//! An enclave has no shell, no config file, and no operator to type flags at it. It gets what its
//! image baked in: an env file in the image's ramdisk, measured into PCR0 with everything else.
//! So **every setting reads from an environment variable**, with a matching flag that wins if
//! present — and changing one means building a new image, exactly as changing a constant does.
//! That is why there are so few: a setting exists only where two deployments of the same code
//! need different values. Everything else is a constant here.
//!
//! The guest component is **not** in the image. The runtime fetches it at boot from
//! [`GUEST_OBJECT`] in the roots bucket, then measures it into PCR16 and locks that register
//! before it asks KMS for anything — see [`enclave_runtime::guest`]. The guest's own settings
//! travel inside its file and are measured with it — see [`enclave_runtime::env`].
//!
//! The master secret comes from KMS, which releases it only against an attestation whose PCR0
//! and PCR16 match the key policy. The emulator's alternatives — a static key, unsigned receipts,
//! the host's clock, a local object store — are [`Testing`] settings, compiled into `testing`
//! builds alone, so no setting can talk a production binary into any of them.
//!
//! Argument parsing over [`enclave_runtime`], which is the same crate: the library half is
//! everything below this file, and lives beside it rather than inside it so integration tests
//! can reach it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;
use enclave_runtime::{
    open_clock, open_entropy, parse_bool_flag, serve_component, AcmeConfig, ClockSource,
    GuestEnvironment, GuestSource, MasterKeySourceKind, MountConfig, NetworkConfig, NetworkMode,
    RandomSource, ReceiptTrust, ServeConfig, DEFAULT_NSM_DEVICE, DEFAULT_PTP_DEVICE,
    EXIT_RUNTIME_FAILURE,
};

/// Where the guest is, in the roots bucket.
const GUEST_OBJECT: &str = "guest/guest.wasm";

/// Every interface, on 443. Inside an enclave the only interface is the one the parent's proxy
/// reaches, and 443 is where it forwards.
const HTTP_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443);

/// The stream within `--guest-log-group`. One per deployment, so the group alone says where.
const GUEST_LOG_STREAM: &str = "guest";

/// How long one S3 request may take, before the SDK's retries.
const S3_TIMEOUT: Duration = Duration::from_secs(30);

/// The deployment name in the KMS encryption context. It was a setting; it stays in the context,
/// with the value every deployment had, so the keys sealed under it still open. The filesystem
/// id is what tells deployments apart.
const KMS_ENVIRONMENT: &str = "production";

/// Notification settings, as far as they can be decided without I/O.
struct NotifySettings {
    app_id: String,
    endpoint: Option<String>,
}

/// A setting's value, with empty meaning unset: the image environment is layered, and setting a
/// variable to "" is how a layer says "not this one".
fn nonempty(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Run a Wasm guest inside an AWS Nitro Enclave",
    long_about = None
)]
struct Cli {
    /// The Object-Locked bucket: the pool's anchor chain, the boot's origin
    /// records, the guest, and the sealed ACME cache. COMPLIANCE retention on
    /// it is the entire rollback guarantee. The state itself is on the pool.
    #[arg(long, env = "ENCLAVE_ROOTS_BUCKET")]
    roots_bucket: String,

    /// Key prefix inside the roots bucket, so deployments can share one locked bucket.
    #[arg(long, env = "ENCLAVE_BUCKET_PREFIX", default_value = "")]
    bucket_prefix: String,

    /// Filesystem identifier, 32 hex characters — the key-derivation salt, so
    /// two filesystems under one master secret stay independent.
    ///
    /// Supplied rather than read from the store: the keys that verify a root
    /// record derive from it, so taking it from the store would mean trusting
    /// the store to say which key checks its own signature.
    #[arg(
        long,
        env = "ENCLAVE_ID",
        default_value = "00000000000000000000000000000000"
    )]
    fs_id: String,

    /// Refuse a store whose newest anchor is older than this sequence number.
    ///
    /// The only defence against a store that hides newer anchors at a cold
    /// boot. Everything else about rollback is closed cryptographically; this
    /// one needs a number from outside the store.
    #[arg(long, env = "ENCLAVE_MIN_ROOT_SEQ")]
    min_root_seq: Option<u64>,

    /// How long each anchor and boot record is locked against deletion, in seconds.
    ///
    /// COMPLIANCE retention: nobody can shorten it, so the rollback guarantee
    /// lasts this long and so does the roots bucket. Ten years unless the image
    /// says otherwise; a test deployment says a day, so it can be retired.
    /// Baked into the image, so PCR0 tells a client which kind it is talking
    /// to. Under a day is refused: it protects nothing worth the name.
    #[arg(long, env = "ENCLAVE_ROOT_RETENTION_SECS",
          default_value_t = enclave_runtime::DEFAULT_ROOT_RETENTION.as_secs(),
          value_parser = clap::value_parser!(u64).range(86_400..))]
    root_retention_secs: u64,

    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    region: String,

    /// The customer master key that releases this filesystem's secret. Its
    /// policy — `kms:RecipientAttestation:PCR0` and `:PCR16`, on both
    /// `GenerateDataKey` and `Decrypt` — is the security control.
    #[arg(long, env = "ENCLAVE_KMS_KEY_ID")]
    kms_key_id: Option<String>,

    /// SSM parameter holding the KMS ciphertext, and nothing else.
    #[arg(long, env = "ENCLAVE_MASTER_KEY_PARAMETER")]
    master_key_parameter: Option<String>,

    /// Domain to put in the certificate. Repeatable; at least one.
    ///
    /// Let's Encrypt issues it over TLS-ALPN-01 on the serving port. The key
    /// is generated inside the enclave and never leaves it; what the CA signs
    /// is what every response's attestation document binds.
    #[arg(
        long = "tls-domain",
        env = "ENCLAVE_TLS_DOMAINS",
        value_delimiter = ','
    )]
    tls_domains: Vec<String>,

    /// The WebAuthn relying-party id — the domain passkeys are scoped to.
    ///
    /// Setting it is what turns authentication on: **every request that could
    /// reach the guest then needs a fresh assertion bound to exactly that
    /// request**, and assertions must claim `https://<rp id>` or one of
    /// `--webauthn-allowed-origin`. Left unset the runtime serves the guest to
    /// anyone who can open a connection, which is a development arrangement and
    /// is warned about at startup. Baked into the image, so PCR0 records which
    /// relying party an enclave will accept assertions for.
    #[arg(long, env = "ENCLAVE_WEBAUTHN_RP_ID")]
    webauthn_rp_id: Option<String>,

    /// A further origin assertions may claim. Repeatable.
    ///
    /// For native apps, which do not claim `https://<rp id>`. An Android app
    /// claims `android:apk-key-hash:<hash>`: the unpadded base64url SHA-256 of
    /// its signing certificate. Debug, upload and Play App Signing keys each
    /// have their own, so a deployment usually lists the one Play signs with.
    /// Android lets an app claim it only after the app is vouched for by
    /// `https://<rp id>/.well-known/assetlinks.json`.
    ///
    /// Compared exactly. Baked into the image, so PCR0 records which apps an
    /// enclave accepts assertions from.
    #[arg(
        long = "webauthn-allowed-origin",
        env = "ENCLAVE_WEBAUTHN_ALLOWED_ORIGINS",
        value_delimiter = ','
    )]
    webauthn_allowed_origins: Vec<String>,

    /// The push application wake signals go through: an AWS End User Messaging Push
    /// application, whose FCM channel holds the Firebase credential.
    ///
    /// Empty means notifications are off, so an image can carry the setting and a
    /// deployment can blank it. The image names the application and nothing else:
    /// requests are signed as the instance's own role, so there is no credential
    /// here to set, or to leak from a published image.
    #[arg(long, env = "ENCLAVE_PUSH_APP_ID")]
    push_app_id: Option<String>,

    /// CloudWatch log group for guest output, written to its `guest` stream.
    /// Empty or unset means the console only.
    #[arg(long, env = "ENCLAVE_GUEST_LOG_GROUP")]
    guest_log_group: Option<String>,

    /// Report on the clock and entropy source and exit, without mounting or
    /// running anything. For diagnosing a deployment.
    #[arg(long, alias = "clock-check")]
    self_check: bool,

    #[cfg_attr(any(test, feature = "testing"), command(flatten))]
    #[cfg_attr(not(any(test, feature = "testing")), arg(skip = Testing::production()))]
    testing: Testing,

    /// Arguments passed to the guest.
    #[arg(last = true)]
    guest_args: Vec<String>,
}

/// The settings only a `testing` build has: the emulator's and the tests'.
///
/// A production binary has none of these flags. It takes [`Testing::production`], so each
/// value a production enclave runs with is written once, there, and no deployment can reach
/// another.
#[derive(clap::Args, Debug)]
struct Testing {
    /// Where the master secret comes from. `static` takes it from `--master-key`
    /// and stores it unsealed, for the emulator, whose NSM cannot produce a
    /// document KMS would accept.
    #[arg(long, env = "ENCLAVE_MASTER_KEY_SOURCE", default_value = "kms",
          value_parser = MasterKeySourceKind::parse)]
    master_key_source: MasterKeySourceKind,

    /// 32-byte master secret, hex encoded. `static` only, and refused under
    /// `kms`: a key from configuration is a key the parent instance holds.
    #[arg(long, env = "ENCLAVE_MASTER_KEY")]
    master_key: Option<String>,

    /// `unsigned-emulator` reads a state-origin receipt without checking a
    /// signature, because the emulator's NSM does not sign.
    #[arg(long, env = "ENCLAVE_RECEIPT_TRUST", default_value = "required",
          value_parser = ReceiptTrust::parse)]
    receipt_trust: ReceiptTrust,

    /// Where the guest's wall-clock time comes from. The emulator has no PTP
    /// clock; `host` uses the system's.
    #[arg(long, env = "ENCLAVE_CLOCK_SOURCE", default_value = "ptp",
          value_parser = ClockSource::parse)]
    clock_source: ClockSource,

    /// PTP character device to read.
    #[arg(long, env = "ENCLAVE_PTP_DEVICE", default_value = DEFAULT_PTP_DEVICE)]
    ptp_device: PathBuf,

    /// Where random bytes come from. `host` is for a machine with no NSM.
    #[arg(long, env = "ENCLAVE_RANDOM_SOURCE", default_value = "nsm",
          value_parser = RandomSource::parse)]
    random_source: RandomSource,

    /// An S3-compatible endpoint in place of AWS's: the emulator's MinIO.
    #[arg(long, env = "ENCLAVE_ENDPOINT")]
    endpoint: Option<String>,

    /// Path-style addressing, which MinIO needs.
    #[arg(long, env = "ENCLAVE_FORCE_PATH_STYLE", value_parser = parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    force_path_style: bool,

    /// Static credentials for that endpoint. Production signs as the instance's role.
    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    access_key_id: Option<String>,

    #[arg(long, env = "AWS_SECRET_ACCESS_KEY")]
    secret_access_key: Option<String>,

    #[arg(long, env = "AWS_SESSION_TOKEN")]
    session_token: Option<String>,

    /// An ACME directory in place of Let's Encrypt production: Pebble, or staging.
    #[arg(long, env = "ENCLAVE_ACME_DIRECTORY")]
    acme_directory: Option<String>,

    /// PEM trust root for the ACME directory's own HTTPS certificate.
    ///
    /// A real CA serves its API under a publicly-trusted certificate and needs
    /// nothing here; a test CA like Pebble does not, so the emulator supplies
    /// its root. An enclave that took issuance orders from a CA of the
    /// operator's choosing would be a different trust model than the one a
    /// production image claims.
    #[arg(long, env = "ENCLAVE_ACME_CA")]
    acme_ca: Option<PathBuf>,

    /// Contact address registered with the ACME directory.
    #[arg(
        long = "acme-contact",
        env = "ENCLAVE_ACME_CONTACTS",
        value_delimiter = ','
    )]
    acme_contacts: Vec<String>,

    /// Point the CloudWatch client somewhere else. An `http://` endpoint hands
    /// guest output to whatever is listening, in clear.
    #[arg(long, env = "ENCLAVE_GUEST_LOG_ENDPOINT")]
    guest_log_endpoint: Option<String>,

    /// Point the push client at a stub: an `http://` endpoint hands wake signals to
    /// whatever is listening, and requests to it are signed with a placeholder
    /// rather than the instance's role.
    #[arg(long, env = "ENCLAVE_PUSH_ENDPOINT")]
    push_endpoint: Option<String>,

    /// Re-sign attestation documents with a certificate chain minted at boot.
    ///
    /// Only useful under an emulator. QEMU's NSM produces documents with
    /// genuine contents — the real PCR0 of the image, the PCR16 the runtime
    /// measured — inside an envelope it does not sign: its source says *"we
    /// don't actually sign the data, so we use -1 as the 'alg' value"*, and -1
    /// is not a COSE algorithm. A client meeting one has to pass
    /// `--unsigned-emulator`, which skips the signature, the chain and the
    /// validity windows entirely.
    ///
    /// With this set, the runtime asks the device for a document and re-signs
    /// that same payload, so a client pins the reported root and runs every
    /// check it would run against hardware. It proves nothing about *who*
    /// produced a document — the key is minted inside an image its operator
    /// controls.
    #[arg(long, env = "ENCLAVE_COSIGN_ATTESTATIONS", value_parser = parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    cosign_attestations: bool,
}

impl Testing {
    /// What a production enclave runs with.
    #[cfg_attr(any(test, feature = "testing"), allow(dead_code))]
    fn production() -> Self {
        Testing {
            master_key_source: MasterKeySourceKind::Kms,
            master_key: None,
            receipt_trust: ReceiptTrust::Required,
            clock_source: ClockSource::Ptp,
            ptp_device: PathBuf::from(DEFAULT_PTP_DEVICE),
            random_source: RandomSource::Nsm,
            endpoint: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            acme_directory: None,
            acme_ca: None,
            acme_contacts: Vec::new(),
            guest_log_endpoint: None,
            push_endpoint: None,
            cosign_attestations: false,
        }
    }
}

impl Cli {
    /// Everything about notifications that can be decided without a network.
    ///
    /// A malformed application id fails at boot rather than the first time somebody is waiting
    /// to be woken; whether the application can deliver is the probe's to find out, once there
    /// is a network.
    fn notify_settings(&self) -> Result<Option<NotifySettings>> {
        match (
            nonempty(&self.push_app_id),
            nonempty(&self.testing.push_endpoint),
        ) {
            (None, None) => Ok(None),
            (None, Some(_)) => anyhow::bail!(
                "--push-endpoint was given without --push-app-id, so there is no application to \
                 send through"
            ),
            (Some(app_id), endpoint) => {
                anyhow::ensure!(
                    enclave_runtime::notify::valid_app_id(&app_id),
                    "--push-app-id must be the application's id, 1-64 letters and digits"
                );
                Ok(Some(NotifySettings { app_id, endpoint }))
            }
        }
    }

    /// Where guest output goes, beyond the console: the `guest` stream of the configured group.
    ///
    /// Empty means off, not malformed. The image environment is layered — the QEMU image
    /// inherits production's and blanks what it cannot use — and "" is how that layer says
    /// "not this one".
    fn guest_log_config(&self) -> Option<enclave_runtime::CloudWatchConfig> {
        nonempty(&self.guest_log_group).map(|log_group| enclave_runtime::CloudWatchConfig {
            log_group,
            log_stream: GUEST_LOG_STREAM.to_string(),
            region: self.region.clone(),
            endpoint: self.testing.guest_log_endpoint.clone(),
        })
    }

    fn mount_config(&self) -> Result<MountConfig> {
        Ok(MountConfig {
            roots_bucket: self.roots_bucket.clone(),
            region: self.region.clone(),
            endpoint: self.testing.endpoint.clone(),
            access_key_id: self.testing.access_key_id.clone(),
            secret_access_key: self.testing.secret_access_key.clone(),
            session_token: self.testing.session_token.clone(),
            force_path_style: self.testing.force_path_style,
            bucket_prefix: self.bucket_prefix.clone(),
            fs_id: enclave_runtime::parse_fs_id(&self.fs_id)?,
            min_root_seq: self.min_root_seq,
            skip_bucket_probe: false,
            request_timeout: S3_TIMEOUT,
            root_retention: Duration::from_secs(self.root_retention_secs),
        })
    }

    fn master_key_config(&self) -> Result<enclave_runtime::MasterKeyConfig> {
        Ok(enclave_runtime::MasterKeyConfig {
            kind: self.testing.master_key_source,
            master_key: self.testing.master_key.clone(),
            kms_key_id: self.kms_key_id.clone(),
            parameter: self.master_key_parameter.clone(),
            environment: KMS_ENVIRONMENT.to_string(),
            fs_id: enclave_runtime::parse_fs_id(&self.fs_id)?,
            region: self.region.clone(),
            kms_endpoint: None,
            ssm_endpoint: None,
            access_key_id: self.testing.access_key_id.clone(),
            secret_access_key: self.testing.secret_access_key.clone(),
            session_token: self.testing.session_token.clone(),
        })
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

    let clock = open_clock(cli.testing.clock_source, &cli.testing.ptp_device)?;
    let entropy = open_entropy(cli.testing.random_source, Path::new(DEFAULT_NSM_DEVICE))?;

    /// Wrap the device so its documents carry a signature, if this build can.
    ///
    /// Two definitions rather than a runtime branch: a production binary has no
    /// cosigning code at all, so no deployment can talk it into signing
    /// attestations with a key it minted itself.
    #[cfg(any(test, feature = "testing"))]
    fn cosign(
        cli: &Cli,
        entropy: std::sync::Arc<dyn nitro_nsm::Nsm>,
    ) -> Result<std::sync::Arc<dyn nitro_nsm::Nsm>> {
        use base64::Engine as _;

        if !cli.testing.cosign_attestations {
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
        mode: NetworkMode::Gvproxy,
        ..Default::default()
    })?;

    let keys = enclave_runtime::open_key_source(&cli.master_key_config()?, entropy.clone())?;
    let guest_source = GuestSource::Object {
        key: GUEST_OBJECT.to_string(),
    };
    tracing::info!(
        key_source = keys.describe(),
        guest = %guest_source,
        "starting"
    );

    let mount_config = cli.mount_config()?;
    let roots = enclave_runtime::connect(&mount_config).await?;

    // The guest, before anything asks for a key. KMS releases the key against
    // an attestation carrying PCR16, so PCR16 has to be final by then: measured,
    // and locked so nothing can extend it afterwards. These same bytes are what
    // get compiled and served below, so what was measured is what runs.
    let component = enclave_runtime::fetch_guest(&guest_source, &roots).await?;
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
        &roots,
        &mount_config,
        &enclave_runtime::BootConfig {
            trust: cli.testing.receipt_trust,
            disk: enclave_runtime::Disk::Parent,
        },
        &entropy,
        &keys,
        &clock,
    )
    .await?;

    tracing::info!(
        mode = ?booted.mode,
        pcr0 = %hex::encode(booted.pair.pcr0),
        pcr16 = %hex::encode(booted.pair.pcr16),
        state_root = %hex::encode(booted.state_root),
        "state origin established"
    );

    let zfs = booted.zfs.clone();

    // The guest's environment is the settings its file carries, measured into PCR16 with its
    // code, and nothing else — see `env::from_guest`. Names only: a value can be a credential.
    let env = enclave_runtime::env::from_guest(&component)?;
    tracing::info!(
        names = %env.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", "),
        "guest environment: the settings the guest file carries"
    );

    /// Open the emulator's host to guests, but not the runtime's own services on it.
    ///
    /// The host is where an emulator's services live — an ASP, a payout platform — and where
    /// the runtime's own are too: its store, its CA, its push stub. A guest may reach the first
    /// and never the second, so the second are named by the runtime's own settings, which cannot
    /// drift from where those services are. Two definitions, as above: a production binary has
    /// no host to open.
    #[cfg(any(test, feature = "testing"))]
    fn open_dev_host(cli: &Cli) -> anyhow::Result<()> {
        let mut own = Vec::new();
        for url in [
            &cli.testing.endpoint,
            &cli.testing.acme_directory,
            &cli.testing.guest_log_endpoint,
            &cli.testing.push_endpoint,
        ]
        .into_iter()
        .flatten()
        {
            let uri: http::Uri = url.parse().with_context(|| format!("{url} is not a URL"))?;
            own.push(uri.port_u16().unwrap_or(match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            }));
        }
        own.sort_unstable();
        own.dedup();
        tracing::warn!(
            ?own,
            "guests may reach the public internet, and the emulator's host on every port but these"
        );
        enclave_runtime::serve::egress::admit_dev_host(own);
        Ok(())
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn open_dev_host(_cli: &Cli) -> anyhow::Result<()> {
        tracing::info!("guests may reach the public internet, and nothing else");
        Ok(())
    }

    // One certificate source. There is no second: a certificate the runtime
    // minted for itself would be one an operator could mint too.
    let directory_ca = match &cli.testing.acme_ca {
        Some(path) => Some(std::fs::read(path).with_context(|| {
            format!("reading the ACME directory trust root {}", path.display())
        })?),
        None => None,
    };
    let acme = Some(enclave_runtime::serve::acme::start(
        &AcmeConfig {
            domains: cli.tls_domains.clone(),
            contacts: cli.testing.acme_contacts.clone(),
            directory: cli.testing.acme_directory.clone(),
            directory_ca,
            prefix: mount_config.bucket_prefix.clone(),
        },
        roots.clone(),
        booted.keys.clone(),
    )?);
    tracing::info!(listen = %HTTP_LISTEN, "serving guest");

    // Not a choice. An enclave nobody can verify is an enclave for nothing, and
    // a flag that turns verification off is a flag that can be turned off by
    // whoever starts the process — which inside an enclave is the party the
    // enclave exists to exclude.
    let attestation = Some(entropy.clone());

    // Per-client views of the one pool. Each client's guest sees its
    // own dataset as `/`, through a fresh instance per request, so a
    // client costs a dataset and a lock.
    //
    // A client is serialised against itself and nobody else, so two
    // clients can execute guest code at the same time. A guest is
    // written for that; it is not a deployment decision.
    let tenancy = Some(std::sync::Arc::new(enclave_runtime::Tenancy::new(
        enclave_runtime::PoolLimits::default(),
    )));

    // WebAuthn, when the deployment named a relying party.
    //
    // Empty entries are dropped, not refused: an image built with no
    // extra origins still sets the variable, to nothing.
    let allowed_origins: Vec<String> = cli
        .webauthn_allowed_origins
        .iter()
        .map(|o| o.trim())
        .filter(|o| !o.is_empty())
        .map(str::to_string)
        .collect();
    // Where guests may send is no setting: the public internet, checked on every connect — see
    // `serve::egress`. Only the emulator widens it, to its host.
    open_dev_host(&cli)?;

    let authentication = match nonempty(&cli.webauthn_rp_id) {
        Some(rp_id) => {
            // What a page on the relying party's own domain claims. Native apps
            // claim theirs, from `--webauthn-allowed-origin`.
            let origin = format!("https://{rp_id}");
            let credentials =
                std::sync::Arc::new(enclave_runtime::FilesystemCredentials::new(zfs.clone()));
            let gate = std::sync::Arc::new(enclave_runtime::Gate::new(
                enclave_runtime::build_relying_party(&rp_id, &origin, &allowed_origins)?,
                enclave_runtime::ChallengeStore::new(
                    enclave_runtime::auth::DEFAULT_TTL,
                    enclave_runtime::DEFAULT_CAPACITY,
                ),
                credentials.clone(),
                enclave_runtime::TokenStore::new(
                    enclave_runtime::auth::DEFAULT_TOKEN_TTL,
                    enclave_runtime::DEFAULT_TOKEN_CAPACITY,
                ),
            ));
            let auth = std::sync::Arc::new(enclave_runtime::AuthEndpoints::new(
                gate.clone(),
                credentials,
                zfs.clone(),
                entropy.clone(),
            ));
            tracing::info!(
                rp_id,
                origin,
                allowed_origins = ?allowed_origins,
                "registration is open to anyone; requiring a passkey assertion per request"
            );
            Some((auth, gate))
        }
        None => {
            anyhow::ensure!(
                allowed_origins.is_empty(),
                "--webauthn-allowed-origin was given without --webauthn-rp-id. With no \
                 relying party, authentication is off and the origin would be silently \
                 ignored."
            );
            None
        }
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

    if let Some(config) = cli.guest_log_config() {
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

    // Decided before the listener binds, so a setting that cannot work is a boot failure rather
    // than a surprise on the first wake. Whether the application can deliver is the probe's to
    // find out once serving starts.
    let notify = match cli.notify_settings()? {
        None => None,
        Some(settings) => {
            tracing::info!(
                app = %settings.app_id,
                "notifications are enabled; wake signals carry no content"
            );
            let credentials = match &settings.endpoint {
                // The emulator's stub checks no signature, and the static keys in an emulator's
                // image are its object store's: neither is the instance's role.
                Some(_) => aws_credential_types::provider::SharedCredentialsProvider::new(
                    aws_credential_types::Credentials::new(
                        "push-stub",
                        "push-stub",
                        None,
                        None,
                        "push-stub",
                    ),
                ),
                None => enclave_runtime::notify::instance_role(),
            };
            Some(enclave_runtime::NotifyConfig {
                app_id: settings.app_id,
                region: cli.region.clone(),
                endpoint: settings.endpoint,
                credentials,
            })
        }
    };

    // Before the listener binds, so no request can produce guest output
    // before there is a task consuming it. Held for the server's
    // lifetime and drained explicitly below.
    let (guest_logs, log_collector) = enclave_runtime::guest_io::start(std::sync::Arc::new(
        enclave_runtime::FanOutSink::new(sinks),
    ));

    let guest = GuestEnvironment::new(zfs, clock, entropy, &env, &cli.guest_args, guest_logs)?;
    let served = serve_component(
        &component,
        guest,
        ServeConfig {
            notify,
            // Whether tasks run is the guest's to say, by exporting `run-task`.
            background_tasks: Some(Default::default()),
            addr: HTTP_LISTEN,
            certificate: None,
            acme,
            attestation,
            tenancy,
            authentication,
            ..ServeConfig::default()
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
    fn cli_from(args: &[&str]) -> Cli {
        let mut full = vec!["enclave-runtime", "--roots-bucket", "b"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).expect("parse")
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_roots_bucket_is_required() {
        assert!(Cli::try_parse_from(["enclave-runtime"]).is_err());
        assert!(Cli::try_parse_from(["enclave-runtime", "--roots-bucket", "b"]).is_ok());
    }

    /// What a production enclave runs with: every value written once, in
    /// `Testing::production`, and nothing a deployment could change.
    #[test]
    fn a_production_build_takes_its_key_from_kms_and_its_time_from_ptp() {
        let production = Testing::production();
        assert_eq!(production.master_key_source, MasterKeySourceKind::Kms);
        assert!(production.master_key.is_none());
        assert_eq!(production.receipt_trust, ReceiptTrust::Required);
        assert_eq!(production.clock_source, ClockSource::Ptp);
        assert_eq!(production.random_source, RandomSource::Nsm);
        assert!(production.endpoint.is_none() && production.access_key_id.is_none());
        assert!(production.acme_directory.is_none() && production.acme_ca.is_none());
        assert!(production.push_endpoint.is_none() && production.guest_log_endpoint.is_none());
        assert!(!production.cosign_attestations);

        // And a testing build's defaults are the same, so an emulator departs
        // from production only where its image says so.
        let defaults = cli_from(&[]).testing;
        assert_eq!(defaults.master_key_source, production.master_key_source);
        assert_eq!(defaults.receipt_trust, production.receipt_trust);
        assert_eq!(defaults.clock_source, production.clock_source);
        assert_eq!(defaults.random_source, production.random_source);
    }

    /// Ten years unless the image says otherwise, what it says reaches the
    /// mount, and under a day is refused.
    #[test]
    fn root_retention_is_ten_years_unless_the_image_says_otherwise() {
        assert_eq!(
            cli_from(&[]).mount_config().expect("valid").root_retention,
            enclave_runtime::DEFAULT_ROOT_RETENTION
        );
        assert_eq!(
            cli_from(&["--root-retention-secs", "86400"])
                .mount_config()
                .expect("valid")
                .root_retention,
            Duration::from_secs(86_400)
        );
        assert!(Cli::try_parse_from([
            "enclave-runtime",
            "--roots-bucket",
            "b",
            "--root-retention-secs",
            "3600",
        ])
        .is_err());
    }

    /// Console-only is the default, and takes no client and no credentials.
    #[test]
    fn notifications_are_off_unless_configured() {
        assert!(cli_from(&[]).notify_settings().expect("valid").is_none());
    }

    /// An image carries the setting; a deployment blanks it. Empty is off, not
    /// malformed — the same rule the guest log settings follow.
    #[test]
    fn an_empty_setting_turns_notifications_off() {
        let cli = cli_from(&["--push-app-id", ""]);
        assert!(cli.notify_settings().expect("valid").is_none());
    }

    /// An application id is all production names: no credential, no endpoint.
    #[test]
    fn an_application_id_is_all_a_deployment_sets() {
        let cli = cli_from(&["--push-app-id", "0123456789abcdef0123456789abcdef"]);
        let settings = cli.notify_settings().expect("valid").expect("configured");
        assert_eq!(settings.app_id, "0123456789abcdef0123456789abcdef");
        assert!(settings.endpoint.is_none());
    }

    /// It goes into a URL path, so a malformed one fails at boot.
    #[test]
    fn a_malformed_application_id_is_refused() {
        assert!(cli_from(&["--push-app-id", "../channels"])
            .notify_settings()
            .is_err());
    }

    #[test]
    fn a_stub_without_an_application_is_refused() {
        assert!(cli_from(&["--push-endpoint", "http://127.0.0.1:9180"])
            .notify_settings()
            .is_err());
    }

    #[test]
    fn guest_logging_is_console_only_unless_configured() {
        assert!(cli_from(&[]).guest_log_config().is_none());
    }

    /// An empty setting means off, not malformed.
    ///
    /// The image environment is layered: the QEMU image inherits production's
    /// and sets what it cannot use to "". Treating that as a typo made the
    /// harness enclave refuse to boot, which is how this rule was learned.
    #[test]
    fn an_empty_setting_turns_guest_logging_off() {
        assert!(cli_from(&["--guest-log-group", ""])
            .guest_log_config()
            .is_none());
    }

    #[test]
    fn a_configured_group_is_written_to_its_guest_stream() {
        let cli = cli_from(&[
            "--region",
            "eu-west-2",
            "--guest-log-group",
            "/enclave/guest",
            "--guest-log-endpoint",
            "http://127.0.0.1:4566",
        ]);
        let config = cli.guest_log_config().expect("configured");
        assert_eq!(config.log_group, "/enclave/guest");
        assert_eq!(config.log_stream, "guest");
        assert_eq!(config.region, "eu-west-2");
        assert_eq!(config.endpoint.as_deref(), Some("http://127.0.0.1:4566"));
    }

    fn source_error(args: &[&str]) -> String {
        let config = cli_from(args).master_key_config().expect("config");
        let nsm = std::sync::Arc::new(nitro_nsm::fake::FakeNsm::new());
        format!(
            "{:#}",
            enclave_runtime::open_key_source(&config, nsm)
                .expect_err("this combination must be refused")
        )
    }

    /// The refusal that matters most. An image that still carried
    /// `ENCLAVE_MASTER_KEY` would work perfectly — quietly taking its key from
    /// the parent instance, which is the whole thing KMS release prevents.
    #[test]
    fn a_plaintext_key_is_refused_under_kms() {
        let err = source_error(&[
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
        assert!(source_error(&[]).contains("--kms-key-id"));
        assert!(
            source_error(&["--kms-key-id", "arn:aws:kms:eu-west-2:1:key/a"])
                .contains("--master-key-parameter")
        );
    }

    /// The encryption context is built from the filesystem id and the
    /// environment, so it is the same at mint and at open by construction —
    /// and the environment is the one every deployment always had, so keys
    /// sealed before it was a constant still open.
    #[test]
    fn the_key_config_carries_the_encryption_context_inputs() {
        let config = cli_from(&["--fs-id", &"cd".repeat(16)])
            .master_key_config()
            .expect("config");
        assert_eq!(config.environment, "production");
        assert_eq!(config.fs_id, [0xcd; 16]);
    }

    #[test]
    fn guest_arguments_come_after_a_separator() {
        let cli = cli_from(&["--", "arg1", "--not-our-flag"]);
        assert_eq!(cli.guest_args, vec!["arg1", "--not-our-flag"]);
    }

    #[test]
    fn an_invalid_filesystem_id_is_rejected_before_anything_is_opened() {
        assert!(cli_from(&["--fs-id", "not-hex"]).mount_config().is_err());
    }

    #[test]
    fn mount_config_carries_the_settings_through() {
        let cli = cli_from(&[
            "--bucket-prefix",
            "tenant",
            "--min-root-seq",
            "42",
            "--force-path-style",
        ]);
        let cfg = cli.mount_config().unwrap();
        assert_eq!(cfg.roots_bucket, "b");
        assert_eq!(cfg.bucket_prefix, "tenant");
        assert_eq!(cfg.min_root_seq, Some(42));
        assert!(cfg.force_path_style);
        assert_eq!(cfg.request_timeout, S3_TIMEOUT);
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
