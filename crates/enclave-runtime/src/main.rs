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
//! What is *not* here yet: NSM attestation, KMS key release, and the vsock
//! transport. The master secret still comes from configuration, which is a
//! development seam — a key in an environment variable is visible to the
//! parent instance, exactly the party an enclave exists to exclude. Replacing
//! it is a new [`s3fs_host::MasterKeySource`] implementation and nothing else.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use s3fs_host::{
    mount, open_clock, read_component, run_component, ClockSource, GuestEnvPolicy, MasterKeySource,
    MountConfig, StaticKey, DEFAULT_PTP_DEVICE, EXIT_RUNTIME_FAILURE,
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
    #[arg(long, env = "S3FS_FORCE_PATH_STYLE", value_parser = s3fs_host::parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    force_path_style: bool,

    /// Skip the `HeadBucket` startup probe.
    #[arg(long, env = "S3FS_SKIP_BUCKET_PROBE", value_parser = s3fs_host::parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    skip_bucket_probe: bool,

    /// Give the guest nothing but what `--guest-env` names.
    ///
    /// By default it inherits this process's environment minus anything under
    /// `AWS_` or `S3FS_`, which is where the credentials and this runtime's
    /// own configuration live.
    #[arg(long, env = "S3FS_NO_INHERIT_ENV", value_parser = s3fs_host::parse_bool_flag, num_args = 0..=1, default_value_t = false, default_missing_value = "true")]
    no_inherit_env: bool,

    /// Extra variable for the guest, as `NAME` (inherit that one by name) or
    /// `NAME=VALUE`. Applied after inheritance, so it overrides — including
    /// for names that are otherwise withheld. Repeatable.
    #[arg(long = "guest-env", value_name = "NAME[=VALUE]")]
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

    /// Report on the configured clock and exit, without mounting or running
    /// anything. For diagnosing a deployment.
    #[arg(long)]
    clock_check: bool,

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
            fs_id: s3fs_host::parse_fs_id(&self.fs_id)?,
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

async fn run() -> Result<s3fs_host::GuestOutcome> {
    let cli = Cli::parse();

    let clock = open_clock(cli.clock_source, &cli.ptp_device)?;
    if cli.clock_check {
        clock_check(clock.as_ref())?;
        return Ok(s3fs_host::GuestOutcome::Success);
    }

    let keys = StaticKey::from_hex(&cli.master_key)?;
    tracing::info!(
        key_source = keys.describe(),
        guest = %cli.guest_path.display(),
        "starting"
    );

    let fs = mount(&cli.mount_config()?, &keys).await?;

    // Read the guest before building the environment so a missing component —
    // the likeliest misconfiguration inside an image — fails immediately and
    // names the path it looked at.
    let component = read_component(&cli.guest_path)?;

    let env = cli.env_policy().build()?;
    tracing::info!(
        variables = env.len(),
        args = cli.guest_args.len(),
        "running guest"
    );

    run_component(fs, clock, &component, &env, &cli.guest_args).await
}

/// Print what the configured clock actually reports.
///
/// The delta against `CLOCK_REALTIME` is the interesting column: a PTP clock
/// disciplined by an external source and a host clock set by the hypervisor
/// have no reason to agree, and how far apart they are is exactly what this
/// feature exists to expose.
fn clock_check(clock: &dyn s3fs_host::TrustedClock) -> Result<()> {
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
