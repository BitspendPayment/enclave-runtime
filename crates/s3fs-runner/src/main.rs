//! `s3fs-runner` — the development CLI: load a `wasi:cli/command` component
//! and run it with `wasi:filesystem` backed by S3 or an S3-compatible store.
//!
//! Everything substantive lives in `s3fs-host`, shared with `enclave-runtime`.
//! The difference between the two binaries is entirely in their defaults:
//! this one is driven by explicit flags and gives the guest **nothing** unless
//! asked, because on a developer's machine the host environment is full of
//! things that have no business inside a guest. `enclave-runtime` inherits by
//! default, because inside an enclave image the environment *is* the
//! deployment configuration.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use s3fs_host::{
    mount, open_clock, open_entropy, read_component, run_component, ClockSource, GuestEnvPolicy,
    MasterKeySource, MountConfig, RandomSource, StaticKey, DEFAULT_NSM_DEVICE, DEFAULT_PTP_DEVICE,
    EXIT_RUNTIME_FAILURE,
};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Run a Wasm component with wasi:filesystem backed by S3"
)]
struct Cli {
    /// Bucket holding the data slabs.
    #[arg(long, env = "S3FS_BUCKET")]
    bucket: String,

    /// Bucket holding the signed root records. Defaults to `--bucket`.
    #[arg(long, env = "S3FS_ROOTS_BUCKET")]
    roots_bucket: Option<String>,

    /// 32-byte master secret, hex encoded. Every other key derives from it.
    #[arg(long, env = "S3FS_MASTER_KEY")]
    master_key: String,

    /// Filesystem identifier, 32 hex characters — the key-derivation salt.
    #[arg(
        long,
        env = "S3FS_ID",
        default_value = "00000000000000000000000000000000"
    )]
    fs_id: String,

    /// Refuse to mount a root record older than this sequence number.
    #[arg(long, env = "S3FS_MIN_ROOT_SEQ")]
    min_root_seq: Option<u64>,

    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    region: String,

    /// Endpoint override, e.g. http://127.0.0.1:9000 for MinIO.
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

    /// Key prefix inside both buckets.
    #[arg(long, env = "S3FS_BUCKET_PREFIX", default_value = "")]
    bucket_prefix: String,

    /// Path the guest sees as its preopen root.
    #[arg(long, env = "S3FS_MOUNT_PATH", default_value = "/")]
    mount_path: String,

    /// Skip the `HeadBucket` startup probe.
    #[arg(long)]
    skip_bucket_probe: bool,

    /// Variable to pass to the guest, as `NAME` (inherit from this process) or
    /// `NAME=VALUE`. Repeatable.
    ///
    /// The guest's environment is empty unless something is named here. Pass
    /// `--inherit-env` for the enclave's default of inheriting everything
    /// except `AWS_*` and `S3FS_*`.
    #[arg(long = "guest-env", value_name = "NAME[=VALUE]")]
    guest_env: Vec<String>,

    /// Inherit this process's environment (minus `AWS_*` and `S3FS_*`) rather
    /// than starting from empty.
    #[arg(long)]
    inherit_env: bool,

    /// Where the guest's wall-clock time comes from: `auto`, `ptp`, or `host`.
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

    /// Path to the `.wasm` component file.
    #[arg(long, short = 'c')]
    component: PathBuf,

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
        if self.inherit_env {
            GuestEnvPolicy {
                inherit: true,
                explicit: self.guest_env.clone(),
            }
        } else {
            GuestEnvPolicy::explicit_only(self.guest_env.clone())
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,s3fs=debug")),
        )
        .with_target(false)
        .compact()
        .init();

    match run().await {
        Ok(outcome) => {
            if outcome.is_success() {
                tracing::info!("guest exited successfully");
            } else {
                tracing::warn!(exit_code = outcome.exit_code(), "guest exited non-zero");
            }
            std::process::ExitCode::from(u8::try_from(outcome.exit_code()).unwrap_or(1))
        }
        Err(e) => {
            tracing::error!(
                error = format!("{e:#}"),
                "runtime failed to start the guest"
            );
            std::process::ExitCode::from(EXIT_RUNTIME_FAILURE as u8)
        }
    }
}

async fn run() -> Result<s3fs_host::GuestOutcome> {
    let cli = Cli::parse();

    let keys = StaticKey::from_hex(&cli.master_key)?;
    tracing::info!(
        key_source = keys.describe(),
        component = %cli.component.display(),
        "starting"
    );

    let clock = open_clock(cli.clock_source, &cli.ptp_device)?;
    let entropy = open_entropy(cli.random_source, &cli.nsm_device)?;
    let fs = mount(&cli.mount_config()?, &keys).await?;
    let component = read_component(&cli.component)?;
    let env = cli.env_policy().build()?;

    run_component(fs, clock, entropy, &component, &env, &cli.guest_args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn cli_from(args: &[&str]) -> Cli {
        let mut full = vec!["s3fs-runner", "--bucket", "b", "--master-key"];
        let key = "aa".repeat(32);
        full.push(Box::leak(key.into_boxed_str()));
        full.extend_from_slice(&["-c", "guest.wasm"]);
        full.extend_from_slice(args);
        Cli::try_parse_from(full).expect("parse")
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// The development default is the opposite of the enclave's: a developer's
    /// environment is full of things a guest has no business seeing, and none
    /// of it is deployment configuration.
    #[test]
    fn the_guest_environment_is_empty_by_default() {
        let cli = cli_from(&[]);
        let policy = cli.env_policy();
        assert!(!policy.inherit);
        assert!(policy.build().unwrap().is_empty());
    }

    #[test]
    fn inherit_env_opts_into_the_enclave_behaviour() {
        let cli = cli_from(&["--inherit-env"]);
        assert!(cli.env_policy().inherit);
    }

    #[test]
    fn named_variables_reach_the_guest() {
        let cli = cli_from(&["--guest-env", "RUST_LOG=trace"]);
        assert_eq!(
            cli.env_policy().build().unwrap(),
            vec![("RUST_LOG".to_string(), "trace".to_string())]
        );
    }

    /// Regression guard for the credential leak this binary used to have: it
    /// forwarded the whole host environment, including AWS_SECRET_ACCESS_KEY,
    /// into the guest.
    #[test]
    fn host_credentials_never_reach_the_guest_by_default() {
        let cli = cli_from(&["--inherit-env"]);
        let env = cli.env_policy().build().unwrap();
        assert!(
            !env.iter()
                .any(|(k, _)| k.starts_with("AWS_") || k.starts_with("S3FS_")),
            "no credential or runtime variable may be inherited"
        );
    }

    #[test]
    fn the_component_path_is_required() {
        assert!(Cli::try_parse_from([
            "s3fs-runner",
            "--bucket",
            "b",
            "--master-key",
            &"aa".repeat(32)
        ])
        .is_err());
    }
}
