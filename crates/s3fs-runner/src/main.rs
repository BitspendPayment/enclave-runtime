//! `s3fs-runner` — load a `wasi:cli/command` component and run it with
//! `wasi:filesystem` backed by S3 (or S3-compatible storage like MinIO).
//!
//! The full WASI surface is provided: `wasi:io`, `wasi:cli`, `wasi:clocks`,
//! `wasi:random`, and `wasi:sockets` come from `wasmtime-wasi`; only
//! `wasi:filesystem` is taken over by `s3fs-wasmtime` and routed to an
//! `s3fs_core::Fs` over an `AwsS3Backend`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result as AnyResult};
use clap::Parser;
use s3fs_core::backend::{AwsS3Backend, AwsS3BackendConfig, Backend};
use s3fs_core::{Fs, MasterSecret};
use s3fs_wasmtime::{S3FsCtxView, S3WasiView};
use wasmtime::component::{Component, HasData, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::cli::{WasiCli, WasiCliView};
use wasmtime_wasi::clocks::{WasiClocks, WasiClocksView};
use wasmtime_wasi::random::{WasiRandom, WasiRandomView};
use wasmtime_wasi::sockets::{WasiSockets, WasiSocketsView};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

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
    ///
    /// In production these should differ: the roots bucket carries Object Lock
    /// COMPLIANCE retention and is the entire rollback guarantee, while the
    /// data bucket stays unlocked so dead copy-on-write blocks remain
    /// reclaimable.
    #[arg(long, env = "S3FS_ROOTS_BUCKET")]
    roots_bucket: Option<String>,

    /// 32-byte master secret, hex encoded. Every other key is derived from it.
    ///
    /// This is a development seam. In an enclave it is replaced by a
    /// `kms:Decrypt` whose key policy binds release to the attestation
    /// document's PCRs; the on-disk format is identical either way.
    #[arg(long, env = "S3FS_MASTER_KEY")]
    master_key: String,

    /// Filesystem identifier, 32 hex characters. Used as the key-derivation
    /// salt, so two filesystems under one master secret stay independent.
    ///
    /// Supplied rather than read from the store: the keys that verify a root
    /// record are derived from it, so taking it from the store would mean
    /// trusting the store to say which key checks its own signature.
    #[arg(
        long,
        env = "S3FS_ID",
        default_value = "00000000000000000000000000000000"
    )]
    fs_id: String,

    /// Refuse to mount a root record older than this sequence number.
    ///
    /// The one defence against a store that hides newer roots at a cold mount.
    #[arg(long, env = "S3FS_MIN_ROOT_SEQ")]
    min_root_seq: Option<u64>,

    /// AWS region.
    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    region: String,

    /// Endpoint override (e.g. http://127.0.0.1:9000 for MinIO).
    #[arg(long, env = "S3FS_ENDPOINT")]
    endpoint: Option<String>,

    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    access_key_id: Option<String>,

    #[arg(long, env = "AWS_SECRET_ACCESS_KEY")]
    secret_access_key: Option<String>,

    #[arg(long, env = "AWS_SESSION_TOKEN")]
    session_token: Option<String>,

    /// Use path-style addressing (required for MinIO and many S3-compatibles).
    #[arg(long, env = "S3FS_FORCE_PATH_STYLE")]
    force_path_style: bool,

    /// Optional key prefix inside the bucket. All paths are scoped under this.
    #[arg(long, env = "S3FS_BUCKET_PREFIX", default_value = "")]
    bucket_prefix: String,

    /// Path the guest sees as its preopen root (default `/`).
    #[arg(long, env = "S3FS_MOUNT_PATH", default_value = "/")]
    mount_path: String,

    /// Skip the `HeadBucket` startup probe.
    #[arg(long)]
    skip_bucket_probe: bool,

    /// Environment variable to pass through to the guest, as `NAME` (inherit
    /// from the host) or `NAME=VALUE` (set explicitly). Repeatable.
    ///
    /// The guest's environment is empty by default. Nothing is inherited
    /// implicitly, because the host environment is where the S3 credentials
    /// live — see [`build_guest_env`].
    #[arg(long = "guest-env", value_name = "NAME[=VALUE]")]
    guest_env: Vec<String>,

    /// Path to the `.wasm` component file.
    #[arg(long, short = 'c')]
    component: PathBuf,

    /// Arguments to pass to the guest as `wasi:cli/environment.get-arguments()`.
    #[arg(last = true)]
    guest_args: Vec<String>,
}

/// Parse the 32-hex-character filesystem identifier.
fn parse_fs_id(s: &str) -> AnyResult<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        anyhow::bail!("--fs-id must be 32 hex characters, got {}", s.len());
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("--fs-id is not valid hex"))?;
    }
    Ok(out)
}

/// Names that almost never belong in a guest environment. Passing one is
/// allowed — the user asked for it by name — but it gets a warning, because
/// in the enclave deployment these hold KMS-released credentials and the
/// guest is the untrusted party.
const SENSITIVE_ENV_PREFIXES: &[&str] = &["AWS_", "S3FS_"];

/// Build the guest's environment from explicit `--guest-env` entries.
///
/// The guest environment is empty unless something is named here. This used
/// to be `std::env::vars()`, which handed the guest every host variable —
/// including `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. Inside an
/// enclave those are KMS-released credentials whose entire purpose is to be
/// unreachable by the code we are running.
///
/// `NAME` inherits the host's value; `NAME=VALUE` sets one explicitly. A bare
/// `NAME` that is unset on the host is skipped rather than passed as empty,
/// so the guest can distinguish "unset" from "set to nothing".
fn build_guest_env(specs: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let (name, value) = match spec.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (spec.as_str(), None),
        };
        if name.is_empty() {
            anyhow::bail!("--guest-env: empty variable name in {spec:?}");
        }
        let value = match value {
            Some(v) => v,
            None => match std::env::var(name) {
                Ok(v) => v,
                Err(_) => {
                    tracing::debug!(name, "--guest-env: not set on host, skipping");
                    continue;
                }
            },
        };
        if SENSITIVE_ENV_PREFIXES.iter().any(|p| name.starts_with(p)) {
            tracing::warn!(
                name,
                "--guest-env: exposing a host credential variable to guest code"
            );
        }
        out.push((name.to_string(), value));
    }
    Ok(out)
}

/// The store-data type. Implements both `WasiView` (so `wasmtime-wasi` can
/// serve `wasi:io`/`wasi:cli`/etc.) and `S3WasiView` (so `s3fs-wasmtime` can
/// serve `wasi:filesystem`).
struct State {
    wasi: WasiCtx,
    table: ResourceTable,
    fs: Arc<Fs>,
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl S3WasiView for State {
    fn s3fs_view(&mut self) -> S3FsCtxView<'_> {
        // Share the SAME ResourceTable instance with wasmtime-wasi so stream
        // resources we push are visible to wasmtime-wasi's stream methods.
        S3FsCtxView {
            fs: &self.fs,
            table: &mut self.table,
        }
    }
}

/// Marker for `wasi:io` interfaces — they need `&mut ResourceTable`.
struct HasIo;
impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

/// Add every `wasmtime-wasi` interface to the linker EXCEPT `wasi:filesystem`,
/// which `s3fs-wasmtime` will provide instead.
///
/// Body cloned from `wasmtime_wasi::p2::add_to_linker_with_options_async`,
/// minus the two `filesystem::*` lines.
fn add_wasi_minus_filesystem(linker: &mut Linker<State>) -> AnyResult<()> {
    use wasmtime_wasi::p2::bindings::{cli, clocks, random, sockets};
    use wasmtime_wasi_io::bindings::wasi::io;
    let l = linker;
    let options = wasmtime_wasi::p2::bindings::LinkOptions::default();

    // wasi:io (async)
    io::error::add_to_linker::<State, HasIo>(l, |t| t.ctx().table)?;
    io::poll::add_to_linker::<State, HasIo>(l, |t| t.ctx().table)?;
    io::streams::add_to_linker::<State, HasIo>(l, |t| t.ctx().table)?;

    // sockets (async)
    sockets::tcp::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::udp::add_to_linker::<State, WasiSockets>(l, State::sockets)?;

    // clocks
    clocks::wall_clock::add_to_linker::<State, WasiClocks>(l, State::clocks)?;
    clocks::monotonic_clock::add_to_linker::<State, WasiClocks>(l, State::clocks)?;

    // random
    random::random::add_to_linker::<State, WasiRandom>(l, State::random)?;
    random::insecure::add_to_linker::<State, WasiRandom>(l, State::random)?;
    random::insecure_seed::add_to_linker::<State, WasiRandom>(l, State::random)?;

    // cli
    cli::exit::add_to_linker::<State, WasiCli>(l, &(&options).into(), State::cli)?;
    cli::environment::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::stdin::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::stdout::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::stderr::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_input::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_output::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_stdin::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_stdout::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_stderr::add_to_linker::<State, WasiCli>(l, State::cli)?;

    // sockets (non-async)
    sockets::tcp_create_socket::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::udp_create_socket::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::instance_network::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::network::add_to_linker::<State, WasiSockets>(l, &(&options).into(), State::sockets)?;
    sockets::ip_name_lookup::add_to_linker::<State, WasiSockets>(l, State::sockets)?;

    Ok(())
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,s3fs=debug")),
        )
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    // ---- Build the S3-backed Fs.
    let backend_cfg = AwsS3BackendConfig {
        bucket: cli.bucket.clone(),
        region: cli.region.clone(),
        endpoint: cli.endpoint.clone(),
        access_key_id: cli.access_key_id.clone(),
        secret_access_key: cli.secret_access_key.clone(),
        session_token: cli.session_token.clone(),
        force_path_style: cli.force_path_style,
        request_timeout: Duration::from_secs(30),
    };
    let roots_backend_cfg = backend_cfg.clone();
    let backend = if cli.skip_bucket_probe {
        AwsS3Backend::connect_unchecked(backend_cfg).await?
    } else {
        AwsS3Backend::connect(backend_cfg).await?
    };
    let roots_backend = match &cli.roots_bucket {
        Some(bucket) if *bucket != cli.bucket => {
            let mut cfg = roots_backend_cfg;
            cfg.bucket = bucket.clone();
            Arc::new(AwsS3Backend::connect_unchecked(cfg).await?) as Arc<dyn Backend>
        }
        // One bucket for both. Simpler to operate, but the anchor and the
        // reclaimable data then share a retention policy.
        _ => {
            Arc::new(AwsS3Backend::connect_unchecked(roots_backend_cfg).await?) as Arc<dyn Backend>
        }
    };

    let fs_config = s3fs_core::Config::builder()
        .bucket_prefix(cli.bucket_prefix.clone())
        .mount_path(cli.mount_path.clone())
        .build();

    let master = MasterSecret::from_hex(&cli.master_key)
        .map_err(|e| anyhow::anyhow!("--master-key: {e}"))?;
    let fs_id = parse_fs_id(&cli.fs_id)?;

    let fs: Arc<Fs> = Fs::mount(
        Arc::new(backend) as Arc<dyn Backend>,
        roots_backend,
        &master,
        fs_id,
        Arc::new(fs_config),
        cli.min_root_seq,
    )
    .await
    .map_err(|e| anyhow::anyhow!("mounting filesystem: {e}"))?;

    tracing::info!(
        bucket = %cli.bucket,
        prefix = %cli.bucket_prefix,
        mount = %cli.mount_path,
        component = %cli.component.display(),
        "loaded S3 backend, instantiating component"
    );

    // ---- Build the wasmtime engine + linker.
    // wasmtime 44 enables async at the engine level by default when the
    // `async` feature is on; `Config::async_support` is now a no-op.
    let config = Config::new();
    let engine = Engine::new(&config)?;

    let mut linker: Linker<State> = Linker::new(&engine);
    add_wasi_minus_filesystem(&mut linker)?;
    s3fs_wasmtime::add_to_linker(&mut linker).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let bytes = std::fs::read(&cli.component).context("reading component bytes")?;
    let component = Component::new(&engine, &bytes)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .with_context(|| format!("compiling component {}", cli.component.display()))?;

    // ---- Build the store with our State.
    let mut wasi_builder = WasiCtxBuilder::new();
    wasi_builder.inherit_stdio();
    wasi_builder.envs(&build_guest_env(&cli.guest_env)?);
    wasi_builder.args(&cli.guest_args);
    let state = State {
        wasi: wasi_builder.build(),
        table: ResourceTable::new(),
        fs: fs.clone(),
    };
    let mut store = Store::new(&engine, state);

    // ---- Instantiate and call the wasi:cli/run.run() export.
    let command =
        wasmtime_wasi::p2::bindings::Command::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("instantiating wasi:cli/command component")?;
    let run_result = command
        .wasi_cli_run()
        .call_run(&mut store)
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .context("calling wasi:cli/run.run()")?;

    match run_result {
        Ok(()) => {
            tracing::info!("guest exited successfully");
            Ok(())
        }
        Err(()) => {
            anyhow::bail!("guest signalled failure (returned Err from wasi:cli/run.run())");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_spec_list_yields_empty_environment() {
        // The property that matters: a guest gets nothing unless asked for.
        assert!(build_guest_env(&[]).unwrap().is_empty());
    }

    #[test]
    fn explicit_value_is_passed_through() {
        let env = build_guest_env(&["RUST_LOG=debug".to_string()]).unwrap();
        assert_eq!(env, vec![("RUST_LOG".to_string(), "debug".to_string())]);
    }

    #[test]
    fn value_may_contain_equals_signs() {
        let env = build_guest_env(&["OPTS=a=1,b=2".to_string()]).unwrap();
        assert_eq!(env, vec![("OPTS".to_string(), "a=1,b=2".to_string())]);
    }

    #[test]
    fn explicit_empty_value_is_kept() {
        let env = build_guest_env(&["EMPTY=".to_string()]).unwrap();
        assert_eq!(env, vec![("EMPTY".to_string(), String::new())]);
    }

    #[test]
    fn bare_name_inherits_from_host() {
        std::env::set_var("S3FS_TEST_INHERIT_PRESENT", "yes");
        let env = build_guest_env(&["S3FS_TEST_INHERIT_PRESENT".to_string()]).unwrap();
        assert_eq!(
            env,
            vec![("S3FS_TEST_INHERIT_PRESENT".to_string(), "yes".to_string())]
        );
        std::env::remove_var("S3FS_TEST_INHERIT_PRESENT");
    }

    #[test]
    fn bare_name_unset_on_host_is_skipped_not_blanked() {
        std::env::remove_var("S3FS_TEST_INHERIT_ABSENT");
        let env = build_guest_env(&["S3FS_TEST_INHERIT_ABSENT".to_string()]).unwrap();
        assert!(
            env.is_empty(),
            "unset host var must not become an empty one"
        );
    }

    /// Regression guard for the credential leak: host secrets must not reach
    /// the guest merely because they exist in the host environment.
    #[test]
    fn host_credentials_are_not_inherited_implicitly() {
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "super-secret");
        let env = build_guest_env(&["RUST_LOG=info".to_string()]).unwrap();
        assert!(
            !env.iter().any(|(k, _)| k.starts_with("AWS_")),
            "no AWS_* variable may appear without being named explicitly"
        );
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    #[test]
    fn empty_variable_name_is_rejected() {
        assert!(build_guest_env(&["=value".to_string()]).is_err());
        assert!(build_guest_env(&[String::new()]).is_err());
    }
}
