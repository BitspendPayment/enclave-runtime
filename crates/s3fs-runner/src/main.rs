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
use s3fs_core::Fs;
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
    /// S3 bucket name.
    #[arg(long, env = "S3FS_BUCKET")]
    bucket: String,

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

    /// Path to the `.wasm` component file.
    #[arg(long, short = 'c')]
    component: PathBuf,

    /// Arguments to pass to the guest as `wasi:cli/environment.get-arguments()`.
    #[arg(last = true)]
    guest_args: Vec<String>,
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
    let backend = if cli.skip_bucket_probe {
        AwsS3Backend::connect_unchecked(backend_cfg).await?
    } else {
        AwsS3Backend::connect(backend_cfg).await?
    };
    let fs_config = s3fs_core::Config::builder()
        .bucket_prefix(cli.bucket_prefix.clone())
        .mount_path(cli.mount_path.clone())
        .build();
    let fs: Arc<Fs> = Fs::new(Arc::new(backend) as Arc<dyn Backend>, Arc::new(fs_config));

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
    wasi_builder.envs(&std::env::vars().collect::<Vec<_>>());
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
