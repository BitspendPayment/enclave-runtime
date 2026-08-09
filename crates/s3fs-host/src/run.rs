//! Compiling a guest component, running it, and reporting what happened.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use s3fs_core::Fs;
use wasmtime::component::Component;
use wasmtime::{Engine, Store};
use wasmtime_wasi::WasiCtxBuilder;

use crate::clock::{TrustedClock, WallClockAdapter};
use crate::linker::build_linker;
use crate::nsm::Nsm;
use crate::random::GuestRandom;
use crate::state::State;

/// Exit code for a guest that trapped.
pub const EXIT_GUEST_TRAPPED: i32 = 70;
/// Exit code for a failure before the guest ever started — the filesystem
/// would not mount, or the component would not compile.
pub const EXIT_RUNTIME_FAILURE: i32 = 71;

/// How a guest run ended.
///
/// Distinguishing these matters for a deployment target: the parent instance
/// reads the enclave's exit status, and "the guest exited 3", "the guest
/// trapped", and "the filesystem refused to mount" call for different
/// responses. The last is a security event, not a bug in the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestOutcome {
    /// `wasi:cli/run.run()` returned `Ok`.
    Success,
    /// `wasi:cli/run.run()` returned `Err`.
    Failed,
    /// The guest called `exit(n)`.
    Exited(i32),
    /// The guest trapped.
    Trapped,
}

impl GuestOutcome {
    pub fn exit_code(self) -> i32 {
        match self {
            GuestOutcome::Success => 0,
            GuestOutcome::Failed => 1,
            GuestOutcome::Exited(code) => code,
            GuestOutcome::Trapped => EXIT_GUEST_TRAPPED,
        }
    }

    pub fn is_success(self) -> bool {
        self.exit_code() == 0
    }
}

/// Read a component from disk.
///
/// Names the path it looked at on failure: inside an enclave image that is the
/// single most likely misconfiguration, and there is no shell to go and check.
pub fn read_component(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading guest component at {}", path.display()))
}

/// Compile and run a `wasi:cli/command` component against `fs`.
///
/// `clock` backs `wasi:clocks/wall-clock` and `set-times`' "now". The monotonic
/// clock is left on `wasmtime-wasi`'s default: it backs timer subscriptions, so
/// it must be cheap, and it must never step backwards — which a clock
/// disciplined by an external source can.
///
/// `entropy` backs `wasi:random/random`. `wasi:random/insecure` keeps
/// `wasmtime-wasi`'s generator — it is explicitly not cryptographic, and making
/// it cost a device round trip would be perverse — but its seed is drawn from
/// `entropy` once so it is not deterministic across runs.
pub async fn run_component(
    fs: Arc<Fs>,
    clock: Box<dyn TrustedClock>,
    entropy: Arc<dyn Nsm>,
    component_bytes: &[u8],
    env: &[(String, String)],
    args: &[String],
) -> Result<GuestOutcome> {
    // wasmtime 44 enables async at the engine level when the `async` feature is
    // on; `Config::async_support` is a no-op.
    let engine = Engine::new(&wasmtime::Config::new())?;
    let linker = build_linker(&engine).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let component = Component::new(&engine, component_bytes)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .context("compiling guest component")?;

    // One adapter shared by the guest's clock interface and the filesystem's
    // "now", so `set-times` cannot disagree with `wall-clock`.
    let wall_clock = Arc::new(WallClockAdapter::new(clock)?);

    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdio();
    wasi.envs(env);
    wasi.args(args);
    wasi.wall_clock(SharedWallClock(wall_clock.clone()));

    let random = GuestRandom::new(entropy.clone());
    wasi.insecure_random_seed(random.insecure_seed()?);
    wasi.secure_random(random);

    let mut store = Store::new(&engine, State::new(wasi.build(), fs, wall_clock));

    let command =
        wasmtime_wasi::p2::bindings::Command::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("instantiating wasi:cli/command component")?;

    match command.wasi_cli_run().call_run(&mut store).await {
        Ok(Ok(())) => Ok(GuestOutcome::Success),
        Ok(Err(())) => Ok(GuestOutcome::Failed),
        Err(e) => Ok(classify_run_error(&e)),
    }
}

/// A guest calling `exit(n)` reaches us as a trap carrying `I32Exit`. Without
/// unwrapping it, a deliberate non-zero exit is indistinguishable from a crash
/// and the guest's own status code is lost.
fn classify_run_error(err: &wasmtime::Error) -> GuestOutcome {
    match err.downcast_ref::<wasmtime_wasi::I32Exit>() {
        Some(exit) => GuestOutcome::Exited(exit.0),
        None => {
            tracing::error!(error = %err, "guest trapped");
            GuestOutcome::Trapped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_distinguish_the_outcomes() {
        assert_eq!(GuestOutcome::Success.exit_code(), 0);
        assert_eq!(GuestOutcome::Failed.exit_code(), 1);
        assert_eq!(GuestOutcome::Exited(3).exit_code(), 3);
        assert_eq!(GuestOutcome::Trapped.exit_code(), EXIT_GUEST_TRAPPED);
        assert_ne!(EXIT_GUEST_TRAPPED, EXIT_RUNTIME_FAILURE);
    }

    #[test]
    fn only_success_counts_as_success() {
        assert!(GuestOutcome::Success.is_success());
        assert!(!GuestOutcome::Failed.is_success());
        assert!(!GuestOutcome::Trapped.is_success());
        assert!(!GuestOutcome::Exited(1).is_success());
        // A guest that exits zero explicitly did succeed.
        assert!(GuestOutcome::Exited(0).is_success());
    }

    /// The distinction the mapping exists to preserve: a deliberate `exit(n)`
    /// must not be reported as a crash.
    #[test]
    fn a_deliberate_exit_is_not_a_trap() {
        let err = wasmtime::Error::from(wasmtime_wasi::I32Exit(3));
        assert_eq!(classify_run_error(&err), GuestOutcome::Exited(3));

        let err = wasmtime::Error::msg("unreachable executed");
        assert_eq!(classify_run_error(&err), GuestOutcome::Trapped);
    }

    #[test]
    fn a_missing_component_names_the_path_it_looked_at() {
        let err = read_component(Path::new("/enclave/definitely-absent.wasm")).unwrap_err();
        assert!(
            format!("{err:#}").contains("/enclave/definitely-absent.wasm"),
            "error must name the path: {err:#}"
        );
    }
}

/// `WasiCtxBuilder::wall_clock` takes ownership, but the filesystem needs the
/// same clock for `set-times`. This shares one.
#[derive(Debug, Clone)]
pub struct SharedWallClock(pub Arc<WallClockAdapter>);

impl wasmtime_wasi::HostWallClock for SharedWallClock {
    fn resolution(&self) -> std::time::Duration {
        self.0.resolution()
    }
    fn now(&self) -> std::time::Duration {
        self.0.now()
    }
}
