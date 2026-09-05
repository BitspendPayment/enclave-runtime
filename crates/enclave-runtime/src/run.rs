//! Reading a guest component, and the environment every instance is built from.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use s3fs_core::Fs;
use wasmtime_wasi::WasiCtxBuilder;

use crate::clock::{TrustedClock, WallClockAdapter};
use crate::guest_io::GuestLogs;
use crate::random::GuestRandom;
use crate::state::State;
use nitro_nsm::Nsm;

/// Exit code for a failure before the guest ever started — the filesystem
/// would not mount, or the component would not compile.
pub const EXIT_RUNTIME_FAILURE: i32 = 71;

/// How the runtime ended.
///
/// The parent instance reads the enclave's exit status, and "it stopped
/// serving" and "the filesystem refused to mount" call for different
/// responses. The second is a security event, not a bug in the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestOutcome {
    /// The runtime did what it was asked and stopped.
    Success,
    /// It stopped for a reason it could report.
    Failed,
}

impl GuestOutcome {
    pub fn exit_code(self) -> i32 {
        match self {
            GuestOutcome::Success => 0,
            GuestOutcome::Failed => 1,
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

/// Everything a guest instance is built from, in a form that can be used more
/// than once.
///
/// A `wasi:cli/command` guest needs one instance and one [`State`]. A
/// `wasi:http/proxy` guest needs a fresh `State` per request — a `Store` cannot
/// be reused across requests, and reusing one would leak a guest's resource
/// table into the next caller's request. Both must produce *identical*
/// environments, so both go through here rather than each building a
/// `WasiCtxBuilder` and drifting.
///
/// The filesystem is shared, deliberately: `Arc<Fs>` is one mounted
/// filesystem with one transaction stream, so writes from separate requests
/// land in the same store rather than racing two views of it.
pub struct GuestEnvironment {
    fs: Arc<Fs>,
    clock: Arc<WallClockAdapter>,
    entropy: Arc<dyn Nsm>,
    env: Vec<(String, String)>,
    args: Vec<String>,
    /// Where the guest's stdout and stderr go. Shared by every instance this
    /// environment builds, so however many guests run, their output meets one
    /// bounded queue and one collector.
    logs: GuestLogs,
}

impl GuestEnvironment {
    /// `logs` is required rather than defaulted, so every caller has to answer
    /// the question of where guest output goes. There is no arrangement in
    /// which it is inherited by omission — that was the previous behaviour,
    /// and it put untrusted guest text straight onto the enclave console with
    /// nothing marking it as untrusted.
    pub fn new(
        fs: Arc<Fs>,
        clock: Box<dyn TrustedClock>,
        entropy: Arc<dyn Nsm>,
        env: &[(String, String)],
        args: &[String],
        logs: GuestLogs,
    ) -> Result<Self> {
        Ok(GuestEnvironment {
            fs,
            // One adapter shared by the guest's clock interface and the
            // filesystem's "now", so `set-times` cannot disagree with
            // `wall-clock`.
            clock: Arc::new(WallClockAdapter::new(clock)?),
            entropy,
            env: env.to_vec(),
            args: args.to_vec(),
            logs,
        })
    }

    pub fn fs(&self) -> &Arc<Fs> {
        &self.fs
    }

    /// Build a fresh [`State`] whose guest sees `scope` as `/`.
    ///
    /// Everything else — the filesystem, the clock, the entropy source, the
    /// environment, the arguments — is shared. One mounted filesystem, one
    /// block cache, one transaction stream; what differs between two clients
    /// is only which directory each of them calls `/`, and that separation is
    /// enforced by the resolver rather than by anything the guest does.
    pub fn new_state_scoped(&self, scope: Arc<s3fs_core::Inode>) -> Result<State> {
        let mut wasi = WasiCtxBuilder::new();
        // Closed, not inherited. An enclave has no console to read from, so an
        // inherited stdin offered a guest nothing but a handle on whatever the
        // parent had attached to this process. Stated rather than left to the
        // builder's default, because "the guest cannot read stdin" is a
        // decision and not an accident.
        wasi.stdin(tokio::io::empty());
        // Never `inherit_stdio`. Guest output is untrusted, attacker-chosen
        // text; on the enclave's own stdout it would be indistinguishable from
        // the runtime's log lines. These carry it into `crate::guest_io`
        // instead, tagged by stream and marked as guest-produced.
        wasi.stdout(self.logs.stdout());
        wasi.stderr(self.logs.stderr());
        wasi.envs(&self.env);
        wasi.args(&self.args);
        wasi.wall_clock(SharedWallClock(self.clock.clone()));

        let random = GuestRandom::new(self.entropy.clone());
        wasi.insecure_random_seed(random.insecure_seed()?);
        wasi.secure_random(random);

        Ok(State::scoped(
            wasi.build(),
            self.fs.clone(),
            scope,
            self.clock.clone(),
        ))
    }

    /// Build a fresh [`State`] with this environment's capabilities.
    ///
    /// Each call draws a new insecure-random seed from the entropy source, so
    /// two guest instances do not share a hash seed.
    pub fn new_state(&self) -> Result<State> {
        self.new_state_scoped(self.fs.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failure before the guest ever started is not the same as the runtime
    /// stopping, and the parent reads the difference off the exit status.
    #[test]
    fn exit_codes_distinguish_the_outcomes() {
        assert_eq!(GuestOutcome::Success.exit_code(), 0);
        assert_eq!(GuestOutcome::Failed.exit_code(), 1);
        assert!(GuestOutcome::Success.is_success());
        assert!(!GuestOutcome::Failed.is_success());
        assert_ne!(EXIT_RUNTIME_FAILURE, GuestOutcome::Failed.exit_code());
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
