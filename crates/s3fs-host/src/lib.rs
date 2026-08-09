//! `s3fs-host` — `wasi:filesystem` over the block store, plus the wiring that
//! turns a mounted filesystem and a Wasm component into a running guest.
//!
//! Shared by two binaries with different jobs. `s3fs-runner` is the
//! development CLI: explicit flags, local or MinIO storage. `enclave-runtime`
//! is the deployment target: configured by environment, guest loaded from a
//! known path inside the enclave image. Both need the same four things, and
//! this crate is those four things.
//!
//! ```text
//!   mount   config          ──▶ Arc<Fs>          two backends, verified root
//!   env     GuestEnvPolicy  ──▶ Vec<(K, V)>      inherit minus a denylist
//!   linker  wasmtime-wasi   ──▶ Linker<State>    everything but filesystem
//!   run     component       ──▶ GuestOutcome     with the guest's exit code
//! ```
//!
//! [`wasi`] holds the `wasi:filesystem@0.2.x` implementation itself. It is
//! written against `s3fs_core::Fs` and knows nothing about AWS, so it works
//! over any `Backend` — which is why [`mount`], the only part needing the SDK,
//! sits behind the `aws` feature. A host with its own state type can take
//! [`add_filesystem_to_linker`] alone and build the rest itself.
//!
//! The [`keys`] seam exists so that replacing a configured secret with a
//! KMS release gated on an NSM attestation document is a new implementation
//! of one trait, not a change to any of the above.

pub mod clock;
pub mod env;
pub mod flag;
pub mod keys;
pub mod linker;
#[cfg(feature = "aws")]
pub mod mount;
pub mod random;
pub mod run;
#[cfg(feature = "serve")]
pub mod serve;
pub mod state;
pub mod wasi;

pub use clock::{open_clock, ClockSource, HostClock, PtpClock, TrustedClock, DEFAULT_PTP_DEVICE};
pub use env::GuestEnvPolicy;
pub use flag::parse_bool_flag;
pub use keys::{MasterKeySource, StaticKey};
pub use linker::build_linker;
#[cfg(feature = "aws")]
pub use mount::{mount, parse_fs_id, MountConfig};
pub use nitro_nsm::{Nsm, NsmDevice, DEFAULT_NSM_DEVICE};
pub use random::{open_entropy, GuestRandom, HostEntropy, RandomSource};
pub use run::{
    read_component, run_component, GuestEnvironment, GuestOutcome, EXIT_GUEST_TRAPPED,
    EXIT_RUNTIME_FAILURE,
};
#[cfg(feature = "serve")]
pub use serve::{
    serve_component, EgressPolicy, EnclaveEndpoints, ServeConfig, ServeHandle, Server, TlsIdentity,
    TlsMode,
};
pub use state::State;
pub use wasi::{add_filesystem_to_linker, S3FsCtxView, S3WasiView};
