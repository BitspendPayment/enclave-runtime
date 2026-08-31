//! Everything the enclave runtime does, except parse arguments.
//!
//! A library beside the binary rather than inside it, because integration
//! tests cannot import a binary-only crate — and `tests/serve_tls.rs`, where a
//! client checks that the attestation document binds the certificate from its
//! own handshake, is the test this whole design exists to pass.
//!
//! This was `s3fs-host` until the split stopped describing anything. It began
//! as `wasi:filesystem` over a block store, reusable by any host; it ended up
//! also holding the NSM, the vsock tap device, TLS termination and the
//! attestation endpoints, none of which mean anything outside an enclave. The
//! layer that is genuinely independent is [`s3fs_core`], which still has no
//! wasmtime dependency at all.
//!
//! ```text
//!   mount   config          ──▶ Arc<Fs>          two backends, verified root
//!   net     vsock + tap     ──▶ a network        gvforwarder against gvproxy
//!   env     GuestEnvPolicy  ──▶ Vec<(K, V)>      inherit minus a denylist
//!   linker  wasmtime-wasi   ──▶ Linker<State>    everything but filesystem
//!   run     component       ──▶ GuestOutcome     once, with its exit code
//!   serve   component       ──▶ TLS + HTTP       until stopped
//! ```
//!
//! [`wasi`] holds the `wasi:filesystem@0.2.x` implementation. It is written
//! against `s3fs_core::Fs` and knows nothing about AWS or enclaves, so a host
//! with its own state type can still take [`add_filesystem_to_linker`] alone —
//! it is simply no longer packaged as though anyone does.
//!
//! The [`keys`] seam exists so that replacing a configured secret with a KMS
//! release gated on an NSM attestation document is a new implementation of one
//! trait, not a change to any of the above.

pub mod boot;
pub mod clock;
pub mod env;
pub mod flag;
pub mod keys;
pub mod linker;
pub mod mount;
pub mod net;
pub mod random;
pub mod run;
pub mod serve;
pub mod state;
pub mod wasi;

pub use boot::{authorise_successor, boot, BootConfig, BootMode, Booted, ReceiptTrust};
pub use clock::{open_clock, ClockSource, HostClock, PtpClock, TrustedClock, DEFAULT_PTP_DEVICE};
pub use env::GuestEnvPolicy;
pub use flag::parse_bool_flag;
pub use keys::{
    open_key_source, KeyPointer, KmsAttestedKey, KmsKeyConfig, MasterKeyConfig, MasterKeySource,
    MasterKeySourceKind, SealedKey, StaticKey,
};
pub use linker::build_linker;
pub use mount::{connect, create, mount_existing, parse_fs_id, Backends, MountConfig, Mounted};
pub use net::{bring_up, Network, NetworkConfig, NetworkMode, DEFAULT_GVFORWARDER};
pub use nitro_nsm::{Nsm, NsmDevice, DEFAULT_NSM_DEVICE};
pub use random::{open_entropy, GuestRandom, HostEntropy, RandomSource};
pub use run::{
    read_component, run_component, GuestEnvironment, GuestOutcome, EXIT_GUEST_TRAPPED,
    EXIT_RUNTIME_FAILURE,
};
pub use serve::{
    serve_component, AcmeConfig, AnyClientCertificate, CertificateSlot, ClientIdentity,
    EgressPolicy, EnclaveEndpoints, SealedAcmeCache, ServeConfig, ServeHandle, Server, TlsIdentity,
    TlsMode, X_ENCLAVE_CLIENT,
};
pub use state::State;
pub use wasi::{add_filesystem_to_linker, S3FsCtxView, S3WasiView};
