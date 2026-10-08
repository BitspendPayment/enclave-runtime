//! Everything the enclave runtime does, except parse arguments.
//!
//! A library beside the binary rather than inside it, because integration
//! tests cannot import a binary-only crate — and `tests/serve_tls.rs`, where a
//! client checks that the attestation document binds the certificate from its
//! own handshake, is the test this whole design exists to pass.
//!
//! ```text
//!   mount   config          ──▶ roots bucket     anchors, boot records, guest
//!   boot    receipt + key   ──▶ Arc<Zfs>         genesis, resume or refusal
//!   zfs     parent's disk   ──▶ /tenants, /runtime   anchored after each write
//!   guest   object or file  ──▶ PCR16, locked    before any key is asked for
//!   net     vsock + tap     ──▶ a network        gvforwarder against gvproxy
//!   env     GuestEnvPolicy  ──▶ Vec<(K, V)>      inherit minus a denylist
//!   linker  wasmtime-wasi   ──▶ Linker<State>    all of WASI, plus our own
//!   run     component       ──▶ GuestOutcome     once, with its exit code
//!   serve   component       ──▶ TLS + HTTP       until stopped
//! ```
//!
//! The [`keys`] seam exists so that replacing a configured secret with a KMS
//! release gated on an NSM attestation document is a new implementation of one
//! trait, not a change to any of the above.

pub mod auth;
pub mod boot;
pub mod clock;
pub mod env;
pub mod flag;
pub mod guest;
pub mod guest_io;
pub mod keys;
pub mod linker;
pub mod mount;
pub mod net;
pub mod notify;
pub mod random;
pub mod run;
pub mod serve;
pub mod state;
pub mod store;
pub mod stream;
pub mod tasks;
pub mod tenant;
pub mod zfs;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(any(test, feature = "testing"))]
pub use auth::SoftwareAuthenticator;
pub use auth::{
    build_relying_party, AuthEndpoints, ChallengeStore, FilesystemCredentials, Gate,
    InteractionScope, TokenStore, AUTH_PREFIX, DEFAULT_CAPACITY, DEFAULT_TOKEN_CAPACITY,
};
pub use boot::{boot, BootConfig, BootMode, Booted, Pair, ReceiptTrust};
pub use clock::{open_clock, ClockSource, HostClock, PtpClock, TrustedClock, DEFAULT_PTP_DEVICE};
pub use env::GuestEnvPolicy;
pub use flag::parse_bool_flag;
pub use guest::{fetch_guest, measure_guest, GuestSource, MAX_GUEST_BYTES};
pub use guest_io::cloudwatch::{
    boot_marker as guest_log_boot_marker, open_stream as open_guest_log_stream,
    start as start_guest_log_forwarder, CloudWatchConfig, CloudWatchDestination, CloudWatchLogSink,
    LogDestination, LogForwarder, PutError, PutOutcome, STARTUP_PROBE_TIMEOUT,
};
pub use guest_io::{
    FanOutSink, GuestLogCollector, GuestLogRecord, GuestLogSink, GuestLogs, GuestStream,
    TracingLogSink, GUEST_LOG_TARGET,
};
pub use keys::{
    open_key_source, KeyPointer, KmsAttestedKey, KmsKeyConfig, MasterKeyConfig, MasterKeySource,
    MasterKeySourceKind, SealedKey, StaticKey,
};
pub use linker::build_linker;
pub use mount::{connect, parse_fs_id, MountConfig, DEFAULT_ROOT_RETENTION};
pub use net::{bring_up, Network, NetworkConfig, NetworkMode, DEFAULT_GVFORWARDER};
pub use nitro_nsm::{Nsm, NsmDevice, DEFAULT_NSM_DEVICE};
pub use notify::{
    start as start_notify_forwarder, DeviceRegistry, Notifier, NotifyConfig, NotifyContext,
    NotifyForwarder, PinpointClient, PushTransport, SendError, NOTIFY_STARTUP_PROBE_TIMEOUT,
};
pub use random::{open_entropy, GuestRandom, HostEntropy, RandomSource};
pub use run::{read_component, GuestEnvironment, GuestOutcome, EXIT_RUNTIME_FAILURE};
pub use serve::{
    apply_tenant, serve_component, AcmeConfig, CertificateSlot, GuestEgress, GuestInstance,
    PoolLimits, SealedAcmeCache, ServeConfig, ServeHandle, Server, Tenancy, TenantPool,
    TlsIdentity, TlsMode, X_ENCLAVE_TENANT,
};
pub use state::State;
pub use tenant::Arrival;
pub use zfs::{Disk, Zfs};
