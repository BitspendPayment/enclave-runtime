//! The bucket and the keys: what the runtime keeps outside the pool.
//!
//! - [`backend`] — S3 (and S3-compatible) object storage, plus an in-memory
//!   fake, with the Object Lock and retained-version reads the anchor chain
//!   and the boot records depend on.
//! - [`crypto`] — the key hierarchy off one master secret, Ed25519 signing,
//!   and BLAKE3.
//! - [`error`] — the error type both speak.
//!
//! The state itself is on the ZFS pool — see [`crate::zfs`].

pub mod backend;
pub mod crypto;
pub mod error;

pub use crypto::MasterSecret;
pub use error::{StoreError, StoreResult};
