//! Cryptographic primitives.
//!
//! - [`hash`] — BLAKE3 digests.
//! - [`sign`] — Ed25519, so an anchor cannot be minted or re-pointed by anyone
//!   holding only bucket write access.
//! - [`keys`] — one master secret, HKDF-separated per purpose.
//!
//! Primitives come from `aws-lc-rs` (the same stack KMS speaks, FIPS-capable)
//! except BLAKE3, which has no aws-lc equivalent.

pub mod hash;
pub mod keys;
pub mod sign;

pub use hash::{Hash256, HASH_LEN};
pub use keys::{KeyMaterial, MasterSecret, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
