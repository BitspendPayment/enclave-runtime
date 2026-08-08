//! Cryptographic primitives for the block store.
//!
//! Three jobs, three submodules:
//!
//! - [`hash`] — BLAKE3 digests. Every block pointer carries the hash of the
//!   block it points at, which is what makes the object tree a Merkle tree.
//! - [`aead`] — AES-256-GCM over stored blocks, with nonces derived from the
//!   txg and additional data binding each block to its position in the tree.
//! - [`sign`] — Ed25519 over root records, so a root cannot be minted or
//!   re-pointed by anyone holding only bucket write access.
//!
//! [`keys`] ties them together: one master secret, HKDF-separated per purpose.
//!
//! Primitives come from `aws-lc-rs` (the same stack KMS speaks, FIPS-capable)
//! except BLAKE3, which has no aws-lc equivalent and is chosen for the block
//! checksum because it is the hot path — every block read verifies one.

pub mod aead;
pub mod hash;
pub mod keys;
pub mod sign;

pub use aead::{BlockAad, BlockNonce, TAG_LEN};
pub use hash::{Hash256, HASH_LEN};
pub use keys::{KeyMaterial, MasterSecret, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
