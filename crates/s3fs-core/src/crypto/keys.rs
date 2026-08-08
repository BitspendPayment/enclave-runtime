//! Key hierarchy.
//!
//! Everything hangs off one 32-byte [`MasterSecret`]. In production that
//! secret comes from `kms:Decrypt` with a `Recipient` attestation document, so
//! KMS releases it only to an enclave whose PCRs match the key policy; in
//! development and tests it comes from config. The derivation below is
//! identical either way, which is the point: the on-disk format does not
//! change when attestation lands.
//!
//! ```text
//!                    MasterSecret (32 bytes, never leaves memory)
//!                            │
//!             HKDF-SHA384(salt = fs_uuid, info = purpose)
//!         ┌──────────────────┼──────────────────┐
//!         ▼                  ▼                  ▼
//!   block AEAD key     Ed25519 seed        dir-hash key
//!   (AES-256-GCM)      (root signing)      (keyed BLAKE3)
//! ```
//!
//! Separate keys per purpose so that a weakness in one use cannot be pivoted
//! into another — in particular, the directory hash key is exposed to
//! chosen-input attacks (a guest picks filenames) in a way the block key
//! never is.

use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
use aws_lc_rs::hkdf::{KeyType, Salt, HKDF_SHA384};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{FsError, FsResult};

/// HKDF info strings. Versioned so a future format revision can rotate
/// derived keys without changing the master secret.
const INFO_BLOCK: &[u8] = b"s3fs/block/v1";
const INFO_ROOTSIGN: &[u8] = b"s3fs/rootsign/v1";
const INFO_DIRHASH: &[u8] = b"s3fs/dirhash/v1";

/// Length of an Ed25519 public key and of a raw signing seed.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// The root of the key hierarchy. Scrubbed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterSecret(bytes)
    }

    /// Parse a 64-character hex string, as supplied by `--data-key` or an
    /// environment variable in development.
    pub fn from_hex(s: &str) -> FsResult<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(FsError::Invalid("master key must be 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| FsError::Invalid("master key is not valid hex"))?;
        }
        Ok(MasterSecret(out))
    }

    /// Generate a fresh random secret. Used when formatting a new filesystem
    /// in development; production keys come from KMS.
    pub fn generate() -> FsResult<Self> {
        let mut out = [0u8; 32];
        aws_lc_rs::rand::fill(&mut out)
            .map_err(|_| FsError::Io("system RNG unavailable".to_string()))?;
        Ok(MasterSecret(out))
    }
}

/// Deliberately opaque: a `Debug` that printed the bytes would leak the key
/// into any log line that formats a struct containing one.
impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret(<redacted>)")
    }
}

/// Arbitrary-length HKDF output.
struct OkmLen(usize);
impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf(secret: &MasterSecret, salt: &[u8], info: &[u8], out: &mut [u8]) -> FsResult<()> {
    let prk = Salt::new(HKDF_SHA384, salt).extract(&secret.0);
    prk.expand(&[info], OkmLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| FsError::Io("HKDF expansion failed".to_string()))
}

/// All keys derived from one master secret, for one filesystem.
pub struct KeyMaterial {
    block_key: LessSafeKey,
    signing_key: Ed25519KeyPair,
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    dir_hash_key: [u8; 32],
    fs_uuid: [u8; 16],
}

impl KeyMaterial {
    /// Derive every per-purpose key.
    ///
    /// `fs_uuid` is the HKDF salt, so two filesystems formatted from the same
    /// master secret still get independent keys. It is stored in the root
    /// record, and is not a secret.
    pub fn derive(master: &MasterSecret, fs_uuid: [u8; 16]) -> FsResult<Self> {
        let mut block_bytes = [0u8; 32];
        hkdf(master, &fs_uuid, INFO_BLOCK, &mut block_bytes)?;
        let block_key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &block_bytes)
                .map_err(|_| FsError::Io("AES key setup failed".to_string()))?,
        );
        block_bytes.zeroize();

        let mut seed = [0u8; 32];
        hkdf(master, &fs_uuid, INFO_ROOTSIGN, &mut seed)?;
        let signing_key = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| FsError::Io("Ed25519 key derivation failed".to_string()))?;
        seed.zeroize();

        let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
        public_key.copy_from_slice(signing_key.public_key().as_ref());

        let mut dir_hash_key = [0u8; 32];
        hkdf(master, &fs_uuid, INFO_DIRHASH, &mut dir_hash_key)?;

        Ok(KeyMaterial {
            block_key,
            signing_key,
            public_key,
            dir_hash_key,
            fs_uuid,
        })
    }

    pub fn block_key(&self) -> &LessSafeKey {
        &self.block_key
    }

    pub fn signing_key(&self) -> &Ed25519KeyPair {
        &self.signing_key
    }

    /// Public half of the root-signing key. Written into each root record so
    /// an external auditor can verify the chain without the master secret.
    pub fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    pub fn dir_hash_key(&self) -> &[u8; 32] {
        &self.dir_hash_key
    }

    pub fn fs_uuid(&self) -> &[u8; 16] {
        &self.fs_uuid
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.dir_hash_key.zeroize();
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("fs_uuid", &hex16(&self.fs_uuid))
            .field("public_key", &hex16(&self.public_key[..8]))
            .finish_non_exhaustive()
    }
}

fn hex16(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterSecret {
        MasterSecret::from_bytes([0x5a; 32])
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = KeyMaterial::derive(&master(), [1u8; 16]).unwrap();
        let b = KeyMaterial::derive(&master(), [1u8; 16]).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.dir_hash_key(), b.dir_hash_key());
    }

    /// The salt is what keeps two filesystems formatted from the same master
    /// secret cryptographically separate.
    #[test]
    fn different_fs_uuid_gives_different_keys() {
        let a = KeyMaterial::derive(&master(), [1u8; 16]).unwrap();
        let b = KeyMaterial::derive(&master(), [2u8; 16]).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.dir_hash_key(), b.dir_hash_key());
    }

    #[test]
    fn different_master_gives_different_keys() {
        let a = KeyMaterial::derive(&MasterSecret::from_bytes([1u8; 32]), [0u8; 16]).unwrap();
        let b = KeyMaterial::derive(&MasterSecret::from_bytes([2u8; 32]), [0u8; 16]).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.dir_hash_key(), b.dir_hash_key());
    }

    /// Purpose separation: the signing seed and the directory hash key are
    /// derived from the same secret and salt, differing only in the info
    /// string. If those collided, the info strings would not be doing
    /// anything.
    #[test]
    fn purposes_are_separated() {
        let km = KeyMaterial::derive(&master(), [0u8; 16]).unwrap();
        assert_ne!(&km.dir_hash_key()[..], &km.public_key()[..]);
    }

    #[test]
    fn hex_parsing_round_trips() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let m = MasterSecret::from_hex(hex).unwrap();
        assert_eq!(m.0[0], 0x01);
        assert_eq!(m.0[31], 0x20);
        // Whitespace from a config file or shell is tolerated.
        assert!(MasterSecret::from_hex(&format!("  {hex}\n")).is_ok());
    }

    #[test]
    fn hex_parsing_rejects_bad_input() {
        assert!(MasterSecret::from_hex("abcd").is_err());
        assert!(MasterSecret::from_hex(&"z".repeat(64)).is_err());
        assert!(MasterSecret::from_hex("").is_err());
    }

    #[test]
    fn generate_produces_distinct_secrets() {
        let a = MasterSecret::generate().unwrap();
        let b = MasterSecret::generate().unwrap();
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, [0u8; 32], "RNG returned all zeros");
    }

    /// A key that prints itself is a key in the logs.
    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let m = MasterSecret::from_bytes([0xab; 32]);
        let s = format!("{m:?}");
        assert_eq!(s, "MasterSecret(<redacted>)");
        assert!(!s.contains("ab"));

        let km = KeyMaterial::derive(&m, [0u8; 16]).unwrap();
        let s = format!("{km:?}");
        assert!(!s.contains(&hex16(km.dir_hash_key())));
    }
}
