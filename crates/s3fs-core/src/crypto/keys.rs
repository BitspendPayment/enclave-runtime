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
/// Derives a tenant identifier — see [`MasterSecret::derive_tenant_id`].
/// Separate from the key labels above because its output is an *identifier*,
/// not key material, and the two must not be confusable.
///
/// The string keeps its original spelling while the constant does not. A label
/// is an on-disk constant: every tenant's directory name is a function of it,
/// so changing it to match a rename would silently move all of them. The `/v1`
/// is there for changes that mean something.
const INFO_TENANT_ID: &[u8] = b"s3fs/tenant-fsid/v1";
/// Seals the runtime's own secrets — the ACME account key and the TLS
/// certificate's private key — which live outside the filesystem.
///
/// Outside, because the guest's preopen is the filesystem *root*: anything
/// stored there is readable by the guest, and a guest that could read the TLS
/// private key could impersonate the enclave to every client. A separate label
/// keeps that material cryptographically distinct from block data as well as
/// physically separate.
const INFO_RUNTIME_SEAL: &[u8] = b"s3fs/runtime-seal/v1";

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

    /// The raw bytes.
    ///
    /// Named to be conspicuous at the call site. There is exactly one
    /// legitimate reason to reach in here — sealing the secret so it can be
    /// stored — and everything else should take a `&MasterSecret` and derive
    /// what it needs through [`KeyMaterial`], which is why no plain `as_bytes`
    /// exists.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
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

    /// A stable name for one tenant, derived rather than assigned.
    ///
    /// `tenant` is whatever names the tenant — for the enclave runtime, the
    /// SHA-256 of a client's TLS public key, which the handshake proves and
    /// nothing else can forge.
    ///
    /// **Derived** so it need never be stored or looked up: the same tenant
    /// resolves to the same name on every boot, from nothing but the
    /// handshake, with no registry to keep in step.
    ///
    /// **Through the master secret** so the name is not the client's identity
    /// wearing a different hat. The tenant's data is separated by the
    /// capability layer, not by this — the name is only a directory name — but
    /// a directory name reaches places the encrypted tree does not: an enclave
    /// console the parent instance reads, and anything that lists tenants. A
    /// name an outsider cannot compute from a certificate keeps client
    /// identity inside the boundary that is supposed to hold it.
    ///
    /// Not a secret, and nothing derives keys from it.
    pub fn derive_tenant_id(&self, tenant: &[u8]) -> FsResult<[u8; 16]> {
        let mut out = [0u8; 16];
        hkdf(self, tenant, INFO_TENANT_ID, &mut out)?;
        Ok(out)
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
    runtime_seal_key: LessSafeKey,
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

        let mut seal_bytes = [0u8; 32];
        hkdf(master, &fs_uuid, INFO_RUNTIME_SEAL, &mut seal_bytes)?;
        let runtime_seal_key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &seal_bytes)
                .map_err(|_| FsError::Io("AES key setup failed".to_string()))?,
        );
        seal_bytes.zeroize();

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
            runtime_seal_key,
            signing_key,
            public_key,
            dir_hash_key,
            fs_uuid,
        })
    }

    pub fn block_key(&self) -> &LessSafeKey {
        &self.block_key
    }

    /// Seals runtime secrets stored outside the filesystem. See
    /// [`INFO_RUNTIME_SEAL`].
    pub fn runtime_seal_key(&self) -> &LessSafeKey {
        &self.runtime_seal_key
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

#[cfg(test)]
mod tenant_tests {
    use super::*;

    fn master(b: u8) -> MasterSecret {
        MasterSecret::from_bytes([b; 32])
    }

    /// The property the whole scheme rests on: a tenant resolves to the same
    /// name on every boot, from the handshake and nothing stored. If this were
    /// not stable, a returning client would arrive at an empty directory and
    /// their state would look lost.
    #[test]
    fn a_tenant_resolves_to_the_same_name_every_time() {
        let m = master(1);
        let tenant = [0xab; 32];
        assert_eq!(
            m.derive_tenant_id(&tenant).unwrap(),
            m.derive_tenant_id(&tenant).unwrap()
        );
    }

    #[test]
    fn two_tenants_never_share_a_name() {
        let m = master(1);
        assert_ne!(
            m.derive_tenant_id(&[0xab; 32]).unwrap(),
            m.derive_tenant_id(&[0xac; 32]).unwrap()
        );
    }

    /// A different master secret is a different deployment. The same client
    /// against staging and production must not land on the same identifier.
    #[test]
    fn the_master_secret_separates_deployments() {
        let tenant = [0xab; 32];
        assert_ne!(
            master(1).derive_tenant_id(&tenant).unwrap(),
            master(2).derive_tenant_id(&tenant).unwrap()
        );
    }

    /// Derived, not copied. Someone holding a client's certificate knows the
    /// tenant bytes; without the master secret that must tell them nothing
    /// about which name is that client's.
    #[test]
    fn the_identifier_does_not_leak_the_tenant() {
        let tenant = [0xab; 32];
        let id = master(1).derive_tenant_id(&tenant).unwrap();
        assert_ne!(id, tenant[..16]);
        assert_ne!(id, tenant[16..]);
        assert!(!tenant.windows(16).any(|w| w == id));
    }

    /// An identifier is not key material, and the labels are what keep the two
    /// apart. Same secret, same salt, different purpose — the outputs must be
    /// unrelated, or a value published in a root record would say something
    /// about a key that never leaves memory.
    #[test]
    fn the_label_separates_an_identifier_from_a_key() {
        let m = master(1);
        let salt = [0xab; 32];
        let mut as_id = [0u8; 16];
        let mut as_key = [0u8; 16];
        hkdf(&m, &salt, INFO_TENANT_ID, &mut as_id).unwrap();
        hkdf(&m, &salt, INFO_BLOCK, &mut as_key).unwrap();
        assert_ne!(as_id, as_key);
    }
}
