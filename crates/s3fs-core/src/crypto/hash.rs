//! BLAKE3 hashing — the Merkle-tree primitive.
//!
//! Every block pointer carries a [`Hash256`] of the *stored* (post-encryption)
//! bytes of the block it points at. That is what makes the tree a Merkle tree:
//! a parent authenticates each child independently of the AEAD key, so
//! integrity is checkable by a party that cannot decrypt, and a tampered block
//! is caught before it is ever handed to the cipher.

use std::fmt;

use crate::errors::{FsError, FsResult};

/// Length of a hash in bytes.
pub const HASH_LEN: usize = 32;

/// A BLAKE3-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash256([u8; HASH_LEN]);

impl Hash256 {
    /// The all-zero hash. Used as the checksum of a hole (a
    /// [`crate::store::BlkPtr`] that points at nothing) and as the
    /// `prev_root_hash` of the genesis root record.
    pub const ZERO: Hash256 = Hash256([0u8; HASH_LEN]);

    /// Hash arbitrary bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Hash256(*blake3::hash(bytes).as_bytes())
    }

    /// Keyed hash. Used for directory name hashing, where an unkeyed hash
    /// would let anyone who can see the bucket craft names that collide into
    /// one bucket block.
    pub fn keyed(key: &[u8; 32], bytes: &[u8]) -> Self {
        Hash256(*blake3::keyed_hash(key, bytes).as_bytes())
    }

    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Hash256(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; HASH_LEN]
    }

    /// First 8 bytes as a `u64`, for hash-bucket indexing. Big-endian so that
    /// "the top `d` bits" is a prefix of the hex representation, which makes
    /// extendible-hash bucket indices legible in logs and test failures.
    pub fn prefix_u64(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().expect("32 >= 8"))
    }

    /// Constant-time comparison against an expected value.
    ///
    /// Verification results are not secret, but a data-dependent early exit
    /// here would leak how many leading bytes of a forged block matched, which
    /// is enough to mount a byte-at-a-time forgery search against any code
    /// path that lets an attacker submit candidate blocks.
    pub fn verify(&self, expected: &Hash256, context: &'static str) -> FsResult<()> {
        let mut diff = 0u8;
        for i in 0..HASH_LEN {
            diff |= self.0[i] ^ expected.0[i];
        }
        if diff == 0 {
            Ok(())
        } else {
            Err(FsError::Integrity(context))
        }
    }
}

/// Defaults to [`Hash256::ZERO`], which is the checksum of a hole. This is
/// what makes `BlkPtr::default()` a valid hole rather than a nonsense pointer.
impl Default for Hash256 {
    fn default() -> Self {
        Hash256::ZERO
    }
}

impl fmt::Debug for Hash256 {
    /// Abbreviated so log lines and assertion failures stay readable. Eight
    /// hex characters is enough to tell two blocks apart when debugging and
    /// short enough not to swamp a trace.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}…",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl fmt::Display for Hash256 {
    /// Full lowercase hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_matches_blake3_spec() {
        // BLAKE3 of the empty input, from the reference test vectors.
        assert_eq!(
            Hash256::of(b"").to_string(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        // BLAKE3 of "abc".
        assert_eq!(
            Hash256::of(b"abc").to_string(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn zero_is_not_the_hash_of_anything_we_write() {
        // A hole is encoded as an all-zero checksum. If that collided with a
        // real block's hash, a hole and a block would be indistinguishable.
        assert!(Hash256::ZERO.is_zero());
        assert!(!Hash256::of(b"").is_zero());
        assert!(!Hash256::of(&[0u8; 4096]).is_zero());
    }

    #[test]
    fn keying_changes_the_digest() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert_ne!(Hash256::keyed(&k1, b"name"), Hash256::keyed(&k2, b"name"));
        assert_ne!(Hash256::keyed(&k1, b"name"), Hash256::of(b"name"));
        // Deterministic for a fixed key.
        assert_eq!(Hash256::keyed(&k1, b"name"), Hash256::keyed(&k1, b"name"));
    }

    #[test]
    fn verify_accepts_match_and_rejects_mismatch() {
        let h = Hash256::of(b"block");
        assert!(h.verify(&h, "test").is_ok());

        let other = Hash256::of(b"block!");
        assert!(matches!(
            h.verify(&other, "blkptr checksum"),
            Err(FsError::Integrity("blkptr checksum"))
        ));
    }

    #[test]
    fn verify_rejects_a_single_flipped_bit() {
        let h = Hash256::of(b"block");
        let mut tampered = *h.as_bytes();
        tampered[31] ^= 0x01;
        assert!(Hash256::from_bytes(tampered).verify(&h, "test").is_err());

        let mut tampered = *h.as_bytes();
        tampered[0] ^= 0x80;
        assert!(Hash256::from_bytes(tampered).verify(&h, "test").is_err());
    }

    #[test]
    fn round_trips_through_bytes() {
        let h = Hash256::of(b"round trip");
        assert_eq!(Hash256::from_bytes(*h.as_bytes()), h);
    }

    #[test]
    fn prefix_is_the_big_endian_leading_bytes() {
        let h = Hash256::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(h.prefix_u64(), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn debug_is_short_display_is_full() {
        let h = Hash256::of(b"abc");
        assert_eq!(format!("{h:?}"), "6437b3ac…");
        assert_eq!(h.to_string().len(), 64);
    }
}
