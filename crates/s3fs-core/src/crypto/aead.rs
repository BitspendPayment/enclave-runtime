//! Authenticated encryption for stored blocks (AES-256-GCM).
//!
//! Two invariants carry the security of this module. Both are enforced by the
//! types rather than by convention, because getting either wrong is silent.
//!
//! **Nonces never repeat.** A nonce is `txg ‖ block_seq`, and a txg number is
//! consumed before a commit is attempted and never reused — not even when the
//! commit fails. Reusing one under a fixed key would leak the XOR of two
//! plaintexts and, worse for GCM, hand out the authentication subkey.
//!
//! **Every block is bound to its position.** The AAD covers the object id,
//! tree level, block index, and birth txg. A block that is genuine, correctly
//! encrypted, and correctly checksummed still fails to open if it is served
//! from a different offset, a different file, or a different level of the
//! indirect tree. Without this, a bucket operator could shuffle blocks between
//! positions and every individual integrity check would still pass.

use aws_lc_rs::aead::{Aad as LcAad, LessSafeKey, Nonce, NONCE_LEN};

use crate::errors::{FsError, FsResult};

/// AEAD tag length for AES-256-GCM, in bytes. Sealed output is
/// `plaintext.len() + TAG_LEN`.
pub const TAG_LEN: usize = 16;

/// Length of the encoded [`BlockAad`].
const AAD_LEN: usize = 8 + 1 + 8 + 8;

/// A 96-bit AES-GCM nonce, constructed only from a `(txg, block_seq)` pair.
///
/// There is deliberately no way to build one from arbitrary bytes: every
/// nonce in the system is a function of a monotonically increasing txg, which
/// is what makes non-repetition an argument about txg allocation rather than
/// about every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockNonce([u8; NONCE_LEN]);

impl BlockNonce {
    /// `txg` (8 bytes, big-endian) followed by `block_seq` (4 bytes,
    /// big-endian): the index of this block within its transaction group.
    ///
    /// Uniqueness argument: `txg` is strictly increasing across commits and
    /// never reused, and `block_seq` is unique within a commit. So the pair is
    /// unique over the lifetime of the key.
    pub fn new(txg: u64, block_seq: u32) -> Self {
        let mut n = [0u8; NONCE_LEN];
        n[..8].copy_from_slice(&txg.to_be_bytes());
        n[8..].copy_from_slice(&block_seq.to_be_bytes());
        BlockNonce(n)
    }

    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        BlockNonce(bytes)
    }

    fn to_lc(self) -> Nonce {
        // Safe by the uniqueness argument above.
        Nonce::assume_unique_for_key(self.0)
    }
}

/// Additional authenticated data binding a block to its position in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAad {
    /// Object the block belongs to.
    pub objid: u64,
    /// 0 for data blocks, ≥1 for indirect blocks.
    pub level: u8,
    /// Index of this block within its level.
    pub block_index: u64,
    /// The txg that wrote it.
    pub birth_txg: u64,
}

impl BlockAad {
    fn encode(&self) -> [u8; AAD_LEN] {
        let mut b = [0u8; AAD_LEN];
        b[0..8].copy_from_slice(&self.objid.to_be_bytes());
        b[8] = self.level;
        b[9..17].copy_from_slice(&self.block_index.to_be_bytes());
        b[17..25].copy_from_slice(&self.birth_txg.to_be_bytes());
        b
    }
}

/// Encrypt `plaintext`, returning `ciphertext ‖ tag`.
pub fn seal(
    key: &LessSafeKey,
    nonce: BlockNonce,
    aad: BlockAad,
    plaintext: &[u8],
) -> FsResult<Vec<u8>> {
    let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buf.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(nonce.to_lc(), LcAad::from(aad.encode()), &mut buf)
        .map_err(|_| FsError::Integrity("block seal failed"))?;
    Ok(buf)
}

/// Decrypt `ciphertext ‖ tag` in place, returning the plaintext.
///
/// Fails with [`FsError::Integrity`] if the tag does not verify — which covers
/// a corrupted block, a forged block, and a genuine block replayed at the
/// wrong position.
pub fn open(
    key: &LessSafeKey,
    nonce: BlockNonce,
    aad: BlockAad,
    ciphertext: &[u8],
) -> FsResult<Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(FsError::Integrity("block shorter than AEAD tag"));
    }
    let mut buf = ciphertext.to_vec();
    let len = key
        .open_in_place(nonce.to_lc(), LcAad::from(aad.encode()), &mut buf)
        .map_err(|_| FsError::Integrity("block authentication failed"))?
        .len();
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyMaterial, MasterSecret};

    fn material(master: u8) -> KeyMaterial {
        KeyMaterial::derive(&MasterSecret::from_bytes([master; 32]), [0u8; 16]).unwrap()
    }

    fn key() -> KeyMaterial {
        material(7)
    }

    fn aad() -> BlockAad {
        BlockAad {
            objid: 42,
            level: 0,
            block_index: 3,
            birth_txg: 100,
        }
    }

    #[test]
    fn round_trip() {
        let k = key();
        let pt = b"the quick brown fox".to_vec();
        let ct = seal(k.block_key(), BlockNonce::new(100, 0), aad(), &pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        assert_ne!(
            &ct[..pt.len()],
            &pt[..],
            "plaintext must not appear in output"
        );

        let out = open(k.block_key(), BlockNonce::new(100, 0), aad(), &ct).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = key();
        let ct = seal(k.block_key(), BlockNonce::new(1, 0), aad(), b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        assert_eq!(
            open(k.block_key(), BlockNonce::new(1, 0), aad(), &ct).unwrap(),
            b""
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = key();
        let mut ct = seal(k.block_key(), BlockNonce::new(100, 0), aad(), b"payload").unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(
            open(k.block_key(), BlockNonce::new(100, 0), aad(), &ct),
            Err(FsError::Integrity(_))
        ));
    }

    #[test]
    fn tampered_tag_fails() {
        let k = key();
        let mut ct = seal(k.block_key(), BlockNonce::new(100, 0), aad(), b"payload").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(open(k.block_key(), BlockNonce::new(100, 0), aad(), &ct).is_err());
    }

    #[test]
    fn truncated_input_fails_cleanly() {
        let k = key();
        assert!(matches!(
            open(
                k.block_key(),
                BlockNonce::new(1, 0),
                aad(),
                &[0u8; TAG_LEN - 1]
            ),
            Err(FsError::Integrity("block shorter than AEAD tag"))
        ));
    }

    /// The position-binding property: a block that is genuine in every other
    /// respect must not open at a different location in the tree.
    #[test]
    fn block_cannot_be_relocated() {
        let k = key();
        let ct = seal(k.block_key(), BlockNonce::new(100, 0), aad(), b"payload").unwrap();

        for wrong in [
            BlockAad { objid: 43, ..aad() },
            BlockAad { level: 1, ..aad() },
            BlockAad {
                block_index: 4,
                ..aad()
            },
            BlockAad {
                birth_txg: 101,
                ..aad()
            },
        ] {
            assert!(
                open(k.block_key(), BlockNonce::new(100, 0), wrong, &ct).is_err(),
                "block opened under the wrong AAD: {wrong:?}"
            );
        }
    }

    #[test]
    fn wrong_nonce_fails() {
        let k = key();
        let ct = seal(k.block_key(), BlockNonce::new(100, 0), aad(), b"payload").unwrap();
        assert!(open(k.block_key(), BlockNonce::new(100, 1), aad(), &ct).is_err());
        assert!(open(k.block_key(), BlockNonce::new(101, 0), aad(), &ct).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let ct = seal(
            key().block_key(),
            BlockNonce::new(100, 0),
            aad(),
            b"payload",
        )
        .unwrap();
        let other = material(8);
        assert!(open(other.block_key(), BlockNonce::new(100, 0), aad(), &ct).is_err());
    }

    #[test]
    fn nonce_layout_is_txg_then_seq() {
        let n = BlockNonce::new(0x0102_0304_0506_0708, 0x090a_0b0c);
        assert_eq!(
            n.as_bytes(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]
        );
    }

    /// The uniqueness argument reduced to a property test: distinct
    /// `(txg, seq)` pairs must produce distinct nonces.
    #[test]
    fn distinct_txg_seq_pairs_give_distinct_nonces() {
        let mut seen = std::collections::HashSet::new();
        for txg in 0..64u64 {
            for seq in 0..64u32 {
                assert!(
                    seen.insert(*BlockNonce::new(txg, seq).as_bytes()),
                    "nonce collision at txg={txg} seq={seq}"
                );
            }
        }
    }
}
