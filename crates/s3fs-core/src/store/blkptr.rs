//! `BlkPtr` — the block pointer, and the edge of the Merkle tree.
//!
//! A block pointer says *where* a block lives, *how* to decrypt it, and *what
//! it should hash to*. Because a parent block is itself a block, and its own
//! pointer carries its own checksum, the checksums chain all the way to the
//! root record. Verifying the root therefore verifies every byte beneath it.
//!
//! ## Location, not content
//!
//! The address is a [`Dva`] — a `(txg, slab, offset, len)` tuple naming a byte
//! range inside an immutable slab object — rather than a content hash. This is
//! the ZFS model, and it is chosen deliberately over content-addressed
//! `blocks/<hash>` keys: every block dirtied in a transaction group is packed
//! into a handful of slabs, so a commit costs a couple of PUTs no matter how
//! many blocks changed. One PUT per 128 KiB block would make small-file
//! workloads (a SQLite page write, say) cost a round trip each.
//!
//! ## Wire layout — 128 bytes, big-endian
//!
//! ```text
//!  offset  size  field
//!       0     8  dva.txg          transaction group that allocated the slab
//!       8     2  dva.slab         slab index within that txg
//!      10     4  dva.offset       byte offset within the slab
//!      14     4  dva.len          stored length (ciphertext + AEAD tag)
//!      18     4  logical_len      plaintext length
//!      22     1  level            0 = data, >=1 = indirect
//!      23     1  flags            low nibble: compression algorithm
//!      24     4  fill             non-hole pointers beneath this one
//!      28     8  birth_txg        txg that wrote this block
//!      36    12  nonce            AEAD nonce (txg || block_seq)
//!      48    32  checksum         BLAKE3-256 of the stored bytes
//!      80    48  reserved         must be zero
//! ```
//!
//! Big-endian throughout, matching the AAD and nonce encodings, so a hex dump
//! of a slab reads in the same order as the struct.
//!
//! An all-zero pointer is a *hole*: a sparse region that reads as zeros and
//! occupies no storage. Holes are why growing a file with `set_size` is free.

use crate::crypto::aead::TAG_LEN;
use crate::crypto::{BlockNonce, Hash256};
use crate::errors::{FsError, FsResult};

/// Encoded size of a block pointer.
pub const BLKPTR_LEN: usize = 128;

/// Offset of the `reserved` tail within the encoding.
const RESERVED_OFFSET: usize = 80;

/// Deepest indirect tree we will decode.
///
/// The binding case is the *smallest* record size, not the default. At 128 KiB
/// the fan-out is 1024 and six levels already address more than any real file;
/// but at the 4 KiB minimum the fan-out is only 32, and a file spanning the
/// full `u64` byte range needs 2^52 blocks, hence `1 + ceil(52 / 5) = 12`
/// levels. The limit is set from that worst case with one level to spare.
///
/// Anything deeper is a corrupt or hostile pointer. Rejecting it at decode
/// bounds recursion in the tree walker.
pub const MAX_LEVEL: u8 = 12;

/// Largest block we will decode, as a sanity bound on `logical_len`.
///
/// Without this, a corrupt length field turns into a multi-gigabyte allocation
/// on the read path — a trivial denial of service from anyone who can write to
/// the bucket.
pub const MAX_BLOCK_LEN: u32 = 16 * 1024 * 1024;

/// How many block pointers fit in one block of the given size.
pub const fn blkptrs_per_block(block_size: usize) -> usize {
    block_size / BLKPTR_LEN
}

/// Compression applied before encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Compression {
    #[default]
    None = 0,
}

impl Compression {
    fn from_u8(v: u8) -> FsResult<Self> {
        match v {
            0 => Ok(Compression::None),
            _ => Err(FsError::Integrity("blkptr: unknown compression algorithm")),
        }
    }
}

/// Data Virtual Address — a byte range inside an immutable slab object.
///
/// Hashable because it is the block cache's key: a DVA is allocated once and
/// never reused, so it identifies an immutable byte range for all time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Dva {
    /// Transaction group whose slab holds this block.
    pub txg: u64,
    /// Slab index within that txg.
    pub slab: u16,
    /// Byte offset within the slab.
    pub offset: u32,
    /// Stored length: ciphertext plus AEAD tag.
    pub len: u32,
}

impl Dva {
    /// Byte range within the slab, for a ranged GET.
    pub fn range(&self) -> std::ops::Range<u64> {
        let start = u64::from(self.offset);
        start..start + u64::from(self.len)
    }
}

/// A pointer to one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlkPtr {
    pub dva: Dva,
    /// Plaintext length. Differs from `dva.len` by the AEAD tag and, once
    /// compression is implemented, by the compression ratio.
    pub logical_len: u32,
    /// 0 for data blocks, ≥1 for indirect blocks.
    pub level: u8,
    pub compression: Compression,
    /// Number of non-hole pointers at or beneath this one. Lets a sparse file
    /// report its allocated size, and lets a tree walk skip empty subtrees
    /// without reading them.
    pub fill: u32,
    /// Transaction group that wrote this block. Part of the AEAD AAD, so it
    /// cannot be altered without invalidating the block.
    pub birth_txg: u64,
    pub nonce: BlockNonce,
    /// BLAKE3-256 of the stored (encrypted) bytes.
    pub checksum: Hash256,
}

impl BlkPtr {
    /// The all-zero pointer: a sparse hole.
    pub const HOLE: BlkPtr = BlkPtr {
        dva: Dva {
            txg: 0,
            slab: 0,
            offset: 0,
            len: 0,
        },
        logical_len: 0,
        level: 0,
        compression: Compression::None,
        fill: 0,
        birth_txg: 0,
        nonce: BlockNonce::from_bytes([0u8; 12]),
        checksum: Hash256::ZERO,
    };

    /// `true` if this pointer addresses nothing — a sparse region that reads
    /// as zeros.
    pub fn is_hole(&self) -> bool {
        self.dva.len == 0 && self.checksum.is_zero()
    }

    pub fn encode(&self) -> [u8; BLKPTR_LEN] {
        let mut b = [0u8; BLKPTR_LEN];
        b[0..8].copy_from_slice(&self.dva.txg.to_be_bytes());
        b[8..10].copy_from_slice(&self.dva.slab.to_be_bytes());
        b[10..14].copy_from_slice(&self.dva.offset.to_be_bytes());
        b[14..18].copy_from_slice(&self.dva.len.to_be_bytes());
        b[18..22].copy_from_slice(&self.logical_len.to_be_bytes());
        b[22] = self.level;
        b[23] = self.compression as u8;
        b[24..28].copy_from_slice(&self.fill.to_be_bytes());
        b[28..36].copy_from_slice(&self.birth_txg.to_be_bytes());
        b[36..48].copy_from_slice(self.nonce.as_bytes());
        b[48..80].copy_from_slice(self.checksum.as_bytes());
        // b[80..128] stays zero.
        b
    }

    /// Decode and validate.
    ///
    /// Validation is strict — every rejection here is a pointer that could
    /// only have come from corruption or tampering, and the cost of accepting
    /// one is either wrong data or an unbounded allocation. Unknown bits are
    /// rejected rather than ignored; the root record's `format_version` is the
    /// mechanism for evolving this layout.
    pub fn decode(bytes: &[u8]) -> FsResult<BlkPtr> {
        if bytes.len() != BLKPTR_LEN {
            return Err(FsError::Integrity("blkptr: wrong length"));
        }
        if bytes[RESERVED_OFFSET..].iter().any(|&b| b != 0) {
            return Err(FsError::Integrity("blkptr: reserved bytes not zero"));
        }
        if bytes.iter().all(|&b| b == 0) {
            return Ok(BlkPtr::HOLE);
        }

        let ptr = BlkPtr {
            dva: Dva {
                txg: u64::from_be_bytes(bytes[0..8].try_into().expect("8 bytes")),
                slab: u16::from_be_bytes(bytes[8..10].try_into().expect("2 bytes")),
                offset: u32::from_be_bytes(bytes[10..14].try_into().expect("4 bytes")),
                len: u32::from_be_bytes(bytes[14..18].try_into().expect("4 bytes")),
            },
            logical_len: u32::from_be_bytes(bytes[18..22].try_into().expect("4 bytes")),
            level: bytes[22],
            compression: Compression::from_u8(bytes[23])?,
            fill: u32::from_be_bytes(bytes[24..28].try_into().expect("4 bytes")),
            birth_txg: u64::from_be_bytes(bytes[28..36].try_into().expect("8 bytes")),
            nonce: BlockNonce::from_bytes(bytes[36..48].try_into().expect("12 bytes")),
            checksum: Hash256::from_bytes(bytes[48..80].try_into().expect("32 bytes")),
        };

        // A non-hole must actually point somewhere. Catching a partially-zero
        // pointer here stops it being mistaken for a hole, which would silently
        // turn tampering into a file full of zeros.
        if ptr.checksum.is_zero() {
            return Err(FsError::Integrity("blkptr: non-hole with zero checksum"));
        }
        if ptr.dva.len < TAG_LEN as u32 {
            return Err(FsError::Integrity("blkptr: stored length below AEAD tag"));
        }
        if ptr.level > MAX_LEVEL {
            return Err(FsError::Integrity("blkptr: level exceeds maximum"));
        }
        if ptr.logical_len > MAX_BLOCK_LEN || ptr.dva.len > MAX_BLOCK_LEN {
            return Err(FsError::Integrity("blkptr: block length exceeds maximum"));
        }
        // Uncompressed blocks are exactly plaintext plus tag. This catches a
        // length field edited to over- or under-read the slab.
        if ptr.compression == Compression::None && ptr.dva.len != ptr.logical_len + TAG_LEN as u32 {
            return Err(FsError::Integrity(
                "blkptr: stored length inconsistent with logical length",
            ));
        }
        if ptr.dva.offset.checked_add(ptr.dva.len).is_none() {
            return Err(FsError::Integrity("blkptr: slab range overflows"));
        }
        Ok(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BlkPtr {
        BlkPtr {
            dva: Dva {
                txg: 0x0102_0304_0506_0708,
                slab: 0x090a,
                offset: 0x0b0c_0d0e,
                len: 4096 + TAG_LEN as u32,
            },
            logical_len: 4096,
            level: 2,
            compression: Compression::None,
            fill: 7,
            birth_txg: 0x1112_1314_1516_1718,
            nonce: BlockNonce::new(0x1112_1314_1516_1718, 5),
            checksum: Hash256::of(b"block bytes"),
        }
    }

    #[test]
    fn encoding_is_exactly_128_bytes() {
        assert_eq!(sample().encode().len(), BLKPTR_LEN);
        assert_eq!(BLKPTR_LEN, 128);
    }

    #[test]
    fn round_trips() {
        let p = sample();
        assert_eq!(BlkPtr::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn hole_round_trips_and_is_all_zero() {
        let encoded = BlkPtr::HOLE.encode();
        assert!(encoded.iter().all(|&b| b == 0));
        assert_eq!(BlkPtr::decode(&encoded).unwrap(), BlkPtr::HOLE);
        assert!(BlkPtr::HOLE.is_hole());
        assert!(!sample().is_hole());
    }

    #[test]
    fn field_offsets_are_stable() {
        // The on-disk layout is a compatibility surface: if these move,
        // existing filesystems become unreadable. Pin them explicitly rather
        // than trusting the round-trip test, which would pass even if two
        // fields swapped places.
        let b = sample().encode();
        assert_eq!(&b[0..8], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&b[8..10], &0x090au16.to_be_bytes());
        assert_eq!(&b[10..14], &0x0b0c_0d0eu32.to_be_bytes());
        assert_eq!(&b[14..18], &(4096u32 + TAG_LEN as u32).to_be_bytes());
        assert_eq!(&b[18..22], &4096u32.to_be_bytes());
        assert_eq!(b[22], 2);
        assert_eq!(b[23], 0);
        assert_eq!(&b[24..28], &7u32.to_be_bytes());
        assert_eq!(&b[28..36], &0x1112_1314_1516_1718u64.to_be_bytes());
        assert_eq!(
            &b[36..48],
            BlockNonce::new(0x1112_1314_1516_1718, 5).as_bytes()
        );
        assert_eq!(&b[48..80], Hash256::of(b"block bytes").as_bytes());
        assert!(b[80..].iter().all(|&x| x == 0));
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(BlkPtr::decode(&[0u8; 127]).is_err());
        assert!(BlkPtr::decode(&[0u8; 129]).is_err());
        assert!(BlkPtr::decode(&[]).is_err());
    }

    #[test]
    fn rejects_nonzero_reserved_bytes() {
        let mut b = sample().encode();
        b[100] = 1;
        assert!(matches!(
            BlkPtr::decode(&b),
            Err(FsError::Integrity("blkptr: reserved bytes not zero"))
        ));
    }

    /// The dangerous near-miss: a pointer zeroed everywhere that matters would
    /// read as a hole and silently produce a file of zeros. It must be an
    /// error instead.
    #[test]
    fn rejects_partially_zeroed_pointer() {
        let mut b = sample().encode();
        b[48..80].fill(0); // wipe the checksum, leave the address
        assert!(matches!(
            BlkPtr::decode(&b),
            Err(FsError::Integrity("blkptr: non-hole with zero checksum"))
        ));
    }

    #[test]
    fn rejects_stored_length_below_tag() {
        let mut p = sample();
        p.dva.len = TAG_LEN as u32 - 1;
        p.logical_len = 0;
        assert!(matches!(
            BlkPtr::decode(&p.encode()),
            Err(FsError::Integrity("blkptr: stored length below AEAD tag"))
        ));
    }

    #[test]
    fn rejects_length_inconsistency() {
        // Over-read: claim more stored bytes than the plaintext accounts for.
        let mut p = sample();
        p.dva.len += 1;
        assert!(BlkPtr::decode(&p.encode()).is_err());

        // Under-read.
        let mut p = sample();
        p.logical_len += 1;
        assert!(BlkPtr::decode(&p.encode()).is_err());
    }

    #[test]
    fn rejects_excessive_level() {
        let mut p = sample();
        p.level = MAX_LEVEL + 1;
        assert!(matches!(
            BlkPtr::decode(&p.encode()),
            Err(FsError::Integrity("blkptr: level exceeds maximum"))
        ));

        p.level = MAX_LEVEL;
        assert!(BlkPtr::decode(&p.encode()).is_ok());
    }

    #[test]
    fn rejects_absurd_block_length() {
        let mut p = sample();
        p.logical_len = MAX_BLOCK_LEN + 1;
        p.dva.len = p.logical_len + TAG_LEN as u32;
        assert!(matches!(
            BlkPtr::decode(&p.encode()),
            Err(FsError::Integrity("blkptr: block length exceeds maximum"))
        ));
    }

    #[test]
    fn rejects_unknown_compression() {
        let mut b = sample().encode();
        b[23] = 9;
        assert!(matches!(
            BlkPtr::decode(&b),
            Err(FsError::Integrity("blkptr: unknown compression algorithm"))
        ));
    }

    #[test]
    fn rejects_slab_range_overflow() {
        let mut p = sample();
        p.dva.offset = u32::MAX;
        assert!(matches!(
            BlkPtr::decode(&p.encode()),
            Err(FsError::Integrity("blkptr: slab range overflows"))
        ));
    }

    #[test]
    fn dva_range_covers_the_stored_bytes() {
        let p = sample();
        assert_eq!(
            p.dva.range(),
            0x0b0c_0d0e..0x0b0c_0d0e + 4096 + TAG_LEN as u64
        );
    }

    #[test]
    fn fanout_at_default_record_size() {
        assert_eq!(blkptrs_per_block(128 * 1024), 1024);
        assert_eq!(blkptrs_per_block(4096), 32);
    }

    /// Every single-byte corruption of a valid pointer must either decode to
    /// something different (and so fail its checksum against the parent) or be
    /// rejected outright. What must never happen is decoding back to the
    /// original pointer, which would mean a byte of the encoding is ignored.
    #[test]
    fn no_byte_of_the_encoding_is_ignored() {
        let p = sample();
        let encoded = p.encode();
        for i in 0..BLKPTR_LEN {
            for bit in [0x01u8, 0x80] {
                let mut b = encoded;
                b[i] ^= bit;
                match BlkPtr::decode(&b) {
                    Err(_) => {}
                    Ok(decoded) => assert_ne!(
                        decoded, p,
                        "flipping bit {bit:#x} of byte {i} decoded back to the original"
                    ),
                }
            }
        }
    }
}
