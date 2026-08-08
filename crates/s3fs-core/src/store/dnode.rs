//! `Dnode` — the on-disk inode.
//!
//! One dnode per file, directory, or symlink. It holds all POSIX metadata and
//! a single block pointer that roots the object's indirect tree. There is no
//! S3 user metadata anywhere in this design: `set_times` is a field write, not
//! a `CopyObject` with `MetadataDirective=REPLACE`.
//!
//! ## Wire layout — 512 bytes, big-endian
//!
//! ```text
//!  offset  size  field
//!       0     8  objid
//!       8     1  kind             Free | File | Dir | Symlink | DnodeArray
//!       9     1  nlevels          height of the indirect tree, data level included
//!      10     1  record_shift     log2(record size)
//!      11     1  reserved         must be zero
//!      12     4  nlink
//!      16     4  mode
//!      20     4  uid
//!      24     4  gid
//!      28     8  size             logical size in bytes
//!      36     8  atime_nanos
//!      44     8  mtime_nanos
//!      52     8  ctime_nanos
//!      60     8  btime_nanos
//!      68     8  gen              bumped on reuse; with objid, a stable identity
//!      76     2  inline_len
//!      78     2  reserved         must be zero
//!      80     8  parent_objid     containing directory; self for the root
//!      88   128  blkptr           root of the indirect tree
//!     216   294  inline           short symlink targets
//!     510     2  reserved         must be zero
//! ```
//!
//! 512 bytes divides the 128 KiB record exactly 256 ways, so a dnode never
//! straddles a block boundary and object id arithmetic is a shift.
//!
//! ## Tree height
//!
//! `nlevels` counts the data level:
//!
//! - `0` — no data at all; the pointer is a hole.
//! - `1` — the pointer *is* the single data block.
//! - `n` — the pointer is a level-`n-1` indirect block.
//!
//! One embedded pointer rather than ZFS's three: the extra two only help
//! objects of exactly two or three blocks, and dropping them buys 256 bytes of
//! inline space, which is what lets almost every symlink target live in the
//! dnode itself.

use crate::errors::{FsError, FsResult};

use super::blkptr::{BlkPtr, BLKPTR_LEN, MAX_LEVEL};

/// Encoded size of a dnode.
pub const DNODE_LEN: usize = 512;

/// Bytes of in-dnode storage for short symlink targets.
pub const INLINE_CAP: usize = 294;

const PARENT_OFFSET: usize = 80;
const BLKPTR_OFFSET: usize = PARENT_OFFSET + 8;
const INLINE_OFFSET: usize = BLKPTR_OFFSET + BLKPTR_LEN;
const RESERVED_KIND_PAD: usize = 11;
const RESERVED0: std::ops::Range<usize> = 78..80;
const RESERVED1: std::ops::Range<usize> = 510..512;

/// Deepest tree we accept: the root pointer sits at `nlevels - 1`, which must
/// itself be a decodable level.
pub const MAX_NLEVELS: u8 = MAX_LEVEL + 1;

/// Object id of the meta-dnode — the dnode array that holds every other
/// dnode. It is never stored *in* the array; its pointer lives in the root
/// record.
pub const META_OBJID: u64 = 0;

/// Object id of the root directory.
pub const ROOT_OBJID: u64 = 1;

/// How many dnodes fit in one block.
pub const fn dnodes_per_block(record_size: usize) -> usize {
    record_size / DNODE_LEN
}

/// What an object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DnodeKind {
    /// Unallocated slot in the dnode array.
    #[default]
    Free = 0,
    File = 1,
    Dir = 2,
    Symlink = 3,
    /// The dnode array itself.
    DnodeArray = 4,
}

impl DnodeKind {
    fn from_u8(v: u8) -> FsResult<Self> {
        Ok(match v {
            0 => DnodeKind::Free,
            1 => DnodeKind::File,
            2 => DnodeKind::Dir,
            3 => DnodeKind::Symlink,
            4 => DnodeKind::DnodeArray,
            _ => return Err(FsError::Integrity("dnode: unknown kind")),
        })
    }
}

/// An object's metadata and the root of its block tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnode {
    pub objid: u64,
    pub kind: DnodeKind,
    pub nlevels: u8,
    pub record_shift: u8,
    /// Containing directory. The root directory is its own parent, which is
    /// what makes `..` terminate there instead of escaping the mount.
    ///
    /// Held in the dnode rather than as a `..` directory entry so that
    /// `read_dir` needs no filtering, `rmdir`'s emptiness check stays honest,
    /// and a hard link to a directory remains inexpressible.
    pub parent_objid: u64,
    pub nlink: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime_nanos: u64,
    pub mtime_nanos: u64,
    pub ctime_nanos: u64,
    pub btime_nanos: u64,
    /// Incremented when an object id is reused. `(objid, gen)` is a stable
    /// identity across mounts, which is what makes `is-same-object` and
    /// `metadata-hash` exact rather than a guess derived from an ETag.
    pub gen: u64,
    /// Short symlink target, stored in the dnode to avoid a block read.
    pub inline: Vec<u8>,
    /// Root of the indirect tree.
    pub blkptr: BlkPtr,
}

impl Dnode {
    /// A free slot.
    pub fn free(objid: u64, record_shift: u8) -> Self {
        Dnode {
            objid,
            kind: DnodeKind::Free,
            nlevels: 0,
            record_shift,
            parent_objid: objid,
            nlink: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime_nanos: 0,
            mtime_nanos: 0,
            ctime_nanos: 0,
            btime_nanos: 0,
            gen: 0,
            inline: Vec::new(),
            blkptr: BlkPtr::HOLE,
        }
    }

    /// A newly allocated object of the given kind.
    pub fn new(objid: u64, kind: DnodeKind, record_shift: u8, now_nanos: u64) -> Self {
        Dnode {
            kind,
            nlink: u32::from(kind != DnodeKind::Free),
            atime_nanos: now_nanos,
            mtime_nanos: now_nanos,
            ctime_nanos: now_nanos,
            btime_nanos: now_nanos,
            ..Dnode::free(objid, record_shift)
        }
    }

    pub fn record_size(&self) -> usize {
        1usize << self.record_shift
    }

    /// Pointers per indirect block at this object's record size.
    pub fn fanout(&self) -> u64 {
        (self.record_size() / BLKPTR_LEN) as u64
    }

    /// Number of level-0 data blocks the logical size spans.
    pub fn block_count(&self) -> u64 {
        blocks_for_size(self.size, self.record_size())
    }

    /// Number of blocks at `level`: level 0 is data, higher levels are the
    /// indirect blocks needed to address them.
    pub fn blocks_at_level(&self, level: u8) -> u64 {
        blocks_at_level(self.block_count(), self.fanout(), level)
    }

    /// Tree height required for this object's current size.
    pub fn required_levels(&self) -> u8 {
        levels_for(self.block_count(), self.fanout())
    }

    pub fn encode(&self) -> FsResult<[u8; DNODE_LEN]> {
        if self.inline.len() > INLINE_CAP {
            return Err(FsError::Invalid("dnode inline data exceeds capacity"));
        }
        let mut b = [0u8; DNODE_LEN];
        b[0..8].copy_from_slice(&self.objid.to_be_bytes());
        b[8] = self.kind as u8;
        b[9] = self.nlevels;
        b[10] = self.record_shift;
        b[RESERVED_KIND_PAD] = 0;
        b[12..16].copy_from_slice(&self.nlink.to_be_bytes());
        b[16..20].copy_from_slice(&self.mode.to_be_bytes());
        b[20..24].copy_from_slice(&self.uid.to_be_bytes());
        b[24..28].copy_from_slice(&self.gid.to_be_bytes());
        b[28..36].copy_from_slice(&self.size.to_be_bytes());
        b[36..44].copy_from_slice(&self.atime_nanos.to_be_bytes());
        b[44..52].copy_from_slice(&self.mtime_nanos.to_be_bytes());
        b[52..60].copy_from_slice(&self.ctime_nanos.to_be_bytes());
        b[60..68].copy_from_slice(&self.btime_nanos.to_be_bytes());
        b[68..76].copy_from_slice(&self.gen.to_be_bytes());
        b[76..78].copy_from_slice(&(self.inline.len() as u16).to_be_bytes());
        b[PARENT_OFFSET..PARENT_OFFSET + 8].copy_from_slice(&self.parent_objid.to_be_bytes());
        b[BLKPTR_OFFSET..BLKPTR_OFFSET + BLKPTR_LEN].copy_from_slice(&self.blkptr.encode());
        b[INLINE_OFFSET..INLINE_OFFSET + self.inline.len()].copy_from_slice(&self.inline);
        Ok(b)
    }

    pub fn decode(bytes: &[u8]) -> FsResult<Dnode> {
        if bytes.len() != DNODE_LEN {
            return Err(FsError::Integrity("dnode: wrong length"));
        }
        if bytes[RESERVED0].iter().any(|&b| b != 0)
            || bytes[RESERVED1].iter().any(|&b| b != 0)
            || bytes[RESERVED_KIND_PAD] != 0
        {
            return Err(FsError::Integrity("dnode: reserved bytes not zero"));
        }

        let inline_len = u16::from_be_bytes(bytes[76..78].try_into().expect("2 bytes")) as usize;
        if inline_len > INLINE_CAP {
            return Err(FsError::Integrity("dnode: inline length exceeds capacity"));
        }
        // Bytes past `inline_len` must be zero. Otherwise the tail is a free
        // channel for smuggling data through a structure that is otherwise
        // fully accounted for.
        if bytes[INLINE_OFFSET + inline_len..RESERVED1.start]
            .iter()
            .any(|&b| b != 0)
        {
            return Err(FsError::Integrity("dnode: inline padding not zero"));
        }

        let record_shift = bytes[10];
        if !(12..=20).contains(&record_shift) {
            return Err(FsError::Integrity("dnode: record_shift out of range"));
        }

        let d = Dnode {
            objid: u64::from_be_bytes(bytes[0..8].try_into().expect("8 bytes")),
            kind: DnodeKind::from_u8(bytes[8])?,
            nlevels: bytes[9],
            record_shift,
            parent_objid: u64::from_be_bytes(
                bytes[PARENT_OFFSET..PARENT_OFFSET + 8]
                    .try_into()
                    .expect("8 bytes"),
            ),
            nlink: u32::from_be_bytes(bytes[12..16].try_into().expect("4 bytes")),
            mode: u32::from_be_bytes(bytes[16..20].try_into().expect("4 bytes")),
            uid: u32::from_be_bytes(bytes[20..24].try_into().expect("4 bytes")),
            gid: u32::from_be_bytes(bytes[24..28].try_into().expect("4 bytes")),
            size: u64::from_be_bytes(bytes[28..36].try_into().expect("8 bytes")),
            atime_nanos: u64::from_be_bytes(bytes[36..44].try_into().expect("8 bytes")),
            mtime_nanos: u64::from_be_bytes(bytes[44..52].try_into().expect("8 bytes")),
            ctime_nanos: u64::from_be_bytes(bytes[52..60].try_into().expect("8 bytes")),
            btime_nanos: u64::from_be_bytes(bytes[60..68].try_into().expect("8 bytes")),
            gen: u64::from_be_bytes(bytes[68..76].try_into().expect("8 bytes")),
            inline: bytes[INLINE_OFFSET..INLINE_OFFSET + inline_len].to_vec(),
            blkptr: BlkPtr::decode(&bytes[BLKPTR_OFFSET..BLKPTR_OFFSET + BLKPTR_LEN])?,
        };

        if d.nlevels > MAX_NLEVELS {
            return Err(FsError::Integrity("dnode: nlevels exceeds maximum"));
        }
        // The height and the root pointer must agree. Disagreement would let a
        // forged dnode redirect a read to a block at the wrong level, where
        // the AAD check is the only thing left standing.
        if d.nlevels == 0 {
            if !d.blkptr.is_hole() {
                return Err(FsError::Integrity("dnode: empty tree with a live pointer"));
            }
        } else if !d.blkptr.is_hole() && d.blkptr.level != d.nlevels - 1 {
            return Err(FsError::Integrity("dnode: root pointer level mismatch"));
        }
        Ok(d)
    }
}

/// Blocks needed to hold `size` bytes.
pub fn blocks_for_size(size: u64, record_size: usize) -> u64 {
    let rs = record_size as u64;
    size.div_ceil(rs)
}

/// Blocks at `level` given `nblocks` data blocks and this fan-out.
pub fn blocks_at_level(nblocks: u64, fanout: u64, level: u8) -> u64 {
    let mut n = nblocks;
    for _ in 0..level {
        n = n.div_ceil(fanout);
    }
    n
}

/// Tree height needed to address `nblocks` data blocks.
///
/// `0` for an empty object, `1` for a single block (the dnode's pointer *is*
/// the data block), and one more level for each factor of `fanout` beyond that.
pub fn levels_for(nblocks: u64, fanout: u64) -> u8 {
    if nblocks == 0 {
        return 0;
    }
    let mut levels: u8 = 1;
    let mut capacity: u64 = 1;
    while capacity < nblocks {
        capacity = capacity.saturating_mul(fanout);
        levels += 1;
    }
    levels
}

/// Index of the entry within a level-`level` indirect block that leads toward
/// data block `block_index`.
pub fn entry_index(block_index: u64, level: u8, fanout: u64) -> u64 {
    debug_assert!(level >= 1, "level 0 blocks have no entries");
    (block_index / fanout.pow(u32::from(level) - 1)) % fanout
}

/// Index, within its own level, of the level-`level` block covering data block
/// `block_index`. This is the value fed to the AEAD as `block_index`, so it
/// must be identical on the write and read paths.
pub fn block_index_at_level(block_index: u64, level: u8, fanout: u64) -> u64 {
    block_index / fanout.pow(u32::from(level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Hash256;
    use crate::store::blkptr::{Compression, Dva};

    const FANOUT: u64 = 1024;

    fn ptr(level: u8) -> BlkPtr {
        BlkPtr {
            dva: Dva {
                txg: 5,
                slab: 1,
                offset: 64,
                len: 1024 + 16,
            },
            logical_len: 1024,
            level,
            compression: Compression::None,
            fill: 1,
            birth_txg: 5,
            nonce: crate::crypto::BlockNonce::new(5, 2),
            checksum: Hash256::of(b"block"),
        }
    }

    fn sample() -> Dnode {
        Dnode {
            objid: 42,
            kind: DnodeKind::File,
            nlevels: 2,
            record_shift: 17,
            parent_objid: 1,
            nlink: 1,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 300_000,
            atime_nanos: 111,
            mtime_nanos: 222,
            ctime_nanos: 333,
            btime_nanos: 444,
            gen: 7,
            inline: Vec::new(),
            blkptr: ptr(1),
        }
    }

    #[test]
    fn dnode_divides_the_record_evenly() {
        assert_eq!(DNODE_LEN, 512);
        assert_eq!(dnodes_per_block(128 * 1024), 256);
        assert_eq!(128 * 1024 % DNODE_LEN, 0);
        assert_eq!(INLINE_OFFSET + INLINE_CAP, RESERVED1.start);
        assert_eq!(BLKPTR_OFFSET, PARENT_OFFSET + 8);
    }

    #[test]
    fn round_trips() {
        let d = sample();
        assert_eq!(Dnode::decode(&d.encode().unwrap()).unwrap(), d);
    }

    #[test]
    fn free_dnode_round_trips() {
        let d = Dnode::free(9, 17);
        let decoded = Dnode::decode(&d.encode().unwrap()).unwrap();
        assert_eq!(decoded, d);
        assert_eq!(decoded.kind, DnodeKind::Free);
        assert!(decoded.blkptr.is_hole());
    }

    #[test]
    fn inline_data_round_trips() {
        let mut d = Dnode::new(3, DnodeKind::Symlink, 17, 99);
        d.inline = b"../relative/target/path".to_vec();
        d.size = d.inline.len() as u64;
        let decoded = Dnode::decode(&d.encode().unwrap()).unwrap();
        assert_eq!(decoded.inline, b"../relative/target/path");
    }

    #[test]
    fn inline_at_exact_capacity_round_trips() {
        let mut d = Dnode::new(3, DnodeKind::Symlink, 17, 0);
        d.inline = vec![0x41; INLINE_CAP];
        let decoded = Dnode::decode(&d.encode().unwrap()).unwrap();
        assert_eq!(decoded.inline.len(), INLINE_CAP);
    }

    #[test]
    fn inline_beyond_capacity_is_rejected_at_encode() {
        let mut d = Dnode::new(3, DnodeKind::Symlink, 17, 0);
        d.inline = vec![0x41; INLINE_CAP + 1];
        assert!(d.encode().is_err());
    }

    #[test]
    fn field_offsets_are_stable() {
        let b = sample().encode().unwrap();
        assert_eq!(&b[0..8], &42u64.to_be_bytes());
        assert_eq!(b[8], DnodeKind::File as u8);
        assert_eq!(b[9], 2);
        assert_eq!(b[10], 17);
        assert_eq!(b[RESERVED_KIND_PAD], 0);
        assert_eq!(
            &b[PARENT_OFFSET..PARENT_OFFSET + 8],
            &1u64.to_be_bytes(),
            "parent link must sit immediately before the block pointer"
        );
        assert_eq!(&b[28..36], &300_000u64.to_be_bytes());
        assert_eq!(&b[68..76], &7u64.to_be_bytes());
        assert_eq!(
            &b[BLKPTR_OFFSET..BLKPTR_OFFSET + BLKPTR_LEN],
            &ptr(1).encode()
        );
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(Dnode::decode(&[0u8; 511]).is_err());
        assert!(Dnode::decode(&[0u8; 513]).is_err());
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut b = sample().encode().unwrap();
        b[8] = 99;
        assert!(matches!(
            Dnode::decode(&b),
            Err(FsError::Integrity("dnode: unknown kind"))
        ));
    }

    #[test]
    fn rejects_reserved_bytes() {
        for i in [78, 79, 510, 511] {
            let mut b = sample().encode().unwrap();
            b[i] = 1;
            assert!(Dnode::decode(&b).is_err(), "byte {i} was ignored");
        }
    }

    /// A non-zero tail past `inline_len` would be an unaccounted channel in an
    /// otherwise fully-described structure.
    #[test]
    fn rejects_dirty_inline_padding() {
        let mut d = Dnode::new(3, DnodeKind::Symlink, 17, 0);
        d.inline = b"short".to_vec();
        let mut b = d.encode().unwrap();
        b[INLINE_OFFSET + 10] = 0xff;
        assert!(matches!(
            Dnode::decode(&b),
            Err(FsError::Integrity("dnode: inline padding not zero"))
        ));
    }

    #[test]
    fn rejects_out_of_range_record_shift() {
        for shift in [11u8, 21, 63] {
            let mut b = sample().encode().unwrap();
            b[10] = shift;
            assert!(Dnode::decode(&b).is_err(), "accepted shift {shift}");
        }
    }

    /// The height and the root pointer must agree, or a forged dnode could
    /// redirect a read to a block at a level it was never sealed for.
    #[test]
    fn rejects_level_disagreement() {
        let mut d = sample();
        d.nlevels = 3; // pointer is still level 1
        assert!(matches!(
            Dnode::decode(&d.encode().unwrap()),
            Err(FsError::Integrity("dnode: root pointer level mismatch"))
        ));

        let mut d = sample();
        d.nlevels = 0; // but the pointer is live
        assert!(matches!(
            Dnode::decode(&d.encode().unwrap()),
            Err(FsError::Integrity("dnode: empty tree with a live pointer"))
        ));
    }

    #[test]
    fn rejects_excessive_nlevels() {
        let mut d = sample();
        d.nlevels = MAX_NLEVELS + 1;
        d.blkptr = BlkPtr::HOLE;
        assert!(Dnode::decode(&d.encode().unwrap()).is_err());
    }

    // ---- tree geometry -----------------------------------------------------

    #[test]
    fn blocks_for_size_rounds_up() {
        assert_eq!(blocks_for_size(0, 4096), 0);
        assert_eq!(blocks_for_size(1, 4096), 1);
        assert_eq!(blocks_for_size(4096, 4096), 1);
        assert_eq!(blocks_for_size(4097, 4096), 2);
    }

    #[test]
    fn levels_grow_with_the_block_count() {
        assert_eq!(levels_for(0, FANOUT), 0);
        assert_eq!(levels_for(1, FANOUT), 1);
        assert_eq!(levels_for(2, FANOUT), 2);
        assert_eq!(levels_for(FANOUT, FANOUT), 2);
        assert_eq!(levels_for(FANOUT + 1, FANOUT), 3);
        assert_eq!(levels_for(FANOUT * FANOUT, FANOUT), 3);
        assert_eq!(levels_for(FANOUT * FANOUT + 1, FANOUT), 4);
    }

    /// Height must stay within what a block pointer can encode, for every
    /// permitted record size at the largest file `u64` bytes can express.
    ///
    /// The worst case is the *smallest* record: fewer pointers per indirect
    /// block means a taller tree. This is what sets `MAX_LEVEL`.
    #[test]
    fn levels_stay_within_the_pointer_limit_at_every_record_size() {
        for shift in 12u8..=20 {
            let record = 1usize << shift;
            let fanout = (record / BLKPTR_LEN) as u64;
            let max_blocks = blocks_for_size(u64::MAX, record);
            let levels = levels_for(max_blocks, fanout);
            assert!(
                levels <= MAX_NLEVELS,
                "record {record}: {levels} levels exceeds {MAX_NLEVELS}"
            );
        }
    }

    /// The smallest record size is the binding constraint, and it is close
    /// enough to the limit to be worth pinning exactly — if `MAX_LEVEL` is
    /// ever lowered, this fails rather than silently rejecting large files.
    #[test]
    fn worst_case_height_is_the_minimum_record_size() {
        let fanout = (4096 / BLKPTR_LEN) as u64;
        assert_eq!(fanout, 32);
        assert_eq!(levels_for(blocks_for_size(u64::MAX, 4096), fanout), 12);
        assert_eq!(
            levels_for(blocks_for_size(u64::MAX, 128 * 1024), FANOUT),
            6,
            "the default record size is nowhere near the limit"
        );
    }

    #[test]
    fn blocks_at_level_collapses_toward_one() {
        assert_eq!(blocks_at_level(2049, FANOUT, 0), 2049);
        assert_eq!(blocks_at_level(2049, FANOUT, 1), 3);
        assert_eq!(blocks_at_level(2049, FANOUT, 2), 1);
        assert_eq!(blocks_at_level(0, FANOUT, 1), 0);
    }

    #[test]
    fn entry_and_block_indices_are_consistent() {
        // Data block 1025 with fan-out 1024 lives in level-1 block 1, entry 1.
        assert_eq!(entry_index(1025, 1, FANOUT), 1);
        assert_eq!(block_index_at_level(1025, 1, FANOUT), 1);
        // That level-1 block is entry 1 of the single level-2 block.
        assert_eq!(entry_index(1025, 2, FANOUT), 1);
        assert_eq!(block_index_at_level(1025, 2, FANOUT), 0);
    }

    #[test]
    fn level_zero_index_is_the_block_itself() {
        for i in [0u64, 1, 1023, 1024, 1_000_000] {
            assert_eq!(block_index_at_level(i, 0, FANOUT), i);
        }
    }

    /// Walking the entry indices from the root down must reconstruct the
    /// original data block index. This is the invariant the tree walker
    /// depends on, in both directions.
    #[test]
    fn entry_path_reconstructs_the_block_index() {
        let fanout = 4u64;
        for block in 0..64u64 {
            let levels = levels_for(block + 1, fanout);
            let mut rebuilt = 0u64;
            for level in (1..levels).rev() {
                rebuilt = rebuilt * fanout + entry_index(block, level, fanout);
            }
            assert_eq!(rebuilt, block, "path for block {block} did not round-trip");
        }
    }
}
