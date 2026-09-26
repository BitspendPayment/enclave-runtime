//! Slab packing — how a transaction group's blocks become S3 objects.
//!
//! Every block dirtied in a txg is sealed and appended to a slab buffer. When
//! a slab reaches `slab_max_bytes` a new one starts. At commit time each slab
//! becomes one immutable `slabs/<txg>/<i>` object.
//!
//! This is where the design earns its keep: a commit costs `ceil(dirty_bytes /
//! slab_max_bytes)` PUTs plus one for the root, whether the txg touched one
//! block or ten thousand. Addressing blocks by content hash instead would cost
//! one PUT per block, which for a SQLite page-write workload means a round
//! trip per 4 KiB.
//!
//! Slabs are write-once and are never revisited: an aborted or crashed commit
//! leaves orphaned slab objects that no root references, which are invisible
//! to readers and reclaimable by lifecycle policy.

use bytes::Bytes;

use crate::crypto::aead::{self, BlockAad, BlockNonce};
use crate::crypto::{Hash256, KeyMaterial};
use crate::errors::{FsError, FsResult};

use super::blkptr::{BlkPtr, Compression, Dva};
use super::config::StoreConfig;

/// One finished slab, ready to PUT.
#[derive(Debug, Clone)]
pub struct FinishedSlab {
    /// Index within the txg.
    pub index: u16,
    pub body: Bytes,
}

/// Accumulates sealed blocks for one transaction group.
///
/// Holds no key material and performs no I/O; it is a pure byte-packer, which
/// keeps it trivially testable.
#[derive(Debug)]
pub struct SlabWriter {
    txg: u64,
    slab_max_bytes: usize,
    /// Sealed slabs already closed out.
    finished: Vec<FinishedSlab>,
    /// The slab currently being filled.
    current: Vec<u8>,
    /// Index of `current` within the txg.
    current_index: u16,
    /// Monotonic counter over every block written in this txg. Combined with
    /// the txg it forms the AEAD nonce, so it must increment for every single
    /// sealed block regardless of which slab the block lands in.
    next_block_seq: u32,
}

impl SlabWriter {
    pub fn new(txg: u64, config: &StoreConfig) -> Self {
        Self {
            txg,
            slab_max_bytes: config.slab_max_bytes,
            finished: Vec::new(),
            current: Vec::new(),
            current_index: 0,
            next_block_seq: 0,
        }
    }

    pub fn txg(&self) -> u64 {
        self.txg
    }

    /// Total bytes staged so far, across finished and in-progress slabs.
    pub fn staged_bytes(&self) -> usize {
        self.finished.iter().map(|s| s.body.len()).sum::<usize>() + self.current.len()
    }

    /// Number of blocks sealed so far.
    pub fn block_count(&self) -> u32 {
        self.next_block_seq
    }

    /// Seal `plaintext` and append it, returning the pointer that addresses it.
    ///
    /// The AAD is built here rather than taken from the caller so that
    /// `birth_txg` is always this writer's txg. That closes the failure mode
    /// where a block is sealed under one txg and its pointer records another,
    /// which would produce a block that can never be opened.
    pub fn write_block(
        &mut self,
        keys: &KeyMaterial,
        objid: u64,
        level: u8,
        block_index: u64,
        fill: u32,
        plaintext: &[u8],
    ) -> FsResult<BlkPtr> {
        if plaintext.len() > super::blkptr::MAX_BLOCK_LEN as usize {
            return Err(FsError::Invalid("block exceeds maximum block length"));
        }

        let block_seq = self.next_block_seq;
        // 2^32 blocks in one txg is ~500 TiB at the default record size; a txg
        // that large means something has gone wrong upstream. Refuse rather
        // than wrap, because wrapping would repeat a nonce.
        self.next_block_seq = block_seq
            .checked_add(1)
            .ok_or(FsError::Invalid("too many blocks in one transaction group"))?;

        let nonce = BlockNonce::new(self.txg, block_seq);
        let aad = BlockAad {
            objid,
            level,
            block_index,
            birth_txg: self.txg,
        };
        let sealed = aead::seal(keys.block_key(), nonce, aad, plaintext)?;

        // Start a new slab if this block would overflow the current one. A
        // block is never split across slabs — a pointer names one contiguous
        // range, and splitting would cost a second GET on every read.
        if !self.current.is_empty() && self.current.len() + sealed.len() > self.slab_max_bytes {
            self.close_current()?;
        }

        let offset =
            u32::try_from(self.current.len()).expect("slab_max_bytes is validated to fit in u32");
        let len = u32::try_from(sealed.len()).expect("block length is bounded by MAX_BLOCK_LEN");
        let checksum = Hash256::of(&sealed);
        self.current.extend_from_slice(&sealed);

        Ok(BlkPtr {
            dva: Dva {
                txg: self.txg,
                slab: self.current_index,
                offset,
                len,
            },
            logical_len: plaintext.len() as u32,
            level,
            compression: Compression::None,
            fill,
            birth_txg: self.txg,
            nonce,
            checksum,
        })
    }

    fn close_current(&mut self) -> FsResult<()> {
        let body = Bytes::from(std::mem::take(&mut self.current));
        self.finished.push(FinishedSlab {
            index: self.current_index,
            body,
        });
        self.current_index = self
            .current_index
            .checked_add(1)
            .ok_or(FsError::Invalid("too many slabs in one transaction group"))?;
        Ok(())
    }

    /// Close out the in-progress slab and return everything to PUT.
    ///
    /// An empty txg yields no slabs — a commit that only changed metadata
    /// already fitting in existing blocks still writes a root, but need not
    /// write any data.
    pub fn finish(mut self) -> FsResult<Vec<FinishedSlab>> {
        if !self.current.is_empty() {
            self.close_current()?;
        }
        Ok(self.finished)
    }
}

/// Decrypt and verify one block read from a slab.
///
/// Both checks run, in this order, and both must pass:
///
/// 1. **Checksum against the parent pointer.** This is the Merkle link. It is
///    checked first because it needs no key, so a corrupt or substituted block
///    is rejected before the cipher ever sees it.
/// 2. **AEAD open with position-binding AAD.** This catches a block that is
///    genuine but served from the wrong place in the tree.
pub fn verify_and_open(
    keys: &KeyMaterial,
    ptr: &BlkPtr,
    objid: u64,
    block_index: u64,
    stored: &[u8],
) -> FsResult<Vec<u8>> {
    if stored.len() != ptr.dva.len as usize {
        return Err(FsError::Integrity("block: short read from slab"));
    }
    Hash256::of(stored).verify(&ptr.checksum, "block: checksum mismatch")?;

    let aad = BlockAad {
        objid,
        level: ptr.level,
        block_index,
        birth_txg: ptr.birth_txg,
    };
    let plaintext = aead::open(keys.block_key(), ptr.nonce, aad, stored)?;
    if plaintext.len() != ptr.logical_len as usize {
        return Err(FsError::Integrity("block: logical length mismatch"));
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterSecret;

    fn keys() -> KeyMaterial {
        KeyMaterial::derive(&MasterSecret::from_bytes([3u8; 32]), [0u8; 16]).unwrap()
    }

    fn config() -> StoreConfig {
        StoreConfig::default()
    }

    /// Pull a block's stored bytes back out of the slab it was packed into.
    fn extract(slabs: &[FinishedSlab], ptr: &BlkPtr) -> Vec<u8> {
        let slab = slabs
            .iter()
            .find(|s| s.index == ptr.dva.slab)
            .expect("slab exists");
        let r = ptr.dva.range();
        slab.body[r.start as usize..r.end as usize].to_vec()
    }

    #[test]
    fn write_then_read_back_round_trips() {
        let k = keys();
        let mut w = SlabWriter::new(7, &config());
        let data = vec![0xabu8; 4096];
        let ptr = w.write_block(&k, 10, 0, 0, 1, &data).unwrap();
        let slabs = w.finish().unwrap();

        assert_eq!(slabs.len(), 1);
        assert_eq!(ptr.dva.txg, 7);
        assert_eq!(ptr.birth_txg, 7);
        assert_eq!(ptr.logical_len, 4096);
        assert_eq!(ptr.dva.len, 4096 + crate::crypto::TAG_LEN as u32);

        let stored = extract(&slabs, &ptr);
        assert_eq!(verify_and_open(&k, &ptr, 10, 0, &stored).unwrap(), data);
    }

    #[test]
    fn blocks_are_packed_contiguously() {
        let k = keys();
        let mut w = SlabWriter::new(1, &config());
        let a = w.write_block(&k, 1, 0, 0, 1, &[1u8; 100]).unwrap();
        let b = w.write_block(&k, 1, 0, 1, 1, &[2u8; 200]).unwrap();

        assert_eq!(a.dva.offset, 0);
        assert_eq!(b.dva.offset, a.dva.len, "second block follows the first");
        assert_eq!(a.dva.slab, b.dva.slab);

        let slabs = w.finish().unwrap();
        assert_eq!(slabs[0].body.len() as u32, a.dva.len + b.dva.len);
    }

    #[test]
    fn empty_txg_produces_no_slabs() {
        let w = SlabWriter::new(1, &config());
        assert!(w.finish().unwrap().is_empty());
    }

    #[test]
    fn oversized_txg_rolls_to_a_new_slab() {
        let k = keys();
        // A stored block is 4096 + 16 bytes of AEAD tag = 4112, so a cap of
        // 8300 admits exactly two per slab and the third must roll over.
        const STORED: u32 = 4096 + crate::crypto::TAG_LEN as u32;
        let cfg = StoreConfig {
            slab_max_bytes: 2 * STORED as usize + 76,
            record_size: 4096,
            ..Default::default()
        };
        let mut w = SlabWriter::new(1, &cfg);

        let ptrs: Vec<_> = (0..3)
            .map(|i| w.write_block(&k, 1, 0, i, 1, &[i as u8; 4096]).unwrap())
            .collect();

        assert_eq!((ptrs[0].dva.slab, ptrs[0].dva.offset), (0, 0));
        assert_eq!((ptrs[1].dva.slab, ptrs[1].dva.offset), (0, STORED));
        assert_eq!(
            (ptrs[2].dva.slab, ptrs[2].dva.offset),
            (1, 0),
            "a new slab restarts the offset"
        );

        let slabs = w.finish().unwrap();
        assert_eq!(slabs.len(), 2);
        for (i, p) in ptrs.iter().enumerate() {
            let stored = extract(&slabs, p);
            assert_eq!(
                verify_and_open(&k, p, 1, i as u64, &stored).unwrap(),
                vec![i as u8; 4096],
                "block {i} failed to verify"
            );
        }
    }

    /// A block never straddles two slabs, because a pointer names exactly one
    /// contiguous range and a split would double the reads.
    #[test]
    fn a_block_is_never_split_across_slabs() {
        let k = keys();
        let cfg = StoreConfig {
            slab_max_bytes: 5000,
            record_size: 4096,
            ..Default::default()
        };
        let mut w = SlabWriter::new(1, &cfg);
        let a = w.write_block(&k, 1, 0, 0, 1, &[0u8; 4096]).unwrap();
        let b = w.write_block(&k, 1, 0, 1, 1, &[0u8; 4096]).unwrap();
        assert_ne!(a.dva.slab, b.dva.slab);

        let slabs = w.finish().unwrap();
        for (s, p) in slabs.iter().zip([a, b]) {
            assert_eq!(s.body.len(), p.dva.len as usize);
        }
    }

    /// The nonce-uniqueness invariant, checked at the level where it is
    /// actually established: the sequence counter spans the whole txg, so
    /// rolling to a new slab must not restart it.
    #[test]
    fn block_sequence_is_unique_across_the_whole_txg() {
        let k = keys();
        let cfg = StoreConfig {
            slab_max_bytes: 8192,
            record_size: 4096,
            ..Default::default()
        };
        let mut w = SlabWriter::new(1, &cfg);
        let mut nonces = std::collections::HashSet::new();
        for i in 0..10u64 {
            let p = w.write_block(&k, 1, 0, i, 1, &[0u8; 4096]).unwrap();
            assert!(
                nonces.insert(*p.nonce.as_bytes()),
                "nonce reused at block {i}"
            );
        }
        assert_eq!(w.block_count(), 10);
    }

    #[test]
    fn identical_plaintext_in_one_txg_gets_distinct_ciphertext() {
        let k = keys();
        let mut w = SlabWriter::new(1, &config());
        let a = w.write_block(&k, 1, 0, 0, 1, &[7u8; 1024]).unwrap();
        let b = w.write_block(&k, 1, 0, 1, 1, &[7u8; 1024]).unwrap();
        assert_ne!(
            a.checksum, b.checksum,
            "distinct nonces must yield distinct ciphertext"
        );
    }

    #[test]
    fn staged_bytes_tracks_both_finished_and_current() {
        let k = keys();
        let cfg = StoreConfig {
            slab_max_bytes: 8192,
            record_size: 4096,
            ..Default::default()
        };
        let mut w = SlabWriter::new(1, &cfg);
        assert_eq!(w.staged_bytes(), 0);
        w.write_block(&k, 1, 0, 0, 1, &[0u8; 4096]).unwrap();
        assert_eq!(w.staged_bytes(), 4096 + 16);
        w.write_block(&k, 1, 0, 1, 1, &[0u8; 4096]).unwrap();
        w.write_block(&k, 1, 0, 2, 1, &[0u8; 4096]).unwrap();
        assert_eq!(w.staged_bytes(), 3 * (4096 + 16));
    }

    // ---- verification failures ---------------------------------------------

    #[test]
    fn rejects_corrupted_bytes() {
        let k = keys();
        let mut w = SlabWriter::new(1, &config());
        let ptr = w.write_block(&k, 1, 0, 0, 1, b"payload").unwrap();
        let slabs = w.finish().unwrap();

        let mut stored = extract(&slabs, &ptr);
        stored[0] ^= 0x01;
        assert!(matches!(
            verify_and_open(&k, &ptr, 1, 0, &stored),
            Err(FsError::Integrity("block: checksum mismatch"))
        ));
    }

    #[test]
    fn rejects_short_read() {
        let k = keys();
        let mut w = SlabWriter::new(1, &config());
        let ptr = w.write_block(&k, 1, 0, 0, 1, b"payload").unwrap();
        let slabs = w.finish().unwrap();

        let stored = extract(&slabs, &ptr);
        assert!(matches!(
            verify_and_open(&k, &ptr, 1, 0, &stored[..stored.len() - 1]),
            Err(FsError::Integrity("block: short read from slab"))
        ));
    }

    /// The substitution attack: swap two genuine, correctly-checksummed blocks
    /// and adjust the pointer to match. The checksum passes; the AAD does not.
    #[test]
    fn rejects_a_genuine_block_moved_to_another_position() {
        let k = keys();
        let mut w = SlabWriter::new(1, &config());
        let a = w.write_block(&k, 1, 0, 0, 1, b"block a").unwrap();
        let b = w.write_block(&k, 7, 0, 3, 1, b"block b").unwrap();
        let slabs = w.finish().unwrap();

        // Serve block b's bytes under a pointer that has b's checksum but
        // claims a's position. The Merkle check passes.
        let stored_b = extract(&slabs, &b);
        assert!(Hash256::of(&stored_b).verify(&b.checksum, "x").is_ok());

        // Wrong objid.
        assert!(verify_and_open(&k, &b, 1, 3, &stored_b).is_err());
        // Wrong block index.
        assert!(verify_and_open(&k, &b, 7, 0, &stored_b).is_err());
        // Right position still works.
        assert!(verify_and_open(&k, &b, 7, 3, &stored_b).is_ok());
        assert!(verify_and_open(&k, &a, 1, 0, &extract(&slabs, &a)).is_ok());
    }

    #[test]
    fn rejects_wrong_key() {
        let mut w = SlabWriter::new(1, &config());
        let ptr = w.write_block(&keys(), 1, 0, 0, 1, b"payload").unwrap();
        let slabs = w.finish().unwrap();

        let other = KeyMaterial::derive(&MasterSecret::from_bytes([9u8; 32]), [0u8; 16]).unwrap();
        assert!(verify_and_open(&other, &ptr, 1, 0, &extract(&slabs, &ptr)).is_err());
    }

    #[test]
    fn rejects_tampered_logical_length() {
        let k = keys();
        let mut w = SlabWriter::new(1, &config());
        let mut ptr = w.write_block(&k, 1, 0, 0, 1, b"payload").unwrap();
        let slabs = w.finish().unwrap();
        let stored = extract(&slabs, &ptr);

        ptr.logical_len -= 1;
        assert!(matches!(
            verify_and_open(&k, &ptr, 1, 0, &stored),
            Err(FsError::Integrity("block: logical length mismatch"))
        ));
    }

    #[test]
    fn zero_length_block_round_trips() {
        let k = keys();
        let mut w = SlabWriter::new(1, &config());
        let ptr = w.write_block(&k, 1, 0, 0, 0, b"").unwrap();
        let slabs = w.finish().unwrap();
        assert_eq!(ptr.logical_len, 0);
        assert!(verify_and_open(&k, &ptr, 1, 0, &extract(&slabs, &ptr))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn pointers_decode_after_a_round_trip_through_bytes() {
        let k = keys();
        let mut w = SlabWriter::new(42, &config());
        let ptr = w.write_block(&k, 5, 2, 9, 3, &[1u8; 1000]).unwrap();
        assert_eq!(BlkPtr::decode(&ptr.encode()).unwrap(), ptr);
        assert!(!ptr.is_hole());
    }
}
