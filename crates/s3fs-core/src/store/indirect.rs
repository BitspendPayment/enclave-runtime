//! The indirect block tree: reading down it, and rebuilding it copy-on-write.
//!
//! An object's data blocks hang off a tree of indirect blocks, each of which
//! is an array of [`BlkPtr`]s. The dnode holds the single pointer at the top.
//! Nothing is ever modified in place: a write produces new blocks bottom-up,
//! new indirect blocks above them, and finally a new root pointer.
//!
//! ## Indirect blocks are variable length
//!
//! An indirect block stores only as many pointers as it actually needs, and
//! any entry past the stored length reads as a hole. Without this, a two-block
//! file would pay a full 128 KiB indirect block to hold two used pointers and
//! 1022 zeros — a 50% storage overhead on a 256 KiB file. Trailing holes are
//! trimmed on write for the same reason, which also makes sparse files cheap
//! at every level of the tree rather than only at the leaves.
//!
//! ## What the caller must dirty
//!
//! The rebuild rewrites exactly the blocks it is given plus the indirect path
//! above them, and — when the object's size changed — the boundary block at
//! each level, so that pointers past the new end are dropped rather than left
//! dangling.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;

use crate::errors::{FsError, FsResult};

use super::blkptr::{BlkPtr, BLKPTR_LEN};
use super::blockstore::BlockStore;
use super::dnode::{blocks_at_level, blocks_for_size, levels_for, Dnode};
use super::slab::SlabWriter;

/// Decode entry `slot` of an indirect block's contents.
///
/// Slots past the stored length are holes — that is what makes indirect blocks
/// variable length.
fn entry_at(block: &[u8], slot: u64) -> FsResult<BlkPtr> {
    let range = usize::try_from(slot)
        .ok()
        .and_then(|s| s.checked_mul(BLKPTR_LEN))
        .and_then(|start| Some(start..start.checked_add(BLKPTR_LEN)?));
    match range.and_then(|r| block.get(r)) {
        Some(raw) => BlkPtr::decode(raw),
        None => Ok(BlkPtr::HOLE),
    }
}

/// Decode a whole indirect block into its pointer array.
fn decode_entries(block: &[u8]) -> FsResult<Vec<BlkPtr>> {
    if !block.len().is_multiple_of(BLKPTR_LEN) {
        return Err(FsError::Integrity(
            "indirect block length is not a multiple of the pointer size",
        ));
    }
    let (entries, _) = block.as_chunks::<BLKPTR_LEN>();
    entries.iter().map(|e| BlkPtr::decode(e)).collect()
}

fn encode_entries(entries: &[BlkPtr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * BLKPTR_LEN);
    for e in entries {
        out.extend_from_slice(&e.encode());
    }
    out
}

/// Logical length of data block `index` given the object's size.
///
/// The last block is short; blocks past the end are empty.
pub fn block_logical_len(size: u64, record_size: usize, index: u64) -> usize {
    let rs = record_size as u64;
    let start = index.saturating_mul(rs);
    if start >= size {
        return 0;
    }
    (size - start).min(rs) as usize
}

/// Resolve the pointer stored at `(level, index)` of an object's tree.
///
/// Walks down from the dnode's root pointer, verifying every block on the way.
/// Returns a hole for anything not present — a sparse region, a level above
/// the current tree height, or an index past the end.
pub async fn resolve_ptr(
    bs: &BlockStore,
    dnode: &Dnode,
    level: u8,
    index: u64,
) -> FsResult<BlkPtr> {
    if dnode.nlevels == 0 {
        return Ok(BlkPtr::HOLE);
    }
    let root_level = dnode.nlevels - 1;
    if level > root_level {
        return Ok(BlkPtr::HOLE);
    }
    let fanout = dnode.fanout();

    let mut ptr = dnode.blkptr;
    let mut cur_level = root_level;
    // Index of the block we are currently sitting on, within its own level.
    let mut cur_index = index / pow(fanout, u32::from(cur_level - level))?;
    if cur_index != 0 {
        // The root is the only block at its level, so an index that maps above
        // it lies beyond what this tree currently covers. That is an ordinary
        // question during a rebuild — "does the old tree already have a block
        // here?" — and the answer is simply no.
        return Ok(BlkPtr::HOLE);
    }

    while cur_level > level {
        if ptr.is_hole() {
            return Ok(BlkPtr::HOLE);
        }
        let block = bs.read_block(&ptr, dnode.objid, cur_index).await?;
        let slot = (index / pow(fanout, u32::from(cur_level - 1 - level))?) % fanout;
        ptr = entry_at(&block, slot)?;
        cur_level -= 1;
        cur_index = index / pow(fanout, u32::from(cur_level - level))?;
    }
    Ok(ptr)
}

fn pow(fanout: u64, exp: u32) -> FsResult<u64> {
    fanout
        .checked_pow(exp)
        .ok_or(FsError::Invalid("tree index arithmetic overflowed"))
}

/// Read data block `index`, returning exactly the bytes the object's size says
/// that block holds.
///
/// A stored block shorter or longer than the size implies is padded or clipped
/// rather than rejected: `set_size` can change a block's logical length without
/// changing its contents, and both directions are legitimate.
pub async fn read_data_block(bs: &BlockStore, dnode: &Dnode, index: u64) -> FsResult<Bytes> {
    let want = block_logical_len(dnode.size, dnode.record_size(), index);
    if want == 0 {
        return Ok(Bytes::new());
    }
    let ptr = resolve_ptr(bs, dnode, 0, index).await?;
    if ptr.is_hole() {
        return Ok(Bytes::from(vec![0u8; want]));
    }
    let got = bs.read_block(&ptr, dnode.objid, index).await?;
    Ok(fit(got, want))
}

/// Read block `index` exactly as it was stored, with no size-based padding or
/// clipping.
///
/// [`read_data_block`] fits its result to what the object's `size` implies,
/// which is right for files — a file is a byte range, and the tail block is
/// short. It is wrong for objects whose blocks are self-describing structures
/// of their own length, such as directory blocks, where padding a 200-byte
/// leaf out to a full record would be pure waste.
///
/// `None` means the block is a hole.
pub async fn read_raw_block(bs: &BlockStore, dnode: &Dnode, index: u64) -> FsResult<Option<Bytes>> {
    let ptr = resolve_ptr(bs, dnode, 0, index).await?;
    if ptr.is_hole() {
        return Ok(None);
    }
    Ok(Some(bs.read_block(&ptr, dnode.objid, index).await?))
}

fn fit(block: Bytes, want: usize) -> Bytes {
    match block.len().cmp(&want) {
        std::cmp::Ordering::Equal => block,
        std::cmp::Ordering::Greater => block.slice(..want),
        std::cmp::Ordering::Less => {
            let mut v = block.to_vec();
            v.resize(want, 0);
            Bytes::from(v)
        }
    }
}

/// Rebuild an object's tree with `dirty` level-0 blocks applied and the object
/// resized to `new_size`.
///
/// Returns the updated dnode. Nothing is written to the backend here — blocks
/// are staged in `writer`, and become durable when the transaction group's
/// slabs are PUT.
pub async fn commit_object(
    bs: &BlockStore,
    writer: &mut SlabWriter,
    dnode: &Dnode,
    dirty: BTreeMap<u64, Vec<u8>>,
    new_size: u64,
) -> FsResult<Dnode> {
    let record_size = dnode.record_size();
    let fanout = dnode.fanout();
    let old_nblocks = dnode.block_count();
    let new_nblocks = blocks_for_size(new_size, record_size);
    let new_levels = levels_for(new_nblocks, fanout);
    let size_changed = new_nblocks != old_nblocks;

    // If the object shrank enough to lose levels, the new root is an interior
    // node of the old tree. Resolve it now so the rebuild below sees a tree of
    // the right height.
    let (base_ptr, base_levels) = if new_levels < dnode.nlevels {
        if new_levels == 0 {
            (BlkPtr::HOLE, 0)
        } else {
            (resolve_ptr(bs, dnode, new_levels - 1, 0).await?, new_levels)
        }
    } else {
        (dnode.blkptr, dnode.nlevels)
    };

    // Level 0: stage every dirty block that survives the resize.
    let mut current: BTreeMap<u64, BlkPtr> = BTreeMap::new();
    for (index, data) in dirty {
        if index >= new_nblocks {
            continue; // written and then truncated away in the same txg
        }
        let ptr = writer.write_block(bs.keys(), dnode.objid, 0, index, 1, &data)?;
        current.insert(index, ptr);
    }

    for level in 1..new_levels {
        // When the tree gains height, the previous root becomes entry 0 of its
        // own level in the new tree. It is not dirty, so nothing else would
        // carry it upward.
        if base_levels >= 1 && level == base_levels && new_levels > base_levels {
            current.entry(0).or_insert(base_ptr);
        }

        let child_count = blocks_at_level(new_nblocks, fanout, level - 1);
        let mut parents: BTreeSet<u64> = current.keys().map(|i| i / fanout).collect();
        // A resize moves the end of every level, so the block containing the
        // new last child must be rewritten to drop what is now past the end.
        if size_changed && child_count > 0 {
            parents.insert((child_count - 1) / fanout);
        }

        let mut next: BTreeMap<u64, BlkPtr> = BTreeMap::new();
        for parent in parents {
            let first_child = parent.saturating_mul(fanout);
            if first_child >= child_count {
                continue; // entirely past the new end; simply unreferenced
            }
            let valid = (child_count - first_child).min(fanout) as usize;

            let mut entries = load_entries(bs, dnode, level, parent, base_levels).await?;
            entries.resize(valid, BlkPtr::HOLE);
            for (index, ptr) in current.range(first_child..first_child + fanout) {
                entries[(index - first_child) as usize] = *ptr;
            }
            while entries.last().is_some_and(|e| e.is_hole()) {
                entries.pop();
            }

            let ptr = if entries.is_empty() {
                BlkPtr::HOLE
            } else {
                let fill = entries.iter().fold(0u32, |a, e| a.saturating_add(e.fill));
                writer.write_block(
                    bs.keys(),
                    dnode.objid,
                    level,
                    parent,
                    fill,
                    &encode_entries(&entries),
                )?
            };
            next.insert(parent, ptr);
        }
        current = next;
    }

    let root = match new_levels {
        0 => BlkPtr::HOLE,
        _ => match current.remove(&0) {
            Some(p) => p,
            // Nothing under the root changed, so the old root still stands.
            None if base_levels == new_levels => base_ptr,
            None => BlkPtr::HOLE,
        },
    };

    Ok(Dnode {
        size: new_size,
        nlevels: if root.is_hole() { 0 } else { new_levels },
        blkptr: root,
        ..dnode.clone()
    })
}

/// Read the existing entries of the level-`level` block at `index`.
///
/// Empty when that block does not exist yet, which is the case for every level
/// above the old tree's height.
async fn load_entries(
    bs: &BlockStore,
    dnode: &Dnode,
    level: u8,
    index: u64,
    base_levels: u8,
) -> FsResult<Vec<BlkPtr>> {
    if base_levels == 0 || level > base_levels - 1 {
        return Ok(Vec::new());
    }
    let ptr = resolve_ptr(bs, dnode, level, index).await?;
    if ptr.is_hole() {
        return Ok(Vec::new());
    }
    let block = bs.read_block(&ptr, dnode.objid, index).await?;
    decode_entries(&block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::backend::{Backend, PutBlobInput};
    use crate::crypto::{KeyMaterial, MasterSecret};
    use crate::store::config::StoreConfig;
    use crate::store::dnode::DnodeKind;
    use std::sync::Arc;

    /// Small records so multi-level trees are reachable in a test: 4 KiB
    /// records give a fan-out of 32, so three levels cover 32 768 blocks.
    fn small_config() -> StoreConfig {
        StoreConfig {
            record_size: 4096,
            slab_max_bytes: 16 * 1024 * 1024,
            ..Default::default()
        }
    }

    fn store(config: StoreConfig) -> (Arc<MemoryBackend>, BlockStore) {
        let backend = Arc::new(MemoryBackend::new());
        let keys =
            Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([2u8; 32]), [0u8; 16]).unwrap());
        let bs = BlockStore::new(backend.clone(), keys, Arc::new(config));
        (backend, bs)
    }

    fn empty_file(record_shift: u8) -> Dnode {
        Dnode::new(42, DnodeKind::File, record_shift, 0)
    }

    /// Apply one transaction group: stage the dirty blocks, rebuild the tree,
    /// PUT the slabs, and return the new dnode.
    async fn commit(
        bs: &BlockStore,
        txg: u64,
        dnode: &Dnode,
        dirty: BTreeMap<u64, Vec<u8>>,
        new_size: u64,
    ) -> Dnode {
        let mut w = SlabWriter::new(txg, bs.config());
        let out = commit_object(bs, &mut w, dnode, dirty, new_size)
            .await
            .unwrap();
        bs.write_slabs(txg, w.finish().unwrap()).await.unwrap();
        out
    }

    fn blocks(spec: &[(u64, u8, usize)]) -> BTreeMap<u64, Vec<u8>> {
        spec.iter()
            .map(|&(idx, fill, len)| (idx, vec![fill; len]))
            .collect()
    }

    async fn read_all(bs: &BlockStore, d: &Dnode) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..d.block_count() {
            out.extend_from_slice(&read_data_block(bs, d, i).await.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn empty_object_has_no_tree() {
        let (backend, bs) = store(small_config());
        let d = commit(&bs, 1, &empty_file(12), BTreeMap::new(), 0).await;

        assert_eq!(d.nlevels, 0);
        assert!(d.blkptr.is_hole());
        assert_eq!(d.size, 0);
        assert_eq!(backend.object_count(), 0);
    }

    #[tokio::test]
    async fn single_block_needs_no_indirect_block() {
        let (_b, bs) = store(small_config());
        let d = commit(&bs, 1, &empty_file(12), blocks(&[(0, 0xaa, 4096)]), 4096).await;

        assert_eq!(d.nlevels, 1, "the dnode pointer is the data block itself");
        assert_eq!(d.blkptr.level, 0);
        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![0xaa; 4096]);
    }

    #[tokio::test]
    async fn short_tail_block_reads_at_its_real_length() {
        let (_b, bs) = store(small_config());
        let d = commit(&bs, 1, &empty_file(12), blocks(&[(0, 7, 100)]), 100).await;
        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![7u8; 100]);
        assert_eq!(d.block_count(), 1);
    }

    #[tokio::test]
    async fn two_blocks_add_one_level() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096)]),
            8192,
        )
        .await;

        assert_eq!(d.nlevels, 2);
        assert_eq!(d.blkptr.level, 1);
        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![1u8; 4096]);
        assert_eq!(read_data_block(&bs, &d, 1).await.unwrap(), vec![2u8; 4096]);
    }

    /// The economy that variable-length indirect blocks buy: a two-block file
    /// must not pay for 32 pointer slots.
    #[tokio::test]
    async fn indirect_blocks_hold_only_the_pointers_they_need() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096)]),
            8192,
        )
        .await;
        assert_eq!(
            d.blkptr.logical_len as usize,
            2 * BLKPTR_LEN,
            "indirect block should hold exactly two pointers"
        );
    }

    #[tokio::test]
    async fn three_levels() {
        let (_b, bs) = store(small_config());
        // Fan-out 32, so block 1000 needs three levels.
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(1000, 9, 4096)]),
            1001 * 4096,
        )
        .await;

        assert_eq!(d.nlevels, 3);
        assert_eq!(d.blkptr.level, 2);
        assert_eq!(
            read_data_block(&bs, &d, 1000).await.unwrap(),
            vec![9u8; 4096]
        );
    }

    #[tokio::test]
    async fn sparse_regions_read_as_zeros() {
        let (backend, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(100, 5, 4096)]),
            101 * 4096,
        )
        .await;

        assert_eq!(
            read_data_block(&bs, &d, 100).await.unwrap(),
            vec![5u8; 4096]
        );
        for i in [0u64, 1, 50, 99] {
            assert_eq!(
                read_data_block(&bs, &d, i).await.unwrap(),
                vec![0u8; 4096],
                "block {i} should be a hole"
            );
        }
        // One data block plus its indirect path — nowhere near 101 blocks.
        assert!(backend.object_count() <= 2);
    }

    #[tokio::test]
    async fn fill_counts_live_blocks_beneath_a_pointer() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (5, 1, 4096), (31, 1, 4096)]),
            32 * 4096,
        )
        .await;
        assert_eq!(d.blkptr.fill, 3);
    }

    // ---- copy-on-write across transaction groups ---------------------------

    #[tokio::test]
    async fn rewriting_one_block_preserves_the_others() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096), (2, 3, 4096)]),
            3 * 4096,
        )
        .await;

        let d = commit(&bs, 2, &d, blocks(&[(1, 0xff, 4096)]), 3 * 4096).await;

        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![1u8; 4096]);
        assert_eq!(read_data_block(&bs, &d, 1).await.unwrap(), vec![0xff; 4096]);
        assert_eq!(read_data_block(&bs, &d, 2).await.unwrap(), vec![3u8; 4096]);
    }

    /// The old tree must still be readable after a new one is committed —
    /// that is what makes an old root a usable snapshot.
    #[tokio::test]
    async fn the_previous_tree_remains_readable() {
        let (_b, bs) = store(small_config());
        let old = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096)]),
            2 * 4096,
        )
        .await;
        let new = commit(&bs, 2, &old, blocks(&[(0, 0xee, 4096)]), 2 * 4096).await;

        assert_eq!(
            read_data_block(&bs, &new, 0).await.unwrap(),
            vec![0xee; 4096]
        );
        assert_eq!(
            read_data_block(&bs, &old, 0).await.unwrap(),
            vec![1u8; 4096],
            "the superseded tree must be unchanged"
        );
        assert_ne!(old.blkptr.dva, new.blkptr.dva);
    }

    #[tokio::test]
    async fn appending_grows_the_tree_and_keeps_existing_data() {
        let (_b, bs) = store(small_config());
        // One block, height 1.
        let d = commit(&bs, 1, &empty_file(12), blocks(&[(0, 1, 4096)]), 4096).await;
        assert_eq!(d.nlevels, 1);

        // Append a second block: height must grow to 2 and block 0 must
        // survive even though it was never dirtied.
        let d = commit(&bs, 2, &d, blocks(&[(1, 2, 4096)]), 2 * 4096).await;
        assert_eq!(d.nlevels, 2);
        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![1u8; 4096]);
        assert_eq!(read_data_block(&bs, &d, 1).await.unwrap(), vec![2u8; 4096]);

        // And again, across a second height increase.
        let d = commit(&bs, 3, &d, blocks(&[(40, 3, 4096)]), 41 * 4096).await;
        assert_eq!(d.nlevels, 3);
        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![1u8; 4096]);
        assert_eq!(read_data_block(&bs, &d, 1).await.unwrap(), vec![2u8; 4096]);
        assert_eq!(read_data_block(&bs, &d, 40).await.unwrap(), vec![3u8; 4096]);
    }

    #[tokio::test]
    async fn growing_by_many_levels_at_once() {
        let (_b, bs) = store(small_config());
        let d = commit(&bs, 1, &empty_file(12), blocks(&[(0, 1, 4096)]), 4096).await;
        // Fan-out 32, so 40 001 blocks needs 32^4 = 1 048 576 of capacity:
        // one jump from height 1 straight to height 5.
        let d = commit(&bs, 2, &d, blocks(&[(40_000, 2, 4096)]), 40_001 * 4096).await;

        assert_eq!(d.nlevels, 5);
        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![1u8; 4096]);
        assert_eq!(
            read_data_block(&bs, &d, 40_000).await.unwrap(),
            vec![2u8; 4096]
        );
    }

    #[tokio::test]
    async fn truncating_shrinks_the_tree() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 4, 4096), (500, 7, 4096)]),
            501 * 4096,
        )
        .await;
        assert_eq!(d.nlevels, 3);

        let d = commit(&bs, 2, &d, BTreeMap::new(), 4096).await;
        assert_eq!(d.nlevels, 1, "one block needs no indirect blocks");
        assert_eq!(d.size, 4096);
        assert_eq!(d.block_count(), 1);
        assert_eq!(
            read_data_block(&bs, &d, 0).await.unwrap(),
            vec![4u8; 4096],
            "the surviving block keeps its contents through the height change"
        );
    }

    /// Truncating a sparse file down to a region that holds no data at all
    /// leaves a live object with no tree — every read is a hole. The size is
    /// still 4 KiB; there is simply nothing stored behind it.
    #[tokio::test]
    async fn truncating_onto_a_hole_leaves_an_empty_tree() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(500, 7, 4096)]),
            501 * 4096,
        )
        .await;
        let d = commit(&bs, 2, &d, BTreeMap::new(), 4096).await;

        assert_eq!(d.nlevels, 0);
        assert!(d.blkptr.is_hole());
        assert_eq!(d.size, 4096);
        assert_eq!(read_data_block(&bs, &d, 0).await.unwrap(), vec![0u8; 4096]);
    }

    #[tokio::test]
    async fn truncating_to_zero_empties_the_tree() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096)]),
            2 * 4096,
        )
        .await;
        let d = commit(&bs, 2, &d, BTreeMap::new(), 0).await;

        assert_eq!(d.nlevels, 0);
        assert!(d.blkptr.is_hole());
        assert_eq!(d.size, 0);
    }

    #[tokio::test]
    async fn truncating_drops_blocks_past_the_new_end() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096), (2, 3, 4096)]),
            3 * 4096,
        )
        .await;
        let d = commit(&bs, 2, &d, BTreeMap::new(), 2 * 4096).await;

        assert_eq!(d.block_count(), 2);
        assert_eq!(read_all(&bs, &d).await.len(), 2 * 4096);
        // The pointer array must have shrunk, not merely been ignored.
        assert_eq!(d.blkptr.logical_len as usize, 2 * BLKPTR_LEN);
    }

    #[tokio::test]
    async fn truncate_then_regrow_reads_zeros_not_stale_data() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 0xcc, 4096)]),
            2 * 4096,
        )
        .await;
        let d = commit(&bs, 2, &d, BTreeMap::new(), 4096).await;
        let d = commit(&bs, 3, &d, BTreeMap::new(), 2 * 4096).await;

        assert_eq!(
            read_data_block(&bs, &d, 1).await.unwrap(),
            vec![0u8; 4096],
            "regrown region must not resurrect the old block"
        );
    }

    #[tokio::test]
    async fn a_committed_block_is_written_only_once() {
        let (_b, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096)]),
            2 * 4096,
        )
        .await;

        // A no-op commit must not rewrite anything: the root pointer stays put.
        let same = commit(&bs, 2, &d, BTreeMap::new(), 2 * 4096).await;
        assert_eq!(
            same.blkptr, d.blkptr,
            "an empty txg must not touch the tree"
        );
    }

    #[tokio::test]
    async fn many_blocks_round_trip() {
        let (_b, bs) = store(small_config());
        let spec: Vec<_> = (0..200u64).map(|i| (i, (i % 251) as u8, 4096)).collect();
        let d = commit(&bs, 1, &empty_file(12), blocks(&spec), 200 * 4096).await;

        assert_eq!(d.nlevels, 3);
        for i in 0..200u64 {
            assert_eq!(
                read_data_block(&bs, &d, i).await.unwrap(),
                vec![(i % 251) as u8; 4096],
                "block {i}"
            );
        }
    }

    // ---- verification ------------------------------------------------------

    /// An indirect block is a block like any other: substituting one must fail
    /// the checksum in its parent.
    #[tokio::test]
    async fn a_tampered_indirect_block_is_rejected() {
        let (backend, bs) = store(small_config());
        let d = commit(
            &bs,
            1,
            &empty_file(12),
            blocks(&[(0, 1, 4096), (1, 2, 4096)]),
            2 * 4096,
        )
        .await;

        let key = bs.config().slab_key(1, 0);
        let mut body = backend.get_blob(&key, None).await.unwrap().body.to_vec();
        // The indirect block is written after the data blocks, so corrupt the tail.
        let last = body.len() - 1;
        body[last] ^= 0xff;
        backend
            .put_blob(PutBlobInput::new(key, Bytes::from(body)))
            .await
            .unwrap();

        assert!(matches!(
            read_data_block(&bs, &d, 0).await,
            Err(FsError::Integrity(_))
        ));
    }

    #[test]
    fn entries_past_the_stored_length_are_holes() {
        let block = [0u8; BLKPTR_LEN];
        assert!(entry_at(&block, 0).unwrap().is_hole());
        assert!(entry_at(&block, 1).unwrap().is_hole());
        assert!(entry_at(&[], 0).unwrap().is_hole());
        assert!(entry_at(&block, u64::MAX).unwrap().is_hole());
    }

    #[test]
    fn ragged_indirect_block_is_rejected() {
        assert!(matches!(
            decode_entries(&[0u8; BLKPTR_LEN + 1]),
            Err(FsError::Integrity(_))
        ));
        assert!(decode_entries(&[0u8; BLKPTR_LEN * 2]).is_ok());
    }

    #[test]
    fn block_logical_len_handles_the_tail() {
        assert_eq!(block_logical_len(0, 4096, 0), 0);
        assert_eq!(block_logical_len(100, 4096, 0), 100);
        assert_eq!(block_logical_len(4096, 4096, 0), 4096);
        assert_eq!(block_logical_len(4097, 4096, 0), 4096);
        assert_eq!(block_logical_len(4097, 4096, 1), 1);
        assert_eq!(block_logical_len(4097, 4096, 2), 0);
    }
}
