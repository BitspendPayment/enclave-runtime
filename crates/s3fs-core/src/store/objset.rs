//! The object set — every dnode in the filesystem, addressed by object id.
//!
//! Dnodes live in the data blocks of one special object, the **meta-dnode**.
//! Object `N` sits at slot `N % 256` of block `N / 256` (at the default record
//! size). Updating one object therefore copies one 128 KiB block and the
//! indirect path above it, and yields a new pointer at the top — and *that
//! pointer is the filesystem's Merkle root*. It is the single value the root
//! record signs, and it transitively covers every dnode, every indirect block,
//! and every byte of data.
//!
//! ```text
//!   root record ──▶ meta_dnode BlkPtr ──▶ indirect ──▶ [dnode][dnode][dnode]…
//!                                                          │
//!                                                          └──▶ that object's own tree
//! ```
//!
//! The meta-dnode is the one object not stored in the array; its pointer lives
//! in the root record. Slot 0 is left permanently free so that slot index and
//! object id are the same number.
//!
//! ## Object ids are never reused
//!
//! Allocation is a monotonic counter. A `u64` cannot be exhausted, and not
//! reusing ids means `(objid, gen)` is a permanently stable identity — which
//! is what lets `is-same-object` and `metadata-hash` be exact, and agree
//! across mounts. Deleted objects leave a `Free` slot behind; reclaiming those
//! is a garbage-collection concern, not an allocation one.

use std::collections::BTreeMap;

use crate::errors::{FsError, FsResult};

use super::blockstore::BlockStore;
use super::dnode::{dnodes_per_block, Dnode, DnodeKind, DNODE_LEN, META_OBJID, ROOT_OBJID};
use super::indirect::{commit_object, read_data_block};
use super::slab::SlabWriter;

/// Every dnode in the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSet {
    /// The dnode array's own dnode. Its `blkptr` is the Merkle root.
    meta: Dnode,
    /// Next object id to hand out.
    next_objid: u64,
}

impl ObjectSet {
    /// A brand-new, empty object set. Object ids start after the root
    /// directory's reserved id.
    pub fn format(record_shift: u8) -> Self {
        ObjectSet {
            meta: Dnode::new(META_OBJID, DnodeKind::DnodeArray, record_shift, 0),
            next_objid: ROOT_OBJID + 1,
        }
    }

    /// Reconstruct from the fields a root record carries.
    pub fn from_root(meta: Dnode, next_objid: u64) -> FsResult<Self> {
        if meta.kind != DnodeKind::DnodeArray || meta.objid != META_OBJID {
            return Err(FsError::Integrity(
                "objset: meta-dnode is not a dnode array",
            ));
        }
        if next_objid <= ROOT_OBJID {
            return Err(FsError::Integrity(
                "objset: next_objid below the root object",
            ));
        }
        Ok(ObjectSet { meta, next_objid })
    }

    pub fn meta(&self) -> &Dnode {
        &self.meta
    }

    pub fn next_objid(&self) -> u64 {
        self.next_objid
    }

    /// The Merkle root: the pointer covering every dnode and everything under
    /// them.
    pub fn merkle_root(&self) -> &super::blkptr::BlkPtr {
        &self.meta.blkptr
    }

    fn slots_per_block(&self) -> u64 {
        dnodes_per_block(self.meta.record_size()) as u64
    }

    /// Claim a fresh object id.
    pub fn alloc_objid(&mut self) -> FsResult<u64> {
        let id = self.next_objid;
        self.next_objid = id
            .checked_add(1)
            .ok_or(FsError::Invalid("object id space exhausted"))?;
        Ok(id)
    }

    /// Read one dnode. Unallocated slots come back as `Free`.
    pub async fn get(&self, bs: &BlockStore, objid: u64) -> FsResult<Dnode> {
        if objid == META_OBJID {
            return Ok(self.meta.clone());
        }
        let per = self.slots_per_block();
        let block_index = objid / per;
        let slot = (objid % per) as usize;

        let block = read_data_block(bs, &self.meta, block_index).await?;
        let start = slot * DNODE_LEN;
        let raw = match block.get(start..start + DNODE_LEN) {
            Some(raw) => raw,
            // Past the end of the array: never allocated.
            None => return Ok(Dnode::free(objid, self.meta.record_shift)),
        };
        // An untouched slot is all zeros, which is not a decodable dnode. Treat
        // it as free rather than as corruption.
        if raw.iter().all(|&b| b == 0) {
            return Ok(Dnode::free(objid, self.meta.record_shift));
        }

        let d = Dnode::decode(raw)?;
        // The AEAD binds a block to its position, but not a dnode to its slot
        // *within* a block. Without this check, two dnodes could be swapped
        // inside one block and every cryptographic check would still pass.
        if d.objid != objid {
            return Err(FsError::Integrity("objset: dnode is in the wrong slot"));
        }
        Ok(d)
    }

    /// Read one dnode, requiring that it is allocated.
    pub async fn get_allocated(&self, bs: &BlockStore, objid: u64) -> FsResult<Dnode> {
        let d = self.get(bs, objid).await?;
        if d.kind == DnodeKind::Free {
            return Err(FsError::NotFound);
        }
        Ok(d)
    }

    /// Write `dirty` dnodes into the array and rebuild it copy-on-write.
    ///
    /// Blocks are staged in `writer`; the returned object set carries the new
    /// Merkle root, which the caller seals into a root record.
    pub async fn commit(
        &self,
        bs: &BlockStore,
        writer: &mut SlabWriter,
        dirty: BTreeMap<u64, Dnode>,
    ) -> FsResult<ObjectSet> {
        for (objid, d) in &dirty {
            if d.objid != *objid {
                return Err(FsError::Invalid(
                    "objset: dnode objid disagrees with its key",
                ));
            }
            if *objid == META_OBJID {
                return Err(FsError::Invalid(
                    "objset: the meta-dnode is not an array entry",
                ));
            }
        }

        let per = self.slots_per_block();
        let record_size = self.meta.record_size();
        let highest = dirty.keys().next_back().copied().unwrap_or(0);
        let next_objid = self.next_objid.max(highest + 1);

        // Every block of the array is full-length, so slot arithmetic never
        // has to reason about a short tail block.
        let nblocks = next_objid.div_ceil(per);
        let new_size = nblocks * record_size as u64;

        // Group by block, then read-modify-write each affected block once.
        let mut by_block: BTreeMap<u64, Vec<&Dnode>> = BTreeMap::new();
        for (objid, d) in &dirty {
            by_block.entry(objid / per).or_default().push(d);
        }

        let mut dirty_blocks: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for (block_index, dnodes) in by_block {
            let old = read_data_block(bs, &self.meta, block_index).await?;
            let mut buf = old.to_vec();
            buf.resize(record_size, 0);
            for d in dnodes {
                let start = (d.objid % per) as usize * DNODE_LEN;
                buf[start..start + DNODE_LEN].copy_from_slice(&d.encode()?);
            }
            dirty_blocks.insert(block_index, buf);
        }

        let meta = commit_object(bs, writer, &self.meta, dirty_blocks, new_size).await?;
        Ok(ObjectSet { meta, next_objid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::crypto::{KeyMaterial, MasterSecret};
    use crate::store::config::StoreConfig;
    use std::sync::Arc;

    /// 4 KiB records give 8 dnodes per block, so block boundaries are easy to
    /// cross in a test.
    fn small_config() -> StoreConfig {
        StoreConfig {
            record_size: 4096,
            ..Default::default()
        }
    }

    fn store(config: StoreConfig) -> (Arc<MemoryBackend>, BlockStore) {
        let backend = Arc::new(MemoryBackend::new());
        let keys =
            Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([6u8; 32]), [0u8; 16]).unwrap());
        let bs = BlockStore::new(backend.clone(), keys, Arc::new(config));
        (backend, bs)
    }

    async fn commit(
        bs: &BlockStore,
        txg: u64,
        os: &ObjectSet,
        dirty: BTreeMap<u64, Dnode>,
    ) -> ObjectSet {
        let mut w = SlabWriter::new(txg, bs.config());
        let out = os.commit(bs, &mut w, dirty).await.unwrap();
        bs.write_slabs(txg, w.finish().unwrap()).await.unwrap();
        out
    }

    fn file(objid: u64, size: u64) -> Dnode {
        Dnode {
            size,
            ..Dnode::new(objid, DnodeKind::File, 12, 1000)
        }
    }

    #[test]
    fn a_fresh_object_set_is_empty() {
        let os = ObjectSet::format(12);
        assert_eq!(os.next_objid(), ROOT_OBJID + 1);
        assert!(os.merkle_root().is_hole());
        assert_eq!(os.meta().kind, DnodeKind::DnodeArray);
    }

    #[test]
    fn object_ids_are_handed_out_monotonically() {
        let mut os = ObjectSet::format(12);
        let a = os.alloc_objid().unwrap();
        let b = os.alloc_objid().unwrap();
        assert_eq!(b, a + 1);
        assert!(a > ROOT_OBJID, "the root directory's id is reserved");
    }

    #[tokio::test]
    async fn store_and_load_one_dnode() {
        let (_b, bs) = store(small_config());
        let os = ObjectSet::format(12);

        let d = file(ROOT_OBJID + 1, 1234);
        let os = commit(&bs, 1, &os, BTreeMap::from([(d.objid, d.clone())])).await;

        assert_eq!(os.get(&bs, d.objid).await.unwrap(), d);
        assert!(!os.merkle_root().is_hole(), "the Merkle root must be live");
    }

    #[tokio::test]
    async fn unallocated_slots_read_as_free() {
        let (_b, bs) = store(small_config());
        let os = ObjectSet::format(12);
        let os = commit(&bs, 1, &os, BTreeMap::from([(5, file(5, 10))])).await;

        // A never-written slot inside an allocated block.
        assert_eq!(os.get(&bs, 4).await.unwrap().kind, DnodeKind::Free);
        // A slot past the end of the array entirely.
        assert_eq!(os.get(&bs, 9_999).await.unwrap().kind, DnodeKind::Free);
        assert!(matches!(
            os.get_allocated(&bs, 4).await,
            Err(FsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn many_dnodes_across_several_blocks() {
        let (_b, bs) = store(small_config());
        let os = ObjectSet::format(12);

        // 8 dnodes per 4 KiB block, so 40 objects spans several blocks.
        let dirty: BTreeMap<_, _> = (2..42u64).map(|i| (i, file(i, i * 100))).collect();
        let os = commit(&bs, 1, &os, dirty).await;

        assert_eq!(os.next_objid(), 42);
        for i in 2..42u64 {
            let d = os.get(&bs, i).await.unwrap();
            assert_eq!(d.objid, i);
            assert_eq!(d.size, i * 100, "object {i}");
        }
    }

    #[tokio::test]
    async fn updating_one_dnode_leaves_its_block_mates_alone() {
        let (_b, bs) = store(small_config());
        let os = ObjectSet::format(12);
        // Objects 2..6 share one block at 8 slots per block.
        let dirty: BTreeMap<_, _> = (2..6u64).map(|i| (i, file(i, i))).collect();
        let os = commit(&bs, 1, &os, dirty).await;

        let mut changed = file(3, 999_999);
        changed.mtime_nanos = 42;
        let os = commit(&bs, 2, &os, BTreeMap::from([(3, changed.clone())])).await;

        assert_eq!(os.get(&bs, 3).await.unwrap(), changed);
        for i in [2u64, 4, 5] {
            assert_eq!(
                os.get(&bs, i).await.unwrap().size,
                i,
                "object {i} was disturbed"
            );
        }
    }

    /// The Merkle root must move whenever anything beneath it does — that is
    /// the entire premise of anchoring the filesystem on one hash.
    #[tokio::test]
    async fn the_merkle_root_changes_on_every_mutation() {
        let (_b, bs) = store(small_config());
        let os = ObjectSet::format(12);

        let os1 = commit(&bs, 1, &os, BTreeMap::from([(2, file(2, 1))])).await;
        let root1 = *os1.merkle_root();

        let os2 = commit(&bs, 2, &os1, BTreeMap::from([(2, file(2, 2))])).await;
        let root2 = *os2.merkle_root();

        assert_ne!(root1.checksum, root2.checksum);
        assert_ne!(
            root1.dva, root2.dva,
            "copy-on-write must not reuse the address"
        );

        // And the superseded object set still reads its own version.
        assert_eq!(os1.get(&bs, 2).await.unwrap().size, 1);
        assert_eq!(os2.get(&bs, 2).await.unwrap().size, 2);
    }

    #[tokio::test]
    async fn an_empty_commit_leaves_the_root_untouched() {
        let (_b, bs) = store(small_config());
        let os = commit(
            &bs,
            1,
            &ObjectSet::format(12),
            BTreeMap::from([(2, file(2, 1))]),
        )
        .await;
        let again = commit(&bs, 2, &os, BTreeMap::new()).await;
        assert_eq!(again.merkle_root(), os.merkle_root());
    }

    #[tokio::test]
    async fn committing_a_high_object_id_extends_the_array() {
        let (_b, bs) = store(small_config());
        let os = commit(
            &bs,
            1,
            &ObjectSet::format(12),
            BTreeMap::from([(1000, file(1000, 7))]),
        )
        .await;

        assert_eq!(os.next_objid(), 1001);
        assert_eq!(os.get(&bs, 1000).await.unwrap().size, 7);
        // The intervening slots cost nothing: they are holes.
        assert_eq!(os.get(&bs, 500).await.unwrap().kind, DnodeKind::Free);
    }

    #[tokio::test]
    async fn rejects_a_dnode_filed_under_the_wrong_key() {
        let (_b, bs) = store(small_config());
        let mut w = SlabWriter::new(1, bs.config());
        let os = ObjectSet::format(12);
        assert!(os
            .commit(&bs, &mut w, BTreeMap::from([(5, file(6, 0))]))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_writing_the_meta_dnode_as_an_entry() {
        let (_b, bs) = store(small_config());
        let mut w = SlabWriter::new(1, bs.config());
        let os = ObjectSet::format(12);
        assert!(os
            .commit(
                &bs,
                &mut w,
                BTreeMap::from([(META_OBJID, file(META_OBJID, 0))])
            )
            .await
            .is_err());
    }

    /// Position-binding AAD covers a whole block, not a dnode's slot inside it.
    /// Two dnodes swapped within one block would pass every cryptographic
    /// check, so the identity field has to be verified explicitly.
    #[tokio::test]
    async fn rejects_a_dnode_moved_to_another_slot() {
        let (_b, bs) = store(small_config());
        let os = ObjectSet::format(12);

        // Hand-build a block where object 2's dnode sits in object 3's slot.
        let mut buf = vec![0u8; 4096];
        buf[3 * DNODE_LEN..4 * DNODE_LEN].copy_from_slice(&file(2, 1).encode().unwrap());

        let mut w = SlabWriter::new(1, bs.config());
        let meta = commit_object(&bs, &mut w, os.meta(), BTreeMap::from([(0u64, buf)]), 4096)
            .await
            .unwrap();
        bs.write_slabs(1, w.finish().unwrap()).await.unwrap();

        let forged = ObjectSet::from_root(meta, 10).unwrap();
        assert!(matches!(
            forged.get(&bs, 3).await,
            Err(FsError::Integrity("objset: dnode is in the wrong slot"))
        ));
    }

    #[test]
    fn from_root_rejects_a_meta_dnode_of_the_wrong_kind() {
        let bad = Dnode::new(META_OBJID, DnodeKind::File, 12, 0);
        assert!(ObjectSet::from_root(bad, 10).is_err());

        let wrong_id = Dnode::new(7, DnodeKind::DnodeArray, 12, 0);
        assert!(ObjectSet::from_root(wrong_id, 10).is_err());

        let good = Dnode::new(META_OBJID, DnodeKind::DnodeArray, 12, 0);
        assert!(ObjectSet::from_root(good.clone(), 10).is_ok());
        assert!(
            ObjectSet::from_root(good, ROOT_OBJID).is_err(),
            "next_objid must leave room for the root directory"
        );
    }

    #[tokio::test]
    async fn round_trips_through_from_root() {
        let (_b, bs) = store(small_config());
        let os = commit(
            &bs,
            1,
            &ObjectSet::format(12),
            BTreeMap::from([(2, file(2, 42))]),
        )
        .await;

        // What a mount does: rebuild the object set from what the root record
        // carries, then read through it.
        let remounted = ObjectSet::from_root(os.meta().clone(), os.next_objid()).unwrap();
        assert_eq!(remounted, os);
        assert_eq!(remounted.get(&bs, 2).await.unwrap().size, 42);
    }
}
