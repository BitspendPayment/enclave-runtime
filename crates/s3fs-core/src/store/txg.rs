//! Transaction groups — the commit protocol, and the mounted filesystem.
//!
//! A commit is the only way state changes, and it is atomic at exactly one
//! point: the conditional PUT of the root record.
//!
//! ```text
//!   1. consume a transaction group number        (never reused, see below)
//!   2. rebuild the dnode array copy-on-write     (staged in memory)
//!   3. PUT every slab, and wait for all of them  ← durability barrier
//!   4. seal and sign a root record
//!   5. PUT roots/<seq+1> with If-None-Match: *   ← the atomic commit point
//! ```
//!
//! **Crash consistency** falls out of the ordering. Slabs written without a
//! root are orphans: nothing references them, no reader can reach them, and
//! they are reclaimable by lifecycle policy. A root that exists implies every
//! block it names was already durable, because step 3 completed before step 4
//! began. There is no journal and no fsck.
//!
//! **Losing step 5 is fatal, not retryable.** Another writer took the sequence
//! number. Retrying would reuse this transaction group, and with it every AEAD
//! nonce in the commit — which for AES-GCM leaks the authentication subkey.
//! So the mount is poisoned and every later operation fails.
//!
//! ## Transaction group numbers are never reused
//!
//! This is the invariant the whole encryption scheme rests on, and the
//! non-obvious threat to it is a crash *between* steps 3 and 4. The tip root
//! still names transaction group `T`, so a naive remount would resume at
//! `T + 1` — the very number whose nonces were already burned writing the
//! orphaned slabs. [`next_safe_txg`] closes that by probing forward past any
//! orphan before the first commit of a session.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use crate::backend::Backend;
use crate::crypto::KeyMaterial;
use crate::errors::{FsError, FsResult};

use super::blockstore::BlockStore;
use super::config::StoreConfig;
use super::dnode::{Dnode, DnodeKind, ROOT_OBJID};
use super::objset::ObjectSet;
use super::root::{RootRecord, RootStore};
use super::slab::SlabWriter;

/// Ceiling on how far [`next_safe_txg`] will probe.
///
/// Each orphan is one crash between writing slabs and publishing a root.
/// Hitting this means either something is crashing in a tight loop or the
/// store is fabricating slabs, and both deserve a loud failure rather than an
/// unbounded scan.
const MAX_ORPHAN_PROBE: u64 = 1024;

/// Default permissions for the root directory.
const ROOT_DIR_MODE: u32 = 0o040755;

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Find the first transaction group number that is safe to use.
///
/// Starts just past the tip's transaction group and steps over any that
/// already have a slab — the remains of a commit that died after writing its
/// data but before publishing a root.
pub async fn next_safe_txg(blocks: &BlockStore, tip_txg: u64) -> FsResult<u64> {
    let mut txg = tip_txg + 1;
    for _ in 0..MAX_ORPHAN_PROBE {
        if !blocks.slab_exists(txg, 0).await? {
            return Ok(txg);
        }
        txg += 1;
    }
    Err(FsError::Integrity(
        "txg: too many orphaned transaction groups to skip",
    ))
}

#[derive(Debug)]
struct State {
    objset: ObjectSet,
    root: RootRecord,
    next_txg: u64,
    /// Once set, every operation fails with this. A poisoned mount has either
    /// lost a race for its sequence number or seen the store misbehave; in
    /// both cases continuing would risk silently diverging from what is
    /// actually committed.
    poison: Option<FsError>,
}

/// A mounted filesystem: the block store, the root chain, and the currently
/// committed object set.
#[derive(Debug)]
pub struct Store {
    blocks: Arc<BlockStore>,
    roots: Arc<RootStore>,
    keys: Arc<KeyMaterial>,
    state: Mutex<State>,
}

impl Store {
    /// Mount an existing filesystem, or create one if the bucket is empty.
    pub async fn open(
        data: Arc<dyn Backend>,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        config: Arc<StoreConfig>,
        min_seq: Option<u64>,
    ) -> FsResult<Store> {
        config.validate()?;
        let blocks = Arc::new(BlockStore::new(data, keys.clone(), config.clone()));
        let root_store = Arc::new(RootStore::new(roots, keys.clone(), config.clone()));

        match root_store.mount(min_seq).await? {
            Some(root) => Store::from_root(blocks, root_store, keys, root).await,
            None => Store::format(blocks, root_store, keys, config).await,
        }
    }

    async fn from_root(
        blocks: Arc<BlockStore>,
        roots: Arc<RootStore>,
        keys: Arc<KeyMaterial>,
        root: RootRecord,
    ) -> FsResult<Store> {
        let objset = ObjectSet::from_root(root.meta_dnode.clone(), root.next_objid)?;
        let next_txg = next_safe_txg(&blocks, root.txg).await?;
        Ok(Store {
            blocks,
            roots,
            keys,
            state: Mutex::new(State {
                objset,
                root,
                next_txg,
                poison: None,
            }),
        })
    }

    /// Create a brand-new filesystem: an empty root directory, committed as
    /// root record 0.
    async fn format(
        blocks: Arc<BlockStore>,
        roots: Arc<RootStore>,
        keys: Arc<KeyMaterial>,
        config: Arc<StoreConfig>,
    ) -> FsResult<Store> {
        let shift = config.record_shift();
        let now = now_nanos();
        let txg = 1;

        let mut root_dir = Dnode::new(ROOT_OBJID, DnodeKind::Dir, shift, now);
        root_dir.mode = ROOT_DIR_MODE;

        let mut writer = SlabWriter::new(txg, &config);
        let objset = ObjectSet::format(shift)
            .commit(
                &blocks,
                &mut writer,
                BTreeMap::from([(ROOT_OBJID, root_dir)]),
            )
            .await?;
        blocks.write_slabs(txg, writer.finish()?).await?;

        let root = RootRecord::seal(
            &keys,
            0,
            None,
            txg,
            now,
            objset.meta().clone(),
            objset.next_objid(),
        )?;
        roots.publish(&root).await?;

        Ok(Store {
            blocks,
            roots,
            keys,
            state: Mutex::new(State {
                objset,
                root,
                next_txg: txg + 1,
                poison: None,
            }),
        })
    }

    pub fn blocks(&self) -> &Arc<BlockStore> {
        &self.blocks
    }

    pub fn roots(&self) -> &Arc<RootStore> {
        &self.roots
    }

    /// Snapshot of the committed object set. Reads go through this.
    pub async fn objset(&self) -> FsResult<ObjectSet> {
        let st = self.state.lock().await;
        st.check()?;
        Ok(st.objset.clone())
    }

    /// The currently committed root record.
    pub async fn root(&self) -> FsResult<RootRecord> {
        let st = self.state.lock().await;
        st.check()?;
        Ok(st.root.clone())
    }

    /// Claim an object id for a new file, directory, or symlink.
    pub async fn reserve_objid(&self) -> FsResult<u64> {
        let mut st = self.state.lock().await;
        st.check()?;
        st.objset.alloc_objid()
    }

    /// Whether this mount has been poisoned, and why.
    pub async fn poison(&self) -> Option<FsError> {
        self.state.lock().await.poison.clone()
    }

    /// Open a past state for reading.
    ///
    /// Every root record ever committed is a complete, self-verifying snapshot
    /// — copy-on-write means the blocks it names were never overwritten. So a
    /// snapshot costs nothing to keep and nothing to take; it is simply an
    /// older root that was never deleted.
    ///
    /// Read-only by construction: a [`Snapshot`] has no transaction, and
    /// opening one does not disturb the live mount or its rollback floor.
    pub async fn snapshot(&self, seq: u64) -> FsResult<Snapshot> {
        let root = self.roots.load_snapshot(seq).await?;
        let objset = ObjectSet::from_root(root.meta_dnode.clone(), root.next_objid)?;
        Ok(Snapshot { root, objset })
    }

    /// The newest `limit` root records, most recent first.
    pub async fn list_snapshots(&self, limit: usize) -> FsResult<Vec<RootRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let tip = self.root().await?.seq;
        let mut out = Vec::new();
        let mut seq = tip;
        loop {
            out.push(self.roots.load_snapshot(seq).await?);
            if seq == 0 || out.len() >= limit {
                return Ok(out);
            }
            seq -= 1;
        }
    }

    /// Begin a transaction.
    ///
    /// The returned handle holds the store's lock, so transactions serialise.
    /// It also owns the transaction group's slab writer: object blocks and the
    /// dnodes naming them **must** be staged through the same transaction, or
    /// the root would reference blocks written under a different transaction
    /// group — a number that may never have been committed at all.
    pub async fn begin(&self) -> FsResult<Transaction<'_>> {
        let mut state = self.state.lock().await;
        state.check()?;

        // Consume the transaction group up front and never give it back. An
        // abandoned transaction burns its number, which is exactly right:
        // nothing may ever reuse it.
        let txg = state.next_txg;
        state.next_txg = txg
            .checked_add(1)
            .ok_or(FsError::Invalid("transaction group space exhausted"))?;

        Ok(Transaction {
            store: self,
            writer: SlabWriter::new(txg, self.blocks.config()),
            state,
            txg,
            dirty: BTreeMap::new(),
        })
    }

    /// Commit a set of modified dnodes whose blocks are already durable.
    ///
    /// Convenience for callers that change only dnode metadata. Anything that
    /// writes object blocks must use [`Store::begin`] instead.
    pub async fn commit(&self, dirty: BTreeMap<u64, Dnode>) -> FsResult<RootRecord> {
        if dirty.is_empty() {
            return self.root().await;
        }
        let mut txn = self.begin().await?;
        for (_, d) in dirty {
            txn.stage(d);
        }
        txn.commit().await
    }
}

/// A past state of the filesystem, opened read-only.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The root record this snapshot was taken from.
    pub root: RootRecord,
    objset: ObjectSet,
}

impl Snapshot {
    pub fn objset(&self) -> &ObjectSet {
        &self.objset
    }
}

/// One transaction group in progress.
///
/// Stage object blocks through [`Transaction::writer`] and the dnodes that
/// name them through [`Transaction::stage`], then [`Transaction::commit`].
/// Dropping without committing abandons the work: nothing was published, and
/// the staged blocks were never written.
#[derive(Debug)]
pub struct Transaction<'a> {
    store: &'a Store,
    state: tokio::sync::MutexGuard<'a, State>,
    txg: u64,
    writer: SlabWriter,
    dirty: BTreeMap<u64, Dnode>,
}

impl Transaction<'_> {
    pub fn txg(&self) -> u64 {
        self.txg
    }

    pub fn blocks(&self) -> &Arc<BlockStore> {
        &self.store.blocks
    }

    /// The slab writer for this transaction group.
    pub fn writer(&mut self) -> &mut SlabWriter {
        &mut self.writer
    }

    /// The committed object set this transaction builds on.
    pub fn objset(&self) -> &ObjectSet {
        &self.state.objset
    }

    /// The root record this transaction will supersede.
    pub fn base_root(&self) -> &RootRecord {
        &self.state.root
    }

    /// Claim an object id for a new object.
    pub fn reserve_objid(&mut self) -> FsResult<u64> {
        self.state.objset.alloc_objid()
    }

    /// Record a modified dnode.
    pub fn stage(&mut self, dnode: Dnode) {
        self.dirty.insert(dnode.objid, dnode);
    }

    /// Whether anything at all has been staged.
    pub fn is_empty(&self) -> bool {
        self.dirty.is_empty() && self.writer.block_count() == 0
    }

    /// Publish. See the module documentation for the ordering and why losing
    /// the final conditional PUT is fatal rather than retryable.
    pub async fn commit(mut self) -> FsResult<RootRecord> {
        if self.is_empty() {
            return Ok(self.state.root.clone());
        }
        match self.run().await {
            Ok((objset, root)) => {
                self.state.objset = objset;
                self.state.root = root.clone();
                Ok(root)
            }
            Err(e) => {
                // A transient failure before the root PUT leaves the store
                // exactly as it was — the slabs are orphans — so the mount
                // stays usable and the caller may retry with a fresh
                // transaction group. Anything else means we no longer know
                // what is committed.
                if !e.is_transient() {
                    self.state.poison = Some(e.clone());
                }
                Err(e)
            }
        }
    }

    async fn run(&mut self) -> FsResult<(ObjectSet, RootRecord)> {
        let blocks = &self.store.blocks;
        let dirty = std::mem::take(&mut self.dirty);
        let objset = self
            .state
            .objset
            .commit(blocks, &mut self.writer, dirty)
            .await?;

        // Durability barrier: every block the root will name must be readable
        // before the root exists, or a crash here would publish a root
        // pointing at data that was never written.
        let slabs = std::mem::replace(&mut self.writer, SlabWriter::new(self.txg, blocks.config()))
            .finish()?;
        blocks.write_slabs(self.txg, slabs).await?;

        let root = RootRecord::seal(
            &self.store.keys,
            self.state.root.seq + 1,
            Some(&self.state.root),
            self.txg,
            now_nanos(),
            objset.meta().clone(),
            objset.next_objid(),
        )?;
        self.store.roots.publish(&root).await?;
        Ok((objset, root))
    }
}

impl State {
    fn check(&self) -> FsResult<()> {
        match &self.poison {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::backend::PutBlobInput;
    use crate::crypto::MasterSecret;
    use crate::store::dir::{DirTxn, Dirent};
    use bytes::Bytes;

    struct Harness {
        data: Arc<MemoryBackend>,
        roots: Arc<MemoryBackend>,
        keys: Arc<KeyMaterial>,
        config: Arc<StoreConfig>,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                data: Arc::new(MemoryBackend::new()),
                roots: Arc::new(MemoryBackend::new()),
                keys: Arc::new(
                    KeyMaterial::derive(&MasterSecret::from_bytes([13u8; 32]), [3u8; 16]).unwrap(),
                ),
                config: Arc::new(StoreConfig {
                    record_size: 4096,
                    root_retention: Some(std::time::Duration::from_secs(3600)),
                    ..Default::default()
                }),
            }
        }

        async fn open(&self) -> FsResult<Store> {
            Store::open(
                self.data.clone(),
                self.roots.clone(),
                self.keys.clone(),
                self.config.clone(),
                None,
            )
            .await
        }
    }

    fn file(objid: u64, size: u64) -> Dnode {
        Dnode {
            size,
            ..Dnode::new(objid, DnodeKind::File, 12, 0)
        }
    }

    #[tokio::test]
    async fn formatting_creates_a_root_directory() {
        let h = Harness::new();
        let store = h.open().await.unwrap();

        let root = store.root().await.unwrap();
        assert_eq!(root.seq, 0);
        assert!(root.prev_root_hash.is_zero(), "genesis has no predecessor");

        let objset = store.objset().await.unwrap();
        let dir = objset
            .get_allocated(store.blocks(), ROOT_OBJID)
            .await
            .unwrap();
        assert_eq!(dir.kind, DnodeKind::Dir);
        assert_eq!(dir.mode, ROOT_DIR_MODE);
    }

    #[tokio::test]
    async fn reopening_finds_the_same_filesystem() {
        let h = Harness::new();
        let first = h.open().await.unwrap();
        let root = first.root().await.unwrap();
        drop(first);

        let second = h.open().await.unwrap();
        assert_eq!(second.root().await.unwrap(), root, "must not re-format");
    }

    #[tokio::test]
    async fn each_commit_advances_the_sequence_and_the_merkle_root() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let genesis = store.root().await.unwrap();

        let objid = store.reserve_objid().await.unwrap();
        let r1 = store
            .commit(BTreeMap::from([(objid, file(objid, 100))]))
            .await
            .unwrap();
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.prev_root_hash, genesis.hash());
        assert_ne!(r1.merkle_root(), genesis.merkle_root());
        assert!(r1.txg > genesis.txg);

        let r2 = store
            .commit(BTreeMap::from([(objid, file(objid, 200))]))
            .await
            .unwrap();
        assert_eq!(r2.seq, 2);
        assert_eq!(r2.prev_root_hash, r1.hash());
        assert_ne!(r2.merkle_root(), r1.merkle_root());
    }

    #[tokio::test]
    async fn committed_state_survives_a_remount() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let objid = store.reserve_objid().await.unwrap();
        store
            .commit(BTreeMap::from([(objid, file(objid, 4242))]))
            .await
            .unwrap();
        drop(store);

        let store = h.open().await.unwrap();
        let objset = store.objset().await.unwrap();
        let d = objset.get_allocated(store.blocks(), objid).await.unwrap();
        assert_eq!(d.size, 4242);
    }

    #[tokio::test]
    async fn an_empty_commit_costs_nothing() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let before = store.root().await.unwrap();
        let objects_before = h.roots.object_count();

        let after = store.commit(BTreeMap::new()).await.unwrap();
        assert_eq!(after, before);
        assert_eq!(h.roots.object_count(), objects_before, "no root published");
    }

    #[tokio::test]
    async fn a_directory_survives_a_remount() {
        let h = Harness::new();
        let store = h.open().await.unwrap();

        let mut txn = store.begin().await.unwrap();
        // Own the handle rather than borrowing it from the transaction, so
        // reads can interleave with staging blocks into the same transaction.
        let blocks = txn.blocks().clone();
        let objid = txn.reserve_objid().unwrap();
        let dir = txn
            .objset()
            .get_allocated(&blocks, ROOT_OBJID)
            .await
            .unwrap();

        let mut dirtxn = DirTxn::load(&blocks, &dir).await.unwrap();
        dirtxn
            .insert(Dirent {
                name: "hello.txt".into(),
                objid,
                kind: DnodeKind::File,
            })
            .await
            .unwrap();

        // The directory's blocks and the dnodes naming them belong to one
        // transaction group. Staging them separately would leave the root
        // pointing at blocks from a group that may never be committed.
        let updated_dir = dirtxn.finish(txn.writer()).await.unwrap();
        txn.stage(updated_dir);
        txn.stage(file(objid, 5));
        txn.commit().await.unwrap();
        drop(store);

        let store = h.open().await.unwrap();
        let objset = store.objset().await.unwrap();
        let dir = objset
            .get_allocated(store.blocks(), ROOT_OBJID)
            .await
            .unwrap();
        let mut txn = DirTxn::load(store.blocks(), &dir).await.unwrap();
        assert_eq!(
            txn.lookup("hello.txt").await.unwrap().map(|e| e.objid),
            Some(objid)
        );
    }

    // ---- transaction group discipline --------------------------------------

    /// The crash that matters: slabs written, no root published. Resuming at
    /// the tip's transaction group plus one would land on the number whose
    /// nonces were already spent.
    #[tokio::test]
    async fn a_crash_between_slabs_and_root_does_not_reuse_a_transaction_group() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let tip_txg = store.root().await.unwrap().txg;

        // Simulate the crash directly: write a slab for the next transaction
        // group, and never publish its root.
        let orphan_txg = tip_txg + 1;
        h.data
            .put_blob(PutBlobInput::new(
                h.config.slab_key(orphan_txg, 0),
                Bytes::from_static(b"orphaned commit"),
            ))
            .await
            .unwrap();
        drop(store);

        let store = h.open().await.unwrap();
        let objid = store.reserve_objid().await.unwrap();
        let root = store
            .commit(BTreeMap::from([(objid, file(objid, 1))]))
            .await
            .unwrap();

        assert!(
            root.txg > orphan_txg,
            "commit reused transaction group {} (orphan at {orphan_txg})",
            root.txg
        );
        // And the orphan is untouched, not overwritten.
        assert_eq!(
            h.data
                .get_blob(&h.config.slab_key(orphan_txg, 0), None)
                .await
                .unwrap()
                .body,
            Bytes::from_static(b"orphaned commit")
        );
    }

    #[tokio::test]
    async fn consecutive_orphans_are_all_stepped_over() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let tip_txg = store.root().await.unwrap().txg;
        drop(store);

        for i in 1..=5 {
            h.data
                .put_blob(PutBlobInput::new(
                    h.config.slab_key(tip_txg + i, 0),
                    Bytes::from_static(b"orphan"),
                ))
                .await
                .unwrap();
        }

        let store = h.open().await.unwrap();
        let objid = store.reserve_objid().await.unwrap();
        let root = store
            .commit(BTreeMap::from([(objid, file(objid, 1))]))
            .await
            .unwrap();
        assert!(root.txg > tip_txg + 5, "landed on {}", root.txg);
    }

    #[tokio::test]
    async fn transaction_groups_never_repeat_across_many_commits() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let mut seen = std::collections::HashSet::new();
        seen.insert(store.root().await.unwrap().txg);

        for i in 0..20u64 {
            let objid = store.reserve_objid().await.unwrap();
            let root = store
                .commit(BTreeMap::from([(objid, file(objid, i))]))
                .await
                .unwrap();
            assert!(
                seen.insert(root.txg),
                "transaction group {} reused",
                root.txg
            );
        }
    }

    #[tokio::test]
    async fn a_transaction_group_is_burned_even_when_the_commit_fails() {
        let h = Harness::new();
        let store = h.open().await.unwrap();

        // Steal the sequence number this commit will try to take.
        let genesis = store.root().await.unwrap();
        let stolen = RootRecord::seal(
            &h.keys,
            1,
            Some(&genesis),
            12345,
            0,
            genesis.meta_dnode.clone(),
            2,
        )
        .unwrap();
        let rs = RootStore::new(h.roots.clone(), h.keys.clone(), h.config.clone());
        rs.publish(&stolen).await.unwrap();

        let objid = store.reserve_objid().await.unwrap();
        let failed_txg = {
            let st = store.state.lock().await;
            st.next_txg
        };
        assert!(matches!(
            store
                .commit(BTreeMap::from([(objid, file(objid, 1))]))
                .await,
            Err(FsError::Conflict)
        ));

        let after = store.state.lock().await.next_txg;
        assert!(
            after > failed_txg,
            "a failed commit must still consume its transaction group"
        );
    }

    // ---- poisoning ---------------------------------------------------------

    /// Losing the race for a sequence number is fatal. Retrying would reuse
    /// the transaction group and repeat every nonce in it.
    #[tokio::test]
    async fn losing_the_sequence_race_poisons_the_mount() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let genesis = store.root().await.unwrap();

        let rs = RootStore::new(h.roots.clone(), h.keys.clone(), h.config.clone());
        let stolen = RootRecord::seal(
            &h.keys,
            1,
            Some(&genesis),
            999,
            0,
            genesis.meta_dnode.clone(),
            2,
        )
        .unwrap();
        rs.publish(&stolen).await.unwrap();

        let objid = store.reserve_objid().await.unwrap();
        assert!(matches!(
            store
                .commit(BTreeMap::from([(objid, file(objid, 1))]))
                .await,
            Err(FsError::Conflict)
        ));

        assert!(matches!(store.poison().await, Some(FsError::Conflict)));
        // Everything afterwards fails, including reads: we no longer know what
        // is committed.
        assert!(store.root().await.is_err());
        assert!(store.objset().await.is_err());
        assert!(store.commit(BTreeMap::new()).await.is_err());
    }

    #[tokio::test]
    async fn a_healthy_mount_is_not_poisoned() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let objid = store.reserve_objid().await.unwrap();
        store
            .commit(BTreeMap::from([(objid, file(objid, 1))]))
            .await
            .unwrap();
        assert!(store.poison().await.is_none());
    }

    // ---- rollback ----------------------------------------------------------

    #[tokio::test]
    async fn a_mount_floor_rejects_a_rewound_store() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        for i in 0..3u64 {
            let objid = store.reserve_objid().await.unwrap();
            store
                .commit(BTreeMap::from([(objid, file(objid, i))]))
                .await
                .unwrap();
        }
        drop(store);

        // Mounting with a floor at or below the real tip is fine.
        assert!(Store::open(
            h.data.clone(),
            h.roots.clone(),
            h.keys.clone(),
            h.config.clone(),
            Some(3)
        )
        .await
        .is_ok());

        // A floor above it means the store is behind where we know it to be.
        assert!(matches!(
            Store::open(
                h.data.clone(),
                h.roots.clone(),
                h.keys.clone(),
                h.config.clone(),
                Some(4)
            )
            .await,
            Err(FsError::Rollback {
                expected: 4,
                found: 3
            })
        ));
    }

    /// The end-to-end rollback story: an adversary who can write to the bucket
    /// cannot make a mount accept an older state, because the newer roots
    /// cannot be deleted and the sequence is checked against the key.
    #[tokio::test]
    async fn an_adversary_cannot_rewind_the_filesystem() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let objid = store.reserve_objid().await.unwrap();
        store
            .commit(BTreeMap::from([(objid, file(objid, 111))]))
            .await
            .unwrap();
        let old_root = store.root().await.unwrap();
        store
            .commit(BTreeMap::from([(objid, file(objid, 222))]))
            .await
            .unwrap();
        drop(store);

        // Try to delete the newest root: Object Lock refuses.
        assert!(matches!(
            h.roots.delete_blob(&h.config.root_key(2)).await,
            Err(FsError::AccessDenied)
        ));

        // Try to replay the older root over the newer key: also refused, and
        // even if it landed, its `seq` would not match the key.
        assert!(matches!(
            h.roots
                .put_blob(PutBlobInput::new(
                    h.config.root_key(2),
                    Bytes::from(old_root.encode().unwrap())
                ))
                .await,
            Err(FsError::AccessDenied)
        ));

        // The filesystem still mounts at the newest state.
        let store = h.open().await.unwrap();
        assert_eq!(store.root().await.unwrap().seq, 2);
        let objset = store.objset().await.unwrap();
        assert_eq!(
            objset
                .get_allocated(store.blocks(), objid)
                .await
                .unwrap()
                .size,
            222
        );
    }

    #[tokio::test]
    async fn a_replayed_root_at_the_wrong_key_is_refused() {
        let h = Harness::new();
        let store = h.open().await.unwrap();
        let objid = store.reserve_objid().await.unwrap();
        store
            .commit(BTreeMap::from([(objid, file(objid, 1))]))
            .await
            .unwrap();
        let old = store.root().await.unwrap();
        drop(store);

        // Plant root 1's bytes at key 2, which no one has claimed yet.
        h.roots
            .put_blob_if_not_exists(PutBlobInput::new(
                h.config.root_key(2),
                Bytes::from(old.encode().unwrap()),
            ))
            .await
            .unwrap();

        // Tip discovery finds key 2; verification rejects it, and the mount
        // fails closed rather than silently falling back to key 1.
        assert!(matches!(
            h.open().await,
            Err(FsError::Integrity("root: sequence does not match its key"))
        ));
    }
}
