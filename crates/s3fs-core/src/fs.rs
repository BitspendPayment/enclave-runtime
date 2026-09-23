//! `Fs` — POSIX semantics over the block store.
//!
//! Every mutation is one transaction group, and therefore one root record: a
//! `mkdir` either happened or did not, and there is no window in which half of
//! it is visible. That is a direct consequence of the store's commit protocol
//! rather than anything this layer arranges, and it is why several operations
//! that the previous engine could only approximate are now exact:
//!
//! - **`rename` is atomic.** It moves a directory entry inside one commit.
//!   There is no copy-then-delete window, no background queue, and a directory
//!   rename costs the same as a file rename instead of `O(entries)` copies.
//! - **`stat` cannot go stale.** Attributes come from the dnode on every call.
//!   The previous engine cached them behind a TTL that was never checked.
//! - **Identity is real.** `(objid, gen)` is stable across mounts.
//!
//! ## Buffering
//!
//! Writes accumulate in the handle as whole records and reach the store on
//! `sync`, `set_size`, or `close` — the transaction-group model the plan
//! specifies. Reads consult the handle's dirty records first, so a writer sees
//! its own unsynced writes; another handle does not, and on a crash they are
//! lost. What cannot happen is a torn or partially-applied state.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use crate::backend::Backend;
use crate::config::Config;
use crate::crypto::{KeyMaterial, MasterSecret};
use crate::errors::{FsError, FsResult};
use crate::inode::{now_nanos, to_nanos, Attrs, DirEntry, Inode, InodeKind};
use crate::path::{validate_segment, validate_symlink_target};
use crate::store::blockstore::BlockStore;
use crate::store::dir::{DirTxn, Dirent};
use crate::store::dnode::{blocks_for_size, Dnode, DnodeKind, INLINE_CAP, ROOT_OBJID};
use crate::store::indirect::{block_logical_len, commit_object, read_data_block};
use crate::store::objset::ObjectSet;
use crate::store::Store;

/// Default permissions for objects this layer creates.
const DEFAULT_FILE_MODE: u32 = 0o100644;
const DEFAULT_DIR_MODE: u32 = 0o040755;
const DEFAULT_SYMLINK_MODE: u32 = 0o120777;

/// Stable handle ID for an open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HandleId(pub NonZeroU64);

impl HandleId {
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// Open-time flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub truncate: bool,
    pub create: bool,
    pub exclusive: bool,
}

impl OpenFlags {
    pub fn read_only() -> Self {
        Self {
            read: true,
            ..Self::default()
        }
    }
    pub fn write_only() -> Self {
        Self {
            write: true,
            ..Self::default()
        }
    }
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            ..Self::default()
        }
    }
    pub fn create_new() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            exclusive: true,
            ..Self::default()
        }
    }
}

/// Unsynced state of one open file.
#[derive(Debug)]
struct HandleState {
    /// Size as this handle sees it, including unsynced growth.
    size: u64,
    /// Whole records awaiting commit, keyed by record index.
    dirty: BTreeMap<u64, Vec<u8>>,
    /// Timestamps or size changed without any data changing.
    meta_dirty: bool,
    atime_nanos: u64,
    mtime_nanos: u64,
}

/// An open file.
#[derive(Debug)]
pub struct FileHandle {
    pub id: HandleId,
    pub inode: Arc<Inode>,
    pub flags: OpenFlags,
    state: Mutex<HandleState>,
}

impl FileHandle {
    /// Size including writes not yet committed.
    pub async fn size(&self) -> u64 {
        self.state.lock().await.size
    }
}

/// Objects that have lost their last name but are still open.
///
/// POSIX keeps an unlinked file alive until the last descriptor closes. The
/// dnode stays allocated with `nlink == 0`, unreachable by name — path
/// resolution goes through directory entries, and there are none left — so the
/// only way to it is a handle that already existed. When the last one closes,
/// it is freed.
///
/// A crash in that window leaks the dnode: allocated, nameless, unreachable.
/// That is garbage, not corruption, and it is the same trade a real filesystem
/// makes with its orphan inode list.
#[derive(Debug, Default)]
struct OpenTracker {
    /// Open handle count per object id.
    counts: HashMap<u64, usize>,
    /// Objects awaiting their last close.
    orphans: HashSet<u64>,
}

impl OpenTracker {
    fn opened(&mut self, objid: u64) {
        *self.counts.entry(objid).or_insert(0) += 1;
    }

    /// Record a close. Returns `true` if this was the last handle on an
    /// orphaned object, meaning the caller must now free it.
    fn closed(&mut self, objid: u64) -> bool {
        let remaining = match self.counts.get_mut(&objid) {
            Some(n) => {
                *n = n.saturating_sub(1);
                *n
            }
            None => 0,
        };
        if remaining == 0 {
            self.counts.remove(&objid);
            return self.orphans.remove(&objid);
        }
        false
    }

    fn is_open(&self, objid: u64) -> bool {
        self.counts.contains_key(&objid)
    }

    fn mark_orphan(&mut self, objid: u64) {
        self.orphans.insert(objid);
    }
}

/// The filesystem.
#[derive(Debug)]
pub struct Fs {
    store: Arc<Store>,
    pub config: Arc<Config>,
    handles: SyncMutex<HashMap<u64, Arc<FileHandle>>>,
    open: SyncMutex<OpenTracker>,
    next_handle: AtomicU64,
}

impl Fs {
    /// Mount an existing filesystem. Fails with [`FsError::NoFilesystem`] if
    /// the store is empty — see [`Store::open_existing`] for why that is not a
    /// cue to create one.
    ///
    /// `roots` is the Object Lock bucket holding the anchor chain; `data`
    /// holds the slabs. They may be the same bucket, but splitting them is
    /// what lets dead copy-on-write blocks stay reclaimable while the anchor
    /// stays immutable.
    ///
    /// `fs_uuid` is the HKDF salt. It is not a secret, but it must be supplied
    /// rather than discovered: the keys that verify a root record are derived
    /// from it, so reading it out of the store would mean trusting the store
    /// to tell us which key to check its own signature with.
    pub async fn mount(
        data: Arc<dyn Backend>,
        roots: Arc<dyn Backend>,
        master: &MasterSecret,
        fs_uuid: [u8; 16],
        config: Arc<Config>,
        min_root_seq: Option<u64>,
    ) -> FsResult<Arc<Fs>> {
        let keys = Arc::new(KeyMaterial::derive(master, fs_uuid)?);
        let store = Store::open_existing(
            data,
            roots,
            keys,
            Arc::new(config.store.clone()),
            min_root_seq,
        )
        .await?;
        Ok(Fs::from_store(Arc::new(store), config))
    }

    /// Create a filesystem in an empty store.
    ///
    /// Separate from [`Fs::mount`] on purpose: creating one is an assertion
    /// that no filesystem should already exist here, and the caller is the only
    /// party that can make it.
    pub async fn create(
        data: Arc<dyn Backend>,
        roots: Arc<dyn Backend>,
        master: &MasterSecret,
        fs_uuid: [u8; 16],
        config: Arc<Config>,
    ) -> FsResult<Arc<Fs>> {
        let keys = Arc::new(KeyMaterial::derive(master, fs_uuid)?);
        let store = Store::create(data, roots, keys, Arc::new(config.store.clone())).await?;
        Ok(Fs::from_store(Arc::new(store), config))
    }

    pub fn from_store(store: Arc<Store>, config: Arc<Config>) -> Arc<Fs> {
        Arc::new(Fs {
            store,
            config,
            handles: SyncMutex::new(HashMap::new()),
            open: SyncMutex::new(OpenTracker::default()),
            next_handle: AtomicU64::new(1),
        })
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The mount's root directory.
    pub fn root(&self) -> Arc<Inode> {
        Inode::new(ROOT_OBJID, 0)
    }

    pub fn get_handle(&self, id: HandleId) -> Option<Arc<FileHandle>> {
        self.handles.lock().get(&id.get()).cloned()
    }

    fn blocks(&self) -> Arc<BlockStore> {
        self.store.blocks().clone()
    }

    async fn objset(&self) -> FsResult<ObjectSet> {
        self.store.objset().await
    }

    async fn dnode(&self, objid: u64) -> FsResult<Dnode> {
        self.objset()
            .await?
            .get_allocated(&self.blocks(), objid)
            .await
    }

    // -- resolution ---------------------------------------------------------

    /// Resolve `path` relative to `base`, following symlinks except optionally
    /// the final component.
    pub async fn lookup_at(&self, base: &Arc<Inode>, path: &str) -> FsResult<Arc<Inode>> {
        self.resolve(base, path, true).await
    }

    pub async fn lookup_at_no_follow(&self, base: &Arc<Inode>, path: &str) -> FsResult<Arc<Inode>> {
        self.resolve(base, path, false).await
    }

    async fn resolve(
        &self,
        base: &Arc<Inode>,
        path: &str,
        follow_final: bool,
    ) -> FsResult<Arc<Inode>> {
        self.resolve_within(ROOT_OBJID, base, path, follow_final)
            .await
    }

    /// Resolve without leaving the subtree rooted at `scope`.
    ///
    /// This is the capability boundary between two tenants of one filesystem.
    /// See [`resolve_in`] for what it forecloses and why those are the only
    /// three routes out.
    async fn resolve_within(
        &self,
        scope: u64,
        base: &Arc<Inode>,
        path: &str,
        follow_final: bool,
    ) -> FsResult<Arc<Inode>> {
        let objset = self.objset().await?;
        let blocks = self.blocks();
        let objid = resolve_in(
            &objset,
            &blocks,
            scope,
            base.objid(),
            path,
            follow_final,
            self.config.max_symlink_depth,
        )
        .await?;
        let d = objset.get_allocated(&blocks, objid).await?;
        Ok(Inode::new(objid, d.gen))
    }

    /// [`Fs::lookup_at`], confined to `scope`.
    pub async fn lookup_within(
        &self,
        scope: &Arc<Inode>,
        base: &Arc<Inode>,
        path: &str,
    ) -> FsResult<Arc<Inode>> {
        self.resolve_within(scope.objid(), base, path, true).await
    }

    /// [`Fs::lookup_at_no_follow`], confined to `scope`.
    pub async fn lookup_within_no_follow(
        &self,
        scope: &Arc<Inode>,
        base: &Arc<Inode>,
        path: &str,
    ) -> FsResult<Arc<Inode>> {
        self.resolve_within(scope.objid(), base, path, false).await
    }

    /// [`Fs::parent_of`], confined to `scope`.
    ///
    /// The scope is its own parent, so a descriptor at the top of a tenant's
    /// subtree cannot be walked upwards out of it — `..` is not the only way
    /// to ask for a parent, and this is the other one.
    pub async fn parent_within(
        &self,
        scope: &Arc<Inode>,
        ino: &Arc<Inode>,
    ) -> FsResult<Arc<Inode>> {
        if ino.objid() == scope.objid() {
            return Ok(scope.clone());
        }
        self.parent_of(ino).await
    }

    // -- metadata -----------------------------------------------------------

    pub async fn stat(&self, ino: &Arc<Inode>) -> FsResult<Attrs> {
        Attrs::from_dnode(&self.dnode(ino.objid()).await?)
    }

    /// The directory containing `ino`. The root is its own parent.
    pub async fn parent_of(&self, ino: &Arc<Inode>) -> FsResult<Arc<Inode>> {
        let d = self.dnode(ino.objid()).await?;
        Ok(Inode::new(d.parent_objid, 0))
    }

    /// Resolve a path to the object itself, for callers that need identity
    /// rather than attributes.
    pub async fn resolve_for_hash(
        &self,
        base: &Arc<Inode>,
        path: &str,
        follow: bool,
    ) -> FsResult<Arc<Inode>> {
        self.resolve(base, path, follow).await
    }

    pub async fn stat_at(&self, base: &Arc<Inode>, path: &str, follow: bool) -> FsResult<Attrs> {
        let ino = self.resolve(base, path, follow).await?;
        self.stat(&ino).await
    }

    /// Directory contents, in name order.
    pub async fn read_dir(&self, dir: &Arc<Inode>) -> FsResult<Vec<DirEntry>> {
        let blocks = self.blocks();
        let d = self.dnode(dir.objid()).await?;
        if d.kind != DnodeKind::Dir {
            return Err(FsError::NotDirectory);
        }
        let mut txn = DirTxn::load(&blocks, &d).await?;
        txn.list()
            .await?
            .into_iter()
            .map(|e| {
                Ok(DirEntry {
                    name: e.name,
                    kind: InodeKind::from_dnode(e.kind)?,
                    objid: e.objid,
                })
            })
            .collect()
    }

    // -- namespace mutation --------------------------------------------------

    pub async fn mkdir(&self, base: &Arc<Inode>, name: &str) -> FsResult<Arc<Inode>> {
        validate_segment(name)?;
        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();

        let parent = objset.get_allocated(&blocks, base.objid()).await?;
        require_dir(&parent)?;
        let mut dir = DirTxn::load(&blocks, &parent).await?;
        if dir.lookup(name).await?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        let now = now_nanos();
        let objid = txn.reserve_objid()?;
        let mut child = Dnode::new(objid, DnodeKind::Dir, parent.record_shift, now);
        child.mode = DEFAULT_DIR_MODE;
        child.parent_objid = parent.objid;

        dir.insert(Dirent {
            name: name.to_string(),
            objid,
            kind: DnodeKind::Dir,
        })
        .await?;
        let mut new_parent = dir.finish(txn.writer()).await?;
        touch(&mut new_parent, now);

        txn.stage(new_parent);
        txn.stage(child);
        txn.commit().await?;
        Ok(Inode::new(objid, 0))
    }

    pub async fn symlink_at(
        &self,
        base: &Arc<Inode>,
        name: &str,
        target: &str,
    ) -> FsResult<Arc<Inode>> {
        validate_segment(name)?;
        validate_symlink_target(target)?;

        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();

        let parent = objset.get_allocated(&blocks, base.objid()).await?;
        require_dir(&parent)?;
        let mut dir = DirTxn::load(&blocks, &parent).await?;
        if dir.lookup(name).await?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        let now = now_nanos();
        let objid = txn.reserve_objid()?;
        let mut link = Dnode::new(objid, DnodeKind::Symlink, parent.record_shift, now);
        link.mode = DEFAULT_SYMLINK_MODE;
        link.parent_objid = parent.objid;
        link.size = target.len() as u64;

        let bytes = target.as_bytes();
        if bytes.len() <= INLINE_CAP {
            // Almost every target fits here, so readlink costs no block read.
            link.inline = bytes.to_vec();
        } else {
            let record = parent.record_size();
            let dirty: BTreeMap<u64, Vec<u8>> = bytes
                .chunks(record)
                .enumerate()
                .map(|(i, c)| (i as u64, c.to_vec()))
                .collect();
            link = commit_object(&blocks, txn.writer(), &link, dirty, bytes.len() as u64).await?;
        }

        dir.insert(Dirent {
            name: name.to_string(),
            objid,
            kind: DnodeKind::Symlink,
        })
        .await?;
        let mut new_parent = dir.finish(txn.writer()).await?;
        touch(&mut new_parent, now);

        txn.stage(new_parent);
        txn.stage(link);
        txn.commit().await?;
        Ok(Inode::new(objid, 0))
    }

    pub async fn readlink_at(&self, base: &Arc<Inode>, name: &str) -> FsResult<String> {
        let ino = self.resolve(base, name, false).await?;
        let d = self.dnode(ino.objid()).await?;
        if d.kind != DnodeKind::Symlink {
            return Err(FsError::Invalid("not a symlink"));
        }
        read_symlink(&self.blocks(), &d).await
    }

    /// Add a second name for an existing object.
    ///
    /// Only files and symlinks: a hard link to a directory would make the
    /// namespace a graph rather than a tree, and the parent link in the dnode
    /// has room for exactly one answer.
    ///
    /// This was permanently unsupported under the previous engine, which had
    /// no way to express shared identity across two S3 keys. Here a directory
    /// entry is already just an object id, so a link is one more entry and an
    /// increment of `nlink`.
    pub async fn link_at(
        &self,
        old_base: &Arc<Inode>,
        old_path: &str,
        new_base: &Arc<Inode>,
        new_name: &str,
        follow: bool,
    ) -> FsResult<()> {
        self.link_within(&self.root(), old_base, old_path, new_base, new_name, follow)
            .await
    }

    /// [`Fs::link_at`], confined to `scope`.
    ///
    /// The *source* is the one that matters here: a hard link is a second name
    /// for an existing inode, so linking to something outside the scope would
    /// pull it inside permanently — an escape that survives the request that
    /// made it.
    #[allow(clippy::too_many_arguments)]
    pub async fn link_within(
        &self,
        scope: &Arc<Inode>,
        old_base: &Arc<Inode>,
        old_path: &str,
        new_base: &Arc<Inode>,
        new_name: &str,
        follow: bool,
    ) -> FsResult<()> {
        validate_segment(new_name)?;
        let target = self
            .resolve_within(scope.objid(), old_base, old_path, follow)
            .await?;

        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();

        let mut victim = objset.get_allocated(&blocks, target.objid()).await?;
        if victim.kind == DnodeKind::Dir {
            return Err(FsError::NotPermitted);
        }

        let parent = objset.get_allocated(&blocks, new_base.objid()).await?;
        require_dir(&parent)?;
        let mut dir = DirTxn::load(&blocks, &parent).await?;
        if dir.lookup(new_name).await?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        let now = now_nanos();
        dir.insert(Dirent {
            name: new_name.to_string(),
            objid: victim.objid,
            kind: victim.kind,
        })
        .await?;
        victim.nlink = victim.nlink.saturating_add(1);
        victim.ctime_nanos = now;

        let mut new_parent = dir.finish(txn.writer()).await?;
        touch(&mut new_parent, now);
        txn.stage(new_parent);
        txn.stage(victim);
        txn.commit().await.map(|_| ())
    }

    pub async fn unlink(&self, base: &Arc<Inode>, name: &str) -> FsResult<()> {
        self.remove_entry(base, name, false).await
    }

    pub async fn rmdir(&self, base: &Arc<Inode>, name: &str) -> FsResult<()> {
        self.remove_entry(base, name, true).await
    }

    async fn remove_entry(&self, base: &Arc<Inode>, name: &str, want_dir: bool) -> FsResult<()> {
        validate_segment(name)?;
        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();

        let parent = objset.get_allocated(&blocks, base.objid()).await?;
        require_dir(&parent)?;
        let mut dir = DirTxn::load(&blocks, &parent).await?;
        let entry = dir.lookup(name).await?.ok_or(FsError::NotFound)?;

        let is_dir = entry.kind == DnodeKind::Dir;
        match (want_dir, is_dir) {
            (true, false) => return Err(FsError::NotDirectory),
            (false, true) => return Err(FsError::IsDirectory),
            _ => {}
        }

        let mut child = objset.get_allocated(&blocks, entry.objid).await?;
        if is_dir {
            let child_dir = DirTxn::load(&blocks, &child).await?;
            if !child_dir.is_empty() {
                return Err(FsError::NotEmpty);
            }
        }

        dir.remove(name).await?;
        let now = now_nanos();
        let mut new_parent = dir.finish(txn.writer()).await?;
        touch(&mut new_parent, now);

        child.nlink = child.nlink.saturating_sub(1);
        child.ctime_nanos = now;
        if child.nlink == 0 {
            // Last name gone. Keep the object alive if a handle still holds
            // it — POSIX promises an unlinked file stays readable until the
            // last descriptor closes. With no entries left, the only way to
            // reach it is a handle that already exists, so no new opener can
            // find it in the meantime.
            let mut open = self.open.lock();
            if open.is_open(child.objid) {
                open.mark_orphan(child.objid);
            } else {
                // Its blocks become unreachable copy-on-write garbage, which
                // lifecycle policy on the data bucket reclaims. Nothing is
                // deleted here.
                child = Dnode::free(child.objid, child.record_shift);
            }
        }

        txn.stage(new_parent);
        txn.stage(child);
        txn.commit().await.map(|_| ()).map(|_| ())
    }

    /// Move an entry. Atomic: one directory-entry move inside one commit.
    pub async fn rename(
        &self,
        from_base: &Arc<Inode>,
        from_name: &str,
        to_base: &Arc<Inode>,
        to_name: &str,
    ) -> FsResult<()> {
        validate_segment(from_name)?;
        validate_segment(to_name)?;
        let (src_id, dst_id) = (from_base.objid(), to_base.objid());
        if src_id == dst_id && from_name == to_name {
            return Ok(());
        }

        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();
        let now = now_nanos();

        let src_dnode = objset.get_allocated(&blocks, src_id).await?;
        require_dir(&src_dnode)?;
        let mut src_dir = DirTxn::load(&blocks, &src_dnode).await?;
        let entry = src_dir.lookup(from_name).await?.ok_or(FsError::NotFound)?;

        // A directory may not move into itself: the subtree would keep its
        // parent link into a directory that now lives inside it, and nothing
        // from the root could reach any of it again. Walk up from the
        // destination; the root is its own parent, which ends the walk.
        if entry.kind == DnodeKind::Dir {
            let mut cursor = dst_id;
            loop {
                if cursor == entry.objid {
                    return Err(FsError::Invalid("cannot rename a directory into itself"));
                }
                let parent = objset.get_allocated(&blocks, cursor).await?.parent_objid;
                if parent == cursor {
                    break;
                }
                cursor = parent;
            }
        }

        // Same directory: one transaction over one structure, or the two would
        // each rebuild from the same base and the second would erase the first.
        let mut dst_dir = if src_id == dst_id {
            None
        } else {
            let d = objset.get_allocated(&blocks, dst_id).await?;
            require_dir(&d)?;
            Some(DirTxn::load(&blocks, &d).await?)
        };

        let existing = match &mut dst_dir {
            Some(d) => d.lookup(to_name).await?,
            None => src_dir.lookup(to_name).await?,
        };
        if let Some(victim) = existing {
            if victim.objid == entry.objid {
                return Ok(()); // already linked here
            }
            let mut victim_dnode = objset.get_allocated(&blocks, victim.objid).await?;
            match (entry.kind == DnodeKind::Dir, victim.kind == DnodeKind::Dir) {
                (true, false) => return Err(FsError::NotDirectory),
                (false, true) => return Err(FsError::IsDirectory),
                (true, true) => {
                    if !DirTxn::load(&blocks, &victim_dnode).await?.is_empty() {
                        return Err(FsError::NotEmpty);
                    }
                }
                (false, false) => {}
            }
            match &mut dst_dir {
                Some(d) => d.remove(to_name).await?,
                None => src_dir.remove(to_name).await?,
            };
            victim_dnode.nlink = victim_dnode.nlink.saturating_sub(1);
            victim_dnode.ctime_nanos = now;
            if victim_dnode.nlink == 0 {
                // Same contract as unlink: a replaced file that is still open
                // survives until its last handle closes.
                let mut open = self.open.lock();
                if open.is_open(victim_dnode.objid) {
                    open.mark_orphan(victim_dnode.objid);
                } else {
                    victim_dnode = Dnode::free(victim_dnode.objid, victim_dnode.record_shift);
                }
            }
            txn.stage(victim_dnode);
        }

        src_dir.remove(from_name).await?;
        let moved = Dirent {
            name: to_name.to_string(),
            objid: entry.objid,
            kind: entry.kind,
        };
        match &mut dst_dir {
            Some(d) => d.insert(moved).await?,
            None => src_dir.insert(moved).await?,
        }

        // A directory carries its parent in its dnode, so moving one across
        // directories has to update that link or `..` would still point home.
        if entry.kind == DnodeKind::Dir && src_id != dst_id {
            let mut child = objset.get_allocated(&blocks, entry.objid).await?;
            child.parent_objid = dst_id;
            child.ctime_nanos = now;
            txn.stage(child);
        }

        let mut new_src = src_dir.finish(txn.writer()).await?;
        touch(&mut new_src, now);
        txn.stage(new_src);
        if let Some(d) = dst_dir {
            let mut new_dst = d.finish(txn.writer()).await?;
            touch(&mut new_dst, now);
            txn.stage(new_dst);
        }
        txn.commit().await.map(|_| ())
    }

    // -- files ---------------------------------------------------------------

    pub async fn open_at(
        &self,
        base: &Arc<Inode>,
        path: &str,
        flags: OpenFlags,
    ) -> FsResult<Arc<FileHandle>> {
        self.open_within(&self.root(), base, path, flags).await
    }

    /// [`Fs::open_at`], confined to `scope`.
    ///
    /// Both halves have to be confined, not just the lookup: a path that does
    /// not resolve may still be *created*, and creating
    /// `../someone-else/file` would be an escape that writes rather than
    /// reads.
    pub async fn open_within(
        &self,
        scope: &Arc<Inode>,
        base: &Arc<Inode>,
        path: &str,
        flags: OpenFlags,
    ) -> FsResult<Arc<FileHandle>> {
        if !flags.read && !flags.write {
            return Err(FsError::Invalid("open with no read or write"));
        }

        let existing = match self.resolve_within(scope.objid(), base, path, true).await {
            Ok(ino) => Some(ino),
            Err(FsError::NotFound) if flags.create => None,
            Err(e) => return Err(e),
        };

        let inode = match existing {
            Some(ino) => {
                if flags.exclusive {
                    return Err(FsError::AlreadyExists);
                }
                ino
            }
            None => self.create_file(scope.objid(), base, path).await?,
        };

        let d = self.dnode(inode.objid()).await?;
        if d.kind == DnodeKind::Dir && flags.write {
            return Err(FsError::IsDirectory);
        }

        let handle = self.register_handle(inode, flags, &d);
        if flags.truncate && flags.write {
            self.set_size(&handle, 0).await?;
        }
        Ok(handle)
    }

    pub async fn open(&self, path: &str, flags: OpenFlags) -> FsResult<Arc<FileHandle>> {
        self.open_at(&self.root(), path, flags).await
    }

    /// Create an empty regular file at `path`, which must not exist.
    async fn create_file(&self, scope: u64, base: &Arc<Inode>, path: &str) -> FsResult<Arc<Inode>> {
        let (parent_path, name) = split_last(path)?;
        let parent = if parent_path.is_empty() {
            base.clone()
        } else {
            self.resolve_within(scope, base, parent_path, true).await?
        };
        validate_segment(name)?;

        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();

        let parent_dnode = objset.get_allocated(&blocks, parent.objid()).await?;
        require_dir(&parent_dnode)?;
        let mut dir = DirTxn::load(&blocks, &parent_dnode).await?;
        // Another commit may have created it between our lookup and this
        // transaction. The whole create is inside the transaction, so losing
        // that race is visible rather than silently overwriting.
        if dir.lookup(name).await?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        let now = now_nanos();
        let objid = txn.reserve_objid()?;
        let mut file = Dnode::new(objid, DnodeKind::File, parent_dnode.record_shift, now);
        file.mode = DEFAULT_FILE_MODE;
        file.parent_objid = parent_dnode.objid;

        dir.insert(Dirent {
            name: name.to_string(),
            objid,
            kind: DnodeKind::File,
        })
        .await?;
        let mut new_parent = dir.finish(txn.writer()).await?;
        touch(&mut new_parent, now);

        txn.stage(new_parent);
        txn.stage(file);
        txn.commit().await?;
        Ok(Inode::new(objid, 0))
    }

    fn register_handle(&self, inode: Arc<Inode>, flags: OpenFlags, d: &Dnode) -> Arc<FileHandle> {
        let raw = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let id = HandleId(NonZeroU64::new(raw).expect("handle ids start at 1"));
        let handle = Arc::new(FileHandle {
            id,
            inode,
            flags,
            state: Mutex::new(HandleState {
                size: d.size,
                dirty: BTreeMap::new(),
                meta_dirty: false,
                atime_nanos: d.atime_nanos,
                mtime_nanos: d.mtime_nanos,
            }),
        });
        self.handles.lock().insert(raw, handle.clone());
        self.open.lock().opened(handle.inode.objid());
        handle
    }

    pub async fn close(&self, handle: &Arc<FileHandle>) -> FsResult<()> {
        let objid = handle.inode.objid();
        let result = if handle.flags.write {
            self.sync(handle).await
        } else {
            Ok(())
        };
        self.handles.lock().remove(&handle.id.get());

        // If this was the last handle on an object whose last name is already
        // gone, now is when it actually goes away.
        let reap = self.open.lock().closed(objid);
        if reap {
            self.free_orphan(objid).await?;
        }
        result
    }

    /// Free an object that lost its last name while it was open.
    async fn free_orphan(&self, objid: u64) -> FsResult<()> {
        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();
        let d = match objset.get_allocated(&blocks, objid).await {
            Ok(d) => d,
            // Already gone: another path freed it, or the mount was
            // reformatted underneath us. Nothing to do.
            Err(FsError::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        };
        if d.nlink > 0 {
            // It was linked again between the unlink and this close, so it is
            // reachable by name once more and must not be freed.
            return Ok(());
        }
        txn.stage(Dnode::free(objid, d.record_shift));
        txn.commit().await.map(|_| ())
    }

    pub async fn pread(&self, handle: &FileHandle, offset: u64, len: usize) -> FsResult<Bytes> {
        if !handle.flags.read {
            return Err(FsError::BadDescriptor);
        }
        let st = handle.state.lock().await;
        if offset >= st.size || len == 0 {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(len as u64).min(st.size);

        // A view of the object at the size this handle sees, so records past
        // the committed end read as holes rather than as past-EOF.
        let mut view = self.dnode(handle.inode.objid()).await?;
        view.size = st.size;
        let record = view.record_size() as u64;
        let blocks = self.blocks();

        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut pos = offset;
        while pos < end {
            let index = pos / record;
            let within = (pos % record) as usize;
            let take = ((record - within as u64).min(end - pos)) as usize;

            let block = match st.dirty.get(&index) {
                Some(buf) => Bytes::from(buf.clone()),
                None => read_data_block(&blocks, &view, index).await?,
            };
            let slice = block.get(within..).unwrap_or(&[]);
            let n = take.min(slice.len());
            out.extend_from_slice(&slice[..n]);
            // A short record means a hole at the tail of the object; the rest
            // of the requested span is zeros.
            out.resize(out.len() + (take - n), 0);
            pos += take as u64;
        }
        Ok(Bytes::from(out))
    }

    pub async fn pwrite(&self, handle: &FileHandle, offset: u64, data: &[u8]) -> FsResult<usize> {
        if !handle.flags.write {
            return Err(FsError::BadDescriptor);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let mut st = handle.state.lock().await;
        let offset = if handle.flags.append { st.size } else { offset };

        let mut view = self.dnode(handle.inode.objid()).await?;
        view.size = st.size;
        let record = view.record_size();
        let blocks = self.blocks();

        let mut written = 0usize;
        while written < data.len() {
            let pos = offset + written as u64;
            let index = pos / record as u64;
            let within = (pos % record as u64) as usize;
            let take = (record - within).min(data.len() - written);

            let mut buf = match st.dirty.remove(&index) {
                Some(buf) => buf,
                None => read_data_block(&blocks, &view, index).await?.to_vec(),
            };
            // Records are held at full width while dirty and trimmed to the
            // object's real tail length at commit, so partial writes into a
            // hole do not have to reason about the boundary.
            buf.resize(record, 0);
            buf[within..within + take].copy_from_slice(&data[written..written + take]);
            st.dirty.insert(index, buf);
            written += take;
        }

        st.size = st.size.max(offset + data.len() as u64);
        st.mtime_nanos = now_nanos();
        Ok(written)
    }

    pub async fn sync(&self, handle: &FileHandle) -> FsResult<()> {
        let mut st = handle.state.lock().await;
        if st.dirty.is_empty() && !st.meta_dirty {
            return Ok(());
        }
        self.flush(handle.inode.objid(), &mut st).await
    }

    async fn flush(&self, objid: u64, st: &mut HandleState) -> FsResult<()> {
        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();

        // Re-read rather than trusting the copy taken at open: another commit
        // may have advanced this object since.
        let base = objset.get_allocated(&blocks, objid).await?;
        let record = base.record_size();

        // A copy, not a take: if the commit fails the buffers must still be
        // here for the retry, or a sync that timed out once loses the file.
        let mut dirty = st.dirty.clone();
        let nblocks = blocks_for_size(st.size, record);
        dirty.retain(|index, _| *index < nblocks);
        for (index, buf) in dirty.iter_mut() {
            buf.resize(block_logical_len(st.size, record, *index), 0);
        }

        // Shrinking has to rewrite the block the new end lands in, not merely
        // record a smaller size. Blocks past the end are dropped by the
        // copy-on-write rebuild, but the boundary block keeps whatever it held
        // — so a later grow would read those bytes back out from under the
        // truncation instead of the zeros POSIX promises.
        if st.size < base.size && nblocks > 0 {
            let index = nblocks - 1;
            if let std::collections::btree_map::Entry::Vacant(slot) = dirty.entry(index) {
                let want = block_logical_len(st.size, record, index);
                let mut buf = read_data_block(&blocks, &base, index).await?.to_vec();
                if buf.len() > want {
                    buf.truncate(want);
                    slot.insert(buf);
                }
            }
        }

        let mut updated = commit_object(&blocks, txn.writer(), &base, dirty, st.size).await?;
        updated.mtime_nanos = st.mtime_nanos;
        updated.atime_nanos = st.atime_nanos;
        updated.ctime_nanos = now_nanos();

        txn.stage(updated);
        txn.commit().await?;
        st.dirty.clear();
        st.meta_dirty = false;
        Ok(())
    }

    pub async fn set_size(&self, handle: &FileHandle, new_size: u64) -> FsResult<()> {
        if !handle.flags.write {
            return Err(FsError::BadDescriptor);
        }
        let mut st = handle.state.lock().await;
        st.size = new_size;
        st.meta_dirty = true;
        st.mtime_nanos = now_nanos();
        self.flush(handle.inode.objid(), &mut st).await
    }

    pub async fn set_times(
        &self,
        handle: &FileHandle,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> FsResult<()> {
        // The same gate `pwrite` and `set_size` apply, and it was missing here.
        // A timestamp is metadata, but setting one is still a *commit*: `flush`
        // publishes a new signed root record under Object Lock retention. A
        // handle opened read-only that can advance the anchor chain is not
        // read-only in any sense worth the name.
        //
        // POSIX would settle this by ownership rather than by the descriptor's
        // open mode — `futimens` on an `O_RDONLY` fd is legal for the owner.
        // There is no owner here: [`Attrs`] carries `mode` but no uid, so
        // "are you allowed?" has no answer other than what the handle was
        // opened for. `set_times_at` stays ungated for the same reason, having
        // no handle to ask.
        if !handle.flags.write {
            return Err(FsError::BadDescriptor);
        }
        let mut st = handle.state.lock().await;
        if let Some(t) = atime {
            st.atime_nanos = to_nanos(t);
        }
        if let Some(t) = mtime {
            st.mtime_nanos = to_nanos(t);
        }
        st.meta_dirty = true;
        self.flush(handle.inode.objid(), &mut st).await
    }

    pub async fn set_times_at(
        &self,
        base: &Arc<Inode>,
        path: &str,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
        follow: bool,
    ) -> FsResult<()> {
        let ino = self.resolve(base, path, follow).await?;
        let mut txn = self.store.begin().await?;
        let blocks = txn.blocks().clone();
        let objset = txn.objset().clone();

        let mut d = objset.get_allocated(&blocks, ino.objid()).await?;
        if let Some(t) = atime {
            d.atime_nanos = to_nanos(t);
        }
        if let Some(t) = mtime {
            d.mtime_nanos = to_nanos(t);
        }
        d.ctime_nanos = now_nanos();
        txn.stage(d);
        txn.commit().await.map(|_| ())
    }
}

// -- snapshots ---------------------------------------------------------------

impl Fs {
    /// The newest `limit` committed states, most recent first.
    ///
    /// Every root record is a snapshot. Copy-on-write means the blocks a past
    /// root names were never overwritten, so taking one costs nothing and
    /// keeping one costs only whatever storage its blocks already occupy.
    pub async fn snapshots(&self, limit: usize) -> FsResult<Vec<SnapshotInfo>> {
        Ok(self
            .store
            .list_snapshots(limit)
            .await?
            .into_iter()
            .map(|r| SnapshotInfo {
                seq: r.seq,
                txg: r.txg,
                timestamp: crate::inode::from_nanos(r.timestamp_nanos),
                merkle_root: *r.merkle_root(),
            })
            .collect())
    }

    /// Open a past state for reading.
    pub async fn open_snapshot(&self, seq: u64) -> FsResult<SnapshotFs> {
        let snapshot = self.store.snapshot(seq).await?;
        Ok(SnapshotFs {
            objset: snapshot.objset().clone(),
            blocks: self.blocks(),
            config: self.config.clone(),
            info: SnapshotInfo {
                seq: snapshot.root.seq,
                txg: snapshot.root.txg,
                timestamp: crate::inode::from_nanos(snapshot.root.timestamp_nanos),
                merkle_root: *snapshot.root.merkle_root(),
            },
        })
    }
}

/// Identifying details of one committed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// Root sequence number. Also its key in the roots bucket.
    pub seq: u64,
    pub txg: u64,
    pub timestamp: SystemTime,
    /// The hash covering the entire filesystem at this point.
    pub merkle_root: crate::crypto::Hash256,
}

/// A past state of the filesystem, opened read-only.
///
/// Reads verify exactly as the live mount does — same checksums, same
/// position-binding — because a snapshot is not a copy of anything. It is the
/// same blocks, reached through an older root.
#[derive(Debug)]
pub struct SnapshotFs {
    objset: ObjectSet,
    blocks: Arc<BlockStore>,
    config: Arc<Config>,
    info: SnapshotInfo,
}

impl SnapshotFs {
    pub fn info(&self) -> SnapshotInfo {
        self.info
    }

    pub fn root(&self) -> Arc<Inode> {
        Inode::new(ROOT_OBJID, 0)
    }

    pub async fn lookup(&self, base: &Arc<Inode>, path: &str) -> FsResult<Arc<Inode>> {
        let objid = resolve_in(
            &self.objset,
            &self.blocks,
            // A snapshot is read-only and whole: there is no tenant to confine
            // to, and confining to one would hide the rest of a snapshot from
            // the operator reading it.
            ROOT_OBJID,
            base.objid(),
            path,
            true,
            self.config.max_symlink_depth,
        )
        .await?;
        let d = self.objset.get_allocated(&self.blocks, objid).await?;
        Ok(Inode::new(objid, d.gen))
    }

    pub async fn stat(&self, ino: &Arc<Inode>) -> FsResult<Attrs> {
        Attrs::from_dnode(&self.objset.get_allocated(&self.blocks, ino.objid()).await?)
    }

    pub async fn read_dir(&self, dir: &Arc<Inode>) -> FsResult<Vec<DirEntry>> {
        let d = self.objset.get_allocated(&self.blocks, dir.objid()).await?;
        require_dir(&d)?;
        DirTxn::load(&self.blocks, &d)
            .await?
            .list()
            .await?
            .into_iter()
            .map(|e| {
                Ok(DirEntry {
                    name: e.name,
                    kind: InodeKind::from_dnode(e.kind)?,
                    objid: e.objid,
                })
            })
            .collect()
    }

    /// Read a byte range of a file as it was at this snapshot.
    pub async fn read(&self, ino: &Arc<Inode>, offset: u64, len: usize) -> FsResult<Bytes> {
        let d = self.objset.get_allocated(&self.blocks, ino.objid()).await?;
        if d.kind == DnodeKind::Dir {
            return Err(FsError::IsDirectory);
        }
        if offset >= d.size || len == 0 {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(len as u64).min(d.size);
        let record = d.record_size() as u64;

        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut pos = offset;
        while pos < end {
            let index = pos / record;
            let within = (pos % record) as usize;
            let take = ((record - within as u64).min(end - pos)) as usize;
            let block = read_data_block(&self.blocks, &d, index).await?;
            let slice = block.get(within..).unwrap_or(&[]);
            let n = take.min(slice.len());
            out.extend_from_slice(&slice[..n]);
            out.resize(out.len() + (take - n), 0);
            pos += take as u64;
        }
        Ok(Bytes::from(out))
    }
}

// -- helpers ----------------------------------------------------------------

fn require_dir(d: &Dnode) -> FsResult<()> {
    if d.kind == DnodeKind::Dir {
        Ok(())
    } else {
        Err(FsError::NotDirectory)
    }
}

fn touch(d: &mut Dnode, now: u64) {
    d.mtime_nanos = now;
    d.ctime_nanos = now;
}

/// Split a path into its parent portion and final component.
fn split_last(path: &str) -> FsResult<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(FsError::Invalid("empty path"));
    }
    Ok(match trimmed.rsplit_once('/') {
        Some((parent, name)) => (parent, name),
        None => ("", trimmed),
    })
}

async fn read_symlink(blocks: &BlockStore, d: &Dnode) -> FsResult<String> {
    let bytes = if !d.inline.is_empty() {
        d.inline.clone()
    } else {
        let mut out = Vec::with_capacity(d.size as usize);
        for i in 0..d.block_count() {
            out.extend_from_slice(&read_data_block(blocks, d, i).await?);
        }
        out
    };
    String::from_utf8(bytes).map_err(|_| FsError::IllegalByteSequence)
}

/// Walk `path` from `start`, following symlinks.
///
/// Recursion is bounded by `depth`, which is decremented on every symlink hop
/// rather than every component, so a chain of links cannot outlast it.
/// Walk `path`, never leaving the subtree rooted at `scope`.
///
/// `scope` is what makes this a capability rather than a convention. Every way
/// a path can name something above where it started is redirected to `scope`
/// instead of to the filesystem root:
///
/// - an **absolute path** starts at `scope`, so `/etc/passwd` means
///   `<scope>/etc/passwd` and cannot mean anything else;
/// - **`..`** at `scope` stays at `scope`, so no number of them walks out;
/// - an **absolute symlink target** resolves from `scope` too, so a guest
///   cannot manufacture an escape by writing one.
///
/// Those three are the whole attack surface, and they hold inductively: a walk
/// begins at `scope` or below, and none of the three can take it higher.
///
/// Pass [`ROOT_OBJID`] for an unscoped filesystem, which is what a guest with
/// the whole store as its preopen gets.
async fn resolve_in(
    objset: &ObjectSet,
    blocks: &BlockStore,
    scope: u64,
    start: u64,
    path: &str,
    follow_final: bool,
    depth: u32,
) -> FsResult<u64> {
    if depth == 0 {
        return Err(FsError::Loop);
    }
    let mut current = if path.starts_with('/') { scope } else { start };

    let components: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();

    for (i, comp) in components.iter().enumerate() {
        let last = i + 1 == components.len();

        if *comp == ".." {
            // Clamped at the scope, not at the mount. Without this a tenant
            // holding `/tenants/a` would reach `/tenants` — and from there
            // every other tenant — with two components of ordinary path.
            if current == scope {
                continue;
            }
            let d = objset.get_allocated(blocks, current).await?;
            // The root is its own parent, so `..` stops at the mount rather
            // than escaping it.
            current = d.parent_objid;
            continue;
        }
        validate_segment(comp)?;

        let dir_dnode = objset.get_allocated(blocks, current).await?;
        require_dir(&dir_dnode)?;
        let mut dir = DirTxn::load(blocks, &dir_dnode).await?;
        let entry = dir.lookup(comp).await?.ok_or(FsError::NotFound)?;
        current = entry.objid;

        if entry.kind == DnodeKind::Symlink && (!last || follow_final) {
            let link = objset.get_allocated(blocks, current).await?;
            let target = read_symlink(blocks, &link).await?;
            let from = if target.starts_with('/') {
                scope
            } else {
                dir_dnode.objid
            };
            current = Box::pin(resolve_in(
                objset,
                blocks,
                scope,
                from,
                &target,
                true,
                depth - 1,
            ))
            .await?;
        }
    }
    Ok(current)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::config::Config;
    use crate::crypto::MasterSecret;

    /// Two tenants under `/tenants`, plus a secret at the root that neither
    /// should ever reach.
    async fn tenanted() -> (Arc<Fs>, Arc<Inode>, Arc<Inode>) {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([3u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();

        let root = fs.root();
        fs.mkdir(&root, "runtime-only").await.unwrap();
        let tenants = fs.mkdir(&root, "tenants").await.unwrap();
        let alice = fs.mkdir(&tenants, "alice").await.unwrap();
        let bob = fs.mkdir(&tenants, "bob").await.unwrap();
        fs.mkdir(&bob, "bobs-private").await.unwrap();
        (fs, alice, bob)
    }

    /// Inside her own subtree Alice works normally.
    #[tokio::test]
    async fn a_scope_does_not_restrict_what_is_inside_it() {
        let (fs, alice, _) = tenanted().await;
        fs.mkdir(&alice, "work").await.unwrap();
        assert!(fs.lookup_within(&alice, &alice, "work").await.is_ok());
        assert!(fs.lookup_within(&alice, &alice, "/work").await.is_ok());
        assert!(fs
            .lookup_within(&alice, &alice, "work/../work")
            .await
            .is_ok());
    }

    /// An absolute path means the *scope's* root, not the filesystem's. This
    /// is the first of the three escapes and the most obvious to try.
    #[tokio::test]
    async fn an_absolute_path_cannot_leave_the_scope() {
        let (fs, alice, _) = tenanted().await;
        assert!(fs
            .lookup_within(&alice, &alice, "/tenants/bob")
            .await
            .is_err());
        assert!(fs
            .lookup_within(&alice, &alice, "/runtime-only")
            .await
            .is_err());
        // And it is not that the names are unknown — unscoped they resolve.
        let root = fs.root();
        assert!(fs.lookup_at(&root, "/tenants/bob").await.is_ok());
    }

    /// The second escape: no number of `..` walks out.
    #[tokio::test]
    async fn dot_dot_cannot_climb_out_of_the_scope() {
        let (fs, alice, _) = tenanted().await;
        for path in ["..", "../..", "../bob", "../../runtime-only", "../../.."] {
            assert!(
                fs.lookup_within(&alice, &alice, path).await.is_err()
                    || fs
                        .lookup_within(&alice, &alice, path)
                        .await
                        .map(|i| i.objid())
                        .unwrap()
                        == alice.objid(),
                "{path} escaped the scope"
            );
        }
    }

    /// The third, and the one a guest can build for itself: an absolute
    /// symlink resolves from the scope too, so writing one buys nothing.
    #[tokio::test]
    async fn an_absolute_symlink_cannot_leave_the_scope() {
        let (fs, alice, _) = tenanted().await;
        fs.symlink_at(&alice, "escape", "/tenants/bob/bobs-private")
            .await
            .unwrap();
        assert!(fs.lookup_within(&alice, &alice, "escape").await.is_err());

        fs.symlink_at(&alice, "up", "../../runtime-only")
            .await
            .unwrap();
        assert!(fs.lookup_within(&alice, &alice, "up").await.is_err());
    }

    /// `..` is not the only way to ask for a parent. A descriptor at the top
    /// of a scope must not be walkable upwards either.
    #[tokio::test]
    async fn the_scope_is_its_own_parent() {
        let (fs, alice, _) = tenanted().await;
        let parent = fs.parent_within(&alice, &alice).await.unwrap();
        assert_eq!(parent.objid(), alice.objid());
        // Unscoped, the same call does reach `/tenants` — which is exactly the
        // difference the scope makes.
        assert_ne!(fs.parent_of(&alice).await.unwrap().objid(), alice.objid());
    }

    /// Two tenants, same relative path, different files. The separation is the
    /// resolver's, not the guest's.
    #[tokio::test]
    async fn two_scopes_name_different_files() {
        let (fs, alice, bob) = tenanted().await;
        fs.mkdir(&alice, "data").await.unwrap();
        fs.mkdir(&bob, "data").await.unwrap();
        let a = fs.lookup_within(&alice, &alice, "/data").await.unwrap();
        let b = fs.lookup_within(&bob, &bob, "/data").await.unwrap();
        assert_ne!(a.objid(), b.objid());
    }
}
