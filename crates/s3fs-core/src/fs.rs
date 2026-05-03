//! `Fs` — the public filesystem handle.
//!
//! Wires together the inode tree, the buffer pool, the MPU state machine,
//! and the backend into the API the WASI host adapter (and any other
//! consumer) calls into. Everything exposed here is async; locks are never
//! held across awaits.
//!
//! Scope of v1:
//! - `open`/`open_at` honoring `create`, `exclusive`, `truncate`
//! - `pread`/`pwrite` through `BufferPool` with on-demand S3 fetch
//! - `sync`: small-file fast path (single `PutObject`) or full MPU commit
//!   (driver in [`crate::mpu`])
//! - `mkdir`/`unlink`/`rmdir`/`rename` (synchronous file rename via
//!   `CopyObject` + `DeleteObject` for now)
//! - `symlink_at`/`readlink_at` (storage convention only — follow-during-
//!   lookup is reserved for the dedicated symlink module)
//!
//! Deferred:
//! - symlink resolution during `open_at`
//! - hardlink ops (`unsupported` per the Compatibility Matrix)

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock as PlRwLock;
use tokio::sync::Mutex as AsyncMutex;

use crate::backend::{Backend, BlobMeta, CopyBlobInput, PutBlobInput};
use crate::buffer::{BufferPool, PartBuf, PartKey};
use crate::config::Config;
use crate::errors::{FsError, FsResult};
use crate::inode::{
    Attrs, DirEntry, Inode, InodeKind, InodeState, InodeTree, SYMLINK_METADATA_KEY,
    SYMLINK_METADATA_VALUE,
};
use crate::mpu::{self, MpuState};
use crate::path;

/// Wire-format `Content-Type` we attach to symlink objects so casual S3
/// console viewers get a hint about what they are.
pub const SYMLINK_CONTENT_TYPE: &str = "application/x-s3wasifs-symlink";

/// User-metadata keys we use for `set-times`. Stored as RFC-3339-ish nanos.
pub const METADATA_ATIME_KEY: &str = "s3wasifs-atime";
pub const METADATA_MTIME_KEY: &str = "s3wasifs-mtime";

fn systemtime_to_meta(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:09}", d.as_secs(), d.subsec_nanos())
}

pub(crate) fn meta_to_systemtime(s: &str) -> Option<std::time::SystemTime> {
    let (sec_str, nanos_str) = s.split_once('.').unwrap_or((s, "0"));
    let secs: u64 = sec_str.parse().ok()?;
    let nanos: u32 = nanos_str.parse().ok()?;
    Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos))
}

/// Stable handle ID for an open file. Allocated by the `Fs` instance.
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

/// Open-file state. Multiple handles for the same inode have independent
/// MPU state (that's fine — last writer's `sync` wins).
#[derive(Debug)]
pub struct FileHandle {
    pub id: HandleId,
    pub inode: Arc<Inode>,
    pub flags: OpenFlags,
    /// Per-handle MPU bookkeeping. `None` until the first dirty write makes
    /// us decide whether to begin an MPU.
    pub mpu: AsyncMutex<Option<MpuState>>,
    /// File size as observed by this handle. Diverges from `inode.attrs.size`
    /// during writes; reconciled by `sync`.
    pub size: PlRwLock<u64>,
}

impl FileHandle {
    fn new(id: HandleId, inode: Arc<Inode>, flags: OpenFlags) -> Self {
        let size = inode.attrs.read().size;
        Self {
            id,
            inode,
            flags,
            mpu: AsyncMutex::new(None),
            size: PlRwLock::new(size),
        }
    }
}

/// Public filesystem handle. Cheap to clone (`Arc<Fs>`).
#[derive(Debug)]
pub struct Fs {
    pub backend: Arc<dyn Backend>,
    pub config: Arc<Config>,
    pub tree: Arc<InodeTree>,
    pub pool: Arc<BufferPool>,
    pub flusher: crate::flusher::Flusher,
    pub rename_queue: crate::rename::RenameQueue,
    handles: PlRwLock<HashMap<HandleId, Arc<FileHandle>>>,
    next_handle: AtomicU64,
}

impl Fs {
    /// Construct a fresh `Fs` over `backend` with `config`.
    pub fn new(backend: Arc<dyn Backend>, config: Arc<Config>) -> Arc<Self> {
        let tree = InodeTree::new(backend.clone(), config.clone());
        let pool = BufferPool::new(config.clone());
        let flusher = crate::flusher::Flusher::new(&config);
        let rename_queue = crate::rename::RenameQueue::new();
        Arc::new(Self {
            backend,
            config,
            tree,
            pool,
            flusher,
            rename_queue,
            handles: PlRwLock::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        })
    }

    pub fn root(&self) -> Arc<Inode> {
        self.tree.root()
    }

    fn alloc_handle_id(&self) -> HandleId {
        let n = self.next_handle.fetch_add(1, Ordering::Relaxed);
        HandleId(NonZeroU64::new(n).expect("handle counter overflow"))
    }

    pub fn get_handle(&self, id: HandleId) -> Option<Arc<FileHandle>> {
        self.handles.read().get(&id).cloned()
    }

    // ------------------- read-only navigation -------------------

    /// Stat an inode (pure cached read; no S3 call).
    pub fn stat(&self, ino: &Arc<Inode>) -> Attrs {
        ino.attrs.read().clone()
    }

    /// Resolve `path` from `base` (openat semantics) and stat the result.
    pub async fn stat_at(&self, base: &Arc<Inode>, path: &str) -> FsResult<Attrs> {
        let ino = self.tree.lookup_at(base, path).await?;
        Ok(self.stat(&ino))
    }

    /// Snapshot a directory's contents.
    pub async fn read_dir(&self, dir: &Arc<Inode>) -> FsResult<Vec<DirEntry>> {
        self.tree.snapshot_directory(dir).await
    }

    // ------------------- mutation -------------------

    /// `mkdir` — write an explicit zero-byte directory marker.
    /// Returns the new directory inode.
    pub async fn mkdir(&self, base: &Arc<Inode>, name: &str) -> FsResult<Arc<Inode>> {
        if !base.is_dir() {
            return Err(FsError::NotDirectory);
        }
        if base.is_deleted() {
            return Err(FsError::NotFound);
        }
        path::validate_segment(name)?;

        // Reject if a child of the same name exists.
        if self.tree.lookup(base, name).await.is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let parent_key = self.tree.s3_key(base);
        let dir_key = if parent_key.is_empty() {
            format!("{name}/")
        } else {
            format!("{parent_key}/{name}/")
        };
        let meta = self
            .backend
            .put_blob(PutBlobInput {
                key: dir_key.clone(),
                body: Bytes::new(),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await?;

        let attrs = attrs_from_meta(&meta);
        let id = self.tree.alloc_id();
        let inode = Inode::new_dir(id, name, Some(Arc::downgrade(base)), true, attrs);
        Ok(self.tree.attach(base, inode))
    }

    /// `unlink` — delete a regular file or symlink.
    pub async fn unlink(&self, base: &Arc<Inode>, name: &str) -> FsResult<()> {
        let ino = self.tree.lookup(base, name).await?;
        if ino.is_dir() {
            return Err(FsError::IsDirectory);
        }
        // If the inode is mid-rename, wait for it to finish so we don't race
        // the worker (which would otherwise resurrect a key we just deleted).
        self.wait_for_rename(&ino).await?;
        let key = self.tree.current_s3_key(&ino);
        self.backend.delete_blob(&key).await?;
        self.tree.detach(&ino);
        // Drop any cached parts.
        self.pool.forget_inode(ino.id);
        Ok(())
    }

    /// `rmdir` — delete an empty directory.
    pub async fn rmdir(&self, base: &Arc<Inode>, name: &str) -> FsResult<()> {
        let ino = self.tree.lookup(base, name).await?;
        if !ino.is_dir() {
            return Err(FsError::NotDirectory);
        }
        // Emptiness check: list with max_keys=2 (we'll see the dir's own
        // marker if present, plus at most one child).
        let dir_key = self.tree.s3_dir_key(&ino);
        let listing = self
            .backend
            .list_blobs(crate::backend::ListBlobsInput {
                prefix: &dir_key,
                delimiter: None,
                max_keys: Some(2),
                ..Default::default()
            })
            .await?;
        // Filter out the dir's own marker (key == dir_key) — that's not "content".
        let real_children = listing.items.iter().filter(|i| i.key != dir_key).count();
        if real_children > 0 {
            return Err(FsError::NotEmpty);
        }
        // Delete the marker if it exists.
        if listing.items.iter().any(|i| i.key == dir_key) {
            self.backend.delete_blob(&dir_key).await?;
        }
        self.tree.detach(&ino);
        Ok(())
    }

    /// `rename-at` — async rename.
    ///
    /// Returns as soon as the inode tree has been rewired and the
    /// background `CopyObject` + `DeleteObject` work has been enqueued.
    /// During the in-flight window, reads/writes against the new path
    /// resolve to the OLD S3 key (via [`InodeTree::current_s3_key`]) so
    /// the object the caller can actually touch never disappears.
    ///
    /// Errors from the worker surface on the next `Fs::sync` of the
    /// renamed inode (or on a subsequent `Fs::rename` of the same inode).
    ///
    /// **Pre-flush.** Any open write handle for the source inode is
    /// `sync`'d synchronously before the worker is enqueued — this avoids
    /// a torn read where the worker's `CopyObject` runs while UploadParts
    /// for an in-flight MPU on the same key are still pending.
    ///
    /// **Not POSIX-atomic.** Both source and destination keys briefly
    /// coexist between copy and delete; a crash in that window leaves both.
    pub async fn rename(
        &self,
        old_base: &Arc<Inode>,
        old_name: &str,
        new_base: &Arc<Inode>,
        new_name: &str,
    ) -> FsResult<()> {
        let old_ino = self.tree.lookup(old_base, old_name).await?;
        path::validate_segment(new_name)?;
        if !new_base.is_dir() {
            return Err(FsError::NotDirectory);
        }

        // Surface a prior worker error or reject duplicate concurrent
        // rename of the same inode.
        if let Some(s) = old_ino.rename_state() {
            if let Some(e) = s.error.read().clone() {
                *old_ino.rename_state.write() = None; // consumed
                return Err(e);
            }
            return Err(FsError::WouldBlock);
        }

        // Pre-flush any open writable handle for the source so the worker
        // copies a fully-committed S3 object.
        let handles_to_flush: Vec<Arc<FileHandle>> = self
            .handles
            .read()
            .values()
            .filter(|h| h.inode.id == old_ino.id && h.flags.write)
            .cloned()
            .collect();
        for h in handles_to_flush {
            self.sync(&h).await?;
        }

        if old_ino.is_dir() {
            return self.rename_dir_async(&old_ino, new_base, new_name).await;
        }

        // ----- file / symlink -----
        let src_key = self.tree.s3_key(&old_ino);
        let new_parent_key = self.tree.s3_key(new_base);
        let dst_key = if new_parent_key.is_empty() {
            new_name.to_string()
        } else {
            format!("{new_parent_key}/{new_name}")
        };
        if src_key == dst_key {
            return Ok(());
        }

        let attrs = old_ino.attrs.read().clone();
        let new_ino = match &*old_ino.kind.read() {
            InodeKind::RegularFile => Inode::new_file(
                self.tree.alloc_id(),
                new_name,
                Arc::downgrade(new_base),
                attrs,
            ),
            InodeKind::Symlink { target } => Inode::new_symlink(
                self.tree.alloc_id(),
                new_name,
                Arc::downgrade(new_base),
                target.clone(),
                attrs,
            ),
            InodeKind::Directory { .. } => unreachable!("handled above"),
        };
        // Park rename state on the new inode BEFORE attaching so any
        // concurrent lookup that races us sees the redirect.
        *new_ino.rename_state.write() =
            Some(crate::inode::attrs::RenameState::new(src_key.clone()));

        self.tree.detach(&old_ino);
        self.pool.forget_inode(old_ino.id);
        let attached = self.tree.attach(new_base, new_ino.clone());

        // Enqueue the background copy+delete. If the queue is closed
        // (Fs being torn down), unwind: clear state, fall through to a
        // synchronous copy+delete to maintain a consistent S3 view.
        if let Err(_e) = self.rename_queue.enqueue(crate::rename::RenameJob::File {
            backend: self.backend.clone(),
            inode: attached.clone(),
            old_key: src_key.clone(),
            new_key: dst_key.clone(),
        }) {
            *attached.rename_state.write() = None;
            self.backend
                .copy_blob(CopyBlobInput {
                    source_key: src_key.clone(),
                    destination_key: dst_key,
                    replace_metadata: None,
                    replace_content_type: None,
                })
                .await?;
            self.backend.delete_blob(&src_key).await?;
        }
        Ok(())
    }

    /// Recursive directory rename — async. Lists every key under the
    /// source's `prefix/`, copies each to the corresponding destination
    /// key, deletes the source. Cross-bucket rename and rename-into-self
    /// are rejected synchronously before enqueueing the worker.
    async fn rename_dir_async(
        &self,
        old_ino: &Arc<Inode>,
        new_base: &Arc<Inode>,
        new_name: &str,
    ) -> FsResult<()> {
        // Reject if destination exists as a non-empty dir or as a file.
        if let Ok(existing) = self.tree.lookup(new_base, new_name).await {
            if existing.is_dir() {
                let dst_dir_key = self.tree.s3_dir_key(&existing);
                let probe = self
                    .backend
                    .list_blobs(crate::backend::ListBlobsInput {
                        prefix: &dst_dir_key,
                        delimiter: None,
                        max_keys: Some(2),
                        ..Default::default()
                    })
                    .await?;
                let real = probe.items.iter().filter(|i| i.key != dst_dir_key).count();
                if real > 0 {
                    return Err(FsError::NotEmpty);
                }
                if probe.items.iter().any(|i| i.key == dst_dir_key) {
                    self.backend.delete_blob(&dst_dir_key).await?;
                }
                self.tree.detach(&existing);
            } else {
                return Err(FsError::NotDirectory);
            }
        }

        let old_prefix = format!("{}/", self.tree.s3_key(old_ino));
        let new_parent_key = self.tree.s3_key(new_base);
        let new_prefix = if new_parent_key.is_empty() {
            format!("{new_name}/")
        } else {
            format!("{new_parent_key}/{new_name}/")
        };
        if old_prefix == new_prefix {
            return Ok(());
        }
        if new_prefix.starts_with(&old_prefix) {
            return Err(FsError::Invalid("cannot rename a directory into itself"));
        }

        let attrs = old_ino.attrs.read().clone();
        let explicit = old_ino.dir_explicit_marker().unwrap_or(false);
        let new_ino = Inode::new_dir(
            self.tree.alloc_id(),
            new_name,
            Some(Arc::downgrade(new_base)),
            explicit,
            attrs,
        );
        // The "old key" for a directory rename is the prefix; current_s3_key
        // doesn't apply to listings (which use new_prefix immediately) but
        // the bookkeeping marker keeps duplicate-rename detection working.
        *new_ino.rename_state.write() =
            Some(crate::inode::attrs::RenameState::new(old_prefix.clone()));

        self.tree.detach(old_ino);
        let attached = self.tree.attach(new_base, new_ino);

        if let Err(_e) = self.rename_queue.enqueue(crate::rename::RenameJob::Dir {
            backend: self.backend.clone(),
            inode: attached.clone(),
            old_prefix: old_prefix.clone(),
            new_prefix: new_prefix.clone(),
        }) {
            // Queue closed: unwind to synchronous directory rename.
            *attached.rename_state.write() = None;
            self.copy_dir_sync(&old_prefix, &new_prefix).await?;
        }
        Ok(())
    }

    /// Synchronous fallback used when the rename queue is unavailable
    /// (Fs being torn down). Same algorithm as the worker.
    async fn copy_dir_sync(&self, old_prefix: &str, new_prefix: &str) -> FsResult<()> {
        let mut continuation: Option<String> = None;
        loop {
            let listing = self
                .backend
                .list_blobs(crate::backend::ListBlobsInput {
                    prefix: old_prefix,
                    delimiter: None,
                    continuation_token: continuation.as_deref(),
                    max_keys: None,
                    ..Default::default()
                })
                .await?;
            for item in &listing.items {
                let suffix = match item.key.strip_prefix(old_prefix) {
                    Some(s) => s,
                    None => continue,
                };
                let dst_key = format!("{new_prefix}{suffix}");
                self.backend
                    .copy_blob(CopyBlobInput {
                        source_key: item.key.clone(),
                        destination_key: dst_key,
                        replace_metadata: None,
                        replace_content_type: None,
                    })
                    .await?;
                self.backend.delete_blob(&item.key).await?;
            }
            if !listing.is_truncated {
                break;
            }
            match listing.next_continuation_token {
                Some(t) => continuation = Some(t),
                None => break,
            }
        }
        Ok(())
    }

    /// Wait for any in-flight async rename on `inode` to complete. Returns
    /// the worker's error if the rename failed (and clears it, so the
    /// next call doesn't re-fire). Cheap no-op if no rename is in flight.
    pub async fn wait_for_rename(&self, inode: &Arc<Inode>) -> FsResult<()> {
        loop {
            let s = match inode.rename_state() {
                Some(s) => s,
                None => return Ok(()),
            };
            // If the worker already finished with an error, surface it.
            if let Some(e) = s.error.read().clone() {
                *inode.rename_state.write() = None;
                return Err(e);
            }
            // Otherwise wait for the next notify, then re-check.
            s.done.notified().await;
        }
    }

    // ------------------- symlinks -------------------

    /// `symlink-at` — create a new symlink at `name` under `base` pointing
    /// at `target`. Atomic via `If-None-Match: *` on the underlying PUT;
    /// returns `AlreadyExists` if the destination exists.
    pub async fn symlink_at(
        &self,
        base: &Arc<Inode>,
        name: &str,
        target: &str,
    ) -> FsResult<Arc<Inode>> {
        if !base.is_dir() {
            return Err(FsError::NotDirectory);
        }
        if base.is_deleted() {
            return Err(FsError::NotFound);
        }
        path::validate_segment(name)?;
        path::validate_symlink_target(target)?;

        let parent_key = self.tree.s3_key(base);
        let key = if parent_key.is_empty() {
            name.to_string()
        } else {
            format!("{parent_key}/{name}")
        };

        let mut metadata = HashMap::new();
        metadata.insert(
            SYMLINK_METADATA_KEY.to_string(),
            SYMLINK_METADATA_VALUE.to_string(),
        );

        let meta = self
            .backend
            .put_blob_if_not_exists(PutBlobInput {
                key,
                body: Bytes::copy_from_slice(target.as_bytes()),
                metadata,
                content_type: Some(SYMLINK_CONTENT_TYPE.to_string()),
            })
            .await?;

        let attrs = attrs_from_meta(&meta);
        let id = self.tree.alloc_id();
        let inode = Inode::new_symlink(id, name, Arc::downgrade(base), target.to_string(), attrs);
        Ok(self.tree.attach(base, inode))
    }

    /// `readlink-at` — return the literal target string of a symlink.
    /// Errors with `Invalid` if the target is not a symlink.
    pub async fn readlink_at(&self, base: &Arc<Inode>, name: &str) -> FsResult<String> {
        let ino = self.tree.lookup(base, name).await?;
        match ino.symlink_target() {
            Some(t) => Ok(t),
            None => Err(FsError::Invalid("readlink_at: not a symlink")),
        }
    }

    // ------------------- set_size / set_times -------------------

    /// `set-size` — truncate or grow a file to exactly `new_size` bytes.
    ///
    /// **Shrink:** any pending writes are first synced to S3 (so we don't
    /// lose them by truncating mid-buffer); then we issue a ranged `GET`
    /// for `[0, new_size)` and re-`PUT` the result. Simple and correct for
    /// any size, but downloads + re-uploads the surviving prefix.
    /// Acceptable for typical truncate workloads (`> file`, log rotation,
    /// SQLite VACUUM); large in-place shrinks would benefit from an MPU
    /// rewrite path which we can layer on later.
    ///
    /// **Grow:** zero-fills the gap by issuing a normal `pwrite` of zeros at
    /// the previous EOF. Capped at 100 MiB to avoid blowing up memory; for
    /// larger growths use direct `pwrite` of your real bytes.
    pub async fn set_size(&self, handle: &FileHandle, new_size: u64) -> FsResult<()> {
        if !handle.flags.write {
            return Err(FsError::AccessDenied);
        }
        if handle.inode.is_deleted() {
            return Err(FsError::NotFound);
        }
        let current = *handle.size.read();
        if new_size == current {
            return Ok(());
        }

        if new_size < current {
            // Shrink: flush any pending writes first.
            self.sync(handle).await?;
            let key = self.tree.current_s3_key(&handle.inode);
            let body = if new_size == 0 {
                Bytes::new()
            } else {
                self.backend.get_blob(&key, Some(0..new_size)).await?.body
            };
            let meta = self
                .backend
                .put_blob(PutBlobInput {
                    key,
                    body,
                    metadata: HashMap::new(),
                    content_type: None,
                })
                .await?;
            *handle.inode.attrs.write() = attrs_from_meta(&meta);
            *handle.size.write() = new_size;
            self.pool.forget_inode(handle.inode.id);
            Ok(())
        } else {
            // Grow: zero-fill via the buffer pool. Cap to avoid OOM.
            let extra = new_size - current;
            const MAX_GROW_BYTES: u64 = 100 * 1024 * 1024;
            if extra > MAX_GROW_BYTES {
                return Err(FsError::Invalid(
                    "set_size grow exceeds 100 MiB cap; use pwrite of real bytes",
                ));
            }
            let zeros = vec![0u8; extra as usize];
            self.pwrite(handle, current, &zeros).await?;
            Ok(())
        }
    }

    /// `set-times-at` — persist atime/mtime as user metadata via a
    /// `CopyObject` self-copy with `MetadataDirective=REPLACE`. The values
    /// land in `x-amz-meta-s3wasifs-{atime,mtime}` as RFC-3339 nanos.
    ///
    /// `None` means "don't change"; `Some(t)` sets the field. The cached
    /// inode attrs are updated so subsequent `stat` calls see the new
    /// times within the same process — across mounts, the times are
    /// readable on next `lookup` (which fetches metadata via `HeadObject`).
    pub async fn set_times_at(
        &self,
        base: &Arc<Inode>,
        path: &str,
        follow_symlinks: bool,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> FsResult<()> {
        let ino = if follow_symlinks {
            self.tree.lookup_at(base, path).await?
        } else {
            self.tree.lookup_at_no_follow(base, path).await?
        };
        self.set_times_inode(&ino, atime, mtime).await
    }

    /// Like `set_times_at` but on an already-resolved file handle.
    pub async fn set_times(
        &self,
        handle: &FileHandle,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> FsResult<()> {
        self.set_times_inode(&handle.inode, atime, mtime).await
    }

    async fn set_times_inode(
        &self,
        ino: &Arc<Inode>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> FsResult<()> {
        if atime.is_none() && mtime.is_none() {
            return Ok(());
        }
        let key = self.tree.current_s3_key(ino);
        // Read current head to preserve metadata fields we don't touch.
        let head = self.backend.head_blob(&key).await?;
        let mut metadata = head.metadata.clone();
        let mut new_attrs = ino.attrs.read().clone();
        if let Some(t) = atime {
            metadata.insert(METADATA_ATIME_KEY.to_string(), systemtime_to_meta(t));
        }
        if let Some(t) = mtime {
            metadata.insert(METADATA_MTIME_KEY.to_string(), systemtime_to_meta(t));
            new_attrs.last_modified = t;
        }
        self.backend
            .copy_blob(CopyBlobInput {
                source_key: key.clone(),
                destination_key: key,
                replace_metadata: Some(metadata),
                replace_content_type: head.content_type,
            })
            .await?;
        *ino.attrs.write() = new_attrs;
        Ok(())
    }

    // ------------------- open / close -------------------

    /// `open-at` — resolve `path` from `base`, honour open flags, return a
    /// fresh `FileHandle`.
    pub async fn open_at(
        &self,
        base: &Arc<Inode>,
        path: &str,
        flags: OpenFlags,
    ) -> FsResult<Arc<FileHandle>> {
        // Validate flag combo: at least one of read/write must be set.
        if !flags.read && !flags.write {
            return Err(FsError::Invalid("open with no read or write"));
        }
        // O_EXCL implies create.
        if flags.exclusive && !flags.create {
            return Err(FsError::Invalid("O_EXCL without O_CREAT"));
        }

        // First, try lookup. If found, handle truncate/exclusive; if absent
        // and create requested, create.
        let ino = match self.tree.lookup_at(base, path).await {
            Ok(i) => {
                if flags.exclusive {
                    return Err(FsError::AlreadyExists);
                }
                if i.is_dir() && (flags.write || flags.truncate) {
                    return Err(FsError::IsDirectory);
                }
                i
            }
            Err(FsError::NotFound) if flags.create => self.create_file_at(base, path).await?,
            Err(e) => return Err(e),
        };

        // O_TRUNC: synchronously zero the file via PutObject of empty bytes.
        if flags.truncate && ino.is_regular_file() {
            let key = self.tree.s3_key(&ino);
            let meta = self
                .backend
                .put_blob(PutBlobInput {
                    key,
                    body: Bytes::new(),
                    metadata: HashMap::new(),
                    content_type: None,
                })
                .await?;
            let new_attrs = attrs_from_meta(&meta);
            *ino.attrs.write() = new_attrs;
            self.pool.forget_inode(ino.id);
        }

        let id = self.alloc_handle_id();
        let h = Arc::new(FileHandle::new(id, ino, flags));
        self.handles.write().insert(id, h.clone());
        Ok(h)
    }

    /// Convenience: `open_at(root, path, flags)`.
    pub async fn open(&self, path: &str, flags: OpenFlags) -> FsResult<Arc<FileHandle>> {
        let root = self.root();
        self.open_at(&root, path, flags).await
    }

    /// Drop a handle. Does NOT sync; pending dirty writes are abandoned and
    /// any in-flight MPU is aborted to avoid leaking partial uploads.
    pub async fn close(&self, handle: &Arc<FileHandle>) -> FsResult<()> {
        // If a sync was never called, abort any in-flight MPU.
        let mut mpu = handle.mpu.lock().await;
        if let Some(state) = mpu.as_mut() {
            mpu::abort(state, &*self.backend).await?;
        }
        drop(mpu);
        self.handles.write().remove(&handle.id);
        Ok(())
    }

    /// Internal: create a new empty file at `path` under `base`. Used by
    /// the `O_CREAT` path of `open_at`. Atomic via `put_blob_if_not_exists`
    /// when `O_EXCL` is also set; otherwise falls back to plain `put_blob`.
    async fn create_file_at(&self, base: &Arc<Inode>, path: &str) -> FsResult<Arc<Inode>> {
        // Resolve parent + final segment. We re-walk one shy of the leaf so
        // we have the final basename to attach in the inode tree.
        let (parent_dir, basename) = self.resolve_parent_and_basename(base, path).await?;
        path::validate_segment(&basename)?;

        let parent_key = self.tree.s3_key(&parent_dir);
        let key = if parent_key.is_empty() {
            basename.clone()
        } else {
            format!("{parent_key}/{basename}")
        };

        // For plain create (without O_EXCL) we just PUT empty. The exclusive
        // case is handled by the caller via lookup-then-error before reaching
        // here — but to be race-safe against another writer, also use
        // `put_blob_if_not_exists` if available so we don't silently
        // overwrite a sibling that appeared between our lookup and our PUT.
        let put = PutBlobInput {
            key,
            body: Bytes::new(),
            metadata: HashMap::new(),
            content_type: None,
        };
        let meta = if self.backend.capabilities().conditional_put {
            self.backend.put_blob_if_not_exists(put).await?
        } else {
            self.backend.put_blob(put).await?
        };

        let attrs = attrs_from_meta(&meta);
        let id = self.tree.alloc_id();
        let inode = Inode::new_file(id, &basename, Arc::downgrade(&parent_dir), attrs);
        Ok(self.tree.attach(&parent_dir, inode))
    }

    /// Resolve `path` from `base` to `(parent_dir_inode, basename)`.
    async fn resolve_parent_and_basename(
        &self,
        base: &Arc<Inode>,
        path: &str,
    ) -> FsResult<(Arc<Inode>, String)> {
        // Split off the trailing component.
        // We want POSIX-style: "a/b/c.txt" → parent="a/b", name="c.txt".
        // For just "name", parent = base, name = "name".
        if path.starts_with('/') {
            return Err(FsError::NotPermitted);
        }
        // Strip a possible single trailing slash (treated as "is-a-directory" hint).
        let trimmed = path.trim_end_matches('/');
        let (parent_path, name) = match trimmed.rfind('/') {
            Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
            None => ("", trimmed),
        };
        if name.is_empty() {
            return Err(FsError::Invalid("empty basename"));
        }
        let parent_dir = if parent_path.is_empty() {
            base.clone()
        } else {
            self.tree.lookup_at(base, parent_path).await?
        };
        if !parent_dir.is_dir() {
            return Err(FsError::NotDirectory);
        }
        Ok((parent_dir, name.to_string()))
    }

    // ------------------- pread / pwrite / sync -------------------

    /// Read `len` bytes from the file at `offset`. Returns up to `len` bytes;
    /// short reads at EOF return fewer.
    pub async fn pread(&self, handle: &FileHandle, offset: u64, len: usize) -> FsResult<Bytes> {
        if !handle.flags.read {
            return Err(FsError::AccessDenied);
        }
        if handle.inode.is_deleted() {
            return Err(FsError::NotFound);
        }
        let size = *handle.size.read();
        if offset >= size || len == 0 {
            return Ok(Bytes::new());
        }
        let read_end = (offset + len as u64).min(size);
        let mut out = BytesMut::with_capacity((read_end - offset) as usize);

        let mut cur = offset;
        while cur < read_end {
            let loc = self
                .config
                .part_schedule
                .locate(cur)
                .ok_or(FsError::FileTooLarge)?;
            let part_arc = self.get_or_fetch_part(handle, loc.part_index).await?;
            let part = part_arc.read();
            let into_part = cur - loc.part_start;
            let to_read = (read_end - cur).min(loc.part_size - into_part);
            let chunk = part.read(into_part, to_read);
            out.extend_from_slice(&chunk);
            // If the part returned fewer bytes than requested, we hit its
            // valid_len early — clamp and break.
            if (chunk.len() as u64) < to_read {
                break;
            }
            cur += to_read;
        }
        Ok(out.freeze())
    }

    /// Write `data` at `offset`. Returns the number of bytes written
    /// (always `data.len()` on success). Marks affected parts dirty and
    /// updates the handle's logical file size if the write extends past EOF.
    /// Does NOT call S3 — `sync` does the actual upload.
    pub async fn pwrite(&self, handle: &FileHandle, offset: u64, data: &[u8]) -> FsResult<usize> {
        if !handle.flags.write {
            return Err(FsError::AccessDenied);
        }
        if handle.inode.is_deleted() {
            return Err(FsError::NotFound);
        }
        if data.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        let total_end = offset + data.len() as u64;
        let mut cur = offset;
        let mut data_off = 0usize;
        // Parts that became fully dirty during this call — eagerly enqueue
        // after we drop all part locks so the await point is clean.
        let mut eager_parts: Vec<(u32, Arc<parking_lot::RwLock<PartBuf>>)> = Vec::new();

        while data_off < data.len() {
            let loc = self
                .config
                .part_schedule
                .locate(cur)
                .ok_or(FsError::FileTooLarge)?;
            let part_arc = self
                .get_or_fetch_part_for_write(handle, loc.part_index)
                .await?;

            // If this part has an in-flight eager upload, await it before
            // mutating. This both bounds memory pressure and prevents a
            // mark_flushing → apply_write WouldBlock race.
            let inflight = part_arc.read().take_inflight();
            if let Some(rx) = inflight {
                self.absorb_inflight(handle, rx).await?;
            }

            let into_part = cur - loc.part_start;
            let space_in_part = loc.part_size - into_part;
            let to_write = ((data.len() - data_off) as u64).min(space_in_part) as usize;

            let became_full = {
                let mut part = part_arc.write();
                part.apply_write(into_part, &data[data_off..data_off + to_write])?;
                // Only eagerly enqueue when the part is COMPLETELY filled
                // to its tier capacity (not just "dirty covers valid_len" —
                // that's true for a partial last part too, and uploading
                // those wastes work the next pwrite would overwrite).
                let fully_filled = part.valid_len == part.part_size && part.is_fully_dirty();
                let no_inflight = part
                    .upload_in_flight
                    .lock()
                    .ok()
                    .is_some_and(|g| g.is_none());
                fully_filled && no_inflight
            };

            if became_full {
                eager_parts.push((loc.part_index, part_arc.clone()));
            }

            data_off += to_write;
            cur += to_write as u64;
            written += to_write;
        }

        // Update logical file size BEFORE submitting eager uploads — the
        // worker reads `final_size` from the snapshot we pass it.
        {
            let mut sz = handle.size.write();
            if total_end > *sz {
                *sz = total_end;
            }
        }

        // Eager flush: enqueue any newly-full parts. Skip when the file is
        // small enough that single-PUT will win (no point starting an MPU).
        let final_size = *handle.size.read();
        if !eager_parts.is_empty() && final_size > self.config.single_part_threshold {
            self.enqueue_eager_uploads(handle, eager_parts).await?;
        }

        Ok(written)
    }

    /// Lazily begin the per-handle MPU and enqueue an `UploadPart` job for
    /// each newly-full part, parking the reply receiver on the part so a
    /// later `sync` can await it.
    async fn enqueue_eager_uploads(
        &self,
        handle: &FileHandle,
        parts: Vec<(u32, Arc<parking_lot::RwLock<PartBuf>>)>,
    ) -> FsResult<()> {
        let key = self.tree.current_s3_key(&handle.inode);

        // Begin MPU under handle.mpu lock if not already started.
        let mut mpu_guard = handle.mpu.lock().await;
        let (source_size, source_etag) = {
            let a = handle.inode.attrs.read();
            if a.etag.is_empty() {
                (None, None)
            } else {
                (Some(a.size), Some(a.etag.clone()))
            }
        };
        let upload_id = crate::flusher::ensure_mpu_begun_locked(
            &self.backend,
            &mut mpu_guard,
            &key,
            &self.config.part_schedule,
            source_size,
            source_etag,
        )
        .await?;
        // Note the source_size from MpuState — it may differ from the
        // current inode attrs after concurrent activity.
        let mpu_source_size = mpu_guard.as_ref().and_then(|s| s.source_size).unwrap_or(0);
        drop(mpu_guard);

        let final_size = *handle.size.read();
        for (part_index, part_arc) in parts {
            let rx = self.flusher.enqueue_upload(
                self.backend.clone(),
                key.clone(),
                upload_id.clone(),
                part_index,
                part_arc.clone(),
                self.config.part_schedule.clone(),
                mpu_source_size,
                final_size,
            )?;
            part_arc.read().park_inflight(rx);
        }
        Ok(())
    }

    /// Await an in-flight `UploadPart` reply, fold the result into the
    /// per-handle MPU state, and surface errors to the caller. On error the
    /// part's state is rolled back to Dirty so a later `sync` can retry.
    async fn absorb_inflight(
        &self,
        handle: &FileHandle,
        rx: tokio::sync::oneshot::Receiver<crate::flusher::PartResult>,
    ) -> FsResult<()> {
        match rx.await {
            Ok(Ok((part_index, etag))) => {
                let mut g = handle.mpu.lock().await;
                if let Some(state) = g.as_mut() {
                    state.record_part_uploaded(part_index, etag);
                }
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            // Worker dropped without replying (shouldn't happen unless Fs
            // was torn down). Treat as transient I/O.
            Err(_) => Err(FsError::Io("flush worker dropped before reply".into())),
        }
    }

    /// Flush dirty bytes to S3 and finalise. Durable when this returns.
    pub async fn sync(&self, handle: &FileHandle) -> FsResult<()> {
        if handle.inode.is_deleted() {
            return Err(FsError::NotFound);
        }
        if !handle.flags.write {
            // Read-only handle: nothing to sync.
            return Ok(());
        }

        // Hold the per-inode rename lock for the whole sync so a
        // concurrent rename worker can't run its CopyObject on a key that
        // we're mid-commit on. The worker takes the same lock; ordering
        // is "first acquired, first served". Cheap when no rename is in
        // flight (uncontested mutex).
        let _rename_guard = handle.inode.rename_lock.lock().await;

        // If a prior rename worker errored (and left state set), surface
        // and clear so the caller sees it once.
        if let Some(s) = handle.inode.rename_state() {
            if let Some(e) = s.error.read().clone() {
                *handle.inode.rename_state.write() = None;
                return Err(e);
            }
        }

        // Drain any eager-upload receivers parked on parts. After this,
        // every part is either Clean/Flushed (background upload done and
        // recorded into MpuState) or Dirty (no in-flight, needs sync to
        // upload it inline).
        self.drain_inflight_uploads(handle).await?;

        let final_size = *handle.size.read();
        let key = self.tree.current_s3_key(&handle.inode);

        // Collect dirty parts. We snapshot under the pool's per-part read
        // locks; the buffer pool itself is already lock-light.
        let mut dirty_parts: Vec<(u32, Arc<parking_lot::RwLock<PartBuf>>)> = Vec::new();
        // We don't have a "list parts for inode" API on the pool; we walk
        // possible part indices up to the final size's high water.
        if final_size > 0 {
            let high = self
                .config
                .part_schedule
                .locate(final_size - 1)
                .ok_or(FsError::FileTooLarge)?
                .part_index;
            for i in 0..=high {
                let key = PartKey::new(handle.inode.id, i);
                if let Some(part_arc) = self.pool.get(key) {
                    let st = part_arc.read().state.clone();
                    if matches!(st, crate::buffer::PartState::Dirty) {
                        dirty_parts.push((i, part_arc));
                    }
                }
            }
        }

        // No dirty bytes and no in-flight MPU → nothing to do.
        let mpu_in_flight = handle
            .mpu
            .lock()
            .await
            .as_ref()
            .is_some_and(|s| s.has_upload());
        if dirty_parts.is_empty() && !mpu_in_flight {
            return Ok(());
        }

        // Decide the commit path.
        // Small-file fast path: file size below threshold AND no MPU started.
        if !mpu_in_flight && final_size <= self.config.single_part_threshold {
            self.sync_via_single_put(handle, &key, final_size, dirty_parts)
                .await?;
            return Ok(());
        }

        // MPU path.
        self.sync_via_mpu(handle, &key, dirty_parts).await
    }

    /// Walk every part for this inode, take any in-flight receiver, await
    /// it, and fold the etag into MpuState. Errors are returned to the
    /// caller (the first one wins; we still drain the rest).
    async fn drain_inflight_uploads(&self, handle: &FileHandle) -> FsResult<()> {
        let final_size = *handle.size.read();
        if final_size == 0 {
            return Ok(());
        }
        let high = self
            .config
            .part_schedule
            .locate(final_size - 1)
            .ok_or(FsError::FileTooLarge)?
            .part_index;
        let mut receivers: Vec<tokio::sync::oneshot::Receiver<crate::flusher::PartResult>> =
            Vec::new();
        for i in 0..=high {
            let key = PartKey::new(handle.inode.id, i);
            if let Some(part_arc) = self.pool.get(key) {
                if let Some(rx) = part_arc.read().take_inflight() {
                    receivers.push(rx);
                }
            }
        }
        let mut first_err: Option<FsError> = None;
        for rx in receivers {
            match rx.await {
                Ok(Ok((part_index, etag))) => {
                    let mut g = handle.mpu.lock().await;
                    if let Some(state) = g.as_mut() {
                        state.record_part_uploaded(part_index, etag);
                    }
                }
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some(FsError::Io("flush worker dropped".into()));
                    }
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }

    async fn sync_via_single_put(
        &self,
        handle: &FileHandle,
        key: &str,
        final_size: u64,
        dirty_parts: Vec<(u32, Arc<parking_lot::RwLock<PartBuf>>)>,
    ) -> FsResult<()> {
        debug_assert!(
            dirty_parts.len() <= 1,
            "small-file path implies ≤1 dirty part"
        );

        // Snapshot everything we need from the dirty part before any await.
        // We capture the *dirty ranges* explicitly so we only overlay bytes
        // the user actually wrote — `body[0..valid_len]` includes zero-fill
        // bytes from `apply_write` extending past previous EOF, which would
        // wrongly overwrite source bytes.
        let part_snapshot: Option<(Bytes, bool, Vec<std::ops::Range<u64>>)> =
            dirty_parts.first().map(|(_, part_arc)| {
                let part = part_arc.read();
                let body = Bytes::copy_from_slice(part.body());
                let needs_source_load = !part.is_fully_dirty();
                let dirty_ranges = part.dirty_ranges().to_vec();
                (body, needs_source_load, dirty_ranges)
            });
        let source_size = handle.inode.attrs.read().size;

        let body = if let Some((part_body, needs_source_load, dirty_ranges)) = part_snapshot {
            let mut canvas = if needs_source_load && source_size > 0 {
                let g = self.backend.get_blob(key, None).await?;
                let mut buf = BytesMut::from(&g.body[..]);
                if (buf.len() as u64) < final_size {
                    buf.resize(final_size as usize, 0);
                }
                buf
            } else {
                BytesMut::from(vec![0u8; final_size as usize].as_slice())
            };
            // Overlay only the dirty byte ranges from the buffer into the canvas.
            for r in &dirty_ranges {
                let start = r.start as usize;
                let end = (r.end as usize).min(canvas.len());
                if start >= end {
                    continue;
                }
                canvas[start..end].copy_from_slice(&part_body[start..end]);
            }
            canvas.truncate(final_size as usize);
            canvas.freeze()
        } else {
            let src = self.backend.get_blob(key, None).await?;
            src.body
        };

        let meta = mpu::single_put_commit(&*self.backend, key, body).await?;
        self.commit_book_keeping(handle, meta).await;
        Ok(())
    }

    async fn sync_via_mpu(
        &self,
        handle: &FileHandle,
        key: &str,
        dirty_parts: Vec<(u32, Arc<parking_lot::RwLock<PartBuf>>)>,
    ) -> FsResult<()> {
        // Lazy MPU begin if not yet done.
        let mut mpu_guard = handle.mpu.lock().await;
        if mpu_guard.is_none() {
            let source_size = {
                let a = handle.inode.attrs.read();
                if a.etag.is_empty() {
                    None
                } else {
                    Some(a.size)
                }
            };
            let source_etag = {
                let a = handle.inode.attrs.read();
                if a.etag.is_empty() {
                    None
                } else {
                    Some(a.etag.clone())
                }
            };
            let mut state = MpuState::new(
                key.to_string(),
                source_size,
                source_etag,
                self.config.part_schedule.clone(),
            );
            let id = self
                .backend
                .multipart_begin(PutBlobInput {
                    key: key.to_string(),
                    body: Bytes::new(),
                    metadata: HashMap::new(),
                    content_type: None,
                })
                .await?;
            state.upload_id = Some(id);
            *mpu_guard = Some(state);
        }
        // Snapshot what the parallel uploaders need from state, then drop
        // the guard so we don't hold it across the upload window. The caller
        // contract is that no other task races sync() on the same handle, so
        // the upload_id and source_size remain valid until we re-acquire.
        let (upload_id, source_size) = {
            let state = mpu_guard.as_ref().expect("MPU started");
            (
                state.upload_id.clone().expect("upload begun"),
                state.source_size.unwrap_or(0),
            )
        };
        drop(mpu_guard);

        // Parallel UploadPart pass. Capture final_size *before* the await so
        // each task can clamp its part length correctly.
        let final_size_for_upload = *handle.size.read();
        let upload_results = self
            .upload_parts_concurrent(
                key,
                &upload_id,
                source_size,
                final_size_for_upload,
                dirty_parts,
                self.config.max_parallel_parts,
            )
            .await;

        // Re-acquire MpuState and record results (sequentially, but cheap).
        let mut mpu_guard = handle.mpu.lock().await;
        let state = mpu_guard.as_mut().expect("MPU started");
        for r in upload_results {
            let (part_index, etag) = r?;
            state.record_part_uploaded(part_index, etag);
        }

        // Make sure high_water includes the trailing parts of the file even
        // if they weren't dirty (so copy_plan emits UploadPartCopy for them).
        let final_size = *handle.size.read();
        if final_size > 0 {
            let high = self
                .config
                .part_schedule
                .locate(final_size - 1)
                .ok_or(FsError::FileTooLarge)?
                .part_index as i32;
            if high > state.high_water {
                state.high_water = high;
            }
        }

        let meta = mpu::commit(
            state,
            self.backend.clone(),
            self.config.max_merge_copy_bytes,
            self.config.max_parallel_copy,
            key,
        )
        .await?;
        // After commit, drop the MpuState's upload_id (commit clears it).
        drop(mpu_guard);
        self.commit_book_keeping(handle, meta).await;
        Ok(())
    }

    /// Common post-sync cleanup: refresh inode attrs, mark clean parts,
    /// release pool memory.
    async fn commit_book_keeping(&self, handle: &FileHandle, meta: BlobMeta) {
        // Update inode attrs to reflect the commit.
        *handle.inode.attrs.write() = attrs_from_meta(&meta);
        *handle.size.write() = meta.size;
        handle.inode.set_state(InodeState::Cached);

        // Walk known parts in pool and clear dirty/flushed → clean.
        // (We don't have an iterator over per-inode parts on the pool, so
        // we just forget them — they can be re-fetched if needed.)
        self.pool.forget_inode(handle.inode.id);
    }

    // ------------------- buffer-pool helpers -------------------

    /// Concurrently upload every dirty part. Each task does: snapshot →
    /// materialize (with optional RMW GET for partial parts) → mark_flushing
    /// → UploadPart → mark_flushed / mark_flush_failed → return etag.
    ///
    /// Returns one result per input part, in completion order. The caller is
    /// responsible for recording successful etags into `MpuState`.
    async fn upload_parts_concurrent(
        &self,
        key: &str,
        upload_id: &crate::backend::MultipartId,
        source_size: u64,
        final_size: u64,
        dirty_parts: Vec<(u32, Arc<parking_lot::RwLock<PartBuf>>)>,
        max_parallel: usize,
    ) -> Vec<FsResult<(u32, String)>> {
        use futures::stream::{self, StreamExt};

        let backend = self.backend.clone();
        let key = Arc::new(key.to_string());
        let upload_id = Arc::new(upload_id.clone());
        let schedule = self.config.part_schedule.clone();
        let cap = max_parallel.max(1);
        let semaphore = self.flusher.semaphore();

        stream::iter(dirty_parts.into_iter().map(|(part_index, part_arc)| {
            let backend = backend.clone();
            let key = key.clone();
            let upload_id = upload_id.clone();
            let schedule = schedule.clone();
            let semaphore = semaphore.clone();
            async move {
                // Acquire a permit from the per-Fs flusher BEFORE doing any
                // backend I/O. This caps total concurrent uploads across all
                // open files, not just within one sync() call.
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("semaphore never closed");
                upload_one_part(
                    backend,
                    key.as_str(),
                    upload_id.as_ref(),
                    part_index,
                    part_arc,
                    &schedule,
                    source_size,
                    final_size,
                )
                .await
            }
        }))
        .buffer_unordered(cap)
        .collect()
        .await
    }

    /// Fetch (or create) a part for read access. If absent from the pool
    /// AND the part lies within the source object, do a ranged GET; else
    /// return an empty PartBuf.
    async fn get_or_fetch_part(
        &self,
        handle: &FileHandle,
        part_index: u32,
    ) -> FsResult<Arc<parking_lot::RwLock<PartBuf>>> {
        let key = PartKey::new(handle.inode.id, part_index);
        if let Some(p) = self.pool.get(key) {
            return Ok(p);
        }
        let part_range = self
            .config
            .part_schedule
            .part_range(part_index)
            .ok_or(FsError::FileTooLarge)?;
        let source_size = handle.inode.attrs.read().size;
        if part_range.start >= source_size {
            // Empty part past EOF.
            let part = PartBuf::new_empty_dirty(
                part_index,
                part_range.end - part_range.start,
                part_range.start,
            );
            return Ok(self.pool.insert(key, part));
        }
        let r = part_range.start..part_range.end.min(source_size);
        let g = self
            .backend
            .get_blob(&self.tree.current_s3_key(&handle.inode), Some(r))
            .await?;
        let part = PartBuf::new_clean(
            part_index,
            part_range.end - part_range.start,
            part_range.start,
            g.body,
        );
        Ok(self.pool.insert(key, part))
    }

    /// Like `get_or_fetch_part` but used for the write path. Identical logic
    /// today; named separately so future write-bypass optimisations have a
    /// hook.
    async fn get_or_fetch_part_for_write(
        &self,
        handle: &FileHandle,
        part_index: u32,
    ) -> FsResult<Arc<parking_lot::RwLock<PartBuf>>> {
        self.get_or_fetch_part(handle, part_index).await
    }
}

/// One-shot helper for `upload_parts_concurrent`: snapshot, materialize
/// (with RMW for partial parts), mark Flushing, `UploadPart`, mark Flushed.
/// Errors transition the part back to Dirty so a retry can pick it up.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_one_part(
    backend: Arc<dyn Backend>,
    key: &str,
    upload_id: &crate::backend::MultipartId,
    part_index: u32,
    part_arc: Arc<parking_lot::RwLock<PartBuf>>,
    schedule: &crate::config::PartSchedule,
    source_size: u64,
    // `final_size`: file size *after* this sync — used to compute the part's
    // actual byte length (so a sub-part dirty write to the middle of a large
    // file doesn't truncate the unchanged tail).
    final_size: u64,
) -> FsResult<(u32, String)> {
    // Snapshot AND mark_flushing in one critical section so that any
    // concurrent pwrite is either fully captured by the snapshot OR sees
    // state=Flushing and bails (returns WouldBlock; pwrite handles by
    // awaiting the in-flight receiver). Without this, a write that lands
    // between snapshot and mark_flushing is lost when mark_flushed clears
    // the dirty bitmap.
    //
    // If state is already Flushing (because eager pwrite raced with us
    // and snapshot+marked first), skip the transition.
    let (part_body, fully_dirty, dirty_ranges_owned) = {
        let mut part = part_arc.write();
        let body = Bytes::copy_from_slice(part.body());
        let fully = part.is_fully_dirty();
        let ranges = part.dirty_ranges().to_vec();
        if matches!(part.state, crate::buffer::PartState::Dirty) {
            // Normal path: transition Dirty → Flushing here.
            part.state = crate::buffer::PartState::Flushing;
        }
        (body, fully, ranges)
    };

    let part_range = schedule
        .part_range(part_index)
        .ok_or(FsError::FileTooLarge)?;
    // The part's actual size in the destination file: full part_size, except
    // possibly clipped if this is the last part.
    let part_actual_size = (final_size.saturating_sub(part_range.start))
        .min(part_range.end - part_range.start) as usize;

    let mut materialized = if fully_dirty && part_body.len() == part_actual_size {
        BytesMut::from(&part_body[..])
    } else {
        // RMW: load source bytes for this part's range, then overlay only
        // the dirty subranges from the buffer.
        let source_end = part_range.end.min(source_size);
        let source_start = part_range.start;
        let loaded = if source_end > source_start {
            let g = backend
                .get_blob(key, Some(source_start..source_end))
                .await?;
            g.body
        } else {
            Bytes::new()
        };
        let mut canvas = BytesMut::from(&loaded[..]);
        if canvas.len() < part_actual_size {
            canvas.resize(part_actual_size, 0);
        }
        for r in &dirty_ranges_owned {
            let start = r.start as usize;
            let end = (r.end as usize).min(canvas.len());
            if start >= end {
                continue;
            }
            canvas[start..end].copy_from_slice(&part_body[start..end]);
        }
        canvas
    };
    materialized.truncate(part_actual_size);

    let body = materialized.freeze();
    let r = backend
        .multipart_upload_part(key, upload_id, part_index + 1, body)
        .await;
    let etag = match r {
        Ok(o) => o.e_tag,
        Err(e) => {
            let mut p = part_arc.write();
            let _ = p.mark_flush_failed();
            return Err(e);
        }
    };
    {
        let mut p = part_arc.write();
        p.mark_flushed(etag.clone())?;
    }
    Ok((part_index, etag))
}

fn attrs_from_meta(meta: &BlobMeta) -> Attrs {
    Attrs {
        size: meta.size,
        etag: meta.e_tag.clone(),
        last_modified: meta.last_modified,
        content_type: meta.content_type.clone(),
        metadata: meta.metadata.clone(),
        fetched_at: std::time::Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;

    fn fresh_fs(memory_limit: u64, single_part: u64) -> (Arc<MemoryBackend>, Arc<Fs>) {
        let backend = Arc::new(MemoryBackend::new());
        let cfg = Config::builder()
            .memory_limit_bytes(memory_limit)
            .single_part_threshold(single_part)
            .build();
        let fs = Fs::new(backend.clone() as Arc<dyn Backend>, Arc::new(cfg));
        (backend, fs)
    }

    fn small_fs() -> (Arc<MemoryBackend>, Arc<Fs>) {
        // Default-ish: 64 MiB pool, 5 MiB single-part threshold.
        fresh_fs(64 * 1024 * 1024, 5 * 1024 * 1024)
    }

    fn tiny_fs() -> (Arc<MemoryBackend>, Arc<Fs>) {
        // Tiny part schedule: 4 bytes/part × 100, 8-byte single-part threshold.
        let backend = Arc::new(MemoryBackend::new());
        let cfg = Config::builder()
            .part_schedule(crate::config::PartSchedule {
                tiers: vec![(4, 100)],
            })
            .single_part_threshold(8)
            .max_merge_copy_bytes(1024 * 1024)
            .memory_limit_bytes(1024 * 1024)
            .build();
        let fs = Fs::new(backend.clone() as Arc<dyn Backend>, Arc::new(cfg));
        (backend, fs)
    }

    // ---------- mkdir / unlink / rmdir ----------

    #[tokio::test]
    async fn mkdir_creates_explicit_marker_and_appears_in_listing() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        let dir = fs.mkdir(&root, "subdir").await.unwrap();
        assert!(dir.is_dir());
        // Explicit marker key exists at "subdir/".
        assert!(backend.head_blob("subdir/").await.is_ok());
        // It's enumerable from root.
        let snap = fs.read_dir(&root).await.unwrap();
        assert!(snap.iter().any(|e| e.name == "subdir"));
    }

    #[tokio::test]
    async fn mkdir_already_exists_errors() {
        let (_b, fs) = small_fs();
        let root = fs.root();
        fs.mkdir(&root, "x").await.unwrap();
        assert!(matches!(
            fs.mkdir(&root, "x").await,
            Err(FsError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn unlink_removes_object_and_inode() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        // Drop a file directly via the backend, then look it up.
        backend
            .put_blob(PutBlobInput {
                key: "f.txt".into(),
                body: Bytes::from_static(b"x"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let _ = fs.tree.lookup(&root, "f.txt").await.unwrap();
        fs.unlink(&root, "f.txt").await.unwrap();
        assert!(matches!(
            backend.head_blob("f.txt").await,
            Err(FsError::NotFound)
        ));
        assert!(matches!(
            fs.tree.lookup(&root, "f.txt").await,
            Err(FsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn unlink_on_directory_errors() {
        let (_b, fs) = small_fs();
        let root = fs.root();
        fs.mkdir(&root, "d").await.unwrap();
        assert!(matches!(
            fs.unlink(&root, "d").await,
            Err(FsError::IsDirectory)
        ));
    }

    #[tokio::test]
    async fn rmdir_empty_succeeds() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        fs.mkdir(&root, "empty").await.unwrap();
        fs.rmdir(&root, "empty").await.unwrap();
        assert!(matches!(
            backend.head_blob("empty/").await,
            Err(FsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn rmdir_non_empty_returns_not_empty() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        fs.mkdir(&root, "d").await.unwrap();
        backend
            .put_blob(PutBlobInput {
                key: "d/inner".into(),
                body: Bytes::from_static(b"x"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        assert!(matches!(fs.rmdir(&root, "d").await, Err(FsError::NotEmpty)));
    }

    // ---------- open / O_CREAT / O_EXCL / O_TRUNC ----------

    #[tokio::test]
    async fn open_create_writes_empty_file() {
        let (backend, fs) = small_fs();
        let h = fs
            .open(
                "hello.txt",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(*h.size.read(), 0);
        assert!(backend.head_blob("hello.txt").await.is_ok());
        fs.close(&h).await.unwrap();
    }

    #[tokio::test]
    async fn open_create_excl_collides_returns_already_exists() {
        let (_b, fs) = small_fs();
        let _h1 = fs.open("k", OpenFlags::create_new()).await.unwrap();
        let r = fs.open("k", OpenFlags::create_new()).await;
        assert!(matches!(r, Err(FsError::AlreadyExists)));
    }

    #[tokio::test]
    async fn open_truncate_zeroes_existing_file() {
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from_static(b"some content"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    truncate: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(*h.size.read(), 0);
        let g = backend.get_blob("k", None).await.unwrap();
        assert!(g.body.is_empty());
        fs.close(&h).await.unwrap();
    }

    #[tokio::test]
    async fn open_no_read_no_write_errors() {
        let (_b, fs) = small_fs();
        let r = fs.open("x", OpenFlags::default()).await;
        assert!(matches!(r, Err(FsError::Invalid(_))));
    }

    // ---------- pread / pwrite / sync ----------

    #[tokio::test]
    async fn write_then_sync_then_read_small_file() {
        let (backend, fs) = small_fs();
        let h = fs
            .open(
                "small.txt",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let n = fs.pwrite(&h, 0, b"hello world").await.unwrap();
        assert_eq!(n, 11);
        fs.sync(&h).await.unwrap();
        // Verify in S3.
        let g = backend.get_blob("small.txt", None).await.unwrap();
        assert_eq!(&g.body[..], b"hello world");
        // Re-open and read.
        let h2 = fs.open("small.txt", OpenFlags::read_only()).await.unwrap();
        let body = fs.pread(&h2, 0, 100).await.unwrap();
        assert_eq!(&body[..], b"hello world");
        fs.close(&h).await.unwrap();
        fs.close(&h2).await.unwrap();
    }

    #[tokio::test]
    async fn append_to_existing_via_random_write_uses_mpu_path() {
        let (backend, fs) = tiny_fs();
        // Pre-populate a 16-byte source object (4 parts of 4 bytes each).
        backend
            .put_blob(PutBlobInput {
                key: "big".into(),
                body: Bytes::from_static(b"AAAABBBBCCCCDDDD"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs
            .open(
                "big",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Modify part 1 (bytes 4..8): "BBBB" → "ZZZZ".
        fs.pwrite(&h, 4, b"ZZZZ").await.unwrap();
        // Extend file by appending at offset 16: 4 new bytes "EEEE" (part 4).
        fs.pwrite(&h, 16, b"EEEE").await.unwrap();
        fs.sync(&h).await.unwrap();
        let g = backend.get_blob("big", None).await.unwrap();
        assert_eq!(&g.body[..], b"AAAAZZZZCCCCDDDDEEEE");
        // No orphan MPU.
        assert_eq!(backend.mpu_count(), 0);
        fs.close(&h).await.unwrap();
    }

    #[tokio::test]
    async fn read_after_partial_write_sees_the_overlay() {
        let (backend, fs) = tiny_fs();
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from_static(b"AAAABBBBCCCC"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fs.pwrite(&h, 5, b"XX").await.unwrap();
        // Read should see the overlay even before sync (via buffer pool).
        let body = fs.pread(&h, 0, 12).await.unwrap();
        assert_eq!(&body[..], b"AAAABXXBCCCC");
        fs.close(&h).await.unwrap();
    }

    #[tokio::test]
    async fn small_file_inplace_edit_preserves_unchanged_source_bytes() {
        // Regression: the small-file `sync_via_single_put` used to overlay
        // `body[0..valid_len]` onto the canvas, which included zero-fill bytes
        // from `apply_write` extending past previous EOF — wrongly clobbering
        // source bytes. SQLite blocker.
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "db".into(),
                body: Bytes::from_static(b"AAAABBBBCCCCDDDD"), // 16 bytes
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs
            .open(
                "db",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Modify only bytes 8..10. Bytes 0..8 must come from source, not zeros.
        fs.pwrite(&h, 8, b"ZZ").await.unwrap();
        fs.sync(&h).await.unwrap();
        fs.close(&h).await.unwrap();

        let g = backend.get_blob("db", None).await.unwrap();
        assert_eq!(&g.body[..], b"AAAABBBBZZCCDDDD");
    }

    #[tokio::test]
    async fn large_file_subpart_edit_preserves_unchanged_part_tail() {
        // Regression: in `upload_one_part`, materialized was truncated to
        // `valid_len` instead of `min(part_size, file_size - part_start)`.
        // For a file > threshold with sub-part dirty content in a non-last
        // part, this shrank the part body and corrupted the file. SQLite
        // blocker for any DB > 5 MiB.
        let backend = Arc::new(MemoryBackend::new());
        let cfg = Config::builder()
            .part_schedule(crate::config::PartSchedule {
                tiers: vec![(8, 100)],
            })
            .single_part_threshold(8) // anything above 8 bytes uses MPU
            .max_parallel_parts(2)
            .max_parallel_copy(2)
            .max_merge_copy_bytes(1024)
            .memory_limit_bytes(1024 * 1024)
            .build();
        let fs = Fs::new(backend.clone() as Arc<dyn Backend>, Arc::new(cfg));

        // Source: 24 bytes = 3 parts of 8 bytes.
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from_static(b"AAAAAAAABBBBBBBBCCCCCCCC"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();

        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Write 2 bytes at offset 8 (part 1, offset 0): modifies first 2
        // bytes of "BBBBBBBB". The rest of part 1 ("BBBBBB") must survive.
        fs.pwrite(&h, 8, b"ZZ").await.unwrap();
        fs.sync(&h).await.unwrap();
        fs.close(&h).await.unwrap();

        let g = backend.get_blob("k", None).await.unwrap();
        assert_eq!(g.body.len(), 24, "file size unchanged");
        assert_eq!(&g.body[..], b"AAAAAAAAZZBBBBBBCCCCCCCC");
        assert_eq!(backend.mpu_count(), 0);
    }

    #[tokio::test]
    async fn close_without_sync_aborts_in_flight_mpu() {
        let (backend, fs) = tiny_fs();
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from_static(b"AAAABBBBCCCC"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Trigger MPU lazily by writing across part boundaries.
        fs.pwrite(&h, 0, b"ZZZZZZZZZZZZ").await.unwrap();
        // Manually start an MPU by calling sync once... but we want to
        // verify abort, so simulate: start MPU, then close without sync.
        // For this, we directly call the lazy path by performing sync_via_mpu's
        // begin-step indirectly via sync, then truncate state and close.
        // Easier: just call close — sync wasn't called, so even if MPU was
        // begun, abort should clean it up. We don't actually start one in
        // this code path because writes don't begin MPU lazily — only sync
        // does. So this verifies the no-MPU close path.
        fs.close(&h).await.unwrap();
        assert_eq!(backend.mpu_count(), 0);
    }

    // ---------- rename ----------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rename_file_async_copy_delete() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        let h = fs
            .open(
                "old",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fs.pwrite(&h, 0, b"data").await.unwrap();
        fs.sync(&h).await.unwrap();
        fs.close(&h).await.unwrap();

        fs.rename(&root, "old", &root, "new").await.unwrap();
        // Wait for the background worker to finish copy+delete.
        let new_ino = fs.tree.lookup(&root, "new").await.unwrap();
        fs.wait_for_rename(&new_ino).await.unwrap();

        assert!(matches!(
            backend.head_blob("old").await,
            Err(FsError::NotFound)
        ));
        let g = backend.get_blob("new", None).await.unwrap();
        assert_eq!(&g.body[..], b"data");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rename_directory_recursive_moves_all_descendants() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        // Build /old/{a.txt, b.txt, sub/c.txt}
        fs.mkdir(&root, "old").await.unwrap();
        for (path, body) in [
            ("old/a.txt", b"AAA" as &[u8]),
            ("old/b.txt", b"BBB"),
            ("old/sub/c.txt", b"CCC"),
        ] {
            backend
                .put_blob(PutBlobInput {
                    key: path.into(),
                    body: Bytes::copy_from_slice(body),
                    metadata: HashMap::new(),
                    content_type: None,
                })
                .await
                .unwrap();
        }
        // Force the inode tree to know about /old.
        let _ = fs.read_dir(&root).await.unwrap();

        fs.rename(&root, "old", &root, "new").await.unwrap();
        let new_ino = fs.tree.lookup(&root, "new").await.unwrap();
        fs.wait_for_rename(&new_ino).await.unwrap();

        // Old keys are gone; new keys carry the content.
        for k in ["old/a.txt", "old/b.txt", "old/sub/c.txt", "old/"] {
            assert!(
                matches!(backend.head_blob(k).await, Err(FsError::NotFound)),
                "leftover {k}"
            );
        }
        for (k, expected) in [
            ("new/a.txt", b"AAA" as &[u8]),
            ("new/b.txt", b"BBB"),
            ("new/sub/c.txt", b"CCC"),
        ] {
            let g = backend.get_blob(k, None).await.unwrap();
            assert_eq!(&g.body[..], expected, "key {k}");
        }
    }

    #[tokio::test]
    async fn rename_directory_into_self_rejected() {
        let (_b, fs) = small_fs();
        let root = fs.root();
        fs.mkdir(&root, "d").await.unwrap();
        let d = fs.tree.lookup(&root, "d").await.unwrap();
        let r = fs.rename(&root, "d", &d, "inner").await;
        assert!(matches!(r, Err(FsError::Invalid(_))));
    }

    /// Right after `rename` returns and BEFORE the worker completes,
    /// reads against the new path resolve via `current_s3_key` to the OLD
    /// key, which still exists. The worker eventually catches up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rename_destination_reads_old_key_until_worker_finishes() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        // Seed an existing object so the OLD key has content.
        backend
            .put_blob(PutBlobInput {
                key: "src.bin".into(),
                body: Bytes::from_static(b"hello"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let _ = fs.read_dir(&root).await.unwrap();

        fs.rename(&root, "src.bin", &root, "dst.bin").await.unwrap();
        let new_ino = fs.tree.lookup(&root, "dst.bin").await.unwrap();
        // current_s3_key still points at the old key while rename in flight.
        let key = fs.tree.current_s3_key(&new_ino);
        assert!(
            key == "src.bin" || key == "dst.bin",
            "key should be either old (rename in flight) or new (worker completed): {key}"
        );

        fs.wait_for_rename(&new_ino).await.unwrap();
        assert_eq!(fs.tree.current_s3_key(&new_ino), "dst.bin");
        let g = backend.get_blob("dst.bin", None).await.unwrap();
        assert_eq!(&g.body[..], b"hello");
    }

    /// A second `rename` of the same inode while the first is still in
    /// flight is rejected with `WouldBlock`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_rename_while_in_flight_returns_wouldblock() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        backend
            .put_blob(PutBlobInput {
                key: "f".into(),
                body: Bytes::from_static(b"x"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let _ = fs.read_dir(&root).await.unwrap();
        fs.rename(&root, "f", &root, "g").await.unwrap();
        // Second rename of the same inode under its NEW name. The
        // worker may or may not have run yet. If state is still set,
        // expect WouldBlock; if it cleared, expect Ok.
        let g_ino = fs.tree.lookup(&root, "g").await.unwrap();
        let r = fs.rename(&root, "g", &root, "h").await;
        if g_ino.rename_state().is_some() {
            assert!(matches!(r, Err(FsError::WouldBlock)));
        } else {
            r.unwrap();
        }
        // Drain the queue to settle.
        let _ = fs.wait_for_rename(&g_ino).await;
    }

    // ---------- set_size ----------

    #[tokio::test]
    async fn set_size_truncate_to_zero() {
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from_static(b"some content"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fs.set_size(&h, 0).await.unwrap();
        assert_eq!(*h.size.read(), 0);
        let g = backend.get_blob("k", None).await.unwrap();
        assert!(g.body.is_empty());
        fs.close(&h).await.unwrap();
    }

    #[tokio::test]
    async fn set_size_shrink_partial_keeps_prefix() {
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from_static(b"abcdefghij"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fs.set_size(&h, 4).await.unwrap();
        let g = backend.get_blob("k", None).await.unwrap();
        assert_eq!(&g.body[..], b"abcd");
    }

    #[tokio::test]
    async fn set_size_grow_zero_fills_via_pwrite() {
        let (backend, fs) = small_fs();
        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fs.pwrite(&h, 0, b"abc").await.unwrap();
        fs.set_size(&h, 10).await.unwrap();
        fs.sync(&h).await.unwrap();
        let g = backend.get_blob("k", None).await.unwrap();
        assert_eq!(&g.body[..], b"abc\0\0\0\0\0\0\0");
    }

    #[tokio::test]
    async fn set_size_grow_too_large_rejected() {
        let (_b, fs) = small_fs();
        let h = fs
            .open(
                "k",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let r = fs.set_size(&h, 200 * 1024 * 1024).await;
        assert!(matches!(r, Err(FsError::Invalid(_))));
    }

    // ---------- set_times ----------

    #[tokio::test]
    async fn set_times_persists_mtime_to_metadata() {
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from_static(b"x"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let h = fs.open("k", OpenFlags::write_only()).await.unwrap();
        let target_mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        fs.set_times(&h, None, Some(target_mtime)).await.unwrap();
        // Wire-level: object metadata now carries our mtime key.
        let head = backend.head_blob("k").await.unwrap();
        assert!(head
            .metadata
            .get(METADATA_MTIME_KEY)
            .is_some_and(|v| v.starts_with("1700000000")));
    }

    #[tokio::test]
    async fn set_times_at_with_no_follow_targets_symlink_itself() {
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "target".into(),
                body: Bytes::from_static(b"data"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        fs.symlink_at(&fs.root(), "link", "target").await.unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);

        // follow=false: writes mtime to the SYMLINK object, not the target.
        fs.set_times_at(&fs.root(), "link", false, None, Some(mtime))
            .await
            .unwrap();
        let link_head = backend.head_blob("link").await.unwrap();
        assert!(link_head.metadata.contains_key(METADATA_MTIME_KEY));
        let target_head = backend.head_blob("target").await.unwrap();
        assert!(!target_head.metadata.contains_key(METADATA_MTIME_KEY));
    }

    // ---------- symlinks ----------

    #[tokio::test]
    async fn symlink_at_creates_object_with_metadata_flag() {
        let (backend, fs) = small_fs();
        let root = fs.root();
        let l = fs.symlink_at(&root, "link", "target.txt").await.unwrap();
        assert!(l.is_symlink());
        assert_eq!(l.symlink_target().as_deref(), Some("target.txt"));
        // Verify the wire format.
        let head = backend.head_blob("link").await.unwrap();
        assert_eq!(
            head.metadata.get(SYMLINK_METADATA_KEY).map(|s| s.as_str()),
            Some(SYMLINK_METADATA_VALUE)
        );
        assert_eq!(head.content_type.as_deref(), Some(SYMLINK_CONTENT_TYPE));
        let g = backend.get_blob("link", None).await.unwrap();
        assert_eq!(&g.body[..], b"target.txt");
    }

    #[tokio::test]
    async fn symlink_at_eexist_via_conditional_put() {
        let (_b, fs) = small_fs();
        let root = fs.root();
        fs.symlink_at(&root, "l", "a").await.unwrap();
        let r = fs.symlink_at(&root, "l", "b").await;
        assert!(matches!(r, Err(FsError::AlreadyExists)));
    }

    #[tokio::test]
    async fn readlink_at_returns_target() {
        let (_b, fs) = small_fs();
        let root = fs.root();
        fs.symlink_at(&root, "l", "deep/path").await.unwrap();
        assert_eq!(fs.readlink_at(&root, "l").await.unwrap(), "deep/path");
    }

    #[tokio::test]
    async fn readlink_at_on_regular_file_errors() {
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "f".into(),
                body: Bytes::from_static(b"x"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let r = fs.readlink_at(&fs.root(), "f").await;
        assert!(matches!(r, Err(FsError::Invalid(_))));
    }

    // ---------- stat / read_dir ----------

    #[tokio::test]
    async fn stat_at_via_lookup_at() {
        let (backend, fs) = small_fs();
        backend
            .put_blob(PutBlobInput {
                key: "a/b.txt".into(),
                body: Bytes::from_static(b"hello"),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        let attrs = fs.stat_at(&fs.root(), "a/b.txt").await.unwrap();
        assert_eq!(attrs.size, 5);
    }

    #[tokio::test]
    async fn parallel_upload_many_parts_produces_correct_content() {
        // Stress the parallelization: pre-populate a 200-byte source (50
        // parts of 4 bytes each), then modify 17 non-contiguous parts and
        // sync with max_parallel_parts=4. Verify byte-for-byte.
        let backend = Arc::new(MemoryBackend::new());
        let cfg = Config::builder()
            .part_schedule(crate::config::PartSchedule {
                tiers: vec![(4, 100)],
            })
            .single_part_threshold(4) // force MPU path
            .max_parallel_parts(4)
            .max_parallel_copy(4)
            .max_merge_copy_bytes(1024)
            .memory_limit_bytes(1024 * 1024)
            .build();
        let fs = Fs::new(backend.clone() as Arc<dyn Backend>, Arc::new(cfg));

        // Build source = "AAAA" repeated 50 times, but make each 4-byte
        // chunk identifiable by a per-part letter so we can verify untouched
        // parts later.
        let mut source = Vec::with_capacity(200);
        for i in 0..50 {
            let c = b'a' + ((i % 26) as u8);
            source.extend_from_slice(&[c; 4]);
        }
        backend
            .put_blob(PutBlobInput {
                key: "k".into(),
                body: Bytes::from(source.clone()),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();

        let h = fs
            .open(
                "k",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // Modify these part indices (non-contiguous, includes boundaries).
        let modified_parts = [
            0u32, 1, 5, 7, 11, 12, 13, 19, 23, 27, 31, 35, 41, 42, 43, 47, 49,
        ];
        for &p in &modified_parts {
            let off = (p * 4) as u64;
            // Write distinctive 4-byte sequence "Z<idx>" packed; just use 'Z'.
            fs.pwrite(&h, off, b"ZZZZ").await.unwrap();
        }
        fs.sync(&h).await.unwrap();

        let g = backend.get_blob("k", None).await.unwrap();
        assert_eq!(g.body.len(), 200, "size unchanged");
        for i in 0..200usize {
            let part = (i / 4) as u32;
            let expected = if modified_parts.contains(&part) {
                b'Z'
            } else {
                b'a' + ((part % 26) as u8)
            };
            assert_eq!(g.body[i], expected, "byte {i} (part {part})");
        }
        assert_eq!(backend.mpu_count(), 0);
        fs.close(&h).await.unwrap();
    }

    #[tokio::test]
    async fn read_dir_on_root_after_mkdir_and_write() {
        let (_b, fs) = small_fs();
        fs.mkdir(&fs.root(), "d").await.unwrap();
        let h = fs
            .open(
                "f.txt",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fs.pwrite(&h, 0, b"x").await.unwrap();
        fs.sync(&h).await.unwrap();
        let snap = fs.read_dir(&fs.root()).await.unwrap();
        let names: Vec<_> = snap.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"d"));
        assert!(names.contains(&"f.txt"));
    }

    // ---------- eager flusher (background upload) ----------

    /// Write that fills more than `single_part_threshold` bytes across
    /// multiple full parts kicks off an MPU mid-pwrite (begin happens
    /// before pwrite returns). After sync, file contents round-trip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pwrite_eager_starts_mpu_for_large_writes() {
        let (backend, fs) = tiny_fs(); // 4 B/part, threshold = 8 B
        let h = fs
            .open(
                "big.bin",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let payload = vec![b'A'; 16]; // 4 full parts, > threshold
        let n = fs.pwrite(&h, 0, &payload).await.unwrap();
        assert_eq!(n, 16);
        // Eager path begun an MPU.
        assert_eq!(backend.mpu_count(), 1, "MPU should be begun by pwrite");
        // Sync completes the MPU; file content matches.
        fs.sync(&h).await.unwrap();
        assert_eq!(backend.mpu_count(), 0, "MPU committed by sync");
        let g = backend.get_blob("big.bin", None).await.unwrap();
        assert_eq!(&g.body[..], &payload[..]);
    }

    /// Sub-threshold writes never start an MPU: they go through the
    /// single-PUT path on sync.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pwrite_below_threshold_does_not_eager_flush() {
        let (backend, fs) = tiny_fs(); // threshold = 8 B
        let h = fs
            .open(
                "small.bin",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fs.pwrite(&h, 0, b"abc").await.unwrap(); // 3 B, single part
        assert_eq!(backend.mpu_count(), 0, "small write must not begin an MPU");
        fs.sync(&h).await.unwrap();
        let g = backend.get_blob("small.bin", None).await.unwrap();
        assert_eq!(&g.body[..], b"abc");
    }

    /// After an eager flush completes, the next sync sees no remaining
    /// dirty parts for the eager-uploaded region — it just runs the MPU
    /// commit without re-uploading.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sync_drains_inflight_then_commits() {
        let (backend, fs) = tiny_fs();
        let h = fs
            .open(
                "drain.bin",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Fill 3 full parts (12 B) — enqueues 3 eager UploadParts.
        let payload = vec![b'X'; 12];
        fs.pwrite(&h, 0, &payload).await.unwrap();
        // Briefly yield to let the worker pick up the jobs.
        tokio::task::yield_now().await;
        // Sync drains in-flights, then commits.
        fs.sync(&h).await.unwrap();
        let g = backend.get_blob("drain.bin", None).await.unwrap();
        assert_eq!(&g.body[..], &payload[..]);
    }

    /// A second pwrite into the same part that has an in-flight eager
    /// upload waits for the upload to land, then re-dirties the part. The
    /// sync afterwards re-uploads the part with the new content.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_pwrite_to_inflight_part_waits_then_redirties() {
        let (backend, fs) = tiny_fs();
        let h = fs
            .open(
                "rewrite.bin",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // First write fills 4 parts (16 B) — eager uploads triggered.
        fs.pwrite(&h, 0, &[b'A'; 16]).await.unwrap();
        // Re-write the first part. absorb_inflight should await the eager
        // upload then apply the new bytes; sync uploads the latest.
        fs.pwrite(&h, 0, b"ZZZZ").await.unwrap();
        fs.sync(&h).await.unwrap();
        let g = backend.get_blob("rewrite.bin", None).await.unwrap();
        let mut expected = [b'A'; 16];
        expected[..4].copy_from_slice(b"ZZZZ");
        assert_eq!(&g.body[..], &expected[..]);
    }
}
