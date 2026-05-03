//! Inode data structures: ID, kind, attributes, and the in-memory tree node.
//!
//! Inodes are reference-counted via `Arc`. Parent references are `Weak` so a
//! drop of the tree's by-id table releases everything cleanly. Per-inode state
//! lives behind `parking_lot::RwLock`s that are short-held and never crossed
//! by `await` points.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::{Arc, Weak};
use std::time::{Instant, SystemTime};

use parking_lot::RwLock;

/// Stable per-`InodeTree` identifier. Root is always `InodeId(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InodeId(pub NonZeroU64);

impl InodeId {
    /// The root of every `InodeTree`.
    pub const ROOT: InodeId = InodeId(match NonZeroU64::new(1) {
        Some(v) => v,
        None => unreachable!(),
    });

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl std::fmt::Display for InodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ino:{}", self.0.get())
    }
}

/// What this inode represents in the storage layer.
#[derive(Debug, Clone)]
pub enum InodeKind {
    RegularFile,
    /// Directory. `explicit_marker` records whether a zero-byte `dir/`
    /// object exists in S3 (set on `mkdir`) or whether the directory is
    /// implicit-from-prefix only.
    Directory {
        explicit_marker: bool,
    },
    /// Symlink. `target` is the literal stored target path string. Resolution
    /// happens at follow-time; at attr-cache level we just remember the body.
    Symlink {
        target: String,
    },
}

impl InodeKind {
    pub fn is_dir(&self) -> bool {
        matches!(self, InodeKind::Directory { .. })
    }
    pub fn is_symlink(&self) -> bool {
        matches!(self, InodeKind::Symlink { .. })
    }
    pub fn is_regular_file(&self) -> bool {
        matches!(self, InodeKind::RegularFile)
    }
}

/// State machine for an inode's relationship to the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeState {
    /// In sync with what we last saw from S3.
    Cached,
    /// Local writes pending; flusher will reconcile. (Reserved for the
    /// upcoming buffer-pool / MPU layers.)
    Modified,
    /// Tombstoned by `unlink`/`rmdir`. Subsequent ops on stale handles must
    /// return [`crate::errors::FsError::NotFound`].
    Deleted,
}

/// Cached attribute snapshot.
#[derive(Debug, Clone)]
pub struct Attrs {
    pub size: u64,
    pub etag: String,
    pub last_modified: SystemTime,
    pub content_type: Option<String>,
    pub metadata: HashMap<String, String>,
    /// When this snapshot was fetched / last validated. Used for TTL checks
    /// against `Config::attr_cache_ttl`.
    pub fetched_at: Instant,
}

impl Attrs {
    /// Synthesize attrs for an implicit directory (no S3 object backs it).
    pub fn synthetic_implicit_dir() -> Self {
        Self {
            size: 0,
            etag: String::new(),
            last_modified: SystemTime::UNIX_EPOCH,
            content_type: None,
            metadata: HashMap::new(),
            fetched_at: Instant::now(),
        }
    }
}

/// Mutable per-directory child table.
#[derive(Debug, Default)]
pub struct Children {
    pub by_name: HashMap<String, Arc<Inode>>,
    /// `true` once a complete directory listing has been ingested; lookup
    /// misses can then short-circuit to `NotFound` without hitting S3.
    pub listing_complete: bool,
    /// When the listing snapshot was taken.
    pub listing_fetched_at: Option<Instant>,
}

/// Tracks an async rename that has rewired the inode tree but whose
/// background copy+delete in S3 has not yet completed.
///
/// While set, `InodeTree::current_s3_key` returns `old_key` (so reads and
/// writes still resolve to the existing object). Once the worker finishes
/// the copy + delete, it clears this state and signals `done`.
///
/// On worker error, `error` is populated and `state` is left set so the
/// next `Fs::sync` / `Fs::rename` for the inode can surface it.
#[derive(Debug)]
pub struct RenameState {
    pub old_key: String,
    /// `Some(_)` after a worker error.
    pub error: RwLock<Option<crate::errors::FsError>>,
    pub done: Arc<tokio::sync::Notify>,
}

impl RenameState {
    pub fn new(old_key: String) -> Arc<Self> {
        Arc::new(Self {
            old_key,
            error: RwLock::new(None),
            done: Arc::new(tokio::sync::Notify::new()),
        })
    }
}

/// In-memory inode. Cheap to clone (`Arc<Inode>`).
#[derive(Debug)]
pub struct Inode {
    pub id: InodeId,
    /// Basename only. The root has `name == ""`.
    pub name: String,
    pub kind: RwLock<InodeKind>,
    pub attrs: RwLock<Attrs>,
    pub state: RwLock<InodeState>,
    pub parent: Option<Weak<Inode>>,
    pub children: RwLock<Children>,
    /// Set on the *destination* inode of an async rename — the in-memory
    /// rewire happened but the underlying S3 copy+delete is still in
    /// flight. Cleared by the rename worker on success.
    pub rename_state: RwLock<Option<Arc<RenameState>>>,
    /// Per-inode async lock that serialises a rename worker against any
    /// sync/pwrite-commit on the same inode. Held by the worker for the
    /// entire copy+delete; held by sync around its commit.
    pub rename_lock: tokio::sync::Mutex<()>,
}

impl Inode {
    /// Construct a directory inode (not yet attached to a parent's child map).
    pub fn new_dir(
        id: InodeId,
        name: impl Into<String>,
        parent: Option<Weak<Inode>>,
        explicit_marker: bool,
        attrs: Attrs,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            name: name.into(),
            kind: RwLock::new(InodeKind::Directory { explicit_marker }),
            attrs: RwLock::new(attrs),
            state: RwLock::new(InodeState::Cached),
            parent,
            children: RwLock::new(Children::default()),
            rename_state: RwLock::new(None),
            rename_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Construct a regular-file inode.
    pub fn new_file(
        id: InodeId,
        name: impl Into<String>,
        parent: Weak<Inode>,
        attrs: Attrs,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            name: name.into(),
            kind: RwLock::new(InodeKind::RegularFile),
            attrs: RwLock::new(attrs),
            state: RwLock::new(InodeState::Cached),
            parent: Some(parent),
            children: RwLock::new(Children::default()),
            rename_state: RwLock::new(None),
            rename_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Construct a symlink inode.
    pub fn new_symlink(
        id: InodeId,
        name: impl Into<String>,
        parent: Weak<Inode>,
        target: impl Into<String>,
        attrs: Attrs,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            name: name.into(),
            kind: RwLock::new(InodeKind::Symlink {
                target: target.into(),
            }),
            attrs: RwLock::new(attrs),
            state: RwLock::new(InodeState::Cached),
            parent: Some(parent),
            children: RwLock::new(Children::default()),
            rename_state: RwLock::new(None),
            rename_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Snapshot of the inode's current rename state (None if not in flight).
    pub fn rename_state(&self) -> Option<Arc<RenameState>> {
        self.rename_state.read().clone()
    }

    pub fn state(&self) -> InodeState {
        *self.state.read()
    }

    pub fn set_state(&self, s: InodeState) {
        *self.state.write() = s;
    }

    pub fn is_deleted(&self) -> bool {
        matches!(self.state(), InodeState::Deleted)
    }

    pub fn is_dir(&self) -> bool {
        self.kind.read().is_dir()
    }

    pub fn is_symlink(&self) -> bool {
        self.kind.read().is_symlink()
    }

    pub fn is_regular_file(&self) -> bool {
        self.kind.read().is_regular_file()
    }

    /// `Some(explicit_marker)` if directory, `None` otherwise. Cheap; releases
    /// the lock before returning.
    pub fn dir_explicit_marker(&self) -> Option<bool> {
        match &*self.kind.read() {
            InodeKind::Directory { explicit_marker } => Some(*explicit_marker),
            _ => None,
        }
    }

    /// `Some(target_clone)` if symlink, `None` otherwise.
    pub fn symlink_target(&self) -> Option<String> {
        match &*self.kind.read() {
            InodeKind::Symlink { target } => Some(target.clone()),
            _ => None,
        }
    }
}
