//! `InodeTree` — the root container that owns every live `Inode` and exposes
//! the navigation primitives (`root`, `get`, `full_key`, `s3_key`).
//!
//! Lookup, openat traversal, and directory snapshots live in sibling modules
//! (`lookup.rs`, `listing.rs`) as additional `impl InodeTree` blocks.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::SystemTime;

use parking_lot::RwLock;

use super::attrs::{Attrs, Children, Inode, InodeId, InodeKind, InodeState};
use crate::backend::Backend;
use crate::config::Config;
use crate::path;

/// In-memory inode cache, parameterised over a `Backend`.
#[derive(Debug)]
pub struct InodeTree {
    by_id: RwLock<HashMap<InodeId, Arc<Inode>>>,
    next_id: AtomicU64,
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) config: Arc<Config>,
}

impl InodeTree {
    /// Build a new tree rooted at the bucket prefix specified in `config`.
    pub fn new(backend: Arc<dyn Backend>, config: Arc<Config>) -> Arc<Self> {
        let tree = Arc::new(Self {
            by_id: RwLock::new(HashMap::new()),
            // start counter at 2 — id 1 is reserved for root
            next_id: AtomicU64::new(2),
            backend,
            config,
        });
        let root = Arc::new(Inode {
            id: InodeId::ROOT,
            name: String::new(),
            kind: RwLock::new(InodeKind::Directory {
                explicit_marker: false,
            }),
            attrs: RwLock::new(Attrs {
                size: 0,
                etag: String::new(),
                last_modified: SystemTime::UNIX_EPOCH,
                content_type: None,
                metadata: HashMap::new(),
                fetched_at: std::time::Instant::now(),
            }),
            state: RwLock::new(InodeState::Cached),
            parent: None,
            children: RwLock::new(Children::default()),
            rename_state: RwLock::new(None),
            rename_lock: tokio::sync::Mutex::new(()),
        });
        tree.by_id.write().insert(InodeId::ROOT, root);
        tree
    }

    pub fn root(&self) -> Arc<Inode> {
        self.by_id
            .read()
            .get(&InodeId::ROOT)
            .expect("root inode always present")
            .clone()
    }

    pub fn get(&self, id: InodeId) -> Option<Arc<Inode>> {
        self.by_id.read().get(&id).cloned()
    }

    pub(crate) fn alloc_id(&self) -> InodeId {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        InodeId(std::num::NonZeroU64::new(n).expect("inode counter overflow"))
    }

    /// Build the bucket-relative (i.e. mount-relative) key for an inode by
    /// walking parent pointers and joining basenames with `/`.
    ///
    /// Returns the empty string for the root inode.
    pub fn full_key(&self, inode: &Inode) -> String {
        // Walk parents, accumulating basenames in reverse.
        let mut segments: Vec<String> = Vec::new();
        if !inode.name.is_empty() {
            segments.push(inode.name.clone());
        }
        let mut cur = inode.parent.as_ref().and_then(Weak::upgrade);
        while let Some(p) = cur {
            if !p.name.is_empty() {
                segments.push(p.name.clone());
            }
            cur = p.parent.as_ref().and_then(Weak::upgrade);
        }
        segments.reverse();
        segments.join("/")
    }

    /// The wire key for this inode's object — `full_key` prepended with the
    /// configured `bucket_prefix`.
    pub fn s3_key(&self, inode: &Inode) -> String {
        path::join_prefix(&self.config.bucket_prefix, &self.full_key(inode))
    }

    /// Wire key honoring an in-flight async rename: returns the OLD key
    /// while the rename worker is still propagating bytes from old → new in
    /// S3, so reads/writes resolve to the object that actually exists.
    /// Once the worker clears `rename_state`, falls back to `s3_key`.
    pub fn current_s3_key(&self, inode: &Inode) -> String {
        if let Some(s) = inode.rename_state() {
            return s.old_key.clone();
        }
        self.s3_key(inode)
    }

    /// The directory-marker form (`s3_key(inode) + "/"`) for use with
    /// `mkdir`-style explicit directory objects.
    pub fn s3_dir_key(&self, inode: &Inode) -> String {
        path::dir_marker_key(&self.s3_key(inode))
    }

    /// Atomically check-or-insert. If the parent already holds a non-deleted
    /// child with the same name, return the existing one (the freshly-built
    /// candidate is dropped). Otherwise install the candidate and return it.
    ///
    /// This is what makes concurrent `lookup`/`snapshot_directory` calls for
    /// the same name safe — the loser's allocated `InodeId` is wasted but the
    /// tree stays single-rooted per name.
    pub(crate) fn attach(&self, parent: &Arc<Inode>, child: Arc<Inode>) -> Arc<Inode> {
        debug_assert!(parent.is_dir(), "parent must be a directory");
        debug_assert!(!child.name.is_empty(), "child must have a name");
        let mut children = parent.children.write();
        if let Some(existing) = children.by_name.get(&child.name) {
            if !existing.is_deleted() {
                return existing.clone();
            }
        }
        children.by_name.insert(child.name.clone(), child.clone());
        drop(children);
        self.by_id.write().insert(child.id, child.clone());
        child
    }

    /// Remove an inode from the by-id table and from its parent's children
    /// map. Marks state `Deleted`. Does NOT recurse — callers handle
    /// directory tree teardown themselves.
    ///
    /// Reserved for the upcoming unlink/rmdir paths; currently exercised by
    /// tests only.
    #[allow(dead_code)]
    pub(crate) fn detach(&self, inode: &Arc<Inode>) {
        inode.set_state(InodeState::Deleted);
        if let Some(parent) = inode.parent.as_ref().and_then(Weak::upgrade) {
            parent.children.write().by_name.remove(&inode.name);
        }
        self.by_id.write().remove(&inode.id);
    }

    /// Total number of live inodes (root + everything below).
    pub fn len(&self) -> usize {
        self.by_id.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::config::Config;

    fn fresh_tree() -> Arc<InodeTree> {
        let backend: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let cfg = Arc::new(Config::default());
        InodeTree::new(backend, cfg)
    }

    fn fresh_tree_with_prefix(prefix: &str) -> Arc<InodeTree> {
        let backend: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let cfg = Arc::new(Config::builder().bucket_prefix(prefix).build());
        InodeTree::new(backend, cfg)
    }

    #[test]
    fn root_id_is_one_and_stored() {
        let t = fresh_tree();
        let r = t.root();
        assert_eq!(r.id, InodeId::ROOT);
        assert_eq!(r.id.get(), 1);
        assert_eq!(t.len(), 1);
        assert!(r.is_dir());
        assert_eq!(t.full_key(&r), "");
    }

    #[test]
    fn alloc_id_is_monotonic_and_skips_root() {
        let t = fresh_tree();
        let a = t.alloc_id();
        let b = t.alloc_id();
        assert_eq!(a.get(), 2);
        assert_eq!(b.get(), 3);
        assert_ne!(a, InodeId::ROOT);
    }

    #[test]
    fn attach_then_detach_a_file() {
        let t = fresh_tree();
        let root = t.root();
        let id = t.alloc_id();
        let attrs = Attrs {
            size: 5,
            etag: "etag1".into(),
            last_modified: SystemTime::UNIX_EPOCH,
            content_type: None,
            metadata: HashMap::new(),
            fetched_at: std::time::Instant::now(),
        };
        let child = Inode::new_file(id, "hello.txt", Arc::downgrade(&root), attrs);
        t.attach(&root, child.clone());

        assert_eq!(t.len(), 2);
        assert_eq!(t.full_key(&child), "hello.txt");
        assert!(root.children.read().by_name.contains_key("hello.txt"));

        t.detach(&child);
        assert_eq!(t.len(), 1);
        assert!(child.is_deleted());
        assert!(!root.children.read().by_name.contains_key("hello.txt"));
    }

    #[test]
    fn full_key_walks_parent_chain() {
        let t = fresh_tree();
        let root = t.root();

        // root → "dir" → "sub" → "file.txt"
        let attrs = || Attrs {
            size: 0,
            etag: String::new(),
            last_modified: SystemTime::UNIX_EPOCH,
            content_type: None,
            metadata: HashMap::new(),
            fetched_at: std::time::Instant::now(),
        };
        let dir = Inode::new_dir(
            t.alloc_id(),
            "dir",
            Some(Arc::downgrade(&root)),
            false,
            attrs(),
        );
        t.attach(&root, dir.clone());
        let sub = Inode::new_dir(
            t.alloc_id(),
            "sub",
            Some(Arc::downgrade(&dir)),
            false,
            attrs(),
        );
        t.attach(&dir, sub.clone());
        let file = Inode::new_file(t.alloc_id(), "file.txt", Arc::downgrade(&sub), attrs());
        t.attach(&sub, file.clone());

        assert_eq!(t.full_key(&file), "dir/sub/file.txt");
        assert_eq!(t.full_key(&sub), "dir/sub");
        assert_eq!(t.full_key(&dir), "dir");
        assert_eq!(t.full_key(&root), "");
    }

    #[test]
    fn s3_key_applies_bucket_prefix() {
        let t = fresh_tree_with_prefix("data");
        let root = t.root();
        let f = Inode::new_file(
            t.alloc_id(),
            "x.txt",
            Arc::downgrade(&root),
            Attrs {
                size: 0,
                etag: String::new(),
                last_modified: SystemTime::UNIX_EPOCH,
                content_type: None,
                metadata: HashMap::new(),
                fetched_at: std::time::Instant::now(),
            },
        );
        t.attach(&root, f.clone());
        assert_eq!(t.s3_key(&f), "data/x.txt");
        assert_eq!(t.s3_dir_key(&f), "data/x.txt/");
        assert_eq!(t.s3_key(&root), "data");
    }

    #[test]
    fn s3_key_with_empty_prefix_is_just_full_key() {
        let t = fresh_tree();
        let root = t.root();
        let f = Inode::new_file(
            t.alloc_id(),
            "x",
            Arc::downgrade(&root),
            Attrs {
                size: 0,
                etag: String::new(),
                last_modified: SystemTime::UNIX_EPOCH,
                content_type: None,
                metadata: HashMap::new(),
                fetched_at: std::time::Instant::now(),
            },
        );
        t.attach(&root, f.clone());
        assert_eq!(t.s3_key(&f), "x");
        assert_eq!(t.s3_dir_key(&f), "x/");
        assert_eq!(t.s3_key(&root), "");
    }

    #[test]
    fn detached_inode_kind_unchanged_but_state_deleted() {
        let t = fresh_tree();
        let root = t.root();
        let f = Inode::new_file(
            t.alloc_id(),
            "x",
            Arc::downgrade(&root),
            Attrs {
                size: 0,
                etag: String::new(),
                last_modified: SystemTime::UNIX_EPOCH,
                content_type: None,
                metadata: HashMap::new(),
                fetched_at: std::time::Instant::now(),
            },
        );
        t.attach(&root, f.clone());
        t.detach(&f);
        assert!(f.is_deleted());
        assert!(f.is_regular_file()); // kind preserved for stale-handle errors
    }
}
