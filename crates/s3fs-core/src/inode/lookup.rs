//! Race-three lookup and openat-style path traversal.
//!
//! `lookup` resolves a single child of a directory using the GeeseFS
//! `LookUpInodeMaybeDir` strategy: race a `HeadObject(name)`, a
//! `HeadObject(name/)`, and a `ListObjectsV2(prefix=name/, max_keys=1)` in
//! parallel. Priority: regular file > explicit directory > implicit directory.
//!
//! `lookup_at` walks a relative POSIX path one component at a time, using
//! `lookup` per step, and enforces preopen containment: `..` cannot escape
//! the [`InodeTree`]'s root (which corresponds to the preopen).

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Instant;

use super::attrs::{Attrs, Inode, InodeKind};
use super::tree::InodeTree;
use crate::backend::{BlobMeta, ListBlobsInput};
use crate::errors::{FsError, FsResult};
use crate::path;

/// Metadata key (after S3 strips the `x-amz-meta-` prefix) marking a symlink
/// object. Body of such an object is the literal target path.
pub const SYMLINK_METADATA_KEY: &str = "s3wasifs-type";
pub const SYMLINK_METADATA_VALUE: &str = "symlink";

fn meta_indicates_symlink(meta: &HashMap<String, String>) -> bool {
    meta.get(SYMLINK_METADATA_KEY)
        .map(|s| s == SYMLINK_METADATA_VALUE)
        .unwrap_or(false)
}

fn attrs_from_head(head: &BlobMeta) -> Attrs {
    Attrs {
        size: head.size,
        etag: head.e_tag.clone(),
        last_modified: head.last_modified,
        content_type: head.content_type.clone(),
        metadata: head.metadata.clone(),
        fetched_at: Instant::now(),
    }
}

impl InodeTree {
    /// Look up `name` as a child of `parent`. Cache-first; on miss, race three
    /// backend ops in parallel.
    ///
    /// Returns the resolved child inode (file, dir, or symlink). Stale
    /// (`Deleted`) cache entries are treated as misses.
    pub async fn lookup(&self, parent: &Arc<Inode>, name: &str) -> FsResult<Arc<Inode>> {
        if !parent.is_dir() {
            return Err(FsError::NotDirectory);
        }
        if parent.is_deleted() {
            return Err(FsError::NotFound);
        }
        path::validate_segment(name)?;

        // 1) Cache lookup. Hold the read lock only for the duration of the
        // probe; release before any await.
        {
            let children = parent.children.read();
            if let Some(child) = children.by_name.get(name) {
                if !child.is_deleted() {
                    return Ok(child.clone());
                }
            } else if children.listing_complete {
                // Directory has been fully enumerated and the child is absent.
                return Err(FsError::NotFound);
            }
        }

        // 2) Race three.
        let parent_key = self.s3_key(parent);
        let file_key = if parent_key.is_empty() {
            name.to_string()
        } else {
            format!("{parent_key}/{name}")
        };
        let dir_key = path::dir_marker_key(&file_key);

        let (file_res, dir_res, list_res) = tokio::join!(
            self.backend.head_blob(&file_key),
            self.backend.head_blob(&dir_key),
            self.backend.list_blobs(ListBlobsInput {
                prefix: &dir_key,
                delimiter: None,
                max_keys: Some(1),
                ..Default::default()
            }),
        );

        // Re-check cache before insert: another concurrent lookup may have
        // installed the same child while we were awaiting.
        {
            let children = parent.children.read();
            if let Some(child) = children.by_name.get(name) {
                if !child.is_deleted() {
                    return Ok(child.clone());
                }
            }
        }

        // Priority order: file > explicit dir > implicit dir.
        if let Ok(meta) = file_res {
            let attrs = attrs_from_head(&meta);
            let kind = if meta_indicates_symlink(&meta.metadata) {
                // For a symlink, the target body lives in the object payload.
                // Issue a follow-up GET so the inode is fully populated.
                let body = self.backend.get_blob(&file_key, None).await?;
                let target = String::from_utf8(body.body.to_vec())
                    .map_err(|_| FsError::IllegalByteSequence)?;
                path::validate_symlink_target(&target)?;
                InodeKind::Symlink { target }
            } else {
                InodeKind::RegularFile
            };
            let id = self.alloc_id();
            let child = match kind {
                InodeKind::Symlink { target } => Inode::new_symlink(
                    id,
                    name,
                    Arc::downgrade(parent),
                    target,
                    attrs,
                ),
                _ => Inode::new_file(id, name, Arc::downgrade(parent), attrs),
            };
            return Ok(self.attach(parent, child));
        }

        if let Ok(meta) = dir_res {
            let attrs = attrs_from_head(&meta);
            let id = self.alloc_id();
            let child = Inode::new_dir(
                id,
                name,
                Some(Arc::downgrade(parent)),
                /* explicit_marker */ true,
                attrs,
            );
            return Ok(self.attach(parent, child));
        }

        if let Ok(out) = list_res {
            if !out.items.is_empty() || !out.prefixes.is_empty() {
                let id = self.alloc_id();
                let child = Inode::new_dir(
                    id,
                    name,
                    Some(Arc::downgrade(parent)),
                    /* explicit_marker */ false,
                    Attrs::synthetic_implicit_dir(),
                );
                return Ok(self.attach(parent, child));
            }
            // Empty listing AND both heads NotFound → genuinely absent.
        }

        Err(FsError::NotFound)
    }

    /// Walk `rel_path` from `start`, calling `lookup` for each non-special
    /// component. `.` is skipped; `..` pops the current node, but cannot
    /// escape the tree root (which is the preopen root).
    ///
    /// Symlinks are followed transparently for **intermediate** components.
    /// The final named component is also followed (POSIX default). To
    /// suppress follow on the final component (POSIX `O_NOFOLLOW` /
    /// WASI `path-flags::symlink-follow` cleared), use [`Self::lookup_at_no_follow`].
    pub async fn lookup_at(
        &self,
        start: &Arc<Inode>,
        rel_path: &str,
    ) -> FsResult<Arc<Inode>> {
        self.lookup_at_inner(start, rel_path, /* follow_last */ true, 0)
            .await
    }

    /// Like `lookup_at` but does NOT follow a symlink at the final named
    /// component. Returns the symlink inode itself if the leaf is a symlink.
    /// Used by `readlink_at` and by `open_at` when `path-flags::symlink-follow`
    /// is cleared (the latter then maps to `error-code::loop`).
    pub async fn lookup_at_no_follow(
        &self,
        start: &Arc<Inode>,
        rel_path: &str,
    ) -> FsResult<Arc<Inode>> {
        self.lookup_at_inner(start, rel_path, /* follow_last */ false, 0)
            .await
    }

    /// Internal recursive implementation. Tracks `depth` to enforce
    /// `Config::max_symlink_depth` (default 40, matching Linux's `MAXSYMLINKS`).
    async fn lookup_at_inner(
        &self,
        start: &Arc<Inode>,
        rel_path: &str,
        follow_last: bool,
        depth: u32,
    ) -> FsResult<Arc<Inode>> {
        if rel_path.starts_with('/') {
            return Err(FsError::NotPermitted);
        }
        if depth > self.config.max_symlink_depth {
            return Err(FsError::Loop);
        }
        let mut current = start.clone();
        let root = self.root();

        let segments: Vec<&str> = rel_path.split('/').collect();
        // Index of the rightmost "named" segment (not "", ".", or ".."). The
        // `follow_last` flag only governs that one — all earlier symlinks are
        // always followed.
        let last_named = segments
            .iter()
            .rposition(|s| !s.is_empty() && *s != "." && *s != "..");

        for (i, seg) in segments.iter().enumerate() {
            if seg.is_empty() || *seg == "." {
                continue;
            }
            if *seg == ".." {
                if Arc::ptr_eq(&current, &root) {
                    return Err(FsError::NotPermitted);
                }
                let parent = current
                    .parent
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .ok_or(FsError::NotPermitted)?;
                current = parent;
                continue;
            }
            if !current.is_dir() {
                return Err(FsError::NotDirectory);
            }
            current = self.lookup(&current, seg).await?;

            // Symlink follow: always for intermediate components, and for
            // the final named component iff `follow_last`.
            let is_last_named = Some(i) == last_named;
            let should_follow = !is_last_named || follow_last;
            if should_follow {
                if let Some(target) = current.symlink_target() {
                    // Resolve relative to the symlink's parent (or root for
                    // absolute targets). Recurse with depth + 1 (Box::pin so
                    // the future has a known size).
                    let (resolution_base, target_relative) = if let Some(stripped) =
                        target.strip_prefix('/')
                    {
                        (root.clone(), stripped.to_string())
                    } else {
                        let parent = current
                            .parent
                            .as_ref()
                            .and_then(Weak::upgrade)
                            .unwrap_or_else(|| root.clone());
                        (parent, target)
                    };
                    current = Box::pin(self.lookup_at_inner(
                        &resolution_base,
                        &target_relative,
                        /* follow_last */ true,
                        depth + 1,
                    ))
                    .await?;
                }
            }
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::backend::{Backend, PutBlobInput};
    use crate::config::Config;
    use bytes::Bytes;
    use std::collections::HashMap;

    fn fresh() -> (Arc<MemoryBackend>, Arc<InodeTree>) {
        let backend = Arc::new(MemoryBackend::new());
        let tree =
            InodeTree::new(backend.clone() as Arc<dyn Backend>, Arc::new(Config::default()));
        (backend, tree)
    }

    fn fresh_with_prefix(prefix: &str) -> (Arc<MemoryBackend>, Arc<InodeTree>) {
        let backend = Arc::new(MemoryBackend::new());
        let cfg = Config::builder().bucket_prefix(prefix).build();
        let tree = InodeTree::new(backend.clone() as Arc<dyn Backend>, Arc::new(cfg));
        (backend, tree)
    }

    async fn put(backend: &MemoryBackend, key: &str, body: &'static [u8]) {
        backend
            .put_blob(PutBlobInput {
                key: key.into(),
                body: Bytes::from_static(body),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
    }

    async fn put_with_meta(
        backend: &MemoryBackend,
        key: &str,
        body: &'static [u8],
        metadata: HashMap<String, String>,
    ) {
        backend
            .put_blob(PutBlobInput {
                key: key.into(),
                body: Bytes::from_static(body),
                metadata,
                content_type: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lookup_finds_regular_file() {
        let (backend, tree) = fresh();
        put(&backend, "hello.txt", b"hi").await;

        let root = tree.root();
        let child = tree.lookup(&root, "hello.txt").await.unwrap();
        assert!(child.is_regular_file());
        assert_eq!(tree.full_key(&child), "hello.txt");
        assert_eq!(child.attrs.read().size, 2);
    }

    #[tokio::test]
    async fn lookup_finds_explicit_directory_marker() {
        let (backend, tree) = fresh();
        // A geesefs-style mkdir: zero-byte object whose key ends in '/'.
        put(&backend, "subdir/", b"").await;

        let root = tree.root();
        let child = tree.lookup(&root, "subdir").await.unwrap();
        assert!(child.is_dir());
        assert_eq!(child.dir_explicit_marker(), Some(true));
    }

    #[tokio::test]
    async fn lookup_finds_implicit_directory_via_prefix() {
        let (backend, tree) = fresh();
        // No marker; only a child key exists. Directory is implicit.
        put(&backend, "implicit/file.txt", b"x").await;

        let root = tree.root();
        let child = tree.lookup(&root, "implicit").await.unwrap();
        assert!(child.is_dir());
        assert_eq!(child.dir_explicit_marker(), Some(false));
    }

    #[tokio::test]
    async fn lookup_returns_not_found_when_absent() {
        let (_backend, tree) = fresh();
        let root = tree.root();
        assert!(matches!(
            tree.lookup(&root, "missing").await,
            Err(FsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn file_wins_over_directory_when_both_present() {
        let (backend, tree) = fresh();
        // Pathological: both `foo` (file) and `foo/bar` (dir contents) exist.
        put(&backend, "foo", b"file body").await;
        put(&backend, "foo/bar", b"x").await;

        let root = tree.root();
        let child = tree.lookup(&root, "foo").await.unwrap();
        assert!(child.is_regular_file());
        assert_eq!(child.attrs.read().size, 9);
    }

    #[tokio::test]
    async fn lookup_caches_then_skips_backend_on_repeat() {
        let (backend, tree) = fresh();
        put(&backend, "hello.txt", b"hi").await;
        let root = tree.root();

        let a = tree.lookup(&root, "hello.txt").await.unwrap();
        let b = tree.lookup(&root, "hello.txt").await.unwrap();
        // Same Arc → cached
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[tokio::test]
    async fn lookup_rejects_not_a_directory_parent() {
        let (backend, tree) = fresh();
        put(&backend, "file.txt", b"x").await;
        let root = tree.root();
        let f = tree.lookup(&root, "file.txt").await.unwrap();
        assert!(matches!(
            tree.lookup(&f, "child").await,
            Err(FsError::NotDirectory)
        ));
    }

    #[tokio::test]
    async fn lookup_validates_segment() {
        let (_backend, tree) = fresh();
        let root = tree.root();
        assert!(matches!(
            tree.lookup(&root, "..").await,
            Err(FsError::Invalid(_))
        ));
        assert!(matches!(
            tree.lookup(&root, "with\0nul").await,
            Err(FsError::IllegalByteSequence)
        ));
    }

    #[tokio::test]
    async fn lookup_with_bucket_prefix_uses_correct_keys() {
        let (backend, tree) = fresh_with_prefix("data");
        put(&backend, "data/file.txt", b"hi").await;

        let root = tree.root();
        let f = tree.lookup(&root, "file.txt").await.unwrap();
        assert!(f.is_regular_file());
        assert_eq!(tree.s3_key(&f), "data/file.txt");
    }

    #[tokio::test]
    async fn lookup_detects_symlink_via_metadata_and_fetches_target() {
        let (backend, tree) = fresh();
        let mut meta = HashMap::new();
        meta.insert(SYMLINK_METADATA_KEY.into(), SYMLINK_METADATA_VALUE.into());
        put_with_meta(&backend, "link", b"target.txt", meta).await;

        let root = tree.root();
        let l = tree.lookup(&root, "link").await.unwrap();
        assert!(l.is_symlink());
        assert_eq!(l.symlink_target().as_deref(), Some("target.txt"));
    }

    #[tokio::test]
    async fn lookup_at_walks_components() {
        let (backend, tree) = fresh();
        put(&backend, "a/b/c.txt", b"deep").await;

        let root = tree.root();
        let c = tree.lookup_at(&root, "a/b/c.txt").await.unwrap();
        assert!(c.is_regular_file());
        assert_eq!(tree.full_key(&c), "a/b/c.txt");
    }

    #[tokio::test]
    async fn lookup_at_skips_dot_and_pops_dotdot() {
        let (backend, tree) = fresh();
        put(&backend, "a/b/c.txt", b"x").await;
        put(&backend, "a/sibling", b"y").await;

        let root = tree.root();
        let r = tree.lookup_at(&root, "a/./b/../sibling").await.unwrap();
        assert!(r.is_regular_file());
        assert_eq!(tree.full_key(&r), "a/sibling");
    }

    #[tokio::test]
    async fn lookup_at_rejects_dotdot_escape_above_root() {
        let (_backend, tree) = fresh();
        let root = tree.root();
        assert!(matches!(
            tree.lookup_at(&root, "..").await,
            Err(FsError::NotPermitted)
        ));
    }

    #[tokio::test]
    async fn lookup_at_rejects_absolute_path() {
        let (_backend, tree) = fresh();
        let root = tree.root();
        assert!(matches!(
            tree.lookup_at(&root, "/etc/passwd").await,
            Err(FsError::NotPermitted)
        ));
    }

    #[tokio::test]
    async fn lookup_at_empty_returns_start() {
        let (_backend, tree) = fresh();
        let root = tree.root();
        let r = tree.lookup_at(&root, "").await.unwrap();
        assert!(Arc::ptr_eq(&r, &root));
    }

    #[tokio::test]
    async fn lookup_at_follows_symlink_intermediate_component() {
        let (backend, tree) = fresh();
        // /target/file.txt
        put(&backend, "target/file.txt", b"hello").await;
        // /link → "target"  (a symlink to a dir)
        let mut meta = HashMap::new();
        meta.insert(SYMLINK_METADATA_KEY.into(), SYMLINK_METADATA_VALUE.into());
        put_with_meta(&backend, "link", b"target", meta).await;

        // lookup "link/file.txt" — intermediate "link" is followed.
        let resolved = tree
            .lookup_at(&tree.root(), "link/file.txt")
            .await
            .unwrap();
        assert!(resolved.is_regular_file());
        assert_eq!(tree.full_key(&resolved), "target/file.txt");
    }

    #[tokio::test]
    async fn lookup_at_follows_symlink_at_leaf_by_default() {
        let (backend, tree) = fresh();
        put(&backend, "target.txt", b"yo").await;
        let mut meta = HashMap::new();
        meta.insert(SYMLINK_METADATA_KEY.into(), SYMLINK_METADATA_VALUE.into());
        put_with_meta(&backend, "link.txt", b"target.txt", meta).await;

        let resolved = tree.lookup_at(&tree.root(), "link.txt").await.unwrap();
        assert!(resolved.is_regular_file());
        assert_eq!(tree.full_key(&resolved), "target.txt");
    }

    #[tokio::test]
    async fn lookup_at_no_follow_returns_symlink_at_leaf() {
        let (backend, tree) = fresh();
        put(&backend, "target.txt", b"yo").await;
        let mut meta = HashMap::new();
        meta.insert(SYMLINK_METADATA_KEY.into(), SYMLINK_METADATA_VALUE.into());
        put_with_meta(&backend, "link.txt", b"target.txt", meta).await;

        let resolved = tree
            .lookup_at_no_follow(&tree.root(), "link.txt")
            .await
            .unwrap();
        assert!(resolved.is_symlink());
        assert_eq!(resolved.symlink_target().as_deref(), Some("target.txt"));
    }

    #[tokio::test]
    async fn lookup_at_symlink_cycle_returns_loop() {
        let (backend, tree) = fresh();
        let meta = || {
            let mut m = HashMap::new();
            m.insert(SYMLINK_METADATA_KEY.into(), SYMLINK_METADATA_VALUE.into());
            m
        };
        // a → b, b → a (mutual cycle)
        put_with_meta(&backend, "a", b"b", meta()).await;
        put_with_meta(&backend, "b", b"a", meta()).await;

        let r = tree.lookup_at(&tree.root(), "a").await;
        assert!(matches!(r, Err(FsError::Loop)), "expected Loop, got {r:?}");
    }

    #[tokio::test]
    async fn lookup_at_symlink_to_absolute_path_resolves_from_root() {
        let (backend, tree) = fresh();
        put(&backend, "deep/target.txt", b"x").await;
        let mut meta = HashMap::new();
        meta.insert(SYMLINK_METADATA_KEY.into(), SYMLINK_METADATA_VALUE.into());
        put_with_meta(&backend, "shortcut", b"/deep/target.txt", meta).await;

        let r = tree.lookup_at(&tree.root(), "shortcut").await.unwrap();
        assert!(r.is_regular_file());
        assert_eq!(tree.full_key(&r), "deep/target.txt");
    }

    #[tokio::test]
    async fn lookup_at_symlink_target_escape_rejected() {
        let (backend, tree) = fresh();
        let mut meta = HashMap::new();
        meta.insert(SYMLINK_METADATA_KEY.into(), SYMLINK_METADATA_VALUE.into());
        put_with_meta(&backend, "evil", b"../../etc/passwd", meta).await;

        let r = tree.lookup_at(&tree.root(), "evil").await;
        assert!(
            matches!(r, Err(FsError::NotPermitted)),
            "expected NotPermitted, got {r:?}"
        );
    }

    #[tokio::test]
    async fn lookup_at_dotdot_within_subtree_pops_to_parent() {
        let (backend, tree) = fresh();
        put(&backend, "a/b/c.txt", b"x").await;
        let root = tree.root();
        // open a/b first, then via that descriptor go ..
        let a = tree.lookup(&root, "a").await.unwrap();
        let b = tree.lookup(&a, "b").await.unwrap();
        // From b, "../" should land back at a.
        let popped = tree.lookup_at(&b, "..").await.unwrap();
        assert!(Arc::ptr_eq(&popped, &a));
    }
}
