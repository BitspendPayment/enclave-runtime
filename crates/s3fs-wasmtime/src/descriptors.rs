//! Resource types stored in the wasmtime `ResourceTable`.

use std::sync::Arc;

use s3fs_core::{FileHandle, Inode};

/// Wasmtime resource handle for `wasi:filesystem/types/descriptor`.
///
/// A descriptor is one of two flavours:
/// - **File descriptor**: holds an `Arc<FileHandle>` plus its parent inode
///   (so paths used in `_at` operations resolve relative to the right place).
/// - **Directory descriptor**: holds the directory inode directly. Reads /
///   writes against a dir-descriptor return `is-directory`.
///
/// Both flavours can be used as the `base` for `*-at` operations; for a file
/// descriptor we resolve relative to its parent.
#[derive(Debug)]
pub enum Descriptor {
    File { handle: Arc<FileHandle> },
    Dir { inode: Arc<Inode> },
}

impl Descriptor {
    /// The inode this descriptor opens or is rooted under. For files, the
    /// file's own inode; for dirs, the directory inode itself.
    pub fn inode(&self) -> &Arc<Inode> {
        match self {
            Descriptor::File { handle } => &handle.inode,
            Descriptor::Dir { inode } => inode,
        }
    }

    /// The directory inode to use as the base for `*-at` path resolution.
    /// For a file descriptor, that's the file's parent (or the file itself
    /// if it has no parent — which would be an open of the root, an
    /// invalid case for files).
    pub fn at_base(&self) -> Arc<Inode> {
        match self {
            Descriptor::Dir { inode } => inode.clone(),
            Descriptor::File { handle } => {
                // For an open file the parent should always exist; fall back
                // to the file inode itself in the degenerate case.
                handle
                    .inode
                    .parent
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .unwrap_or_else(|| handle.inode.clone())
            }
        }
    }
}

/// Wasmtime resource handle for `wasi:filesystem/types/directory-entry-stream`.
///
/// Holds a snapshot of directory entries plus an iteration cursor.
#[derive(Debug)]
pub struct DirectoryEntryStream {
    pub entries: Vec<s3fs_core::DirEntry>,
    pub cursor: usize,
}

impl DirectoryEntryStream {
    pub fn new(entries: Vec<s3fs_core::DirEntry>) -> Self {
        Self { entries, cursor: 0 }
    }
}
