//! Resource types stored in the wasmtime `ResourceTable`.

use std::sync::Arc;

use s3fs_core::{FileHandle, Inode};

/// Wasmtime resource handle for `wasi:filesystem/types/descriptor`.
///
/// A descriptor is one of two flavours:
/// - **File descriptor**: an `Arc<FileHandle>` plus the directory it was
///   opened under, so paths used in `*-at` operations resolve relative to the
///   right place.
/// - **Directory descriptor**: the directory inode itself. Reads and writes
///   against one return `is-directory`.
///
/// The parent is captured at open time rather than walked back to on demand:
/// `at_base` is synchronous, and the parent link now lives in the dnode, which
/// would make resolving it an I/O operation.
#[derive(Debug)]
pub enum Descriptor {
    File {
        handle: Arc<FileHandle>,
        parent: Arc<Inode>,
    },
    Dir {
        inode: Arc<Inode>,
    },
}

impl Descriptor {
    /// The inode this descriptor opens or is rooted under. For files, the
    /// file's own inode; for dirs, the directory inode itself.
    pub fn inode(&self) -> &Arc<Inode> {
        match self {
            Descriptor::File { handle, .. } => &handle.inode,
            Descriptor::Dir { inode } => inode,
        }
    }

    /// The directory to use as the base for `*-at` path resolution.
    pub fn at_base(&self) -> Arc<Inode> {
        match self {
            Descriptor::Dir { inode } => inode.clone(),
            Descriptor::File { parent, .. } => parent.clone(),
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
