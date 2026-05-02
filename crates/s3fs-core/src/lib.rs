//! `s3fs-core` — async S3-backed filesystem engine.
//!
//! See the workspace README and the design plan for context. The Compatibility
//! Matrix in the README is the authoritative user-facing semantic contract.

pub mod backend;
pub mod buffer;
pub mod config;
pub mod errors;
pub mod fs;
pub mod inode;
pub mod mpu;
pub mod path;

pub use buffer::{BufferPool, PartBuf, PartKey, PartState, RangeSet};
pub use config::Config;
pub use errors::FsError;
pub use fs::{FileHandle, Fs, HandleId, OpenFlags};
pub use inode::{DirEntry, Inode, InodeId, InodeKind, InodeState, InodeTree};
