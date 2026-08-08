//! `s3fs-core` — a ZFS-style, Merkle-anchored filesystem over S3.
//!
//! Data lives in immutable, encrypted blocks packed into slab objects; the
//! whole filesystem hangs off a single signed, hash-chained root record written
//! with a conditional PUT under S3 Object Lock. Verifying that record
//! transitively verifies every byte beneath it, and the chain of records is
//! what makes a rollback detectable rather than merely unlikely.
//!
//! ```text
//!   Fs               POSIX semantics: paths, handles, directories
//!    │
//!   store::Store     transaction groups, the root chain, the object set
//!    │
//!   Backend          S3, S3-compatible, or an in-memory fake
//! ```
//!
//! See [`store`] for the on-disk format and [`crypto`] for the key hierarchy.

pub mod backend;
pub mod config;
pub mod crypto;
pub mod errors;
pub mod fs;
pub mod inode;
pub mod path;
pub mod store;

pub use config::Config;
pub use crypto::MasterSecret;
pub use errors::{FsError, FsResult};
pub use fs::{FileHandle, Fs, HandleId, OpenFlags, SnapshotFs, SnapshotInfo};
pub use inode::{Attrs, DirEntry, Inode, InodeId, InodeKind};
pub use store::{RootRecord, Store};
