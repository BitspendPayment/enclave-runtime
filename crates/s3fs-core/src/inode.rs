//! `Inode` — a handle on one object, and the attributes callers see.
//!
//! An inode is just an object id. There is no cached metadata and no parent
//! pointer: the dnode in the object set is the only source of truth, and it is
//! cheap to read because its block sits in the decrypted-block cache. That is
//! a deliberate change from the previous engine, whose inode tree cached
//! attributes with a TTL that was never actually checked — so a cache could
//! disagree with the store indefinitely and nothing would notice.
//!
//! Identity is `(objid, gen)`. Object ids are never reused, so this is stable
//! across mounts, which is what makes `is-same-object` and `metadata-hash`
//! exact rather than a hash of an ETag.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::{FsError, FsResult};
use crate::store::dnode::{Dnode, DnodeKind};

/// Stable identifier for an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InodeId(pub u64);

impl InodeId {
    pub fn get(self) -> u64 {
        self.0
    }
}

/// What an object is, as the WASI layer sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    RegularFile,
    Directory,
    Symlink,
}

impl InodeKind {
    pub(crate) fn from_dnode(kind: DnodeKind) -> FsResult<Self> {
        Ok(match kind {
            DnodeKind::File => InodeKind::RegularFile,
            DnodeKind::Dir => InodeKind::Directory,
            DnodeKind::Symlink => InodeKind::Symlink,
            DnodeKind::Free => return Err(FsError::NotFound),
            DnodeKind::DnodeArray => return Err(FsError::NotSupported),
        })
    }

    /// Used by callers that create objects of a chosen kind.
    pub fn to_dnode(self) -> DnodeKind {
        match self {
            InodeKind::RegularFile => DnodeKind::File,
            InodeKind::Directory => DnodeKind::Dir,
            InodeKind::Symlink => DnodeKind::Symlink,
        }
    }

    pub fn is_dir(self) -> bool {
        matches!(self, InodeKind::Directory)
    }
}

/// A reference to one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Inode {
    pub id: InodeId,
    /// Generation, paired with the id to form an identity that survives a
    /// remount.
    pub gen: u64,
}

impl Inode {
    pub fn new(objid: u64, gen: u64) -> Arc<Inode> {
        Arc::new(Inode {
            id: InodeId(objid),
            gen,
        })
    }

    pub fn objid(&self) -> u64 {
        self.id.0
    }
}

/// Everything `stat` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attrs {
    pub kind: InodeKind,
    /// Logical size in bytes. For a directory this is the size of its block
    /// structure, not an entry count.
    pub size: u64,
    /// Number of directory entries pointing at this object.
    pub nlink: u32,
    pub mode: u32,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub btime: SystemTime,
}

impl Attrs {
    pub(crate) fn from_dnode(d: &Dnode) -> FsResult<Attrs> {
        Ok(Attrs {
            kind: InodeKind::from_dnode(d.kind)?,
            size: d.size,
            nlink: d.nlink,
            mode: d.mode,
            atime: from_nanos(d.atime_nanos),
            mtime: from_nanos(d.mtime_nanos),
            ctime: from_nanos(d.ctime_nanos),
            btime: from_nanos(d.btime_nanos),
        })
    }
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: InodeKind,
    /// Object id, so a caller can compare identity without a second lookup.
    pub objid: u64,
}

pub(crate) fn from_nanos(nanos: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(nanos)
}

pub(crate) fn to_nanos(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

pub(crate) fn now_nanos() -> u64 {
    to_nanos(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_maps_both_ways() {
        for k in [
            InodeKind::RegularFile,
            InodeKind::Directory,
            InodeKind::Symlink,
        ] {
            assert_eq!(InodeKind::from_dnode(k.to_dnode()).unwrap(), k);
        }
    }

    /// A free slot is "no such file", not a kind of file. Mapping it to
    /// anything else would let a deleted object be stat'd.
    #[test]
    fn a_free_slot_is_not_a_file() {
        assert!(matches!(
            InodeKind::from_dnode(DnodeKind::Free),
            Err(FsError::NotFound)
        ));
        assert!(InodeKind::from_dnode(DnodeKind::DnodeArray).is_err());
    }

    #[test]
    fn timestamps_round_trip() {
        for nanos in [0u64, 1, 1_000_000_000, 1_700_000_000_123_456_789] {
            assert_eq!(to_nanos(from_nanos(nanos)), nanos);
        }
    }

    #[test]
    fn pre_epoch_times_clamp_rather_than_panic() {
        assert_eq!(to_nanos(UNIX_EPOCH - Duration::from_secs(1)), 0);
    }

    #[test]
    fn attrs_come_from_the_dnode() {
        let mut d = Dnode::new(5, DnodeKind::File, 12, 42);
        d.size = 1234;
        d.mode = 0o100644;
        d.nlink = 2;
        let a = Attrs::from_dnode(&d).unwrap();

        assert_eq!(a.kind, InodeKind::RegularFile);
        assert_eq!(a.size, 1234);
        assert_eq!(a.nlink, 2, "link count is real, not hardcoded to 1");
        assert_eq!(a.mode, 0o100644);
        assert_eq!(to_nanos(a.mtime), 42);
    }

    #[test]
    fn identity_pairs_the_id_with_the_generation() {
        let a = Inode::new(7, 1);
        let b = Inode::new(7, 2);
        assert_eq!(a.objid(), b.objid());
        assert_ne!(*a, *b, "a reused id with a new generation is a new object");
    }
}
