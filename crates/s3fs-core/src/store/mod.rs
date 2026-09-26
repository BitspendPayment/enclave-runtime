//! The block store: a ZFS-style copy-on-write object tree over S3.
//!
//! A write allocates new blocks, rebuilds the indirect blocks above them, and
//! ends by publishing a new *root record* whose Merkle root covers the entire
//! filesystem. Old blocks stay exactly where they were, which is what makes
//! every historical root a usable snapshot.
//!
//! ```text
//!   roots/<seq>              ← signed, hash-chained, Object Lock COMPLIANCE
//!        │ meta_dnode BlkPtr ← the Merkle root
//!        ▼
//!   meta-dnode ──▶ indirect blocks ──▶ dnodes (one per file/dir/symlink)
//!                                          │ blkptrs
//!                                          ▼
//!                                     indirect blocks ──▶ data blocks
//!                                          │
//!                                          ▼
//!                              slabs/<txg>/<i>  (packed per txg, unlocked)
//! ```
//!
//! Each arrow is a [`BlkPtr`] carrying the BLAKE3 checksum of the block it
//! points at, so verifying the root's signature transitively verifies every
//! byte below it.
//!
//! ## Two different senses of "immutable"
//!
//! These are easy to conflate and mean very different things:
//!
//! **The writer never overwrites.** Copy-on-write plus a txg number that is
//! consumed once and never reused means every block lands at an address
//! nothing has occupied before. This is a property of our code, and it holds
//! for slabs and roots alike. It is also what makes Object Lock usable at all:
//! a mutable object could not live in a COMPLIANCE bucket and keep being
//! updated.
//!
//! **S3 prevents *others* from overwriting — only the roots.** Retention is
//! applied to `roots/<seq>` and nothing else. That is the anchor, and it is
//! the whole of the rollback guarantee. Slabs deliberately live in an unlocked
//! bucket so that dead copy-on-write blocks stay reclaimable, which means
//! anyone with write access to the data bucket can delete one. Doing so is a
//! *detectable denial of service* — the read fails with
//! [`crate::errors::FsError::Integrity`] and the root chain still verifies —
//! never a rollback and never a forgery.
//!
//! One object is genuinely mutable by design: `roots/latest`, the tip hint. It
//! is rewritten on every commit, is never trusted, and exists only to turn tip
//! discovery into one HEAD instead of a search. The mount protocol verifies it
//! by probing for `seq + 1`, so a stale or hostile hint costs a round trip and
//! changes nothing else.

pub mod blkptr;
pub mod blockstore;
pub mod cache;
pub mod config;
pub mod dir;
pub mod dnode;
pub mod indirect;
pub mod objset;
pub mod root;
pub mod slab;
pub mod txg;

pub use blkptr::{blkptrs_per_block, BlkPtr, Compression, Dva, BLKPTR_LEN, MAX_LEVEL};
pub use blockstore::BlockStore;
pub use cache::{BlockCache, BlockKey, CacheStats};
pub use config::StoreConfig;
pub use dir::{DirTxn, Dirent};
pub use dnode::{Dnode, DnodeKind, DNODE_LEN, META_OBJID, ROOT_OBJID};
pub use indirect::{commit_object, read_data_block, read_raw_block, resolve_ptr};
pub use objset::ObjectSet;
pub use root::{RootRecord, RootStore, FORMAT_VERSION};
pub use slab::{verify_and_open, FinishedSlab, SlabWriter};
pub use txg::{Snapshot, Store, Transaction};
