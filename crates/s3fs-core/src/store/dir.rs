//! Directories — a two-level B+tree of name-ordered entries.
//!
//! A directory object's data blocks are:
//!
//! ```text
//!   block 0     index:  [(separator, leaf block), …]  sorted by separator
//!   block 1..N  leaves: sorted runs of (name, objid, kind)
//! ```
//!
//! Lookup binary-searches the index for the leaf whose separator range covers
//! the name, then binary-searches that leaf: two block reads, both of which
//! stay cached for a hot directory. Inserting dirties one leaf plus the index,
//! and a leaf that overflows splits in half — so an insert costs three blocks
//! and their indirect path, not a rewrite of the directory.
//!
//! Because leaves are name-ordered and the index is separator-ordered,
//! `read_dir` is a concatenation with no sort step.
//!
//! ## Why not extendible hashing
//!
//! The plan called for an extendible hash table, whose cheap-doubling property
//! depends on many slots pointing at one shared bucket block. That is
//! unavailable here: [`crate::crypto::BlockAad`] binds every block to its
//! block index, so one physical block genuinely cannot be read from two
//! positions — which is exactly the property that stops an attacker relocating
//! blocks, and not one worth weakening for a directory layout. Sharing would
//! have to be expressed indirectly anyway, through a level of mapping; a
//! separator index is that mapping, and it also yields sorted iteration for
//! free.

use std::collections::{BTreeMap, BTreeSet};

use crate::errors::{FsError, FsResult};

use super::blockstore::BlockStore;
use super::dnode::{Dnode, DnodeKind};
use super::indirect::{commit_object, read_raw_block};
use super::slab::SlabWriter;

const INDEX_MAGIC: u32 = 0x4449_5831; // "DIX1"
const LEAF_MAGIC: u32 = 0x444C_4631; // "DLF1"

/// The index always lives at data block 0; leaves start at 1.
const INDEX_BLOCK: u64 = 0;

/// Longest permitted entry name, matching the path validator.
pub const MAX_NAME_LEN: usize = 255;

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirent {
    pub name: String,
    pub objid: u64,
    pub kind: DnodeKind,
}

impl Dirent {
    fn encoded_len(&self) -> usize {
        12 + self.name.len()
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        out.push(self.kind as u8);
        out.push(0); // reserved
        out.extend_from_slice(&self.objid.to_be_bytes());
        out.extend_from_slice(self.name.as_bytes());
    }
}

/// Cursor over a byte slice that refuses to read past the end.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> FsResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(FsError::Integrity(what))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(FsError::Integrity(what))?;
        self.pos = end;
        Ok(slice)
    }

    fn u16(&mut self, what: &'static str) -> FsResult<u16> {
        Ok(u16::from_be_bytes(
            self.take(2, what)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self, what: &'static str) -> FsResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4, what)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self, what: &'static str) -> FsResult<u64> {
        Ok(u64::from_be_bytes(
            self.take(8, what)?.try_into().expect("8 bytes"),
        ))
    }
}

fn encode_leaf(entries: &[Dirent]) -> Vec<u8> {
    let cap = 8 + entries.iter().map(Dirent::encoded_len).sum::<usize>();
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&LEAF_MAGIC.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        e.encode(&mut out);
    }
    out
}

fn leaf_encoded_len(entries: &[Dirent]) -> usize {
    8 + entries.iter().map(Dirent::encoded_len).sum::<usize>()
}

fn decode_leaf(buf: &[u8]) -> FsResult<Vec<Dirent>> {
    const BAD: &str = "dir: malformed leaf block";
    let mut r = Reader::new(buf);
    if r.u32(BAD)? != LEAF_MAGIC {
        return Err(FsError::Integrity("dir: bad leaf magic"));
    }
    let count = r.u32(BAD)? as usize;
    let mut out: Vec<Dirent> = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let name_len = r.u16(BAD)? as usize;
        let kind = r.take(1, BAD)?[0];
        if r.take(1, BAD)?[0] != 0 {
            return Err(FsError::Integrity("dir: entry reserved byte not zero"));
        }
        let objid = r.u64(BAD)?;
        let name = std::str::from_utf8(r.take(name_len, BAD)?)
            .map_err(|_| FsError::Integrity("dir: entry name is not valid UTF-8"))?
            .to_string();
        out.push(Dirent {
            name,
            objid,
            kind: decode_kind(kind)?,
        });
    }
    if r.pos != buf.len() {
        return Err(FsError::Integrity("dir: trailing bytes in leaf block"));
    }
    // Strictly increasing order is what makes binary search sound, and it also
    // rules out duplicate names — which a forged block could otherwise use to
    // make one name resolve to two different objects.
    if out.windows(2).any(|w| w[0].name >= w[1].name) {
        return Err(FsError::Integrity("dir: leaf entries are not sorted"));
    }
    Ok(out)
}

fn decode_kind(v: u8) -> FsResult<DnodeKind> {
    Ok(match v {
        1 => DnodeKind::File,
        2 => DnodeKind::Dir,
        3 => DnodeKind::Symlink,
        _ => return Err(FsError::Integrity("dir: entry has a non-linkable kind")),
    })
}

/// A leaf and the smallest name that may live in it.
///
/// The separator is a boundary, not necessarily a name that exists: entries
/// are deleted without disturbing it, so an empty leaf keeps its place in the
/// ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafRef {
    sep: String,
    block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirIndex {
    entry_count: u64,
    leaves: Vec<LeafRef>,
}

impl DirIndex {
    /// A directory with one empty leaf whose separator matches everything.
    fn empty() -> Self {
        DirIndex {
            entry_count: 0,
            leaves: vec![LeafRef {
                sep: String::new(),
                block: 1,
            }],
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.leaves.len() * 24);
        out.extend_from_slice(&INDEX_MAGIC.to_be_bytes());
        out.extend_from_slice(&(self.leaves.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.entry_count.to_be_bytes());
        for l in &self.leaves {
            out.extend_from_slice(&l.block.to_be_bytes());
            out.extend_from_slice(&(l.sep.len() as u16).to_be_bytes());
            out.extend_from_slice(l.sep.as_bytes());
        }
        out
    }

    fn decode(buf: &[u8]) -> FsResult<Self> {
        const BAD: &str = "dir: malformed index block";
        let mut r = Reader::new(buf);
        if r.u32(BAD)? != INDEX_MAGIC {
            return Err(FsError::Integrity("dir: bad index magic"));
        }
        let leaf_count = r.u32(BAD)? as usize;
        let entry_count = r.u64(BAD)?;
        let mut leaves = Vec::with_capacity(leaf_count.min(4096));
        for _ in 0..leaf_count {
            let block = r.u64(BAD)?;
            let sep_len = r.u16(BAD)? as usize;
            let sep = std::str::from_utf8(r.take(sep_len, BAD)?)
                .map_err(|_| FsError::Integrity("dir: separator is not valid UTF-8"))?
                .to_string();
            leaves.push(LeafRef { sep, block });
        }
        if r.pos != buf.len() {
            return Err(FsError::Integrity("dir: trailing bytes in index block"));
        }
        if leaves.is_empty() {
            return Err(FsError::Integrity("dir: index has no leaves"));
        }
        if !leaves[0].sep.is_empty() {
            return Err(FsError::Integrity("dir: first separator is not empty"));
        }
        if leaves.windows(2).any(|w| w[0].sep >= w[1].sep) {
            return Err(FsError::Integrity("dir: separators are not sorted"));
        }
        if leaves.iter().any(|l| l.block == INDEX_BLOCK) {
            return Err(FsError::Integrity(
                "dir: leaf collides with the index block",
            ));
        }
        let mut seen = BTreeSet::new();
        if !leaves.iter().all(|l| seen.insert(l.block)) {
            return Err(FsError::Integrity("dir: duplicate leaf block"));
        }
        Ok(DirIndex {
            entry_count,
            leaves,
        })
    }

    /// Position of the leaf that owns `name`: the last one whose separator
    /// does not exceed it.
    fn position_of(&self, name: &str) -> usize {
        match self.leaves.binary_search_by(|l| l.sep.as_str().cmp(name)) {
            Ok(i) => i,
            // `partition_point`-style: the insertion point is one past the
            // owning leaf. Index 0 has an empty separator, so this never
            // underflows.
            Err(i) => i - 1,
        }
    }

    fn next_block(&self) -> u64 {
        self.leaves.iter().map(|l| l.block).max().unwrap_or(0) + 1
    }
}

/// A staged set of changes to one directory.
///
/// Leaves are loaded on demand, so a lookup or a single insert touches one
/// leaf regardless of how large the directory is. Call [`DirTxn::finish`] to
/// stage the modified blocks into a transaction group.
#[derive(Debug)]
pub struct DirTxn<'a> {
    bs: &'a BlockStore,
    dnode: Dnode,
    index: DirIndex,
    loaded: BTreeMap<u64, Vec<Dirent>>,
    dirty: BTreeSet<u64>,
}

impl<'a> DirTxn<'a> {
    /// Open a directory for reading and modification.
    pub async fn load(bs: &'a BlockStore, dnode: &Dnode) -> FsResult<DirTxn<'a>> {
        if dnode.kind != DnodeKind::Dir {
            return Err(FsError::NotDirectory);
        }
        let (index, dirty) = match read_raw_block(bs, dnode, INDEX_BLOCK).await? {
            Some(raw) => (DirIndex::decode(&raw)?, BTreeSet::new()),
            // A directory that has never been written has no blocks at all.
            // Synthesise the empty shape and mark it dirty so the first commit
            // materialises it.
            None => (DirIndex::empty(), BTreeSet::from([INDEX_BLOCK, 1])),
        };
        let mut txn = DirTxn {
            bs,
            dnode: dnode.clone(),
            index,
            loaded: BTreeMap::new(),
            dirty,
        };
        if txn.dirty.contains(&1) {
            txn.loaded.insert(1, Vec::new());
        }
        Ok(txn)
    }

    pub fn entry_count(&self) -> u64 {
        self.index.entry_count
    }

    async fn leaf(&mut self, block: u64) -> FsResult<&mut Vec<Dirent>> {
        if !self.loaded.contains_key(&block) {
            let entries = match read_raw_block(self.bs, &self.dnode, block).await? {
                Some(raw) => decode_leaf(&raw)?,
                None => Vec::new(),
            };
            self.loaded.insert(block, entries);
        }
        Ok(self.loaded.get_mut(&block).expect("just inserted"))
    }

    /// Find one entry by name.
    pub async fn lookup(&mut self, name: &str) -> FsResult<Option<Dirent>> {
        let block = self.index.leaves[self.index.position_of(name)].block;
        let entries = self.leaf(block).await?;
        Ok(entries
            .binary_search_by(|e| e.name.as_str().cmp(name))
            .ok()
            .map(|i| entries[i].clone()))
    }

    /// Add an entry. Fails with [`FsError::AlreadyExists`] if the name is taken.
    pub async fn insert(&mut self, entry: Dirent) -> FsResult<()> {
        if entry.name.is_empty() || entry.name.len() > MAX_NAME_LEN {
            return Err(FsError::NameTooLong);
        }
        if entry.kind == DnodeKind::Free || entry.kind == DnodeKind::DnodeArray {
            return Err(FsError::Invalid("directory entry has a non-linkable kind"));
        }

        let record_size = self.dnode.record_size();
        let pos = self.index.position_of(&entry.name);
        let block = self.index.leaves[pos].block;
        let entries = self.leaf(block).await?;

        let at = match entries.binary_search_by(|e| e.name.cmp(&entry.name)) {
            Ok(_) => return Err(FsError::AlreadyExists),
            Err(at) => at,
        };
        entries.insert(at, entry);
        let overflowed = leaf_encoded_len(entries) > record_size;

        self.dirty.insert(block);
        self.index.entry_count += 1;
        if overflowed {
            self.split_leaf(pos, record_size)?;
        }
        Ok(())
    }

    /// Split the leaf at index `pos` in half.
    ///
    /// The new leaf takes the upper half and its separator is that half's first
    /// name, so every existing name still resolves to the leaf that holds it.
    fn split_leaf(&mut self, pos: usize, record_size: usize) -> FsResult<()> {
        let block = self.index.leaves[pos].block;
        let entries = self.loaded.get_mut(&block).expect("leaf is loaded");
        if entries.len() < 2 {
            // A single entry that does not fit cannot be split apart. With
            // names capped at 255 bytes and records at 4 KiB or more, this is
            // unreachable; refusing beats looping.
            return Err(FsError::FileTooLarge);
        }
        let mid = entries.len() / 2;
        let upper: Vec<Dirent> = entries.split_off(mid);
        let sep = upper[0].name.clone();
        let new_block = self.index.next_block();

        self.loaded.insert(new_block, upper);
        self.dirty.insert(new_block);
        self.index.leaves.insert(
            pos + 1,
            LeafRef {
                sep,
                block: new_block,
            },
        );

        if self.index.encode().len() > record_size {
            return Err(FsError::FileTooLarge);
        }
        Ok(())
    }

    /// Remove an entry by name, returning it.
    ///
    /// An emptied leaf keeps its slot rather than being merged away. Its
    /// separator still partitions the name space correctly, it costs eight
    /// stored bytes, and a later insert in that range refills it.
    pub async fn remove(&mut self, name: &str) -> FsResult<Dirent> {
        let block = self.index.leaves[self.index.position_of(name)].block;
        let entries = self.leaf(block).await?;
        let at = entries
            .binary_search_by(|e| e.name.as_str().cmp(name))
            .map_err(|_| FsError::NotFound)?;
        let removed = entries.remove(at);
        self.dirty.insert(block);
        self.index.entry_count -= 1;
        Ok(removed)
    }

    /// Every entry, in name order.
    pub async fn list(&mut self) -> FsResult<Vec<Dirent>> {
        let blocks: Vec<u64> = self.index.leaves.iter().map(|l| l.block).collect();
        let mut out = Vec::with_capacity(self.index.entry_count as usize);
        for block in blocks {
            out.extend_from_slice(self.leaf(block).await?);
        }
        Ok(out)
    }

    /// `true` if the directory holds no entries. Used by `rmdir`.
    pub fn is_empty(&self) -> bool {
        self.index.entry_count == 0
    }

    /// Stage every modified block into `writer` and return the updated dnode.
    pub async fn finish(mut self, writer: &mut SlabWriter) -> FsResult<Dnode> {
        if self.dirty.is_empty() {
            return Ok(self.dnode);
        }
        self.dirty.insert(INDEX_BLOCK);

        let mut blocks: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for block in &self.dirty {
            let bytes = if *block == INDEX_BLOCK {
                self.index.encode()
            } else {
                encode_leaf(self.loaded.get(block).map(Vec::as_slice).unwrap_or(&[]))
            };
            blocks.insert(*block, bytes);
        }

        // Blocks 0..=highest leaf; the geometry only needs to cover them.
        let nblocks = self.index.next_block();
        let new_size = nblocks * self.dnode.record_size() as u64;
        commit_object(self.bs, writer, &self.dnode, blocks, new_size).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::crypto::{KeyMaterial, MasterSecret};
    use crate::store::config::StoreConfig;
    use std::sync::Arc;

    fn store(record_size: usize) -> BlockStore {
        let backend = Arc::new(MemoryBackend::new());
        let keys =
            Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([8u8; 32]), [0u8; 16]).unwrap());
        BlockStore::new(
            backend,
            keys,
            Arc::new(StoreConfig {
                record_size,
                ..Default::default()
            }),
        )
    }

    fn new_dir(record_shift: u8) -> Dnode {
        Dnode::new(7, DnodeKind::Dir, record_shift, 0)
    }

    fn entry(name: &str, objid: u64) -> Dirent {
        Dirent {
            name: name.to_string(),
            objid,
            kind: DnodeKind::File,
        }
    }

    /// Apply a closure to the directory and commit it as one transaction group.
    async fn apply<F>(bs: &BlockStore, txg: u64, dnode: &Dnode, f: F) -> Dnode
    where
        F: for<'x> FnOnce(
            &'x mut DirTxn<'_>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = FsResult<()>> + 'x>,
        >,
    {
        let mut txn = DirTxn::load(bs, dnode).await.unwrap();
        f(&mut txn).await.unwrap();
        let mut w = SlabWriter::new(txg, bs.config());
        let out = txn.finish(&mut w).await.unwrap();
        bs.write_slabs(txg, w.finish().unwrap()).await.unwrap();
        out
    }

    async fn insert_all(bs: &BlockStore, txg: u64, dnode: &Dnode, names: &[&str]) -> Dnode {
        let mut txn = DirTxn::load(bs, dnode).await.unwrap();
        for (i, n) in names.iter().enumerate() {
            txn.insert(entry(n, 100 + i as u64)).await.unwrap();
        }
        let mut w = SlabWriter::new(txg, bs.config());
        let out = txn.finish(&mut w).await.unwrap();
        bs.write_slabs(txg, w.finish().unwrap()).await.unwrap();
        out
    }

    async fn names_of(bs: &BlockStore, dnode: &Dnode) -> Vec<String> {
        let mut txn = DirTxn::load(bs, dnode).await.unwrap();
        txn.list()
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    #[tokio::test]
    async fn a_fresh_directory_is_empty() {
        let bs = store(4096);
        let d = new_dir(12);
        let mut txn = DirTxn::load(&bs, &d).await.unwrap();
        assert!(txn.is_empty());
        assert_eq!(txn.list().await.unwrap(), vec![]);
        assert_eq!(txn.lookup("anything").await.unwrap(), None);
    }

    #[tokio::test]
    async fn insert_then_look_up() {
        let bs = store(4096);
        let d = insert_all(&bs, 1, &new_dir(12), &["hello.txt"]).await;

        let mut txn = DirTxn::load(&bs, &d).await.unwrap();
        assert_eq!(
            txn.lookup("hello.txt").await.unwrap(),
            Some(entry("hello.txt", 100))
        );
        assert_eq!(txn.lookup("missing").await.unwrap(), None);
        assert_eq!(txn.entry_count(), 1);
    }

    #[tokio::test]
    async fn entries_come_back_in_name_order() {
        let bs = store(4096);
        let d = insert_all(&bs, 1, &new_dir(12), &["zebra", "apple", "Mango", "banana"]).await;
        assert_eq!(
            names_of(&bs, &d).await,
            vec!["Mango", "apple", "banana", "zebra"],
            "byte order, so uppercase sorts first"
        );
    }

    #[tokio::test]
    async fn duplicate_names_are_rejected() {
        let bs = store(4096);
        let d = insert_all(&bs, 1, &new_dir(12), &["dup"]).await;

        let mut txn = DirTxn::load(&bs, &d).await.unwrap();
        assert!(matches!(
            txn.insert(entry("dup", 999)).await,
            Err(FsError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn remove_takes_the_entry_out() {
        let bs = store(4096);
        let d = insert_all(&bs, 1, &new_dir(12), &["a", "b", "c"]).await;
        let d = apply(&bs, 2, &d, |t| {
            Box::pin(async move {
                t.remove("b").await?;
                Ok(())
            })
        })
        .await;

        assert_eq!(names_of(&bs, &d).await, vec!["a", "c"]);
        let mut txn = DirTxn::load(&bs, &d).await.unwrap();
        assert_eq!(txn.lookup("b").await.unwrap(), None);
        assert_eq!(txn.entry_count(), 2);
        assert!(matches!(txn.remove("b").await, Err(FsError::NotFound)));
    }

    #[tokio::test]
    async fn removing_everything_leaves_an_empty_directory() {
        let bs = store(4096);
        let d = insert_all(&bs, 1, &new_dir(12), &["only"]).await;
        let d = apply(&bs, 2, &d, |t| {
            Box::pin(async move {
                t.remove("only").await?;
                Ok(())
            })
        })
        .await;

        let txn = DirTxn::load(&bs, &d).await.unwrap();
        assert!(txn.is_empty(), "rmdir depends on this");
        assert_eq!(names_of(&bs, &d).await, Vec::<String>::new());
    }

    #[tokio::test]
    async fn names_are_validated() {
        let bs = store(4096);
        let d = new_dir(12);
        let mut txn = DirTxn::load(&bs, &d).await.unwrap();

        assert!(matches!(
            txn.insert(entry("", 1)).await,
            Err(FsError::NameTooLong)
        ));
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert!(matches!(
            txn.insert(entry(&long, 1)).await,
            Err(FsError::NameTooLong)
        ));
        assert!(txn
            .insert(entry(&"x".repeat(MAX_NAME_LEN), 1))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_directory_entry_cannot_point_at_a_free_slot() {
        let bs = store(4096);
        let d = new_dir(12);
        let mut txn = DirTxn::load(&bs, &d).await.unwrap();
        for kind in [DnodeKind::Free, DnodeKind::DnodeArray] {
            assert!(txn
                .insert(Dirent {
                    name: "x".into(),
                    objid: 5,
                    kind
                })
                .await
                .is_err());
        }
    }

    // ---- splitting ---------------------------------------------------------

    #[tokio::test]
    async fn a_leaf_that_overflows_splits() {
        let bs = store(4096);
        // ~40 bytes per entry, so a 4 KiB leaf holds roughly 100.
        let names: Vec<String> = (0..300).map(|i| format!("file-{i:04}-padding")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let d = insert_all(&bs, 1, &new_dir(12), &refs).await;

        let mut expected = names.clone();
        expected.sort();
        assert_eq!(names_of(&bs, &d).await, expected);

        // Every name must still be individually reachable through the index.
        let mut txn = DirTxn::load(&bs, &d).await.unwrap();
        assert!(txn.index.leaves.len() > 1, "the leaf should have split");
        for n in &names {
            assert!(txn.lookup(n).await.unwrap().is_some(), "lost {n}");
        }
        assert_eq!(txn.entry_count(), 300);
    }

    #[tokio::test]
    async fn splits_survive_across_transaction_groups() {
        let bs = store(4096);
        let mut d = new_dir(12);
        let mut all = Vec::new();
        for txg in 1..=6u64 {
            let names: Vec<String> = (0..50)
                .map(|i| format!("g{txg}-entry-{i:03}-padding"))
                .collect();
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            d = insert_all(&bs, txg, &d, &refs).await;
            all.extend(names);
        }

        all.sort();
        assert_eq!(names_of(&bs, &d).await, all);

        let mut txn = DirTxn::load(&bs, &d).await.unwrap();
        assert_eq!(txn.entry_count(), 300);
        for n in &all {
            assert!(txn.lookup(n).await.unwrap().is_some(), "lost {n}");
        }
    }

    #[tokio::test]
    async fn an_emptied_leaf_still_accepts_inserts() {
        let bs = store(4096);
        let names: Vec<String> = (0..300).map(|i| format!("file-{i:04}-padding")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let d = insert_all(&bs, 1, &new_dir(12), &refs).await;

        // Empty one leaf's worth of the name space, then refill part of it.
        let d = apply(&bs, 2, &d, |t| {
            Box::pin(async move {
                for i in 0..300 {
                    t.remove(&format!("file-{i:04}-padding")).await?;
                }
                Ok(())
            })
        })
        .await;
        assert!(DirTxn::load(&bs, &d).await.unwrap().is_empty());

        let d = insert_all(&bs, 3, &d, &["file-0100-padding", "file-0200-padding"]).await;
        assert_eq!(
            names_of(&bs, &d).await,
            vec!["file-0100-padding", "file-0200-padding"]
        );
    }

    // ---- copy-on-write -----------------------------------------------------

    #[tokio::test]
    async fn a_superseded_directory_still_reads() {
        let bs = store(4096);
        let old = insert_all(&bs, 1, &new_dir(12), &["a", "b"]).await;
        let new = insert_all(&bs, 2, &old, &["c"]).await;

        assert_eq!(names_of(&bs, &new).await, vec!["a", "b", "c"]);
        assert_eq!(
            names_of(&bs, &old).await,
            vec!["a", "b"],
            "the previous version of the directory must be unchanged"
        );
    }

    #[tokio::test]
    async fn a_no_op_transaction_does_not_rewrite_the_directory() {
        let bs = store(4096);
        let d = insert_all(&bs, 1, &new_dir(12), &["a"]).await;

        let txn = DirTxn::load(&bs, &d).await.unwrap();
        let mut w = SlabWriter::new(2, bs.config());
        let same = txn.finish(&mut w).await.unwrap();
        assert_eq!(same.blkptr, d.blkptr);
        assert_eq!(w.block_count(), 0);
    }

    #[tokio::test]
    async fn loading_a_non_directory_is_refused() {
        let bs = store(4096);
        let f = Dnode::new(3, DnodeKind::File, 12, 0);
        assert!(matches!(
            DirTxn::load(&bs, &f).await,
            Err(FsError::NotDirectory)
        ));
    }

    // ---- encoding and tamper resistance ------------------------------------

    #[test]
    fn leaf_round_trips() {
        let entries = vec![
            entry("alpha", 1),
            Dirent {
                name: "beta".into(),
                objid: 2,
                kind: DnodeKind::Dir,
            },
            Dirent {
                name: "gamma".into(),
                objid: 3,
                kind: DnodeKind::Symlink,
            },
        ];
        let encoded = encode_leaf(&entries);
        assert_eq!(encoded.len(), leaf_encoded_len(&entries));
        assert_eq!(decode_leaf(&encoded).unwrap(), entries);
    }

    #[test]
    fn empty_leaf_round_trips() {
        assert_eq!(decode_leaf(&encode_leaf(&[])).unwrap(), vec![]);
    }

    #[test]
    fn index_round_trips() {
        let idx = DirIndex {
            entry_count: 9,
            leaves: vec![
                LeafRef {
                    sep: String::new(),
                    block: 1,
                },
                LeafRef {
                    sep: "m".into(),
                    block: 2,
                },
            ],
        };
        assert_eq!(DirIndex::decode(&idx.encode()).unwrap(), idx);
    }

    /// Unsorted entries would break binary search, and duplicates would let one
    /// name resolve to two objects depending on which the search happened to
    /// land on.
    #[test]
    fn unsorted_or_duplicated_leaf_entries_are_rejected() {
        let unsorted = encode_leaf(&[entry("b", 1), entry("a", 2)]);
        assert!(matches!(
            decode_leaf(&unsorted),
            Err(FsError::Integrity("dir: leaf entries are not sorted"))
        ));

        let duplicated = encode_leaf(&[entry("a", 1), entry("a", 2)]);
        assert!(decode_leaf(&duplicated).is_err());
    }

    #[test]
    fn malformed_blocks_are_rejected() {
        assert!(decode_leaf(&[]).is_err());
        assert!(decode_leaf(&[0u8; 4]).is_err());
        assert!(DirIndex::decode(&[]).is_err());

        // Wrong magic.
        let mut leaf = encode_leaf(&[entry("a", 1)]);
        leaf[0] ^= 0xff;
        assert!(matches!(
            decode_leaf(&leaf),
            Err(FsError::Integrity("dir: bad leaf magic"))
        ));

        // A count that overruns the buffer.
        let mut leaf = encode_leaf(&[entry("a", 1)]);
        leaf[7] = 9;
        assert!(decode_leaf(&leaf).is_err());

        // Trailing bytes: everything in the block must be accounted for.
        let mut leaf = encode_leaf(&[entry("a", 1)]);
        leaf.push(0);
        assert!(matches!(
            decode_leaf(&leaf),
            Err(FsError::Integrity("dir: trailing bytes in leaf block"))
        ));
    }

    #[test]
    fn index_invariants_are_enforced() {
        let mk = |leaves: Vec<LeafRef>| DirIndex {
            entry_count: 0,
            leaves,
        };

        // No leaves at all.
        assert!(DirIndex::decode(&mk(vec![]).encode()).is_err());
        // First separator must be empty or some names resolve nowhere.
        assert!(DirIndex::decode(
            &mk(vec![LeafRef {
                sep: "m".into(),
                block: 1
            }])
            .encode()
        )
        .is_err());
        // Out-of-order separators break binary search.
        assert!(DirIndex::decode(
            &mk(vec![
                LeafRef {
                    sep: String::new(),
                    block: 1
                },
                LeafRef {
                    sep: "z".into(),
                    block: 2
                },
                LeafRef {
                    sep: "a".into(),
                    block: 3
                },
            ])
            .encode()
        )
        .is_err());
        // A leaf pointing at block 0 would alias the index itself.
        assert!(DirIndex::decode(
            &mk(vec![LeafRef {
                sep: String::new(),
                block: 0
            }])
            .encode()
        )
        .is_err());
        // Two separators pointing at one block.
        assert!(DirIndex::decode(
            &mk(vec![
                LeafRef {
                    sep: String::new(),
                    block: 1
                },
                LeafRef {
                    sep: "m".into(),
                    block: 1
                },
            ])
            .encode()
        )
        .is_err());
    }

    #[test]
    fn separator_search_finds_the_owning_leaf() {
        let idx = DirIndex {
            entry_count: 0,
            leaves: vec![
                LeafRef {
                    sep: String::new(),
                    block: 1,
                },
                LeafRef {
                    sep: "m".into(),
                    block: 2,
                },
                LeafRef {
                    sep: "t".into(),
                    block: 3,
                },
            ],
        };
        assert_eq!(idx.position_of(""), 0);
        assert_eq!(idx.position_of("a"), 0);
        assert_eq!(idx.position_of("lzzz"), 0);
        assert_eq!(idx.position_of("m"), 1, "exact separator match");
        assert_eq!(idx.position_of("s"), 1);
        assert_eq!(idx.position_of("t"), 2);
        assert_eq!(idx.position_of("zzz"), 2);
    }

    #[tokio::test]
    async fn a_tampered_directory_block_is_rejected() {
        use crate::backend::{Backend, PutBlobInput};
        let backend = Arc::new(MemoryBackend::new());
        let keys =
            Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([8u8; 32]), [0u8; 16]).unwrap());
        let bs = BlockStore::new(
            backend.clone(),
            keys,
            Arc::new(StoreConfig {
                record_size: 4096,
                ..Default::default()
            }),
        );

        let d = insert_all(&bs, 1, &new_dir(12), &["a", "b"]).await;

        let key = bs.config().slab_key(1, 0);
        let mut body = backend.get_blob(&key, None).await.unwrap().body.to_vec();
        body[0] ^= 0xff;
        backend
            .put_blob(PutBlobInput::new(key, bytes::Bytes::from(body)))
            .await
            .unwrap();

        // Whether the corruption is caught opening the index or reading a leaf
        // is an implementation detail; that no entries come back is not.
        let result = async {
            let mut txn = DirTxn::load(&bs, &d).await?;
            txn.list().await
        }
        .await;
        assert!(
            matches!(result, Err(FsError::Integrity(_))),
            "expected an integrity failure, got {result:?}"
        );
    }
}
