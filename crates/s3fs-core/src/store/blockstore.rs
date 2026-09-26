//! `BlockStore` — the verified read path and the slab-writing commit path.
//!
//! Everything above this module deals in `BlkPtr`s and plaintext blocks and
//! never touches the backend directly. Everything below is ranged GETs and
//! PUTs against immutable objects.
//!
//! The read path is fail-closed by construction: there is no way to obtain a
//! block's bytes except through [`BlockStore::read_block`], which verifies the
//! BLAKE3 checksum against the parent's pointer and then AEAD-opens with
//! position-binding AAD. A caller cannot opt out, and no partial result
//! escapes on failure.

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::backend::{Backend, ObjectLock, PutBlobInput};
use crate::crypto::KeyMaterial;
use crate::errors::{FsError, FsResult};

use super::blkptr::BlkPtr;
use super::cache::{BlockCache, BlockKey, CacheStats};
use super::config::StoreConfig;
use super::slab::{verify_and_open, FinishedSlab};

/// Reads and writes verified, encrypted blocks against a backend.
#[derive(Debug)]
pub struct BlockStore {
    data: Arc<dyn Backend>,
    keys: Arc<KeyMaterial>,
    config: Arc<StoreConfig>,
    cache: BlockCache,
}

impl BlockStore {
    pub fn new(data: Arc<dyn Backend>, keys: Arc<KeyMaterial>, config: Arc<StoreConfig>) -> Self {
        let cache = BlockCache::new(config.block_cache_bytes);
        Self {
            data,
            keys,
            config,
            cache,
        }
    }

    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    pub fn keys(&self) -> &KeyMaterial {
        &self.keys
    }

    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Read, verify, and decrypt the block a pointer addresses.
    ///
    /// A hole yields `logical_len` zero bytes without any I/O — that is what
    /// makes sparse files free.
    ///
    /// `objid` and `block_index` must be the position the caller *expects* the
    /// block to occupy, not a position read back from the store. They are fed
    /// into the AEAD's additional data, so passing what the store told us
    /// would defeat the check entirely.
    pub async fn read_block(&self, ptr: &BlkPtr, objid: u64, block_index: u64) -> FsResult<Bytes> {
        if ptr.is_hole() {
            return Ok(Bytes::from(vec![0u8; ptr.logical_len as usize]));
        }
        let cache_key = BlockKey::new(ptr.dva, objid, block_index);
        if let Some(hit) = self.cache.get(&cache_key) {
            return Ok(hit);
        }

        let key = self.config.slab_key(ptr.dva.txg, ptr.dva.slab);
        let got = self
            .data
            .get_blob(&key, Some(ptr.dva.range()))
            .await
            .map_err(|e| match e {
                // A missing slab under a root that references it means the
                // data was deleted out from under us. That is a denial of
                // service, not a forgery — but it is still fatal for this read
                // and must not be confused with "the file does not exist".
                FsError::NotFound => FsError::Integrity("slab referenced by root is missing"),
                other => other,
            })?;

        let plaintext = Bytes::from(verify_and_open(
            &self.keys,
            ptr,
            objid,
            block_index,
            &got.body,
        )?);
        self.cache.insert(cache_key, plaintext.clone());
        Ok(plaintext)
    }

    /// PUT every slab of a transaction group, in parallel.
    ///
    /// Returns only once all of them are durable. The commit protocol depends
    /// on this: the root record must not be published until every block it
    /// references is readable, or a crash between the two would leave a root
    /// pointing at blocks that do not exist.
    pub async fn write_slabs(&self, txg: u64, slabs: Vec<FinishedSlab>) -> FsResult<()> {
        if slabs.is_empty() {
            return Ok(());
        }
        let limit = self.config.max_parallel_slab_puts;
        let mut in_flight = FuturesUnordered::new();
        let mut queue = slabs.into_iter();

        loop {
            while in_flight.len() < limit {
                match queue.next() {
                    Some(slab) => in_flight.push(self.put_one_slab(txg, slab)),
                    None => break,
                }
            }
            match in_flight.next().await {
                Some(result) => result?,
                None => return Ok(()),
            }
        }
    }

    async fn put_one_slab(&self, txg: u64, slab: FinishedSlab) -> FsResult<()> {
        let key = self.config.slab_key(txg, slab.index);
        // Slabs carry no retention: they live in the unlocked data bucket, so
        // dead copy-on-write blocks stay reclaimable. Deleting one is a
        // detectable denial of service, never a rollback — the rollback
        // guarantee lives entirely in the locked root records.
        self.data
            .put_blob(PutBlobInput::new(key, slab.body))
            .await
            .map(|_| ())
    }

    /// Retention to stamp on a root record, resolved against wall-clock now.
    pub fn root_retention(&self) -> Option<ObjectLock> {
        self.config.root_retention.map(|d| ObjectLock {
            mode: crate::backend::ObjectLockMode::Compliance,
            retain_until: std::time::SystemTime::now() + d,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::crypto::MasterSecret;
    use crate::store::slab::SlabWriter;

    fn store(config: StoreConfig) -> (Arc<MemoryBackend>, BlockStore) {
        let backend = Arc::new(MemoryBackend::new());
        let keys =
            Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([4u8; 32]), [0u8; 16]).unwrap());
        let bs = BlockStore::new(backend.clone(), keys, Arc::new(config));
        (backend, bs)
    }

    /// Seal `blocks` into slabs, PUT them, and return their pointers.
    async fn commit_blocks(
        bs: &BlockStore,
        txg: u64,
        blocks: &[(u64, u64, Vec<u8>)],
    ) -> Vec<BlkPtr> {
        let mut w = SlabWriter::new(txg, bs.config());
        let ptrs: Vec<_> = blocks
            .iter()
            .map(|(objid, idx, data)| w.write_block(bs.keys(), *objid, 0, *idx, 1, data).unwrap())
            .collect();
        bs.write_slabs(txg, w.finish().unwrap()).await.unwrap();
        ptrs
    }

    #[tokio::test]
    async fn round_trip_through_the_backend() {
        let (_b, bs) = store(StoreConfig::default());
        let data = vec![0x5au8; 8192];
        let ptrs = commit_blocks(&bs, 1, &[(10, 0, data.clone())]).await;

        assert_eq!(bs.read_block(&ptrs[0], 10, 0).await.unwrap(), data);
    }

    #[tokio::test]
    async fn holes_read_as_zeros_without_io() {
        let (backend, bs) = store(StoreConfig::default());
        let mut hole = BlkPtr::HOLE;
        hole.logical_len = 4096;

        let got = bs.read_block(&hole, 1, 0).await.unwrap();
        assert_eq!(got.len(), 4096);
        assert!(got.iter().all(|&b| b == 0));
        assert_eq!(backend.object_count(), 0, "a hole must not touch storage");
    }

    #[tokio::test]
    async fn second_read_is_served_from_cache() {
        let (_b, bs) = store(StoreConfig::default());
        let ptrs = commit_blocks(&bs, 1, &[(10, 0, vec![1u8; 4096])]).await;

        bs.read_block(&ptrs[0], 10, 0).await.unwrap();
        bs.read_block(&ptrs[0], 10, 0).await.unwrap();
        let stats = bs.cache_stats();
        assert_eq!((stats.hits, stats.misses), (1, 1));
    }

    #[tokio::test]
    async fn many_blocks_pack_into_few_objects() {
        // The economic claim behind slab packing: a txg dirtying many blocks
        // costs a handful of PUTs, not one per block.
        let (backend, bs) = store(StoreConfig::default());
        let blocks: Vec<_> = (0..64u64).map(|i| (7, i, vec![i as u8; 4096])).collect();
        let ptrs = commit_blocks(&bs, 3, &blocks).await;

        assert_eq!(ptrs.len(), 64);
        assert_eq!(backend.object_count(), 1, "64 blocks should be one slab");

        for (i, p) in ptrs.iter().enumerate() {
            assert_eq!(
                bs.read_block(p, 7, i as u64).await.unwrap(),
                vec![i as u8; 4096]
            );
        }
    }

    #[tokio::test]
    async fn multiple_slabs_are_all_written() {
        let cfg = StoreConfig {
            record_size: 4096,
            slab_max_bytes: 8300,
            ..Default::default()
        };
        let (backend, bs) = store(cfg);
        let blocks: Vec<_> = (0..7u64).map(|i| (1, i, vec![i as u8; 4096])).collect();
        let ptrs = commit_blocks(&bs, 1, &blocks).await;

        assert_eq!(backend.object_count(), 4, "7 blocks, 2 per slab");
        for (i, p) in ptrs.iter().enumerate() {
            assert_eq!(
                bs.read_block(p, 1, i as u64).await.unwrap(),
                vec![i as u8; 4096]
            );
        }
    }

    #[tokio::test]
    async fn empty_commit_writes_nothing() {
        let (backend, bs) = store(StoreConfig::default());
        bs.write_slabs(1, vec![]).await.unwrap();
        assert_eq!(backend.object_count(), 0);
    }

    // ---- adversarial reads -------------------------------------------------

    #[tokio::test]
    async fn tampered_slab_bytes_are_rejected() {
        let (backend, bs) = store(StoreConfig::default());
        let ptrs = commit_blocks(&bs, 1, &[(10, 0, vec![0xaau8; 4096])]).await;

        // Rewrite the slab with corrupted contents, as a bucket operator could.
        let key = bs.config().slab_key(1, 0);
        let mut body = backend.get_blob(&key, None).await.unwrap().body.to_vec();
        body[0] ^= 0xff;
        backend
            .put_blob(PutBlobInput::new(key, Bytes::from(body)))
            .await
            .unwrap();

        assert!(matches!(
            bs.read_block(&ptrs[0], 10, 0).await,
            Err(FsError::Integrity(_))
        ));
    }

    #[tokio::test]
    async fn deleted_slab_reports_integrity_not_missing_file() {
        let (backend, bs) = store(StoreConfig::default());
        let ptrs = commit_blocks(&bs, 1, &[(10, 0, vec![1u8; 4096])]).await;
        backend
            .delete_blob(&bs.config().slab_key(1, 0))
            .await
            .unwrap();

        // Must not look like "no such file" — the root says this block exists,
        // so its absence is the store failing us, not the guest asking for
        // something that was never there.
        assert!(matches!(
            bs.read_block(&ptrs[0], 10, 0).await,
            Err(FsError::Integrity("slab referenced by root is missing"))
        ));
    }

    #[tokio::test]
    async fn a_block_cannot_be_read_at_the_wrong_position() {
        let (_b, bs) = store(StoreConfig::default());
        let ptrs = commit_blocks(&bs, 1, &[(10, 5, vec![9u8; 1024])]).await;

        assert!(bs.read_block(&ptrs[0], 10, 5).await.is_ok());
        assert!(bs.read_block(&ptrs[0], 11, 5).await.is_err(), "wrong objid");
        assert!(bs.read_block(&ptrs[0], 10, 6).await.is_err(), "wrong index");
    }

    /// Point a pointer at a neighbouring block's bytes. Both blocks are
    /// genuine; only the checksum in the pointer disagrees.
    #[tokio::test]
    async fn a_pointer_cannot_be_aimed_at_another_block() {
        let (_b, bs) = store(StoreConfig::default());
        let ptrs = commit_blocks(
            &bs,
            1,
            &[(10, 0, vec![1u8; 1024]), (10, 1, vec![2u8; 1024])],
        )
        .await;

        let mut forged = ptrs[0];
        forged.dva.offset = ptrs[1].dva.offset;
        assert!(matches!(
            bs.read_block(&forged, 10, 0).await,
            Err(FsError::Integrity("block: checksum mismatch"))
        ));
    }

    #[tokio::test]
    async fn a_block_from_another_filesystem_is_rejected() {
        let (backend, bs) = store(StoreConfig::default());
        let ptrs = commit_blocks(&bs, 1, &[(10, 0, vec![1u8; 1024])]).await;

        // Same bucket, same pointers, different key material.
        let other_keys = Arc::new(
            KeyMaterial::derive(&MasterSecret::from_bytes([99u8; 32]), [0u8; 16]).unwrap(),
        );
        let other = BlockStore::new(backend, other_keys, Arc::new(StoreConfig::default()));
        assert!(matches!(
            other.read_block(&ptrs[0], 10, 0).await,
            Err(FsError::Integrity(_))
        ));
    }

    #[tokio::test]
    async fn root_retention_is_compliance_mode_and_in_the_future() {
        let (_b, bs) = store(StoreConfig::default());
        let lock = bs.root_retention().expect("default config locks roots");
        assert_eq!(lock.mode, crate::backend::ObjectLockMode::Compliance);
        assert!(lock.retain_until > std::time::SystemTime::now());

        let (_b, unlocked) = store(StoreConfig {
            root_retention: None,
            ..Default::default()
        });
        assert!(unlocked.root_retention().is_none());
    }
}
