//! Byte-accounted LRU cache of decrypted blocks.
//!
//! Entries never go stale and need no invalidation. Copy-on-write gives us
//! that for free: a modified block is written to a *new* address, so a cached
//! entry describes bytes that can never change, and the old entry simply ages
//! out.
//!
//! Entries are stored decrypted, so a hit skips the GET, the BLAKE3 pass, and
//! the AEAD open. That is safe because the cache lives in enclave memory,
//! which is the same trust boundary the plaintext already occupies.
//!
//! ## Why the key includes the position
//!
//! A hit bypasses verification, so the key must carry everything verification
//! would have checked. The address alone is not enough: keyed only by
//! [`Dva`], a block legitimately read at one position would then be served
//! from cache when a *forged* indirect block claimed it belonged at another —
//! exactly the relocation attack the AEAD's additional data exists to stop.
//! Including `(objid, block_index)` in the key turns that into a miss, and the
//! miss then fails the real check.
//!
//! No legitimate tree ever holds one address at two positions: a block sealed
//! for one position cannot be opened at another, so the duplicate keys this
//! permits in principle do not arise in practice.

use bytes::Bytes;
use hashlink::LinkedHashMap;
use parking_lot::Mutex;

use super::blkptr::Dva;

/// Cache key: an immutable address plus the tree position it was verified at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockKey {
    pub dva: Dva,
    pub objid: u64,
    pub block_index: u64,
}

impl BlockKey {
    pub fn new(dva: Dva, objid: u64, block_index: u64) -> Self {
        Self {
            dva,
            objid,
            block_index,
        }
    }
}

/// Cache statistics, for tests and metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Debug)]
struct Inner {
    used: u64,
    /// Insertion order is age; entries move to the back on access.
    lru: LinkedHashMap<BlockKey, Bytes>,
    stats: CacheStats,
}

/// In-memory cache of decrypted blocks.
#[derive(Debug)]
pub struct BlockCache {
    limit: u64,
    inner: Mutex<Inner>,
}

impl BlockCache {
    pub fn new(limit_bytes: u64) -> Self {
        Self {
            limit: limit_bytes,
            inner: Mutex::new(Inner {
                used: 0,
                lru: LinkedHashMap::new(),
                stats: CacheStats::default(),
            }),
        }
    }

    pub fn get(&self, key: &BlockKey) -> Option<Bytes> {
        let mut g = self.inner.lock();
        match g.lru.raw_entry_mut().from_key(key) {
            hashlink::linked_hash_map::RawEntryMut::Occupied(mut e) => {
                e.to_back();
                let v = e.get().clone();
                g.stats.hits += 1;
                Some(v)
            }
            hashlink::linked_hash_map::RawEntryMut::Vacant(_) => {
                g.stats.misses += 1;
                None
            }
        }
    }

    /// Insert, evicting oldest-first until the entry fits.
    ///
    /// A block larger than the whole budget is simply not cached, rather than
    /// evicting everything to make room for something that will immediately be
    /// evicted itself.
    pub fn insert(&self, key: BlockKey, block: Bytes) {
        let len = block.len() as u64;
        if len > self.limit {
            return;
        }
        let mut g = self.inner.lock();
        if let Some(old) = g.lru.insert(key, block) {
            g.used -= old.len() as u64;
        }
        g.used += len;
        while g.used > self.limit {
            match g.lru.pop_front() {
                Some((_, evicted)) => {
                    g.used -= evicted.len() as u64;
                    g.stats.evictions += 1;
                }
                None => break,
            }
        }
    }

    pub fn used_bytes(&self) -> u64 {
        self.inner.lock().used
    }

    pub fn len(&self) -> usize {
        self.inner.lock().lru.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self) -> CacheStats {
        self.inner.lock().stats
    }

    #[cfg(test)]
    fn contains(&self, key: &BlockKey) -> bool {
        self.inner.lock().lru.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dva(offset: u32, len: u32) -> Dva {
        Dva {
            txg: 1,
            slab: 0,
            offset,
            len,
        }
    }

    /// A key at the canonical position, for tests that only care about LRU
    /// behaviour rather than about position binding.
    fn k(offset: u32, len: u32) -> BlockKey {
        BlockKey::new(dva(offset, len), 1, 0)
    }

    fn block(n: usize) -> Bytes {
        Bytes::from(vec![0u8; n])
    }

    #[test]
    fn hit_and_miss() {
        let c = BlockCache::new(1024);
        assert!(c.get(&k(0, 10)).is_none());
        c.insert(k(0, 10), block(10));
        assert_eq!(c.get(&k(0, 10)).unwrap().len(), 10);
        assert_eq!(
            c.stats(),
            CacheStats {
                hits: 1,
                misses: 1,
                evictions: 0
            }
        );
    }

    #[test]
    fn accounts_bytes() {
        let c = BlockCache::new(1024);
        c.insert(k(0, 100), block(100));
        c.insert(k(100, 200), block(200));
        assert_eq!(c.used_bytes(), 300);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn evicts_oldest_first() {
        let c = BlockCache::new(300);
        c.insert(k(0, 100), block(100));
        c.insert(k(1, 100), block(100));
        c.insert(k(2, 100), block(100));
        assert_eq!(c.used_bytes(), 300);

        c.insert(k(3, 100), block(100));
        assert_eq!(c.used_bytes(), 300);
        assert!(!c.contains(&k(0, 100)), "oldest should have been evicted");
        assert!(c.contains(&k(3, 100)));
        assert_eq!(c.stats().evictions, 1);
    }

    #[test]
    fn access_refreshes_recency() {
        let c = BlockCache::new(300);
        c.insert(k(0, 100), block(100));
        c.insert(k(1, 100), block(100));
        c.insert(k(2, 100), block(100));

        // Touch the oldest so it is no longer the eviction candidate.
        assert!(c.get(&k(0, 100)).is_some());
        c.insert(k(3, 100), block(100));

        assert!(c.contains(&k(0, 100)), "touched entry must survive");
        assert!(!c.contains(&k(1, 100)));
    }

    #[test]
    fn oversized_block_is_not_cached() {
        let c = BlockCache::new(100);
        c.insert(k(0, 200), block(200));
        assert!(c.is_empty());
        assert_eq!(c.used_bytes(), 0);
    }

    #[test]
    fn reinsert_does_not_double_count() {
        let c = BlockCache::new(1024);
        c.insert(k(0, 100), block(100));
        c.insert(k(0, 100), block(100));
        assert_eq!(c.used_bytes(), 100);
        assert_eq!(c.len(), 1);
    }

    /// Copy-on-write is what makes this cache safe without invalidation:
    /// two different versions of a block occupy two different addresses, so a
    /// stale entry is unreachable rather than wrong.
    #[test]
    fn rewritten_blocks_get_distinct_keys() {
        let c = BlockCache::new(1024);
        let at = |txg| {
            BlockKey::new(
                Dva {
                    txg,
                    slab: 0,
                    offset: 0,
                    len: 100,
                },
                1,
                0,
            )
        };
        c.insert(at(1), Bytes::from_static(b"old"));
        c.insert(at(2), Bytes::from_static(b"new"));
        assert_eq!(c.get(&at(1)).unwrap(), Bytes::from_static(b"old"));
        assert_eq!(c.get(&at(2)).unwrap(), Bytes::from_static(b"new"));
    }

    /// Regression guard. Keyed on the address alone, a block cached after a
    /// legitimate read would be served straight back when a forged pointer
    /// claimed it belonged somewhere else — silently skipping the AEAD's
    /// position check. The position must be part of the key.
    #[test]
    fn the_same_address_at_a_different_position_is_a_miss() {
        let c = BlockCache::new(1024);
        let d = dva(0, 100);
        c.insert(BlockKey::new(d, 10, 5), Bytes::from_static(b"payload"));

        assert!(c.get(&BlockKey::new(d, 10, 5)).is_some());
        assert!(c.get(&BlockKey::new(d, 11, 5)).is_none(), "wrong objid");
        assert!(c.get(&BlockKey::new(d, 10, 6)).is_none(), "wrong index");
    }

    #[test]
    fn zero_budget_caches_nothing() {
        let c = BlockCache::new(0);
        c.insert(k(0, 10), block(10));
        assert!(c.is_empty());
    }
}
