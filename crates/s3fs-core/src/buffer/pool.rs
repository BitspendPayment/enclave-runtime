//! `BufferPool` — memory-bounded cache of `PartBuf`s, keyed by `(inode, part)`.
//!
//! The pool's only job is in-memory accounting and LRU eviction of *clean*
//! parts. Dirty / in-flight parts are pinned (cannot be evicted). Fetching
//! parts from S3 is the caller's responsibility — this module never touches
//! the backend.
//!
//! Eviction policy:
//! - Targets (`memory_limit_bytes`) come from `Config`.
//! - Eviction runs at insert-time when adding the new part would exceed the
//!   limit. Walks LRU oldest-first, dropping `Clean` and `Flushed` parts
//!   until headroom is reclaimed. If we can't reclaim enough (everything
//!   pinned), the insert succeeds anyway and `used > limit` becomes true;
//!   future flushes are responsible for relieving pressure.

use std::sync::Arc;

use hashlink::LinkedHashMap;
use parking_lot::{Mutex, RwLock};

use super::part::{PartBuf, PartState};
use crate::config::Config;
use crate::inode::InodeId;

/// Identifies one part in the pool.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct PartKey {
    pub inode_id: InodeId,
    pub part_index: u32,
}

impl PartKey {
    pub fn new(inode_id: InodeId, part_index: u32) -> Self {
        Self { inode_id, part_index }
    }
}

#[derive(Debug)]
struct Inner {
    used: u64,
    /// Insertion order = age. Move-to-back on access.
    lru: LinkedHashMap<PartKey, Arc<RwLock<PartBuf>>>,
}

/// In-memory part cache.
#[derive(Debug)]
pub struct BufferPool {
    config: Arc<Config>,
    inner: Mutex<Inner>,
}

impl BufferPool {
    pub fn new(config: Arc<Config>) -> Arc<Self> {
        Arc::new(Self {
            config,
            inner: Mutex::new(Inner {
                used: 0,
                lru: LinkedHashMap::new(),
            }),
        })
    }

    pub fn limit(&self) -> u64 {
        self.config.memory_limit_bytes
    }

    pub fn used(&self) -> u64 {
        self.inner.lock().used
    }

    pub fn len(&self) -> usize {
        self.inner.lock().lru.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up a part. On hit, marks it most-recently-used.
    pub fn get(&self, key: PartKey) -> Option<Arc<RwLock<PartBuf>>> {
        let mut g = self.inner.lock();
        // hashlink's `to_back` returns the value reference; use raw_entry-ish dance
        // via remove + reinsert (cheap; the value is an Arc clone).
        let v = g.lru.remove(&key)?;
        g.lru.insert(key, v.clone());
        Some(v)
    }

    /// Cheap probe: does the pool currently hold this key? Doesn't bump LRU.
    pub fn contains(&self, key: PartKey) -> bool {
        self.inner.lock().lru.contains_key(&key)
    }

    /// Install a fresh `PartBuf` for `key`. Returns the wrapped `Arc<RwLock>`.
    /// If a part already exists for `key`, the existing entry is replaced
    /// and its memory is subtracted before the new entry's memory is added.
    ///
    /// Before inserting, evicts clean parts in LRU order to make headroom.
    pub fn insert(&self, key: PartKey, part: PartBuf) -> Arc<RwLock<PartBuf>> {
        let new_cost = part.alloc_bytes();
        let mut g = self.inner.lock();

        if let Some(existing) = g.lru.remove(&key) {
            g.used = g.used.saturating_sub(existing.read().alloc_bytes());
        }

        // Evict clean parts until we'd fit, or we run out of evictable parts.
        if g.used + new_cost > self.config.memory_limit_bytes {
            let target = self
                .config
                .memory_limit_bytes
                .saturating_sub(new_cost);
            self.evict_clean_locked(&mut g, target);
        }

        g.used = g.used.saturating_add(new_cost);
        let arc = Arc::new(RwLock::new(part));
        g.lru.insert(key, arc.clone());
        arc
    }

    /// Drop a part unconditionally — used on file unlink / abort. Returns
    /// `true` if anything was removed.
    pub fn forget(&self, key: PartKey) -> bool {
        let mut g = self.inner.lock();
        if let Some(v) = g.lru.remove(&key) {
            g.used = g.used.saturating_sub(v.read().alloc_bytes());
            true
        } else {
            false
        }
    }

    /// Forget every part owned by a given inode. Returns the count removed.
    pub fn forget_inode(&self, inode_id: InodeId) -> usize {
        let mut g = self.inner.lock();
        let to_drop: Vec<PartKey> = g
            .lru
            .iter()
            .filter(|(k, _)| k.inode_id == inode_id)
            .map(|(k, _)| *k)
            .collect();
        let n = to_drop.len();
        for k in to_drop {
            if let Some(v) = g.lru.remove(&k) {
                g.used = g.used.saturating_sub(v.read().alloc_bytes());
            }
        }
        n
    }

    /// Evict clean / flushed parts in LRU order until `used` drops to
    /// `target` or fewer bytes. Pinned parts (`Dirty`, `Flushing`) are
    /// skipped. Returns the number evicted.
    pub fn evict_clean(&self, target: u64) -> usize {
        let mut g = self.inner.lock();
        self.evict_clean_locked(&mut g, target)
    }

    fn evict_clean_locked(&self, g: &mut Inner, target: u64) -> usize {
        let mut n = 0;
        // Walk LRU oldest-first.
        let candidates: Vec<PartKey> = g.lru.iter().map(|(k, _)| *k).collect();
        for k in candidates {
            if g.used <= target {
                break;
            }
            let evictable = match g.lru.get(&k) {
                None => continue,
                Some(part) => {
                    let st = part.read().state.clone();
                    matches!(st, PartState::Clean | PartState::Flushed)
                }
            };
            if !evictable {
                continue;
            }
            if let Some(part) = g.lru.remove(&k) {
                g.used = g.used.saturating_sub(part.read().alloc_bytes());
                n += 1;
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::InodeId;
    use bytes::Bytes;
    use std::num::NonZeroU64;

    fn key(ino: u64, part: u32) -> PartKey {
        PartKey::new(InodeId(NonZeroU64::new(ino).unwrap()), part)
    }

    fn small_pool(limit: u64) -> Arc<BufferPool> {
        let cfg = Arc::new(Config::builder().memory_limit_bytes(limit).build());
        BufferPool::new(cfg)
    }

    fn clean_part(part_index: u32, body: &[u8], part_size: u64) -> PartBuf {
        PartBuf::new_clean(part_index, part_size, 0, Bytes::copy_from_slice(body))
    }

    #[test]
    fn insert_and_get_basic() {
        let p = small_pool(1024);
        let k = key(1, 0);
        p.insert(k, clean_part(0, &[1u8; 64], 64));
        assert_eq!(p.len(), 1);
        let part = p.get(k).expect("hit");
        assert_eq!(part.read().valid_len, 64);
    }

    #[test]
    fn get_misses_when_absent() {
        let p = small_pool(1024);
        assert!(p.get(key(1, 0)).is_none());
    }

    #[test]
    fn insert_overwrites_and_recomputes_memory() {
        let p = small_pool(1024);
        let k = key(1, 0);
        p.insert(k, clean_part(0, &[0u8; 64], 64));
        let used_after_first = p.used();
        p.insert(k, clean_part(0, &[0u8; 128], 128));
        assert!(p.used() > used_after_first);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn forget_removes_and_credits_memory() {
        let p = small_pool(1024);
        let k = key(1, 0);
        p.insert(k, clean_part(0, &[0u8; 64], 64));
        assert!(p.forget(k));
        assert!(p.is_empty());
        assert_eq!(p.used(), 0);
        // Idempotent.
        assert!(!p.forget(k));
    }

    #[test]
    fn forget_inode_drops_all_parts_of_one_inode() {
        let p = small_pool(4096);
        for i in 0..5 {
            p.insert(key(1, i), clean_part(i, &[0u8; 64], 64));
        }
        for i in 0..5 {
            p.insert(key(2, i), clean_part(i, &[0u8; 64], 64));
        }
        assert_eq!(p.len(), 10);
        let dropped = p.forget_inode(InodeId(NonZeroU64::new(1).unwrap()));
        assert_eq!(dropped, 5);
        assert_eq!(p.len(), 5);
    }

    #[test]
    fn lru_promotes_on_get() {
        // Limit fits two 64-byte parts comfortably but a third triggers
        // eviction. After touching k0, k1 becomes the LRU victim.
        let p = small_pool(150);
        let k0 = key(1, 0);
        let k1 = key(1, 1);
        let k2 = key(1, 2);
        p.insert(k0, clean_part(0, &[0u8; 64], 64));
        p.insert(k1, clean_part(1, &[0u8; 64], 64));
        let _ = p.get(k0); // promote k0
        p.insert(k2, clean_part(2, &[0u8; 64], 64));
        assert!(p.contains(k0));
        assert!(!p.contains(k1));
        assert!(p.contains(k2));
    }

    #[test]
    fn dirty_parts_are_not_evicted() {
        // Insert a Dirty part, then try to evict.
        let p = small_pool(64);
        let k = key(1, 0);
        let mut dirty = PartBuf::new_empty_dirty(0, 64, 0);
        dirty.apply_write(0, &[7u8; 32]).unwrap();
        p.insert(k, dirty);
        // Force eviction with a small target.
        let evicted = p.evict_clean(0);
        assert_eq!(evicted, 0);
        assert!(p.contains(k));
        // used > limit is allowed when only dirty parts exist.
    }

    #[test]
    fn flushed_parts_are_evictable() {
        let p = small_pool(64);
        let k = key(1, 0);
        let mut part = PartBuf::new_empty_dirty(0, 64, 0);
        part.apply_write(0, &[1u8; 32]).unwrap();
        part.mark_flushing().unwrap();
        part.mark_flushed("etag-1".into()).unwrap();
        p.insert(k, part);
        let evicted = p.evict_clean(0);
        assert_eq!(evicted, 1);
        assert!(p.is_empty());
    }

    #[test]
    fn insert_pressure_evicts_oldest_clean_first() {
        // Two clean parts + one dirty; insert a new clean → dirty must remain.
        let p = small_pool(192);
        let k0 = key(1, 0);
        let k1 = key(1, 1);
        let k_dirty = key(1, 2);
        p.insert(k0, clean_part(0, &[0u8; 64], 64));
        let mut d = PartBuf::new_empty_dirty(2, 64, 0);
        d.apply_write(0, &[5u8; 32]).unwrap();
        p.insert(k_dirty, d);
        p.insert(k1, clean_part(1, &[0u8; 64], 64));

        // Now insert a 4th. The dirty one must survive; one of k0/k1 evicted.
        let k_new = key(1, 3);
        p.insert(k_new, clean_part(3, &[0u8; 64], 64));
        assert!(p.contains(k_dirty));
        assert!(p.contains(k_new));
        // At least one of k0/k1 was evicted to make room.
        let still = p.contains(k0) as u8 + p.contains(k1) as u8;
        assert!(still <= 1);
    }
}
