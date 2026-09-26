//! Store tuning knobs and key-space layout.
//!
//! Kept separate from [`crate::config::Config`] while the old path→key engine
//! still exists; the two merge when that engine is removed.

use std::time::Duration;

use crate::errors::{FsError, FsResult};

/// Default record size. Matches ZFS's default for the same reasons: large
/// enough that per-block overhead (128-byte pointer, 16-byte AEAD tag, one
/// BLAKE3 pass) is negligible, small enough that rewriting one record after a
/// small write does not amplify badly.
pub const DEFAULT_RECORD_SIZE: usize = 128 * 1024;

/// Default cap on a single slab object. A commit writes `ceil(dirty /
/// SLAB_MAX)` objects, so this trades PUT count against how much has to be
/// re-sent if one PUT fails.
pub const DEFAULT_SLAB_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Smallest and largest permitted record sizes.
const MIN_RECORD_SIZE: usize = 4 * 1024;
const MAX_RECORD_SIZE: usize = 1024 * 1024;

/// How long a committed root is retained when per-object Object Lock is used.
/// Ten years, per the deployment contract.
pub const DEFAULT_ROOT_RETENTION: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Store configuration.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Key prefix inside both buckets. Empty for bucket root.
    pub prefix: String,
    /// Size of a level-0 data block and of an indirect block. Power of two.
    pub record_size: usize,
    /// Cap on one slab object.
    pub slab_max_bytes: usize,
    /// Byte budget for the decrypted-block cache.
    pub block_cache_bytes: u64,
    /// Max concurrent slab PUTs during a commit.
    pub max_parallel_slab_puts: usize,
    /// How many links of the root hash chain to verify at mount.
    ///
    /// 1 is enough to detect a spliced history at the tip, which is the live
    /// attack; walking the whole chain is an audit operation, not a mount-time
    /// one, because it costs one GET per root and roots are never deleted.
    pub root_chain_verify_depth: u32,
    /// Retention to stamp on root records, or `None` to rely on the bucket's
    /// default retention configuration.
    pub root_retention: Option<Duration>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            record_size: DEFAULT_RECORD_SIZE,
            slab_max_bytes: DEFAULT_SLAB_MAX_BYTES,
            block_cache_bytes: 64 * 1024 * 1024,
            max_parallel_slab_puts: 8,
            root_chain_verify_depth: 1,
            root_retention: Some(DEFAULT_ROOT_RETENTION),
        }
    }
}

impl StoreConfig {
    pub fn validate(&self) -> FsResult<()> {
        if !self.record_size.is_power_of_two() {
            return Err(FsError::Invalid("record_size must be a power of two"));
        }
        if self.record_size < MIN_RECORD_SIZE || self.record_size > MAX_RECORD_SIZE {
            return Err(FsError::Invalid("record_size out of range"));
        }
        if self.slab_max_bytes < self.record_size {
            return Err(FsError::Invalid("slab_max_bytes below record_size"));
        }
        // A slab offset is a u32 in the block pointer.
        if self.slab_max_bytes > u32::MAX as usize {
            return Err(FsError::Invalid("slab_max_bytes exceeds u32 addressing"));
        }
        if self.max_parallel_slab_puts == 0 {
            return Err(FsError::Invalid("max_parallel_slab_puts must be nonzero"));
        }
        Ok(())
    }

    /// `log2(record_size)`, as stored in a dnode.
    pub fn record_shift(&self) -> u8 {
        self.record_size.trailing_zeros() as u8
    }

    /// Key of a slab object. Zero-padded hex so S3's lexicographic ordering
    /// matches numeric ordering, which is what makes a range scan over txgs
    /// meaningful.
    pub fn slab_key(&self, txg: u64, slab: u16) -> String {
        format!("{}slabs/{:016x}/{:04x}", self.prefix, txg, slab)
    }

    /// Key of a root record.
    pub fn root_key(&self, seq: u64) -> String {
        format!("{}roots/{:016x}", self.prefix, seq)
    }

    /// Key of the (untrusted) tip hint.
    pub fn root_hint_key(&self) -> String {
        format!("{}roots/latest", self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        StoreConfig::default().validate().unwrap();
    }

    #[test]
    fn record_shift_matches_record_size() {
        let mut c = StoreConfig::default();
        assert_eq!(c.record_shift(), 17); // 128 KiB
        c.record_size = 4096;
        assert_eq!(c.record_shift(), 12);
        assert_eq!(1usize << c.record_shift(), c.record_size);
    }

    #[test]
    fn rejects_non_power_of_two_record_size() {
        let c = StoreConfig {
            record_size: 100_000,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_out_of_range_record_size() {
        for size in [1024, 2 * 1024 * 1024] {
            let c = StoreConfig {
                record_size: size,
                ..Default::default()
            };
            assert!(c.validate().is_err(), "accepted record_size {size}");
        }
    }

    #[test]
    fn rejects_slab_smaller_than_a_record() {
        let c = StoreConfig {
            slab_max_bytes: 4096,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    /// A slab offset is a `u32` in the block pointer, so a slab larger than
    /// 4 GiB would silently truncate addresses.
    #[test]
    fn rejects_slab_beyond_u32_addressing() {
        let c = StoreConfig {
            slab_max_bytes: u32::MAX as usize + 1,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn keys_are_zero_padded_and_sort_numerically() {
        let c = StoreConfig::default();
        assert_eq!(c.root_key(1), "roots/0000000000000001");
        assert_eq!(c.root_key(0x2a), "roots/000000000000002a");
        assert_eq!(c.slab_key(9, 3), "slabs/0000000000000009/0003");

        // The property that matters: lexicographic order == numeric order,
        // so a LIST or a range scan sees roots in sequence order.
        let mut keys: Vec<_> = [300u64, 2, 41, 1].iter().map(|&s| c.root_key(s)).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                c.root_key(1),
                c.root_key(2),
                c.root_key(41),
                c.root_key(300)
            ]
        );
    }

    #[test]
    fn prefix_is_applied_to_every_key() {
        let c = StoreConfig {
            prefix: "tenant-a/".into(),
            ..Default::default()
        };
        assert!(c.root_key(1).starts_with("tenant-a/roots/"));
        assert!(c.slab_key(1, 0).starts_with("tenant-a/slabs/"));
        assert!(c.root_hint_key().starts_with("tenant-a/roots/"));
    }
}
