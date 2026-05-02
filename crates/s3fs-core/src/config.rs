//! Engine configuration.
//!
//! `Config` is the single source of truth for tuning knobs (part sizes, memory
//! caps, parallelism, timeouts). Construct with [`Config::builder`].

use std::path::PathBuf;
use std::time::Duration;

/// Tiered multipart-upload part schedule.
///
/// S3 caps an MPU at 10 000 parts. To support large files without paying the
/// 50 GiB-per-file price of using 5 MiB parts everywhere, we use a tiered
/// schedule: small parts at the start of the file (so small files / appends
/// stay cheap), larger parts further in.
///
/// The default schedule allows files up to ~1.03 TiB:
///   - parts 0..1000: 5 MiB each →    5 GiB
///   - parts 1000..2000: 25 MiB each →   25 GiB additional
///   - parts 2000..10000: 125 MiB each → 1000 GiB additional
#[derive(Debug, Clone)]
pub struct PartSchedule {
    /// Each tier is `(part_size_bytes, part_count)`. The `part_count` of the
    /// final tier is also the cap on total part count (S3's hard limit is
    /// 10 000).
    pub tiers: Vec<(u64, u32)>,
}

impl Default for PartSchedule {
    fn default() -> Self {
        Self {
            tiers: vec![
                (5 * 1024 * 1024, 1000),         // 5 MiB × 1000  →    5 GiB
                (25 * 1024 * 1024, 1000),        // 25 MiB × 1000  →   25 GiB
                (125 * 1024 * 1024, 8000),       // 125 MiB × 8000 → 1000 GiB
            ],
        }
    }
}

impl PartSchedule {
    /// Maximum file size representable with this schedule.
    pub fn max_file_size(&self) -> u64 {
        self.tiers.iter().map(|(sz, n)| sz * (*n as u64)).sum()
    }

    /// Total part count across all tiers (must be ≤ 10 000 per S3).
    pub fn total_parts(&self) -> u32 {
        self.tiers.iter().map(|(_, n)| *n).sum()
    }

    /// Reverse direction: given a part index, return its byte range
    /// `[start, end)` in the file. Returns `None` if `part_index` is past the
    /// schedule's last tier.
    pub fn part_range(&self, part_index: u32) -> Option<std::ops::Range<u64>> {
        let mut accum_parts: u32 = 0;
        let mut accum_bytes: u64 = 0;
        for &(part_size, count) in &self.tiers {
            if part_index < accum_parts + count {
                let into_tier = (part_index - accum_parts) as u64;
                let start = accum_bytes + into_tier * part_size;
                let end = start + part_size;
                return Some(start..end);
            }
            accum_parts += count;
            accum_bytes += part_size * (count as u64);
        }
        None
    }

    /// Map a byte offset to its `(part_index, part_size, part_offset_in_file)`.
    /// `part_index` is 0-based; S3's `PartNumber` is `part_index + 1`.
    /// Returns `None` if the offset exceeds the schedule's representable range.
    pub fn locate(&self, offset: u64) -> Option<PartLocation> {
        let mut accum_parts: u32 = 0;
        let mut accum_bytes: u64 = 0;
        for &(part_size, count) in &self.tiers {
            let tier_bytes = part_size * (count as u64);
            if offset < accum_bytes + tier_bytes {
                let into_tier = offset - accum_bytes;
                let part_in_tier = (into_tier / part_size) as u32;
                let part_index = accum_parts + part_in_tier;
                let part_start = accum_bytes + (part_in_tier as u64) * part_size;
                return Some(PartLocation {
                    part_index,
                    part_size,
                    part_start,
                });
            }
            accum_parts += count;
            accum_bytes += tier_bytes;
        }
        None
    }
}

/// Location of a byte within the tiered MPU schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartLocation {
    /// Zero-based part index. S3's wire `PartNumber` is `part_index + 1`.
    pub part_index: u32,
    /// Part size in bytes for the tier this part belongs to.
    pub part_size: u64,
    /// Offset of this part's first byte within the file.
    pub part_start: u64,
}

/// Engine configuration. Defaults are tuned for a single 8-core host with
/// ~64 MiB available for the buffer pool.
#[derive(Debug, Clone)]
pub struct Config {
    /// Tiered MPU part schedule. Defaults to ~1.03 TiB max file size.
    pub part_schedule: PartSchedule,
    /// Files smaller than this go via single `PutObject`, skipping MPU entirely.
    /// Defaults to 5 MiB (one S3 part).
    pub single_part_threshold: u64,
    /// Max in-flight `UploadPart` requests per file.
    pub max_parallel_parts: usize,
    /// Max in-flight `UploadPartCopy` requests per `commit`.
    pub max_parallel_copy: usize,
    /// Max bytes a single `UploadPartCopy` will cover when merging unchanged
    /// ranges. Larger merges reduce the number of copy parts but each
    /// `UploadPartCopy` is capped at 5 GiB by S3.
    pub max_merge_copy_bytes: u64,
    /// Total buffer-pool memory cap. Bytes pinned by dirty pages count
    /// against this; eviction targets clean pages first.
    pub memory_limit_bytes: u64,
    /// If `Some`, clean pages may spill to this directory when memory pressure
    /// exceeds the cap. Disabled by default — enclave use cases prefer no
    /// disk.
    pub disk_overflow_dir: Option<PathBuf>,
    /// Sequential-read prefetch distance, in chunks.
    pub read_ahead_chunks: usize,
    /// Symlink resolution recursion limit. Linux uses 40.
    pub max_symlink_depth: u32,
    /// Per-S3-request timeout.
    pub request_timeout: Duration,
    /// How long cached file/directory attrs are considered fresh before the
    /// next op triggers a re-validation.
    pub attr_cache_ttl: Duration,
    /// Path the guest sees for the single preopen. Defaults to `/`.
    pub mount_path: String,
    /// Optional key prefix inside the bucket. All operations are relative to
    /// `bucket/{prefix}`. Empty = bucket root.
    pub bucket_prefix: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            part_schedule: PartSchedule::default(),
            single_part_threshold: 5 * 1024 * 1024,        // 5 MiB
            max_parallel_parts: 8,
            max_parallel_copy: 8,
            max_merge_copy_bytes: 128 * 1024 * 1024,       // 128 MiB
            memory_limit_bytes: 64 * 1024 * 1024,          // 64 MiB
            disk_overflow_dir: None,
            read_ahead_chunks: 2,
            max_symlink_depth: 40,
            request_timeout: Duration::from_secs(30),
            attr_cache_ttl: Duration::from_secs(1),
            mount_path: "/".to_string(),
            bucket_prefix: String::new(),
        }
    }
}

impl Config {
    /// Start from defaults; mutate via the returned builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder { inner: Self::default() }
    }
}

/// Fluent builder over [`Config`].
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    inner: Config,
}

macro_rules! setter {
    ($name:ident, $ty:ty) => {
        pub fn $name(mut self, v: $ty) -> Self {
            self.inner.$name = v;
            self
        }
    };
}

impl ConfigBuilder {
    setter!(part_schedule, PartSchedule);
    setter!(single_part_threshold, u64);
    setter!(max_parallel_parts, usize);
    setter!(max_parallel_copy, usize);
    setter!(max_merge_copy_bytes, u64);
    setter!(memory_limit_bytes, u64);
    setter!(disk_overflow_dir, Option<PathBuf>);
    setter!(read_ahead_chunks, usize);
    setter!(max_symlink_depth, u32);
    setter!(request_timeout, Duration);
    setter!(attr_cache_ttl, Duration);

    pub fn mount_path(mut self, v: impl Into<String>) -> Self {
        self.inner.mount_path = v.into();
        self
    }

    pub fn bucket_prefix(mut self, v: impl Into<String>) -> Self {
        self.inner.bucket_prefix = v.into();
        self
    }

    pub fn build(self) -> Config {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schedule_caps_at_about_one_tib() {
        let s = PartSchedule::default();
        // 5 GiB + 25 GiB + 1000 GiB = 1030 GiB ≈ 1.006 TiB
        assert_eq!(
            s.max_file_size(),
            5u64 * 1024 * 1024 * 1000
                + 25u64 * 1024 * 1024 * 1000
                + 125u64 * 1024 * 1024 * 8000
        );
        assert_eq!(s.total_parts(), 10_000);
    }

    #[test]
    fn locate_in_first_tier() {
        let s = PartSchedule::default();
        let loc = s.locate(0).unwrap();
        assert_eq!(loc.part_index, 0);
        assert_eq!(loc.part_size, 5 * 1024 * 1024);
        assert_eq!(loc.part_start, 0);

        let loc = s.locate(5 * 1024 * 1024).unwrap();
        assert_eq!(loc.part_index, 1);
        assert_eq!(loc.part_start, 5 * 1024 * 1024);
    }

    #[test]
    fn locate_at_tier_boundaries() {
        let s = PartSchedule::default();
        let first_tier_end = 5u64 * 1024 * 1024 * 1000;
        let loc = s.locate(first_tier_end).unwrap();
        assert_eq!(loc.part_index, 1000); // first part of tier 2
        assert_eq!(loc.part_size, 25 * 1024 * 1024);

        let second_tier_end = first_tier_end + 25u64 * 1024 * 1024 * 1000;
        let loc = s.locate(second_tier_end).unwrap();
        assert_eq!(loc.part_index, 2000); // first part of tier 3
        assert_eq!(loc.part_size, 125 * 1024 * 1024);
    }

    #[test]
    fn locate_beyond_max_returns_none() {
        let s = PartSchedule::default();
        assert!(s.locate(s.max_file_size()).is_none());
        assert!(s.locate(u64::MAX).is_none());
    }

    #[test]
    fn part_range_round_trips_with_locate() {
        let s = PartSchedule::default();
        // Spot-check a few part indices in different tiers.
        for &idx in &[0u32, 1, 999, 1000, 1500, 1999, 2000, 5000, 9999] {
            let r = s.part_range(idx).unwrap();
            let loc = s.locate(r.start).unwrap();
            assert_eq!(loc.part_index, idx, "round-trip idx {idx}");
            assert_eq!(loc.part_start, r.start);
            assert_eq!(loc.part_size, r.end - r.start);
        }
        assert!(s.part_range(10_000).is_none());
    }

    #[test]
    fn builder_overrides_defaults() {
        let c = Config::builder()
            .memory_limit_bytes(8 * 1024 * 1024)
            .max_parallel_parts(4)
            .mount_path("/data")
            .bucket_prefix("my/prefix")
            .build();
        assert_eq!(c.memory_limit_bytes, 8 * 1024 * 1024);
        assert_eq!(c.max_parallel_parts, 4);
        assert_eq!(c.mount_path, "/data");
        assert_eq!(c.bucket_prefix, "my/prefix");
        // Unset fields keep defaults.
        assert_eq!(c.max_symlink_depth, 40);
    }
}
