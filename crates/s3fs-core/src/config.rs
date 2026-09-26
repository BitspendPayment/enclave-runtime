//! Engine configuration.
//!
//! The tuning knobs that used to live here — multipart part schedules, buffer
//! pool budgets, upload parallelism — belonged to the old path-to-key engine
//! and are gone with it. What remains is the mount's own shape plus
//! [`StoreConfig`], which owns everything about the block store.

use std::sync::Arc;

use crate::store::StoreConfig;

/// Default cap on symlink hops during one path resolution.
pub const DEFAULT_MAX_SYMLINK_DEPTH: u32 = 40;

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path the guest sees as its preopen root.
    pub mount_path: String,
    /// How many symlinks one resolution may follow before giving up. Bounds
    /// the work a malicious or merely circular symlink graph can cause.
    pub max_symlink_depth: u32,
    /// Block store settings.
    pub store: StoreConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mount_path: "/".to_string(),
            max_symlink_depth: DEFAULT_MAX_SYMLINK_DEPTH,
            store: StoreConfig::default(),
        }
    }
}

impl Config {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder {
            config: Config::default(),
        }
    }

    pub fn record_size(&self) -> usize {
        self.store.record_size
    }

    pub fn shared(self) -> Arc<Config> {
        Arc::new(self)
    }
}

/// Fluent builder for [`Config`].
#[derive(Debug)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn mount_path(mut self, path: impl Into<String>) -> Self {
        self.config.mount_path = path.into();
        self
    }

    /// Key prefix inside both buckets.
    pub fn bucket_prefix(mut self, prefix: impl Into<String>) -> Self {
        let mut prefix = prefix.into();
        // A prefix is a path component, not a substring: without the
        // separator, prefix "a" would also match keys under "ab/".
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        self.config.store.prefix = prefix;
        self
    }

    pub fn record_size(mut self, bytes: usize) -> Self {
        self.config.store.record_size = bytes;
        self
    }

    pub fn max_symlink_depth(mut self, depth: u32) -> Self {
        self.config.max_symlink_depth = depth;
        self
    }

    pub fn block_cache_bytes(mut self, bytes: u64) -> Self {
        self.config.store.block_cache_bytes = bytes;
        self
    }

    pub fn root_retention(mut self, retention: Option<std::time::Duration>) -> Self {
        self.config.store.root_retention = retention;
        self
    }

    pub fn build(self) -> Config {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_usable() {
        let c = Config::default();
        assert_eq!(c.mount_path, "/");
        assert_eq!(c.max_symlink_depth, DEFAULT_MAX_SYMLINK_DEPTH);
        c.store.validate().unwrap();
    }

    /// A prefix names a directory-like scope. Without the separator, prefix
    /// "tenant" would also cover keys belonging to "tenant-other".
    #[test]
    fn bucket_prefix_gains_a_trailing_separator() {
        let c = Config::builder().bucket_prefix("tenant").build();
        assert_eq!(c.store.prefix, "tenant/");

        let c = Config::builder().bucket_prefix("tenant/").build();
        assert_eq!(c.store.prefix, "tenant/");

        let c = Config::builder().bucket_prefix("").build();
        assert_eq!(c.store.prefix, "", "an empty prefix stays empty");
    }

    #[test]
    fn builder_sets_every_field() {
        let c = Config::builder()
            .mount_path("/mnt")
            .record_size(8192)
            .max_symlink_depth(8)
            .block_cache_bytes(1024)
            .root_retention(None)
            .build();

        assert_eq!(c.mount_path, "/mnt");
        assert_eq!(c.record_size(), 8192);
        assert_eq!(c.max_symlink_depth, 8);
        assert_eq!(c.store.block_cache_bytes, 1024);
        assert_eq!(c.store.root_retention, None);
        c.store.validate().unwrap();
    }
}
