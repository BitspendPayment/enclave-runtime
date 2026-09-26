//! Turning configuration into a mounted filesystem.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use s3fs_core::backend::{AwsS3Backend, AwsS3BackendConfig, Backend};
use s3fs_core::crypto::KeyMaterial;
use s3fs_core::{Config, Fs, MasterSecret};

/// Everything needed to open the store.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Bucket holding the data slabs.
    pub bucket: String,
    /// Bucket holding the signed root records. `None` uses `bucket`.
    pub roots_bucket: Option<String>,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub force_path_style: bool,
    pub bucket_prefix: String,
    pub mount_path: String,
    /// Filesystem identifier, the key-derivation salt.
    pub fs_id: [u8; 16],
    /// Refuse to mount a root older than this.
    pub min_root_seq: Option<u64>,
    /// Skip the `HeadBucket` startup probe.
    pub skip_bucket_probe: bool,
    pub request_timeout: Duration,
}

impl MountConfig {
    fn backend_config(&self, bucket: &str) -> AwsS3BackendConfig {
        AwsS3BackendConfig {
            bucket: bucket.to_string(),
            region: self.region.clone(),
            endpoint: self.endpoint.clone(),
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            force_path_style: self.force_path_style,
            request_timeout: self.request_timeout,
        }
    }
}

/// Parse the 32-hex-character filesystem identifier.
pub fn parse_fs_id(s: &str) -> Result<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        anyhow::bail!("filesystem id must be 32 hex characters, got {}", s.len());
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("filesystem id is not valid hex"))?;
    }
    Ok(out)
}

/// A mounted filesystem, plus the pieces a runtime needs alongside it.
///
/// `Debug` names the store rather than dumping the filesystem: an `Fs` renders
/// its whole handle table, which is noise in a boot log and unbounded in a
/// panic message.
///
/// The ACME cache writes sealed objects to the data bucket and seals them
/// under a key derived from the same master secret, so it needs both — but it
/// deliberately does *not* go through the filesystem, because the guest's
/// preopen is the filesystem root and the blob contains a TLS private key.
pub struct Mounted {
    pub fs: Arc<Fs>,
    pub data: Arc<dyn Backend>,
    pub keys: Arc<KeyMaterial>,
    pub bucket_prefix: String,
}

impl std::fmt::Debug for Mounted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mounted")
            .field("bucket_prefix", &self.bucket_prefix)
            .finish_non_exhaustive()
    }
}

/// Both backends, connected but not yet mounted.
///
/// Separate from mounting because the boot machine has to *read* the store —
/// the state-origin receipt lives in the roots bucket — before it can decide
/// whether this is a genesis or a resume, and only after deciding does it know
/// which master secret to use.
pub struct Backends {
    pub data: Arc<dyn Backend>,
    pub roots: Arc<dyn Backend>,
}

/// Connect to both buckets.
pub async fn connect(config: &MountConfig) -> Result<Backends> {
    let data_cfg = config.backend_config(&config.bucket);
    let data: Arc<dyn Backend> = Arc::new(if config.skip_bucket_probe {
        AwsS3Backend::connect_unchecked(data_cfg).await?
    } else {
        AwsS3Backend::connect(data_cfg)
            .await
            .context("connecting to the data bucket")?
    });

    let roots_name = config.roots_bucket.as_deref().unwrap_or(&config.bucket);
    let roots: Arc<dyn Backend> = if roots_name == config.bucket {
        // One bucket for both. Simpler to operate, but the anchor and the
        // reclaimable data then share a retention policy, which defeats the
        // point of splitting them.
        tracing::warn!(
            bucket = %config.bucket,
            "roots and data share a bucket; Object Lock retention cannot then \
             differ between the rollback anchor and reclaimable block storage"
        );
        data.clone()
    } else {
        Arc::new(AwsS3Backend::connect_unchecked(config.backend_config(roots_name)).await?)
    };

    Ok(Backends { data, roots })
}

/// Mount an existing filesystem with a secret the caller has already resolved.
pub async fn mount_existing(
    backends: &Backends,
    config: &MountConfig,
    master: &MasterSecret,
) -> Result<Mounted> {
    finish(backends, config, master, false).await
}

/// Create a filesystem. Only genesis calls this.
pub async fn create(
    backends: &Backends,
    config: &MountConfig,
    master: &MasterSecret,
) -> Result<Mounted> {
    finish(backends, config, master, true).await
}

async fn finish(
    backends: &Backends,
    config: &MountConfig,
    master: &MasterSecret,
    genesis: bool,
) -> Result<Mounted> {
    let data = backends.data.clone();
    let roots = backends.roots.clone();

    let fs_config = Config::builder()
        .bucket_prefix(config.bucket_prefix.clone())
        .mount_path(config.mount_path.clone())
        .build();

    // Derived twice — once here and once inside `Fs::mount` — rather than
    // reaching into the store for them. The derivation is cheap and pure, and
    // threading them out would widen the store's API for one caller.
    let derived = Arc::new(
        KeyMaterial::derive(master, config.fs_id)
            .map_err(|e| anyhow::anyhow!("deriving keys: {e}"))?,
    );

    let fs = if genesis {
        Fs::create(
            data.clone(),
            roots,
            master,
            config.fs_id,
            Arc::new(fs_config),
        )
        .await
        .map_err(|e| anyhow::anyhow!("creating filesystem: {e}"))?
    } else {
        Fs::mount(
            data.clone(),
            roots,
            master,
            config.fs_id,
            Arc::new(fs_config),
            config.min_root_seq,
        )
        .await
        .map_err(|e| anyhow::anyhow!("mounting filesystem: {e}"))?
    };

    // The operator's evidence of which committed state this process came up
    // on. Under attestation this is what the health endpoint reports, and it
    // is the number to compare against an external freshness floor.
    let root = fs
        .store()
        .root()
        .await
        .map_err(|e| anyhow::anyhow!("reading root record: {e}"))?;
    tracing::info!(
        mode = if genesis { "genesis" } else { "resume" },
        root_seq = root.seq,
        txg = root.txg,
        merkle_root = %root.merkle_root(),
        data_bucket = %config.bucket,
        roots_bucket = %config.roots_bucket.as_deref().unwrap_or(&config.bucket),
        "mounted"
    );

    Ok(Mounted {
        fs,
        data,
        keys: derived,
        bucket_prefix: config.bucket_prefix.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_id_round_trips() {
        let id = parse_fs_id("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(id[0], 0x00);
        assert_eq!(id[15], 0x0f);
        assert!(parse_fs_id("  00000000000000000000000000000000\n").is_ok());
    }

    #[test]
    fn fs_id_rejects_bad_input() {
        assert!(parse_fs_id("abcd").is_err());
        assert!(parse_fs_id(&"z".repeat(32)).is_err());
        assert!(parse_fs_id("").is_err());
    }

    #[test]
    fn the_roots_bucket_defaults_to_the_data_bucket() {
        let cfg = MountConfig {
            bucket: "data".into(),
            roots_bucket: None,
            region: "us-east-1".into(),
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            force_path_style: false,
            bucket_prefix: String::new(),
            mount_path: "/".into(),
            fs_id: [0u8; 16],
            min_root_seq: None,
            skip_bucket_probe: true,
            request_timeout: Duration::from_secs(30),
        };
        assert_eq!(cfg.roots_bucket.as_deref().unwrap_or(&cfg.bucket), "data");
        assert_eq!(cfg.backend_config("roots").bucket, "roots");
    }
}
