//! Turning configuration into a connection to the roots bucket.
//!
//! The bucket holds what must outlive any disk and that no host may rewrite:
//! the pool's anchor chain, the state-origin receipt and pair records, the
//! sealed master key's pointer, the guest, and the sealed ACME cache. The
//! state itself is on the pool — see [`crate::zfs`].

use std::sync::Arc;
use std::time::Duration;

use crate::store::backend::{AwsS3Backend, AwsS3BackendConfig, Backend};
use anyhow::{Context, Result};

/// How long each anchor and boot record is locked by default: ten years, per
/// the deployment contract.
pub const DEFAULT_ROOT_RETENTION: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Everything needed to reach the store.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// The Object-Locked bucket: anchors, boot records, guest, ACME cache.
    pub roots_bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub force_path_style: bool,
    pub bucket_prefix: String,
    /// Filesystem identifier, the key-derivation salt.
    pub fs_id: [u8; 16],
    /// Refuse a store whose newest anchor is older than this.
    pub min_root_seq: Option<u64>,
    /// Skip the `HeadBucket` startup probe.
    pub skip_bucket_probe: bool,
    pub request_timeout: Duration,
    /// How long each anchor, and every record the boot writes beside them, is
    /// locked against deletion (Object Lock, COMPLIANCE). Rollback protection
    /// lasts exactly this long, and so does the bucket.
    pub root_retention: Duration,
}

impl MountConfig {
    fn backend_config(&self) -> AwsS3BackendConfig {
        AwsS3BackendConfig {
            bucket: self.roots_bucket.clone(),
            region: self.region.clone(),
            endpoint: self.endpoint.clone(),
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            // No keys is production: the instance's role, as the KMS and SSM
            // clients use (`keys::kms_client`).
            credentials_provider: self
                .access_key_id
                .is_none()
                .then(crate::notify::pinpoint::instance_role),
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

/// Connect to the roots bucket.
pub async fn connect(config: &MountConfig) -> Result<Arc<dyn Backend>> {
    let backend = if config.skip_bucket_probe {
        AwsS3Backend::connect_unchecked(config.backend_config()).await?
    } else {
        AwsS3Backend::connect(config.backend_config())
            .await
            .context("connecting to the roots bucket")?
    };
    Ok(Arc::new(backend))
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

    fn config() -> MountConfig {
        MountConfig {
            roots_bucket: "roots".into(),
            region: "us-east-1".into(),
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            force_path_style: false,
            bucket_prefix: String::new(),
            fs_id: [0u8; 16],
            min_root_seq: None,
            skip_bucket_probe: true,
            request_timeout: Duration::from_secs(30),
            root_retention: Duration::from_secs(86_400),
        }
    }

    /// Production sets no keys. A store client without a provider signs nothing, and that shows
    /// only on hardware, at the first request of the boot.
    #[test]
    fn without_keys_the_store_signs_as_the_instance_role() {
        let mut cfg = config();
        assert!(cfg.backend_config().credentials_provider.is_some());

        cfg.access_key_id = Some("minio".into());
        cfg.secret_access_key = Some("minio".into());
        assert!(cfg.backend_config().credentials_provider.is_none());
    }
}
