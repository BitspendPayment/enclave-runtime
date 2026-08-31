//! The development key source: a secret from configuration, stored in the clear.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use s3fs_core::MasterSecret;

use super::{MasterKeySource, SealedKey};

/// Marks a blob that is not sealed at all, so that nothing can mistake one for
/// protection, and so a real source can refuse to open one.
const UNSEALED_MAGIC: &[u8] = b"s3fs-UNSEALED-development-key-v1\n";

/// A secret supplied by configuration, stored in the clear.
///
/// The development seam. `mint` uses the configured secret rather than drawing
/// a fresh one, so a test can predict the filesystem it creates; `open`
/// returns whatever the blob holds, so resume genuinely recovers from stored
/// state rather than from configuration that might since have changed.
pub struct StaticKey(MasterSecret);

impl StaticKey {
    pub fn from_hex(hex: &str) -> Result<Self> {
        MasterSecret::from_hex(hex)
            .map(StaticKey)
            .map_err(|e| anyhow::anyhow!("master key: {e}"))
    }

    pub fn new(secret: MasterSecret) -> Self {
        StaticKey(secret)
    }
}

/// Opaque: a `Debug` that printed the secret would leak it into any log line
/// that formats a struct containing one.
impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticKey(<redacted>)")
    }
}

#[async_trait]
impl MasterKeySource for StaticKey {
    fn describe(&self) -> &'static str {
        "static, UNSEALED (development only)"
    }

    async fn mint(&self) -> Result<(MasterSecret, SealedKey)> {
        let mut blob = UNSEALED_MAGIC.to_vec();
        blob.extend_from_slice(self.0.expose_secret());
        Ok((self.0.clone(), SealedKey(blob)))
    }

    async fn open(&self, sealed: &SealedKey) -> Result<MasterSecret> {
        let bytes = sealed.as_bytes();
        // Refuse anything this source did not write. A blob sealed by KMS
        // opened here would either fail confusingly or, worse, be misread as
        // key material — so the shape is checked before anything else.
        if !bytes.starts_with(UNSEALED_MAGIC) {
            bail!(
                "this filesystem's key was sealed by something else — a static \
                 key source cannot open it. That is the expected outcome of \
                 pointing a development build at a real deployment."
            );
        }
        let raw = &bytes[UNSEALED_MAGIC.len()..];
        let raw: [u8; 32] = raw
            .try_into()
            .context("unsealed key blob is not 32 bytes after its marker")?;
        Ok(MasterSecret::from_bytes(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> StaticKey {
        StaticKey::new(MasterSecret::from_bytes([5u8; 32]))
    }

    #[tokio::test]
    async fn a_minted_key_opens_back_to_itself() {
        let source = key();
        let (secret, sealed) = source.mint().await.unwrap();
        assert_eq!(
            source.open(&sealed).await.unwrap().expose_secret(),
            secret.expose_secret()
        );
    }

    /// Resume recovers from the *blob*, not from configuration. A deployment
    /// whose `S3FS_MASTER_KEY` has drifted must still open the filesystem it
    /// created, or the drift would be discovered as unreadable data.
    #[tokio::test]
    async fn opening_uses_the_blob_rather_than_the_configured_secret() {
        let (_, sealed) = key().mint().await.unwrap();
        let different = StaticKey::new(MasterSecret::from_bytes([99u8; 32]));
        assert_eq!(
            different.open(&sealed).await.unwrap().expose_secret(),
            &[5u8; 32]
        );
    }

    /// The marker exists so a development build cannot quietly mishandle a
    /// real deployment's key blob.
    #[tokio::test]
    async fn a_blob_from_another_source_is_refused() {
        let err = key()
            .open(&SealedKey::from_bytes(b"KMS-shaped ciphertext".to_vec()))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("sealed by something else"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_truncated_blob_is_refused_rather_than_padded() {
        let mut short = UNSEALED_MAGIC.to_vec();
        short.extend_from_slice(&[1u8; 16]);
        assert!(key().open(&SealedKey::from_bytes(short)).await.is_err());
    }

    /// A `Debug` that rendered the blob would print a master key, because for
    /// this source the blob *is* the key.
    #[test]
    fn the_sealed_form_never_debug_prints_its_contents() {
        let blob = SealedKey::from_bytes(b"a very secret value".to_vec());
        let rendered = format!("{blob:?}");
        assert!(!rendered.contains("secret value"), "{rendered}");
        assert!(rendered.contains("sha256"), "{rendered}");
    }

    #[test]
    fn the_commitment_is_over_the_ciphertext() {
        let blob = SealedKey::from_bytes(b"abc".to_vec());
        assert_eq!(blob.sha256(), nitro_attestation::sha256(b"abc"));
    }
}
