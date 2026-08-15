//! Where the master secret comes from.
//!
//! One method, so that swapping a hex string on the command line for a
//! `kms:Decrypt` gated on an NSM attestation document is a new implementation
//! rather than a refactor. Everything downstream — key derivation, the on-disk
//! format, the root signatures — is identical either way, which was the point
//! of shaping [`s3fs_core::crypto::KeyMaterial`] to take 32 bytes and not care
//! where they came from.

use anyhow::Result;
use async_trait::async_trait;
use s3fs_core::MasterSecret;

#[async_trait]
pub trait MasterKeySource: Send + Sync + std::fmt::Debug {
    /// A short description for startup logging. Must not reveal key material.
    fn describe(&self) -> &'static str;

    async fn master_secret(&self) -> Result<MasterSecret>;
}

/// A secret supplied by configuration.
///
/// A development seam. A key passed on the command line or through an
/// environment variable is visible to the parent instance, which is exactly
/// the party an enclave exists to exclude — so this is not what a real
/// deployment uses.
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
        "static (from configuration)"
    }

    async fn master_secret(&self) -> Result<MasterSecret> {
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_static_key_round_trips() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let source = StaticKey::from_hex(hex).unwrap();
        assert!(source.master_secret().await.is_ok());
        assert_eq!(source.describe(), "static (from configuration)");
    }

    #[test]
    fn a_bad_key_is_rejected_with_a_useful_message() {
        let err = StaticKey::from_hex("too short").unwrap_err();
        assert!(format!("{err}").contains("master key"));
        assert!(StaticKey::from_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn the_key_is_redacted_in_debug_output() {
        let source = StaticKey::from_hex(&"ab".repeat(32)).unwrap();
        let rendered = format!("{source:?}");
        assert_eq!(rendered, "StaticKey(<redacted>)");
        assert!(!rendered.contains("ab"));
    }
}
