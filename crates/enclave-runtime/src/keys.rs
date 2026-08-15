//! Where the master secret comes from, and where it goes.
//!
//! Two operations, not one, because genesis and resume are different
//! questions. Genesis **mints** a secret that has never existed before and
//! hands back the sealed form for the caller to persist; resume **opens** the
//! blob that a previous genesis wrote. A single `master_secret()` could not
//! express the difference, and the difference is the point: a filesystem's key
//! is created once, with it, and recovered every time after.
//!
//! ## Why the secret belongs to the stored state
//!
//! It used to arrive as `S3FS_MASTER_KEY`, from the parent instance. A parent
//! that supplies the key *has* the key, and can decrypt the whole filesystem —
//! so the party an enclave exists to exclude held the only thing that mattered.
//! No amount of boot verification fixes that: an enclave could prove perfectly
//! that it had loaded genuine state while the host read that state over its
//! shoulder.
//!
//! Minting inside the enclave and persisting only the sealed form is what
//! closes it. The plaintext exists in enclave memory and nowhere else.
//!
//! ## What is not built yet
//!
//! [`StaticKey`] seals by *not* sealing: it writes the secret into the blob
//! behind a marker that says so. That is enough to exercise every boot mode —
//! genesis, resume, migration and all four refusals — without hardware, and it
//! is what the QEMU harness uses. It is not protection, and it does not
//! pretend to be.
//!
//! Real sealing needs KMS: `Decrypt` with a `Recipient` carrying an
//! attestation document, under a key policy conditioned on
//! `kms:RecipientAttestation:PCR0`. That is where *"only the correct enclave
//! boots"* is actually enforced — a wrong enclave does not get a refused
//! mount, it gets no key at all — and it is the next implementation of this
//! trait. Nothing above this file changes when it lands.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use s3fs_core::MasterSecret;

/// A master secret in the form that is safe to store.
///
/// Opaque bytes: what is inside depends on which [`MasterKeySource`] produced
/// it, and no caller should look. A state-origin receipt commits to
/// `sha256(bytes)` — never the plaintext, because the receipt is readable by
/// anyone who can read the bucket it sits in.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedKey(Vec<u8>);

impl SealedKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        SealedKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// What a receipt commits to.
    pub fn sha256(&self) -> [u8; 32] {
        nitro_attestation::sha256(&self.0)
    }
}

/// Never print the blob. For [`StaticKey`] it *is* the secret, and a `Debug`
/// that rendered it would put a master key in any log line that formats a
/// struct containing one.
impl std::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SealedKey({} bytes, sha256 {})",
            self.0.len(),
            hex::encode(&self.sha256()[..8])
        )
    }
}

#[async_trait]
pub trait MasterKeySource: Send + Sync + std::fmt::Debug {
    /// A short description for startup logging. Must not reveal key material.
    fn describe(&self) -> &'static str;

    /// Create a secret that has never existed before, and return it with the
    /// form the caller must persist.
    ///
    /// Only genesis calls this. Calling it against a filesystem that already
    /// exists would produce a key that cannot read it.
    async fn mint(&self) -> Result<(MasterSecret, SealedKey)>;

    /// Recover the secret from a blob a previous genesis wrote.
    async fn open(&self, sealed: &SealedKey) -> Result<MasterSecret>;
}

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
