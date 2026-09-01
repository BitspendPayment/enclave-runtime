//! Who is allowed to become a tenant in the first place.
//!
//! Registering a passkey creates a tenant, and a tenant is storage the enclave
//! will keep and serve. Left open, anyone who can reach the port could mint
//! them without limit — so enrollment is gated by a single-use token the
//! operator provisions out of band.
//!
//! ## What a token does and does not authorize
//!
//! It authorizes **creating a new tenant**, and nothing else. It cannot reach
//! an existing tenant's data, approve a transaction, or add a passkey to
//! somebody else's account — those need an assertion from a credential already
//! registered to that tenant.
//!
//! That distinction is what makes the mechanism sound despite an uncomfortable
//! fact: inside an enclave, a token supplied by configuration reaches the
//! runtime through the parent instance, which is the party the enclave exists
//! to exclude. A parent that steals a token can create a tenant of its own. It
//! still cannot read anyone else's, because reading requires a passkey the
//! parent does not hold. Enrollment gates resource creation; passkeys gate
//! access. Conflating the two would be the mistake.
//!
//! Tokens are stored hashed, so the file that records one does not let its
//! holder use it — the same reason a password file stores hashes.

use std::sync::Arc;

use anyhow::{Context, Result};
use s3fs_core::{Fs, FsError, OpenFlags};

use crate::auth::credential::RUNTIME_DIR;
use crate::tenant::ensure_dir;

/// Where used and unused tokens live.
pub const ENROLLMENT_DIR: &str = "enrollment";

/// Enrollment tokens, single use.
pub struct EnrollmentTokens {
    fs: Arc<Fs>,
}

impl EnrollmentTokens {
    pub fn new(fs: Arc<Fs>) -> Self {
        EnrollmentTokens { fs }
    }

    fn name(token: &str) -> String {
        // Hashed, so possession of the store is not possession of a token.
        hex::encode(nitro_attestation::sha256(token.trim().as_bytes()))
    }

    fn path(token: &str) -> String {
        format!("/{RUNTIME_DIR}/{ENROLLMENT_DIR}/{}", Self::name(token))
    }

    async fn dir(&self) -> Result<()> {
        let root = self.fs.root();
        let runtime = ensure_dir(&self.fs, &root, RUNTIME_DIR).await?;
        ensure_dir(&self.fs, &runtime, ENROLLMENT_DIR).await?;
        Ok(())
    }

    /// Make a token usable once.
    ///
    /// Idempotent: seeding the same token twice leaves one usable token, so a
    /// restart with the same configuration does not accumulate them.
    pub async fn seed(&self, token: &str) -> Result<()> {
        anyhow::ensure!(
            token.trim().len() >= 16,
            "an enrollment token shorter than 16 characters is guessable"
        );
        self.dir().await?;
        let path = Self::path(token);
        match self.fs.open(&path, OpenFlags::create_new()).await {
            Ok(handle) => {
                self.fs
                    .sync(&handle)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
                    .context("committing an enrollment token")?;
                self.fs
                    .close(&handle)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
                    .context("closing an enrollment token")?;
                Ok(())
            }
            Err(FsError::AlreadyExists) => Ok(()),
            Err(e) => Err(anyhow::anyhow!(e)).context("seeding an enrollment token"),
        }
    }

    /// Spend a token. `false` means it was never valid, or has been used.
    ///
    /// Removal is the whole mechanism, and it happens before the caller is
    /// told it succeeded: two registrations racing on one token must not both
    /// get a tenant, and `unlink` under the filesystem's transaction is what
    /// decides which one does.
    pub async fn spend(&self, token: &str) -> Result<bool> {
        let root = self.fs.root();
        let Ok(runtime) = self.fs.lookup_at(&root, RUNTIME_DIR).await else {
            return Ok(false);
        };
        let Ok(dir) = self.fs.lookup_at(&runtime, ENROLLMENT_DIR).await else {
            return Ok(false);
        };
        match self.fs.unlink(&dir, &Self::name(token)).await {
            Ok(()) => Ok(true),
            Err(FsError::NotFound) => Ok(false),
            Err(e) => Err(anyhow::anyhow!(e)).context("spending an enrollment token"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, MasterSecret};

    async fn tokens() -> EnrollmentTokens {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([7u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .expect("filesystem");
        EnrollmentTokens::new(fs)
    }

    #[tokio::test]
    async fn a_token_works_once() {
        let t = tokens().await;
        t.seed("an-invite-code-long-enough").await.unwrap();
        assert!(t.spend("an-invite-code-long-enough").await.unwrap());
        assert!(!t.spend("an-invite-code-long-enough").await.unwrap());
    }

    #[tokio::test]
    async fn an_unknown_token_is_refused_rather_than_erroring() {
        let t = tokens().await;
        assert!(!t.spend("never-seeded-but-long-enough").await.unwrap());
    }

    /// A restart with the same configuration must not pile up tokens.
    #[tokio::test]
    async fn seeding_twice_leaves_one_token() {
        let t = tokens().await;
        t.seed("an-invite-code-long-enough").await.unwrap();
        t.seed("an-invite-code-long-enough").await.unwrap();
        assert!(t.spend("an-invite-code-long-enough").await.unwrap());
        assert!(!t.spend("an-invite-code-long-enough").await.unwrap());
    }

    /// A short token is guessable, and a guessable enrollment token is an open
    /// door to minting tenants.
    #[tokio::test]
    async fn a_short_token_is_refused() {
        let t = tokens().await;
        assert!(t.seed("short").await.is_err());
    }

    /// The stored name must not be the token: whoever can read the store must
    /// not thereby be able to spend it.
    #[tokio::test]
    async fn the_token_is_not_stored_in_the_clear() {
        let t = tokens().await;
        let token = "an-invite-code-long-enough";
        t.seed(token).await.unwrap();
        assert!(
            !EnrollmentTokens::name(token).contains("invite"),
            "the token appears in its own filename"
        );
    }
}
