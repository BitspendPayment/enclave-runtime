//! Registered passkeys, and the tenants they speak for.
//!
//! Records live in `/runtime/credentials/` on the pool — **outside every
//! tenant's directory**, so no guest can name them: a guest's only preopen is
//! its own `/tenants/<id>`, and `wasmtime-wasi` resolves nothing above it.
//!
//! Being on the pool at all is what makes them trustworthy. It is encrypted
//! under a key the host never sees and pinned by an anchor the boot checks,
//! so a host cannot add a credential, repoint one at another tenant, or
//! un-revoke one — nor roll back to before a revocation — without the boot
//! refusing the pool.
//!
//! ## The tenant id is derived from the credential id
//!
//! [`tenant_of`]: nothing to mint and nothing to store. It was once sixteen
//! random bytes from the NSM, so that a host could not predict a tenant's
//! directory and create it first. On the pool a host cannot create anything,
//! and a guest can name nothing but its own directory, so an unpredictable
//! name protects nothing.
//!
//! A credential id is registered once (`create_new`) and kept when revoked,
//! so it names one tenant forever. The cost is that a passkey *is* its tenant:
//! a replacement passkey starts with an empty directory. A synced passkey is
//! the same credential on every device, so a new phone is not a new passkey.
//! When rotation is built, an optional per-record override names an existing
//! tenant, and a record without one keeps deriving — nothing on disk changes.
//!
//! ## Why the sign counter is not persisted per request
//!
//! The counter exists to spot a cloned authenticator. Writing it on every
//! request would put an anchor — a pool sync and a write to S3 — in the path
//! of every signature, to record a number that platform
//! passkeys synced through iCloud or Google report as zero forever.
//!
//! So it is held in memory, checked for regression while the process lives,
//! and logged when it moves backwards. A restart forgets it, which loses the
//! ability to detect a clone *across* restarts and costs nothing else. That is
//! a deliberate trade rather than an omission; if counters ever become
//! meaningful for the authenticators in use, persisting them is a small change
//! and this comment is where to start.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use webauthn_rs::prelude::Passkey;

use crate::auth::gate::{CredentialRecord, CredentialStore};
use crate::zfs::Zfs;

/// Registered credentials, one file each, under `/runtime`.
pub const CREDENTIALS_DIR: &str = "credentials";

/// Ceiling on a record. A `Passkey` is a few hundred bytes; this is loose
/// enough never to bite and tight enough that a corrupt entry cannot be read
/// into unbounded memory.
const MAX_RECORD_BYTES: usize = 8 * 1024;

/// A credential as it is stored.
///
/// Versioned because it is on-disk and outlives the code that wrote it: an
/// unknown version has to be a refusal rather than a misparse of key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub version: u32,
    pub passkey: Passkey,
    /// Revoked credentials are kept, not deleted. A lost phone's key must be
    /// refused *by name*; forgetting it would mean the same credential could
    /// simply register again.
    pub active: bool,
    pub created_ms: u64,
    pub counter: u32,
}

/// 2: the tenant id is derived, not stored. A version-1 record carries a
/// minted one, and is refused rather than quietly given a different directory.
pub(crate) const RECORD_VERSION: u32 = 2;

/// Credentials on the pool, with the volatile parts in memory.
pub struct FilesystemCredentials {
    zfs: Arc<Zfs>,
    /// Records read from the pool, plus the counters that are not written
    /// back. Also the invalidation point: revocation updates both.
    cache: Mutex<HashMap<Vec<u8>, CredentialRecord>>,
}

impl FilesystemCredentials {
    pub fn new(zfs: Arc<Zfs>) -> Self {
        FilesystemCredentials {
            zfs,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn path(&self, credential_id: &[u8]) -> Result<PathBuf> {
        Ok(self
            .zfs
            .runtime_dir(CREDENTIALS_DIR)
            .await?
            .join(hex::encode(credential_id)))
    }

    fn encode(record: &StoredCredential) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(record, &mut bytes).context("encoding a credential record")?;
        anyhow::ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "credential record is {} bytes, over the {MAX_RECORD_BYTES} limit",
            bytes.len()
        );
        Ok(bytes)
    }

    /// Write a credential, refusing to overwrite one that exists.
    ///
    /// `create_new`, so a second registration of the same credential id is an
    /// error rather than a silent repointing — which is what taking over
    /// somebody else's tenant would look like.
    pub async fn register(&self, credential_id: &[u8], record: StoredCredential) -> Result<()> {
        let path = self.path(credential_id).await?;
        let bytes = Self::encode(&record)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .with_context(|| format!("creating {}", path.display()))?;
        file.write_all(&bytes)
            .await
            .context("writing a credential record")?;
        drop(file);
        // Anchored before the caller is told it is registered: a registration
        // the anchor did not cover would be a passkey the user believes works
        // and the next boot has never heard of.
        self.zfs
            .anchor_control()
            .await
            .context("anchoring a credential record")?;

        self.cache.lock().expect("credentials poisoned").insert(
            credential_id.to_vec(),
            CredentialRecord {
                tenant_id: tenant_of(credential_id),
                passkey: record.passkey,
                active: record.active,
                counter: record.counter,
            },
        );
        Ok(())
    }

    /// Mark a credential unusable, on the pool and in memory.
    pub async fn revoke(&self, credential_id: &[u8]) -> Result<()> {
        let mut stored = self
            .read(credential_id)
            .await?
            .context("no such credential")?;
        stored.active = false;
        tokio::fs::write(self.path(credential_id).await?, Self::encode(&stored)?)
            .await
            .context("writing a credential record")?;
        // A revocation a rewind could undo is not one.
        self.zfs
            .anchor_control()
            .await
            .context("anchoring a revocation")?;
        // The cache is what the gate reads, so it must not outlive the
        // decision to revoke by even one request.
        if let Some(cached) = self
            .cache
            .lock()
            .expect("credentials poisoned")
            .get_mut(credential_id)
        {
            cached.active = false;
        }
        Ok(())
    }

    async fn read(&self, credential_id: &[u8]) -> Result<Option<StoredCredential>> {
        let path = self.path(credential_id).await?;
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        anyhow::ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "credential record {} is over the {MAX_RECORD_BYTES} limit",
            path.display()
        );
        let stored: StoredCredential =
            ciborium::from_reader(bytes.as_slice()).context("decoding a credential record")?;
        anyhow::ensure!(
            stored.version == RECORD_VERSION,
            "credential record is version {}, this build understands {RECORD_VERSION}",
            stored.version
        );
        Ok(Some(stored))
    }
}

#[async_trait::async_trait]
impl CredentialStore for FilesystemCredentials {
    async fn lookup(&self, credential_id: &[u8]) -> Result<Option<CredentialRecord>> {
        if let Some(hit) = self
            .cache
            .lock()
            .expect("credentials poisoned")
            .get(credential_id)
        {
            return Ok(Some(hit.clone()));
        }
        let Some(stored) = self.read(credential_id).await? else {
            return Ok(None);
        };
        let record = CredentialRecord {
            tenant_id: tenant_of(credential_id),
            passkey: stored.passkey,
            active: stored.active,
            counter: stored.counter,
        };
        self.cache
            .lock()
            .expect("credentials poisoned")
            .insert(credential_id.to_vec(), record.clone());
        Ok(Some(record))
    }

    async fn record_use(&self, credential_id: &[u8], counter: u32) -> Result<()> {
        let mut cache = self.cache.lock().expect("credentials poisoned");
        let Some(record) = cache.get_mut(credential_id) else {
            return Ok(());
        };
        // Zero means the authenticator does not keep one — which is what a
        // synced platform passkey reports — so it says nothing either way and
        // is not a regression.
        if counter != 0 && counter <= record.counter {
            tracing::warn!(
                credential = %hex::encode(&credential_id[..8.min(credential_id.len())]),
                stored = record.counter,
                presented = counter,
                "authenticator sign counter did not advance; this can mean a cloned \
                 credential and is recorded rather than acted on, because the policy for \
                 it has to be a deliberate decision"
            );
        }
        record.counter = record.counter.max(counter);
        Ok(())
    }
}

/// The tenant a credential speaks for: the first sixteen bytes of
/// `sha256("enclave/tenant/v1" || credential_id)`.
///
/// Every tenant's dataset is named by this, so changing it strands them all;
/// `tenant_of_is_pinned` is what notices.
pub fn tenant_of(credential_id: &[u8]) -> [u8; 16] {
    let digest =
        nitro_attestation::sha256(&[b"enclave/tenant/v1".as_slice(), credential_id].concat());
    digest[..16].try_into().expect("16 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::{Relying, RP_ID};
    use crate::auth::SoftwareAuthenticator;

    async fn shared_fs() -> Arc<Zfs> {
        Zfs::scratch().await
    }

    fn stored(passkey: Passkey) -> StoredCredential {
        StoredCredential {
            version: RECORD_VERSION,
            passkey,
            active: true,
            created_ms: 0,
            counter: 0,
        }
    }

    async fn registered() -> (
        Arc<Zfs>,
        FilesystemCredentials,
        SoftwareAuthenticator,
        [u8; 16],
    ) {
        let fs = shared_fs().await;
        let store = FilesystemCredentials::new(fs.clone());
        let rp = Relying::new();
        let auth = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&auth);
        store
            .register(auth.credential_id(), stored(passkey))
            .await
            .expect("registering");
        let tenant_id = tenant_of(auth.credential_id());
        (fs, store, auth, tenant_id)
    }

    /// A record written on one boot is readable on the next: the point of
    /// putting it in the anchored filesystem rather than in memory.
    #[tokio::test]
    async fn a_credential_survives_a_restart() {
        let (fs, _store, auth, tenant_id) = registered().await;

        // A second store over the same filesystem, with an empty cache — as
        // close to a restart as this gets without a second process.
        let after = FilesystemCredentials::new(fs);
        let found = after
            .lookup(auth.credential_id())
            .await
            .unwrap()
            .expect("the credential is still there");
        assert_eq!(found.tenant_id, tenant_id);
        assert!(found.active);
    }

    #[tokio::test]
    async fn an_unregistered_credential_is_absent_rather_than_an_error() {
        let fs = shared_fs().await;
        let store = FilesystemCredentials::new(fs);
        assert!(store.lookup(&[0xff; 32]).await.unwrap().is_none());
    }

    /// Registering the same credential twice must not silently repoint it —
    /// that is what taking over somebody else's tenant would look like.
    #[tokio::test]
    async fn a_credential_cannot_be_registered_over() {
        let (_fs, store, auth, _) = registered().await;
        let rp = Relying::new();
        let other = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&other);
        assert!(store
            .register(auth.credential_id(), stored(passkey))
            .await
            .is_err());
    }

    /// Revocation must be visible immediately — the gate reads the cache, and
    /// a cache that outlived the decision by even one request would be one
    /// more signature from a lost phone.
    #[tokio::test]
    async fn revocation_takes_effect_at_once_and_survives_a_restart() {
        let (fs, store, auth, _) = registered().await;
        assert!(
            store
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .active
        );

        store.revoke(auth.credential_id()).await.unwrap();
        assert!(
            !store
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .active
        );

        let after = FilesystemCredentials::new(fs);
        assert!(
            !after
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .active
        );
    }

    /// Every tenant's dataset is named by this value. A change here is every
    /// tenant waking up to an empty directory, so it has to be deliberate.
    #[test]
    fn tenant_of_is_pinned() {
        assert_eq!(
            hex::encode(tenant_of(b"credential")),
            "a0e215ab9e6d4fc553fe89c4d78b844f"
        );
    }

    /// A version-1 record carries a minted tenant id this build no longer
    /// reads. Refused, rather than quietly given a derived one, which would be
    /// a different directory.
    #[tokio::test]
    async fn a_version_1_record_is_refused() {
        let fs = shared_fs().await;
        let store = FilesystemCredentials::new(fs);
        let auth = SoftwareAuthenticator::new(RP_ID);
        let old = StoredCredential {
            version: 1,
            ..stored(Relying::new().register(&auth))
        };
        tokio::fs::write(
            store.path(auth.credential_id()).await.unwrap(),
            FilesystemCredentials::encode(&old).unwrap(),
        )
        .await
        .unwrap();
        assert!(store.lookup(auth.credential_id()).await.is_err());
    }

    /// A counter that does not advance is recorded, not fatal — a synced
    /// passkey reports zero forever and must keep working.
    #[tokio::test]
    async fn a_zero_counter_is_not_treated_as_a_regression() {
        let (_fs, store, auth, _) = registered().await;
        store.record_use(auth.credential_id(), 5).await.unwrap();
        store.record_use(auth.credential_id(), 0).await.unwrap();
        // Never moves backwards, and the credential stays usable.
        assert_eq!(
            store
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .counter,
            5
        );
        assert!(
            store
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .active
        );
    }

    /// Records are runtime-owned and sit outside every tenant's directory, so
    /// no guest preopen reaches them. This asserts the location, which is what
    /// that guarantee rests on.
    #[tokio::test]
    async fn credentials_live_outside_every_tenant_directory() {
        let (zfs, _store, auth, tenant_id) = registered().await;
        let record = zfs
            .runtime_dir(CREDENTIALS_DIR)
            .await
            .unwrap()
            .join(hex::encode(auth.credential_id()));
        assert!(record.exists());

        let (tenant, _) = zfs.tenant_dir(tenant_id).await.unwrap();
        assert!(
            !record.starts_with(&tenant),
            "a tenant's directory contains the credentials"
        );
    }
}
