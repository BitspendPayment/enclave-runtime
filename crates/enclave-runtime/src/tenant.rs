//! One filesystem, one directory per client, and a `/` that means different
//! things to different guests.
//!
//! Every client's data lives under `/tenants/<derived-id>/` in the runtime's
//! single mounted filesystem. There is one `Fs`, one `BlockStore`, one block
//! cache and one transaction stream — a client costs a directory, not a mount.
//!
//! ## Where the separation actually is
//!
//! Not in the guest. A tenant's instance is handed its own directory as its
//! preopen, and [`s3fs_core::Fs::lookup_within`] refuses every way a path can
//! name something above it: absolute paths restart at the tenant's root rather
//! than the filesystem's, `..` stops there, and an absolute symlink target
//! resolves from there too. A guest that tries `/tenants/other/secret` gets
//! its own `tenants/other/secret`, which does not exist.
//!
//! That is a capability, not a convention, and it is why this is safe to do
//! with a shared filesystem at all.
//!
//! ## Why the identifier is derived
//!
//! `HKDF(master, sha256(client SPKI))`, so it need never be stored or looked
//! up: the same client lands on the same directory on every boot, from nothing
//! but the TLS handshake. Unguessable without the master secret, so holding a
//! client's certificate does not tell an outsider which directory is theirs.
//!
//! ## Why there is no separate register
//!
//! An earlier design gave each client their own filesystem, and then needed a
//! register to answer "should this client have one?" — because a host who hid
//! a client's root record would otherwise get a fresh, empty filesystem built
//! for them, resetting their policy and emptying their nonce ledger.
//!
//! With one filesystem that question answers itself. `/tenants/<id>` either
//! exists in the Merkle tree or it does not, the tree is covered by one signed
//! root record, and that record is attested by the state-origin receipt at
//! boot. Hiding one client's directory means changing the root hash, which
//! fails the signature before any request is served. **The filesystem is the
//! register.**

use std::sync::Arc;

use anyhow::{Context, Result};
use s3fs_core::{Fs, FsError, Inode};

/// The directory holding every tenant's subtree.
const TENANTS_DIR: &str = "tenants";

/// A client's arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// Their directory was already there.
    Returning,
    /// First contact: it was created.
    New,
}

/// A client's own directory, and how they arrived at it.
#[derive(Debug, Clone)]
pub struct TenantRoot {
    pub scope: Arc<Inode>,
    pub tenant_id: [u8; 16],
    pub arrival: Arrival,
}

/// Find or create a client's directory in the shared filesystem.
///
/// Cheap by construction: a lookup, and on first contact one `mkdir`. There is
/// no mount, no key derivation for a second filesystem, and no root record to
/// read — the costs the per-filesystem design would have paid on every cold
/// client.
/// Find or create a tenant's directory.
///
/// Registration mints an id and needs the directory for it; a request resolves
/// an id from a verified assertion and needs the same. One function, so the two
/// cannot disagree about where a tenant lives.
///
/// Cheap by construction: a lookup, and on first contact one `mkdir`. No mount,
/// no key derivation, no root record to read.
pub async fn tenant_root_by_id(fs: &Arc<Fs>, tenant_id: [u8; 16]) -> Result<TenantRoot> {
    let name = hex::encode(tenant_id);
    let root = fs.root();
    let parent = ensure_dir(fs, &root, TENANTS_DIR).await?;

    // Looked up before it is created, so an arrival can be reported honestly:
    // "new" means this runtime had never seen the tenant, which is worth a log
    // line and, later, worth a policy.
    let arrival = match fs.lookup_at(&parent, &name).await {
        Ok(_) => Arrival::Returning,
        Err(FsError::NotFound) => Arrival::New,
        Err(e) => return Err(anyhow::anyhow!(e)).context("opening a tenant directory"),
    };
    let scope = ensure_dir(fs, &parent, &name).await?;
    Ok(TenantRoot {
        scope,
        tenant_id,
        arrival,
    })
}

/// Open a directory, creating it if it is not there.
///
/// `AlreadyExists` is success, not failure: two requests racing to first
/// contact both want the same directory, and whichever loses should find what
/// the winner made rather than report a conflict nobody caused.
pub async fn ensure_dir(fs: &Arc<Fs>, parent: &Arc<Inode>, name: &str) -> Result<Arc<Inode>> {
    match fs.lookup_at(parent, name).await {
        Ok(dir) => Ok(dir),
        Err(FsError::NotFound) => match fs.mkdir(parent, name).await {
            Ok(dir) => Ok(dir),
            Err(FsError::AlreadyExists) => fs
                .lookup_at(parent, name)
                .await
                .map_err(|e| anyhow::anyhow!(e))
                .with_context(|| format!("opening {name} after losing the race to create it")),
            Err(e) => Err(anyhow::anyhow!(e)).with_context(|| format!("creating {name}")),
        },
        Err(e) => Err(anyhow::anyhow!(e)).with_context(|| format!("opening {name}")),
    }
}

/// Every client with a directory. Diagnostics, and a future sweeper.
pub async fn tenants(fs: &Arc<Fs>) -> Result<Vec<String>> {
    let root = fs.root();
    let dir = match fs.lookup_at(&root, TENANTS_DIR).await {
        Ok(dir) => dir,
        Err(FsError::NotFound) => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!(e)).context("opening the tenants directory"),
    };
    Ok(fs
        .read_dir(&dir)
        .await
        .map_err(|e| anyhow::anyhow!(e))
        .context("listing tenants")?
        .into_iter()
        .map(|e| e.name)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, MasterSecret};

    async fn shared_fs() -> Arc<Fs> {
        let backend = Arc::new(MemoryBackend::new());
        Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([7u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .expect("the shared filesystem")
    }

    /// A returning client lands where it left its data. If this were not
    /// stable their state would look lost on every request.
    #[tokio::test]
    async fn a_client_returns_to_the_same_directory() {
        let fs = shared_fs().await;
        let first = tenant_root_by_id(&fs, [0xab; 16]).await.unwrap();
        let second = tenant_root_by_id(&fs, [0xab; 16]).await.unwrap();

        assert_eq!(first.tenant_id, second.tenant_id);
        assert_eq!(first.scope.objid(), second.scope.objid());
        assert_eq!(first.arrival, Arrival::New);
        assert_eq!(second.arrival, Arrival::Returning);
    }

    #[tokio::test]
    async fn two_clients_get_two_directories() {
        let fs = shared_fs().await;
        let a = tenant_root_by_id(&fs, [0xaa; 16]).await.unwrap();
        let b = tenant_root_by_id(&fs, [0xbb; 16]).await.unwrap();
        assert_ne!(a.tenant_id, b.tenant_id);
        assert_ne!(a.scope.objid(), b.scope.objid());
    }

    /// A registration and a later request must land in the same directory, or
    /// a passkey would be registered against storage it could never reach.
    #[tokio::test]
    async fn registration_and_a_request_land_in_the_same_directory() {
        let fs = shared_fs().await;
        let at_registration = tenant_root_by_id(&fs, [0xcd; 16]).await.unwrap();
        let at_request = tenant_root_by_id(&fs, [0xcd; 16]).await.unwrap();
        assert_eq!(at_request.scope.objid(), at_registration.scope.objid());
        assert_eq!(at_registration.arrival, Arrival::New);
        assert_eq!(at_request.arrival, Arrival::Returning);
    }

    /// Losing the race to create a directory must not be an error: both
    /// callers want the same directory.
    #[tokio::test]
    async fn ensure_dir_is_idempotent() {
        let fs = shared_fs().await;
        let root = fs.root();
        let first = ensure_dir(&fs, &root, "runtime").await.unwrap();
        let second = ensure_dir(&fs, &root, "runtime").await.unwrap();
        assert_eq!(first.objid(), second.objid());
    }

    #[tokio::test]
    async fn tenants_are_listed_and_none_is_not_an_error() {
        let fs = shared_fs().await;
        assert!(tenants(&fs).await.unwrap().is_empty());

        let a = tenant_root_by_id(&fs, [0xaa; 16]).await.unwrap();
        let b = tenant_root_by_id(&fs, [0xbb; 16]).await.unwrap();
        let listed = tenants(&fs).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&hex::encode(a.tenant_id)));
        assert!(listed.contains(&hex::encode(b.tenant_id)));
    }

    /// Tenant directories sit under one parent, and that parent is above every
    /// tenant's scope — which is what keeps `/runtime/` unreachable from a
    /// guest too.
    #[tokio::test]
    async fn a_tenant_directory_is_not_the_filesystem_root() {
        let fs = shared_fs().await;
        let t = tenant_root_by_id(&fs, [0xab; 16]).await.unwrap();
        assert_ne!(t.scope.objid(), fs.root().objid());
    }
}
