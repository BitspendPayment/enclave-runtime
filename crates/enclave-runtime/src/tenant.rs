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
use s3fs_core::{Fs, FsError, Inode, MasterSecret};

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
pub async fn tenant_root(
    fs: &Arc<Fs>,
    master: &MasterSecret,
    client: &[u8; 32],
) -> Result<TenantRoot> {
    let tenant_id = master
        .derive_tenant_id(client)
        .map_err(|e| anyhow::anyhow!(e))
        .context("deriving the tenant id")?;
    let name = hex::encode(tenant_id);
    let root = fs.root();

    let parent = match fs.lookup_at(&root, TENANTS_DIR).await {
        Ok(dir) => dir,
        Err(FsError::NotFound) => match fs.mkdir(&root, TENANTS_DIR).await {
            Ok(dir) => dir,
            // Another client created it between the lookup and the mkdir.
            Err(FsError::AlreadyExists) => fs
                .lookup_at(&root, TENANTS_DIR)
                .await
                .map_err(|e| anyhow::anyhow!(e))
                .context("opening the tenants directory")?,
            Err(e) => return Err(anyhow::anyhow!(e)).context("creating the tenants directory"),
        },
        Err(e) => return Err(anyhow::anyhow!(e)).context("opening the tenants directory"),
    };

    match fs.lookup_at(&parent, &name).await {
        Ok(scope) => Ok(TenantRoot {
            scope,
            tenant_id,
            arrival: Arrival::Returning,
        }),
        Err(FsError::NotFound) => {
            let scope = match fs.mkdir(&parent, &name).await {
                Ok(scope) => scope,
                // Two first requests from one client raced. Either directory
                // is the same directory; take whichever is there now.
                Err(FsError::AlreadyExists) => fs
                    .lookup_at(&parent, &name)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
                    .context("opening a tenant directory")?,
                Err(e) => return Err(anyhow::anyhow!(e)).context("creating a tenant directory"),
            };
            Ok(TenantRoot {
                scope,
                tenant_id,
                arrival: Arrival::New,
            })
        }
        Err(e) => Err(anyhow::anyhow!(e)).context("opening a tenant directory"),
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
