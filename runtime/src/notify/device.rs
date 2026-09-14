//! Which devices a tenant can be woken on.
//!
//! A registration token is a capability: whoever holds one can wake that device
//! from anywhere, as this Firebase project. So tokens live at
//! `/runtime/devices/<tenant>/`, above every tenant scope and unreachable from
//! any guest — the same placement, and the same reason, as
//! [`crate::auth::credential`]. A guest enrols one and asks for a count; it
//! never reads one back.
//!
//! ## Why the filename is a hash
//!
//! A token's character set is Google's business and may widen. Naming the file
//! after the token would make path safety depend on a validator agreeing with
//! FCM forever; naming it `sha256(token)` makes the name safe by construction
//! and keeps the check that the record matches its own filename.
//!
//! ## Why the cap evicts instead of refusing
//!
//! At [`MAX_DEVICES_PER_TENANT`] a new enrolment drops the oldest rather than
//! failing. This is a cache of places a person can be reached, not a list of
//! credentials: somebody on their ninth phone must still be able to enrol it,
//! and the entry evicted is the one least likely to still be live. That is the
//! deliberate opposite of [`crate::auth::credential`], where a revoked passkey
//! is kept for ever so it can never be silently reinstated.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use s3fs_core::{Fs, FsError, Inode, InodeKind, OpenFlags};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::auth::credential::RUNTIME_DIR;
use crate::tenant::ensure_dir;

/// Where every tenant's devices live, one directory each.
pub const DEVICES_DIR: &str = "devices";

/// Devices one tenant may have enrolled at once.
pub const MAX_DEVICES_PER_TENANT: usize = 8;
/// Devices across every tenant, bounding what a recovery scan will load.
pub const MAX_DEVICES: usize = 4096;
/// An FCM registration token is ~160 characters today; these bound the shape
/// without pretending to know the format.
const MIN_TOKEN_LEN: usize = 32;
const MAX_TOKEN_LEN: usize = 512;
const MAX_RECORD: usize = 4 * 1024;
const RECORD_VERSION: u32 = 1;

/// One enrolled device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredDevice {
    /// An unknown version is a refusal, never a misparse.
    pub version: u32,
    /// Repeated inside the record so it can be checked against the directory
    /// the record was found in. Neither check is sufficient alone: the filename
    /// proves the token, the directory proves the owner.
    pub tenant: [u8; 16],
    pub token: String,
    pub created_ms: u64,
}

/// What the registry will hold. Injectable for the same reason `TaskLimits` is:
/// the caps are the interesting behaviour, and a test that had to write four
/// thousand records to reach one would not be written.
#[derive(Debug, Clone, Copy)]
pub struct DeviceLimits {
    pub max_devices: usize,
    pub per_tenant: usize,
}

impl Default for DeviceLimits {
    fn default() -> Self {
        DeviceLimits {
            max_devices: MAX_DEVICES,
            per_tenant: MAX_DEVICES_PER_TENANT,
        }
    }
}

/// Every tenant's devices, held in memory and backed by the filesystem.
///
/// Held in memory because the forwarder needs a tenant's tokens on every wake,
/// and a `read_dir` per wake is a filesystem transaction — in production an S3
/// round trip — in the path of a signal whose only value is being prompt.
pub struct DeviceRegistry {
    fs: Arc<Fs>,
    dir: Arc<Inode>,
    limits: DeviceLimits,
    devices: Mutex<BTreeMap<[u8; 16], Vec<StoredDevice>>>,
}

impl std::fmt::Debug for DeviceRegistry {
    /// Counts, never tokens. A token in a log line is a token in whatever reads
    /// that log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistry").finish_non_exhaustive()
    }
}

fn valid_token(token: &str) -> bool {
    (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

fn record_name(token: &str) -> String {
    hex::encode(nitro_attestation::sha256(token.as_bytes()))
}

fn is_hex(name: &str, len: usize) -> bool {
    name.len() == len
        && name
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl DeviceRegistry {
    pub async fn open(fs: Arc<Fs>) -> Result<Arc<Self>> {
        Self::open_with_limits(fs, DeviceLimits::default()).await
    }

    pub async fn open_with_limits(fs: Arc<Fs>, limits: DeviceLimits) -> Result<Arc<Self>> {
        anyhow::ensure!(
            limits.max_devices > 0 && limits.per_tenant > 0,
            "device limits must be positive"
        );
        let runtime = ensure_dir(&fs, &fs.root(), RUNTIME_DIR).await?;
        let dir = ensure_dir(&fs, &runtime, DEVICES_DIR).await?;
        let registry = Arc::new(DeviceRegistry {
            fs,
            dir,
            limits,
            devices: Mutex::new(BTreeMap::new()),
        });
        let loaded = registry.scan().await?;
        *registry.devices.lock().await = loaded;
        Ok(registry)
    }

    /// Read every published record back, refusing anything that does not
    /// account for itself.
    async fn scan(&self) -> Result<BTreeMap<[u8; 16], Vec<StoredDevice>>> {
        let mut devices: BTreeMap<[u8; 16], Vec<StoredDevice>> = BTreeMap::new();
        let mut total = 0usize;

        for tenant_entry in self.fs.read_dir(&self.dir).await? {
            ensure!(
                tenant_entry.kind == InodeKind::Directory && is_hex(&tenant_entry.name, 32),
                "unexpected entry {:?} under /{RUNTIME_DIR}/{DEVICES_DIR}",
                tenant_entry.name
            );
            let mut tenant = [0u8; 16];
            hex::decode_to_slice(&tenant_entry.name, &mut tenant)
                .context("decoding a tenant directory name")?;
            let tenant_dir = self
                .fs
                .lookup_at(&self.dir, &tenant_entry.name)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            for entry in self.fs.read_dir(&tenant_dir).await? {
                // A write interrupted before its rename. Nothing published it,
                // so nothing may read it.
                if entry.name.ends_with(".tmp") {
                    self.fs.unlink(&tenant_dir, &entry.name).await?;
                    continue;
                }
                total += 1;

                let path = format!(
                    "/{RUNTIME_DIR}/{DEVICES_DIR}/{}/{}",
                    tenant_entry.name, entry.name
                );
                let h = self.fs.open(&path, OpenFlags::read_only()).await?;
                let bytes = self.fs.pread(&h, 0, MAX_RECORD + 1).await;
                // Closed before the read is unwrapped, so a decode failure does
                // not leak a handle on every attempt.
                self.fs.close(&h).await?;
                let bytes = bytes?;
                ensure!(bytes.len() <= MAX_RECORD, "oversized device record");

                let device: StoredDevice =
                    serde_json::from_slice(&bytes).context("decoding a device record")?;
                ensure!(
                    device.version == RECORD_VERSION
                        && device.tenant == tenant
                        && valid_token(&device.token)
                        && record_name(&device.token) == entry.name,
                    "invalid device record at {path}"
                );
                devices.entry(tenant).or_default().push(device);
            }
        }

        // Oldest first, so eviction and reporting have one order to rely on.
        for list in devices.values_mut() {
            list.sort_by_key(|d| (d.created_ms, d.token.clone()));
        }

        // Over the cap, drop the oldest rather than refuse to start.
        //
        // A device record is a cache of where somebody can be reached, not work
        // that must not be lost — so unlike a task record, the right answer to
        // too many is to keep the newest and serve. Refusing would turn an
        // over-full store into one that can never be booted to fix, and a store
        // can be over-full legitimately: a lowered cap in a new image, or
        // records written before the cap was enforced on the way in.
        if total > self.limits.max_devices {
            let mut all: Vec<([u8; 16], u64, String)> = devices
                .iter()
                .flat_map(|(tenant, list)| {
                    list.iter()
                        .map(move |d| (*tenant, d.created_ms, d.token.clone()))
                })
                .collect();
            all.sort_by(|a, b| (a.1, &a.2).cmp(&(b.1, &b.2)));
            let excess = total - self.limits.max_devices;
            tracing::warn!(
                total,
                cap = self.limits.max_devices,
                dropping = excess,
                "the device store is over its cap; dropping the oldest records"
            );
            for (tenant, _, token) in all.into_iter().take(excess) {
                self.remove(tenant, &token).await?;
                if let Some(list) = devices.get_mut(&tenant) {
                    list.retain(|d| d.token != token);
                }
            }
            devices.retain(|_, list| !list.is_empty());
        }

        Ok(devices)
    }

    /// Publish a record: temp file, committed, then renamed into place.
    ///
    /// The rename is what makes the record visible, so a crash leaves either
    /// the old state or the new one and never a half-written record.
    async fn write(&self, device: &StoredDevice) -> Result<()> {
        let bytes = serde_json::to_vec(device)?;
        ensure!(bytes.len() <= MAX_RECORD, "device record exceeds its limit");

        let tenant_name = hex::encode(device.tenant);
        let tenant_dir = ensure_dir(&self.fs, &self.dir, &tenant_name).await?;
        let name = record_name(&device.token);
        let temp = format!("{name}.tmp");

        // Remove an unpublished write left by a cancelled host call.
        match self.fs.unlink(&tenant_dir, &temp).await {
            Ok(()) | Err(FsError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let path = format!("/{RUNTIME_DIR}/{DEVICES_DIR}/{tenant_name}/{temp}");
        let h = self.fs.open(&path, OpenFlags::create_new()).await?;
        let write = self.fs.pwrite(&h, 0, &bytes).await;
        let close = self.fs.close(&h).await;
        write?;
        close?; // close commits the complete contents before publication
        self.fs
            .rename(&tenant_dir, &temp, &tenant_dir, &name)
            .await?;
        Ok(())
    }

    async fn remove(&self, tenant: [u8; 16], token: &str) -> Result<()> {
        let tenant_name = hex::encode(tenant);
        let Ok(tenant_dir) = self.fs.lookup_at(&self.dir, &tenant_name).await else {
            return Ok(());
        };
        match self.fs.unlink(&tenant_dir, &record_name(token)).await {
            Ok(()) | Err(FsError::NotFound) => Ok(()),
            Err(e) => Err(anyhow::anyhow!(e)).context("removing a device record"),
        }
    }

    /// Enrol a token for this tenant.
    ///
    /// Enrolling a token the tenant already has is success and changes nothing,
    /// including its `created_ms`: a client that re-registers on every launch —
    /// which is what the FCM SDKs encourage — must not thereby keep itself at
    /// the front of the eviction queue for ever.
    pub async fn register(&self, tenant: [u8; 16], token: &str, now_ms: u64) -> Result<()> {
        ensure!(
            valid_token(token),
            "a registration token must be {MIN_TOKEN_LEN}-{MAX_TOKEN_LEN} characters of \
             letters, digits, '-', '_', ':' or '.'"
        );
        let mut devices = self.devices.lock().await;
        if devices
            .get(&tenant)
            .is_some_and(|list| list.iter().any(|d| d.token == token))
        {
            return Ok(());
        }

        // The global cap, enforced where the write happens — the same place
        // `tasks::enqueue` enforces `max_records`. Without it, enrolments this
        // call accepted could put the store past what a restart will load.
        let total: usize = devices.values().map(Vec::len).sum();
        ensure!(
            total < self.limits.max_devices,
            "the device store is full ({} records); devices must be forgotten \
             before another can enrol",
            self.limits.max_devices
        );

        let device = StoredDevice {
            version: RECORD_VERSION,
            tenant,
            token: token.to_string(),
            created_ms: now_ms,
        };
        self.write(&device).await?;

        let list = devices.entry(tenant).or_default();
        list.push(device);
        list.sort_by_key(|d| (d.created_ms, d.token.clone()));
        // Published first, evicted second: a crash between the two leaves one
        // device too many, which the next enrolment trims. The other order
        // could leave the tenant with nothing enrolled at all.
        while list.len() > self.limits.per_tenant {
            let evicted = list.remove(0);
            self.remove(tenant, &evicted.token).await?;
        }
        Ok(())
    }

    /// Forgetting a token this tenant does not have is success.
    ///
    /// A client that was pruned while it was offline is not wrong to ask.
    pub async fn forget(&self, tenant: [u8; 16], token: &str) -> Result<()> {
        let mut devices = self.devices.lock().await;
        self.remove(tenant, token).await?;
        if let Some(list) = devices.get_mut(&tenant) {
            list.retain(|d| d.token != token);
        }
        Ok(())
    }

    /// Remove a token only if it is still the record we failed to reach.
    ///
    /// The forwarder decides to prune and applies it later, and in between an
    /// interactive call may have re-enrolled the same token. Comparing
    /// `created_ms` makes that a no-op rather than deleting a live enrolment.
    pub async fn forget_if_unchanged(
        &self,
        tenant: [u8; 16],
        token: &str,
        created_ms: u64,
    ) -> Result<bool> {
        let mut devices = self.devices.lock().await;
        let Some(list) = devices.get_mut(&tenant) else {
            return Ok(false);
        };
        if !list
            .iter()
            .any(|d| d.token == token && d.created_ms == created_ms)
        {
            return Ok(false);
        }
        self.remove(tenant, token).await?;
        list.retain(|d| d.token != token);
        Ok(true)
    }

    /// What this tenant can be woken on, oldest first.
    pub async fn devices(&self, tenant: [u8; 16]) -> Vec<StoredDevice> {
        self.devices
            .lock()
            .await
            .get(&tenant)
            .cloned()
            .unwrap_or_default()
    }

    /// How many devices this tenant has enrolled. Never the tokens.
    pub async fn count(&self, tenant: [u8; 16]) -> u32 {
        self.devices
            .lock()
            .await
            .get(&tenant)
            .map(|l| l.len() as u32)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, MasterSecret};

    const ALICE: [u8; 16] = [1; 16];
    const BOB: [u8; 16] = [2; 16];

    fn token(seed: &str) -> String {
        format!("{seed}{}", "x".repeat(MIN_TOKEN_LEN))
    }

    async fn memory() -> Arc<Fs> {
        let backend = Arc::new(MemoryBackend::new());
        Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([5u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .expect("filesystem")
    }

    async fn registry() -> Arc<DeviceRegistry> {
        DeviceRegistry::open(memory().await).await.unwrap()
    }

    #[tokio::test]
    async fn a_device_registered_by_one_tenant_is_invisible_to_another() {
        let r = registry().await;
        r.register(ALICE, &token("alice"), 1000).await.unwrap();
        assert_eq!(r.count(ALICE).await, 1);
        assert_eq!(r.count(BOB).await, 0);
        assert!(r.devices(BOB).await.is_empty());
    }

    #[tokio::test]
    async fn registering_a_token_a_tenant_already_has_changes_nothing() {
        let r = registry().await;
        r.register(ALICE, &token("a"), 1000).await.unwrap();
        r.register(ALICE, &token("a"), 9999).await.unwrap();
        let devices = r.devices(ALICE).await;
        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].created_ms, 1000,
            "re-registering moved the device to the back of the eviction queue"
        );
    }

    #[tokio::test]
    async fn the_device_cap_evicts_the_oldest_rather_than_refusing_the_newest() {
        let r = registry().await;
        for i in 0..MAX_DEVICES_PER_TENANT {
            r.register(ALICE, &token(&format!("d{i}")), 1000 + i as u64)
                .await
                .unwrap();
        }
        r.register(ALICE, &token("newest"), 9000).await.unwrap();

        let devices = r.devices(ALICE).await;
        assert_eq!(devices.len(), MAX_DEVICES_PER_TENANT);
        assert!(
            devices.iter().any(|d| d.token == token("newest")),
            "the newest device was refused instead of admitted"
        );
        assert!(
            !devices.iter().any(|d| d.token == token("d0")),
            "the oldest device survived the cap"
        );
    }

    /// Accepting an enrolment past the cap would write a store that the next
    /// restart refuses to load — an enclave made unbootable by ordinary use.
    #[tokio::test]
    async fn an_enrolment_past_the_global_cap_is_refused_rather_than_written() {
        let r = DeviceRegistry::open_with_limits(
            memory().await,
            DeviceLimits {
                max_devices: 3,
                per_tenant: 8,
            },
        )
        .await
        .unwrap();
        r.register(ALICE, &token("a"), 1).await.unwrap();
        r.register(BOB, &token("b"), 2).await.unwrap();
        r.register(BOB, &token("c"), 3).await.unwrap();

        let err = r
            .register(ALICE, &token("d"), 4)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("full"), "unhelpful refusal: {err}");
        assert_eq!(
            r.count(ALICE).await,
            1,
            "a refused enrolment was still stored"
        );

        // Forgetting one makes room again.
        r.forget(BOB, &token("c")).await.unwrap();
        r.register(ALICE, &token("d"), 5).await.unwrap();
        assert_eq!(r.count(ALICE).await, 2);
    }

    /// A store can be over the cap legitimately — a lowered cap in a new image,
    /// or records written before the cap was enforced on the way in. Booting is
    /// what matters; these are cached addresses, not work.
    #[tokio::test]
    async fn a_store_over_its_cap_still_opens_and_drops_the_oldest() {
        let fs = memory().await;
        let roomy = DeviceRegistry::open_with_limits(
            fs.clone(),
            DeviceLimits {
                max_devices: 8,
                per_tenant: 8,
            },
        )
        .await
        .unwrap();
        for i in 0..6 {
            roomy
                .register(ALICE, &token(&format!("d{i}")), 1000 + i as u64)
                .await
                .unwrap();
        }
        drop(roomy);

        // The same store, reopened under a tighter cap.
        let tight = DeviceRegistry::open_with_limits(
            fs,
            DeviceLimits {
                max_devices: 2,
                per_tenant: 8,
            },
        )
        .await
        .expect("an over-full store must still open");
        let left = tight.devices(ALICE).await;
        assert_eq!(left.len(), 2, "the store was not trimmed to its cap");
        assert_eq!(
            left.iter().map(|d| d.created_ms).collect::<Vec<_>>(),
            vec![1004, 1005],
            "trimming kept the wrong records"
        );
    }

    #[tokio::test]
    async fn forgetting_a_token_that_is_not_there_is_success_not_an_error() {
        let r = registry().await;
        r.forget(ALICE, &token("never")).await.unwrap();
        r.register(ALICE, &token("a"), 1).await.unwrap();
        r.forget(ALICE, &token("other")).await.unwrap();
        assert_eq!(r.count(ALICE).await, 1);
    }

    #[tokio::test]
    async fn a_token_that_is_not_a_plausible_registration_token_is_refused() {
        let r = registry().await;
        assert!(r.register(ALICE, "short", 1).await.is_err());
        assert!(r
            .register(ALICE, &"x".repeat(MAX_TOKEN_LEN + 1), 1)
            .await
            .is_err());
        assert!(
            r.register(ALICE, &format!("has spaces{}", "x".repeat(40)), 1)
                .await
                .is_err(),
            "a token with a path-hostile character was accepted"
        );
        assert_eq!(r.count(ALICE).await, 0);
    }

    #[tokio::test]
    async fn a_token_reregistered_while_a_prune_was_in_flight_survives_it() {
        let r = registry().await;
        r.register(ALICE, &token("a"), 1000).await.unwrap();
        // The forwarder failed against the record created at 1000; by the time
        // it prunes, the client has re-enrolled and the record is newer.
        r.forget(ALICE, &token("a")).await.unwrap();
        r.register(ALICE, &token("a"), 5000).await.unwrap();

        assert!(!r
            .forget_if_unchanged(ALICE, &token("a"), 1000)
            .await
            .unwrap());
        assert_eq!(r.count(ALICE).await, 1, "a live re-enrolment was pruned");

        assert!(r
            .forget_if_unchanged(ALICE, &token("a"), 5000)
            .await
            .unwrap());
        assert_eq!(r.count(ALICE).await, 0);
    }

    #[tokio::test]
    async fn a_published_device_record_survives_a_fresh_filesystem_mount() {
        let backend = Arc::new(MemoryBackend::new());
        let master = MasterSecret::from_bytes([7u8; 32]);
        let fs = Fs::create(
            backend.clone(),
            backend.clone(),
            &master,
            [8u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();
        r.register(BOB, &token("b"), 2000).await.unwrap();
        drop(r);
        drop(fs);

        let fs = Fs::mount(
            backend.clone(),
            backend,
            &master,
            [8u8; 16],
            Arc::new(Config::default()),
            None,
        )
        .await
        .unwrap();
        let reopened = DeviceRegistry::open(fs).await.unwrap();
        assert_eq!(reopened.count(ALICE).await, 1);
        assert_eq!(reopened.count(BOB).await, 1);
        assert_eq!(reopened.devices(ALICE).await[0].token, token("a"));
    }

    #[tokio::test]
    async fn an_unpublished_temporary_file_is_discarded_but_a_corrupt_record_stops_startup() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();

        let dir = format!("/{RUNTIME_DIR}/{DEVICES_DIR}/{}", hex::encode(ALICE));
        let h = fs
            .open(&format!("{dir}/orphan.tmp"), OpenFlags::create_new())
            .await
            .unwrap();
        fs.close(&h).await.unwrap();
        assert_eq!(
            DeviceRegistry::open(fs.clone())
                .await
                .unwrap()
                .count(ALICE)
                .await,
            1,
            "an unpublished temporary file was treated as a record"
        );

        // A published record that will not decode is a different matter: it is
        // storage this runtime does not understand, and guessing is worse than
        // refusing to start.
        let h = fs
            .open(
                &format!("{dir}/{}", record_name(&token("bad"))),
                OpenFlags::create_new(),
            )
            .await
            .unwrap();
        fs.pwrite(&h, 0, b"not json").await.unwrap();
        fs.close(&h).await.unwrap();
        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    #[tokio::test]
    async fn a_record_that_names_a_tenant_other_than_its_directory_is_refused() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();

        // Alice's directory, a record claiming to be Bob's: the filename still
        // matches its token, so only the directory check catches this.
        let forged = StoredDevice {
            version: RECORD_VERSION,
            tenant: BOB,
            token: token("forged"),
            created_ms: 1,
        };
        let path = format!(
            "/{RUNTIME_DIR}/{DEVICES_DIR}/{}/{}",
            hex::encode(ALICE),
            record_name(&forged.token)
        );
        let h = fs.open(&path, OpenFlags::create_new()).await.unwrap();
        fs.pwrite(&h, 0, &serde_json::to_vec(&forged).unwrap())
            .await
            .unwrap();
        fs.close(&h).await.unwrap();

        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    #[tokio::test]
    async fn a_record_whose_hash_does_not_match_its_token_is_refused() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();

        // The right owner, but filed under another token's name — so only the
        // filename check catches this one.
        let device = StoredDevice {
            version: RECORD_VERSION,
            tenant: ALICE,
            token: token("real"),
            created_ms: 1,
        };
        let path = format!(
            "/{RUNTIME_DIR}/{DEVICES_DIR}/{}/{}",
            hex::encode(ALICE),
            record_name(&token("someone-else"))
        );
        let h = fs.open(&path, OpenFlags::create_new()).await.unwrap();
        fs.pwrite(&h, 0, &serde_json::to_vec(&device).unwrap())
            .await
            .unwrap();
        fs.close(&h).await.unwrap();

        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    #[tokio::test]
    async fn a_record_from_an_unknown_version_is_refused_rather_than_misparsed() {
        let fs = memory().await;
        DeviceRegistry::open(fs.clone()).await.unwrap();

        let device = StoredDevice {
            version: RECORD_VERSION + 1,
            tenant: ALICE,
            token: token("a"),
            created_ms: 1,
        };
        let dir = ensure_dir(
            &fs,
            &fs.lookup_at(&fs.root(), RUNTIME_DIR).await.unwrap(),
            DEVICES_DIR,
        )
        .await
        .unwrap();
        ensure_dir(&fs, &dir, &hex::encode(ALICE)).await.unwrap();
        let path = format!(
            "/{RUNTIME_DIR}/{DEVICES_DIR}/{}/{}",
            hex::encode(ALICE),
            record_name(&device.token)
        );
        let h = fs.open(&path, OpenFlags::create_new()).await.unwrap();
        fs.pwrite(&h, 0, &serde_json::to_vec(&device).unwrap())
            .await
            .unwrap();
        fs.close(&h).await.unwrap();

        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    /// The registry sits above every tenant scope, so no guest can name it.
    #[tokio::test]
    async fn device_records_live_above_every_tenant_scope() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1).await.unwrap();

        let root = fs.root();
        let runtime = fs.lookup_at(&root, RUNTIME_DIR).await.unwrap();
        let devices = fs.lookup_at(&runtime, DEVICES_DIR).await.unwrap();
        assert!(fs.lookup_at(&devices, &hex::encode(ALICE)).await.is_ok());

        // A tenant's scope is a sibling of `/runtime`, never an ancestor.
        let tenant = crate::tenant::tenant_root_by_id(&fs, ALICE).await.unwrap();
        assert_ne!(tenant.scope.objid(), root.objid());
        assert_ne!(tenant.scope.objid(), devices.objid());
    }
}
