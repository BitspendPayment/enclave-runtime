//! Storage: one ZFS pool holds everything the enclave keeps.
//!
//! ```text
//!   /tenants/<id>          a dataset per tenant, the guest's preopen
//!   /runtime/...           credentials, tasks, streams, devices
//!   pool "enclave"         checksum=sha256, sync=disabled, atime=off
//!   /dev/mapper/zcrypt     plain dm-crypt, key from the master secret
//!   /dev/nbd0              the parent's disk, over vsock
//! ```
//!
//! dm-crypt is what makes the host's disk safe to read. Without the key the
//! host can only replay sectors it once saw or scramble them, and to ZFS both
//! look like the ordinary corruption its checksums exist to catch. No header
//! is parsed from the disk: plain mode has none.
//!
//! ## The anchor
//!
//! Every ZFS block pointer carries its child's checksum, so a pool state is
//! pinned by its uberblock. But a txg number does not name one: forks reuse
//! numbers, and every uberblock the disk ever held may still be on it for the
//! host to serve.
//!
//! So each anchor writes a fresh random value into the pool itself, the marker
//! `zfs set enclave:anchor=<seq>-<nonce>-<previous anchor's hash>`, which also
//! syncs everything written before it. A second sync follows, and the txg that
//! reached is the one the anchor names. Signed with the nonce, chained to the
//! anchor before, it is published to the roots bucket under Object Lock.
//! Nothing is acknowledged — a response, a registration, a finished task —
//! until the anchor covering it exists.
//!
//! The marker's txg is older than the anchored one, and a write that lands
//! between the two is acknowledged by the anchor, so the nonce alone does not
//! pin the state. Boot imports the newest state on the disk and asks the kernel
//! which txg it loaded. It refuses one older than the anchored txg, and one
//! whose marker is neither the newest anchor's nor that of an unpublished
//! successor naming it ([`admit`]). A rolled-back disk, an abandoned fork and
//! the disk as of the marker are all refused.
//!
//! There is no rewind. What an enclave synced and died before anchoring stays,
//! unacknowledged: rewinding even three txgs can find the anchored state's
//! blocks reused, and ZFS would then quietly load an older one.
//!
//! Anchors cannot be hidden either: they are found by their retained version,
//! beneath any delete marker, and Object Lock keeps every one. What a cold boot
//! cannot know on its own is whether the store is still adding them; that is
//! what `--min-root-seq` is for.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::store::backend::{Backend, ObjectLock, ObjectLockMode, PutBlobInput};
use crate::store::crypto::keys::hkdf;
use crate::store::crypto::{
    sign, Hash256, KeyMaterial, MasterSecret, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::store::error::{StoreError, StoreResult};
use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use rustix::ioctl::{self, opcode, IntegerSetter, NoArg};
use rustix::net::addr::{SocketAddrArg, SocketAddrLen, SocketAddrOpaque};
use rustix::net::{AddressFamily, SocketType};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::tenant::Arrival;

pub const POOL: &str = "enclave";
const MAPPED: &str = "/dev/mapper/zcrypt";
const NBD_DEVICE: &str = "/dev/nbd0";
/// The parent, as every enclave sees it.
const PARENT_CID: u32 = 3;
/// Where the parent serves the disk: NBD's registered port, on vsock.
const NBD_PORT: u32 = 10809;
const PROPERTY: &str = "enclave:anchor";
/// No txg starts on a timer, a request's writes fit in one txg, and the txg
/// history reaches back further than the gap between two anchors.
/// The debug log records which uberblock an import loaded.
const ZFS_PARAMS: &str = "zfs_txg_timeout=3600 zfs_txg_history=4096 \
    zfs_arc_max=268435456 zfs_dirty_data_max=268435456 zfs_dirty_data_sync_percent=90 \
    spa_load_verify_data=0 zfs_dbgmsg_enable=1";

const ANCHOR_MAGIC: &[u8; 8] = b"ZFSANCH2";

// magic | seq | prev | fs_uuid | kind | pool_id | tenant_id | pool_guid | txg | nonce | pubkey | sig
const OFF_SEQ: usize = 8;
const OFF_PREV: usize = OFF_SEQ + 8;
const OFF_FS_UUID: usize = OFF_PREV + 32;
const OFF_KIND: usize = OFF_FS_UUID + 16;
const OFF_POOL_ID: usize = OFF_KIND + 1;
const OFF_TENANT_ID: usize = OFF_POOL_ID + 16;
const OFF_POOL_GUID: usize = OFF_TENANT_ID + 16;
const OFF_TXG: usize = OFF_POOL_GUID + 8;
const OFF_NONCE: usize = OFF_TXG + 8;
const OFF_PUBKEY: usize = OFF_NONCE + 32;
const SIGNED_LEN: usize = OFF_PUBKEY + ED25519_PUBLIC_KEY_LEN;
pub const ANCHOR_LEN: usize = SIGNED_LEN + ED25519_SIGNATURE_LEN;

/// The control pool holds the catalog and runtime records; a tenant pool holds
/// one tenant's data. Which a pool is settles what an anchor speaks for, so it
/// is signed into the anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolKind {
    Control,
    Tenant,
}

impl PoolKind {
    fn byte(self) -> u8 {
        match self {
            PoolKind::Control => 0,
            PoolKind::Tenant => 1,
        }
    }
    fn from_byte(b: u8) -> Option<PoolKind> {
        match b {
            0 => Some(PoolKind::Control),
            1 => Some(PoolKind::Tenant),
            _ => None,
        }
    }
}

/// The one control pool's id: a fixed sentinel, never a random tenant id.
const CONTROL_POOL_ID: [u8; 16] = *b"enclave-control!";

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

fn id_at(b: &[u8], off: usize) -> [u8; 16] {
    b[off..off + 16].try_into().expect("16 bytes")
}

/// One anchored pool state, chained to the one before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub prev: Hash256,
    pub kind: PoolKind,
    /// Which pool this anchor speaks for: a fixed sentinel for the control
    /// pool, a random id for a tenant's. Signed in, and checked on load, so
    /// the host cannot serve one pool's anchor as another's.
    pub pool_id: [u8; 16],
    /// The tenant the pool belongs to, or zero for the control pool.
    pub tenant_id: [u8; 16],
    pub pool_guid: u64,
    pub txg: u64,
    /// Also in the pool, as `enclave:anchor`: what tells this state apart
    /// from another that reached the same txg.
    pub nonce: [u8; 32],
    encoded: Bytes,
}

impl Anchor {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        keys: &KeyMaterial,
        prev: Option<&Anchor>,
        kind: PoolKind,
        pool_id: [u8; 16],
        tenant_id: [u8; 16],
        pool_guid: u64,
        txg: u64,
        nonce: [u8; 32],
    ) -> Anchor {
        let seq = prev.map_or(0, |p| p.seq + 1);
        let prev_hash = prev.map_or(Hash256::ZERO, Anchor::hash);
        let mut b = Vec::with_capacity(ANCHOR_LEN);
        b.extend_from_slice(ANCHOR_MAGIC);
        b.extend_from_slice(&seq.to_be_bytes());
        b.extend_from_slice(prev_hash.as_bytes());
        b.extend_from_slice(keys.fs_uuid());
        b.push(kind.byte());
        b.extend_from_slice(&pool_id);
        b.extend_from_slice(&tenant_id);
        b.extend_from_slice(&pool_guid.to_be_bytes());
        b.extend_from_slice(&txg.to_be_bytes());
        b.extend_from_slice(&nonce);
        b.extend_from_slice(keys.public_key());
        let sig = sign::sign(keys.signing_key(), &b);
        b.extend_from_slice(&sig);
        Anchor {
            seq,
            prev: prev_hash,
            kind,
            pool_id,
            tenant_id,
            pool_guid,
            txg,
            nonce,
            encoded: Bytes::from(b),
        }
    }

    /// Identity for chaining: the full encoding, signature included.
    pub fn hash(&self) -> Hash256 {
        Hash256::of(&self.encoded)
    }

    pub fn encoded(&self) -> Bytes {
        self.encoded.clone()
    }

    /// The value written to the pool's `enclave:anchor` property.
    pub fn property(&self) -> String {
        marker(self.seq, &self.nonce, &self.prev)
    }

    /// The checks `RootRecord::decode_and_verify` makes, for the same
    /// reasons: our key and not the one the record names, our filesystem, and
    /// a sequence that matches the key it was read from.
    pub fn decode_and_verify(
        bytes: &[u8],
        keys: &KeyMaterial,
        expected_seq: u64,
        expected_pool_id: [u8; 16],
    ) -> StoreResult<Anchor> {
        if bytes.len() != ANCHOR_LEN || &bytes[..8] != ANCHOR_MAGIC {
            return Err(StoreError::Integrity("zfs anchor: not an anchor"));
        }
        if &bytes[OFF_PUBKEY..SIGNED_LEN] != keys.public_key() {
            return Err(StoreError::Integrity(
                "zfs anchor: signed by an unexpected key",
            ));
        }
        let sig: [u8; ED25519_SIGNATURE_LEN] = bytes[SIGNED_LEN..].try_into().expect("64 bytes");
        sign::verify(keys.public_key(), &bytes[..SIGNED_LEN], &sig)?;
        if &bytes[OFF_FS_UUID..OFF_KIND] != keys.fs_uuid() {
            return Err(StoreError::Integrity(
                "zfs anchor: belongs to another filesystem",
            ));
        }
        if id_at(bytes, OFF_POOL_ID) != expected_pool_id {
            return Err(StoreError::Integrity("zfs anchor: belongs to another pool"));
        }
        let kind = PoolKind::from_byte(bytes[OFF_KIND])
            .ok_or(StoreError::Integrity("zfs anchor: unknown pool kind"))?;
        let seq = u64_at(bytes, OFF_SEQ);
        if seq != expected_seq {
            return Err(StoreError::Integrity(
                "zfs anchor: sequence does not match its key",
            ));
        }
        let prev = Hash256::from_bytes(bytes[OFF_PREV..OFF_FS_UUID].try_into().expect("32 bytes"));
        if seq == 0 && !prev.is_zero() {
            return Err(StoreError::Integrity(
                "zfs anchor: genesis has a predecessor",
            ));
        }
        Ok(Anchor {
            seq,
            prev,
            kind,
            pool_id: id_at(bytes, OFF_POOL_ID),
            tenant_id: id_at(bytes, OFF_TENANT_ID),
            pool_guid: u64_at(bytes, OFF_POOL_GUID),
            txg: u64_at(bytes, OFF_TXG),
            nonce: bytes[OFF_NONCE..OFF_PUBKEY].try_into().expect("32 bytes"),
            encoded: Bytes::copy_from_slice(bytes),
        })
    }
}

const GEN_MAGIC: &[u8; 8] = b"ZFSGEN01";
// magic | generation | fs_uuid | pubkey | sig
const GEN_OFF_G: usize = 8;
const GEN_OFF_FS_UUID: usize = GEN_OFF_G + 8;
const GEN_OFF_PUBKEY: usize = GEN_OFF_FS_UUID + 16;
const GEN_SIGNED_LEN: usize = GEN_OFF_PUBKEY + ED25519_PUBLIC_KEY_LEN;
const GEN_LEN: usize = GEN_SIGNED_LEN + ED25519_SIGNATURE_LEN;

/// A boot's generation claim. One per enclave start, chained only by its
/// number: a running enclave stops anchoring for good once a higher one
/// exists, so a second enclave the host starts while the first is mid-anchor
/// cannot let the first acknowledge a write the second has forked away from.
/// Signed and Object-Locked like an anchor, so the host can neither forge one
/// for another filesystem nor hide the newest.
fn seal_generation(keys: &KeyMaterial, generation: u64) -> Bytes {
    let mut b = Vec::with_capacity(GEN_LEN);
    b.extend_from_slice(GEN_MAGIC);
    b.extend_from_slice(&generation.to_be_bytes());
    b.extend_from_slice(keys.fs_uuid());
    b.extend_from_slice(keys.public_key());
    let sig = sign::sign(keys.signing_key(), &b);
    b.extend_from_slice(&sig);
    Bytes::from(b)
}

fn verify_generation(bytes: &[u8], keys: &KeyMaterial, expected: u64) -> StoreResult<()> {
    if bytes.len() != GEN_LEN || &bytes[..8] != GEN_MAGIC {
        return Err(StoreError::Integrity("zfs generation: not a generation"));
    }
    if &bytes[GEN_OFF_PUBKEY..GEN_SIGNED_LEN] != keys.public_key() {
        return Err(StoreError::Integrity(
            "zfs generation: signed by an unexpected key",
        ));
    }
    let sig: [u8; ED25519_SIGNATURE_LEN] = bytes[GEN_SIGNED_LEN..].try_into().expect("64 bytes");
    sign::verify(keys.public_key(), &bytes[..GEN_SIGNED_LEN], &sig)?;
    if &bytes[GEN_OFF_FS_UUID..GEN_OFF_PUBKEY] != keys.fs_uuid() {
        return Err(StoreError::Integrity(
            "zfs generation: belongs to another filesystem",
        ));
    }
    if u64_at(bytes, GEN_OFF_G) != expected {
        return Err(StoreError::Integrity(
            "zfs generation: number does not match its key",
        ));
    }
    Ok(())
}

/// Where the pool lives.
#[derive(Debug, Clone)]
pub enum Disk {
    /// The parent's disk, over vsock: the only one an enclave has.
    Parent,
    /// A temporary directory standing in for the pool, for tests that cannot
    /// load ZFS. Anchors are still published (at txg 0); nothing is synced,
    /// so `anchor` does nothing. Clones share the directory, so a test can
    /// "restart" onto the same disk.
    #[cfg(any(test, feature = "testing"))]
    Directory(Arc<tempfile::TempDir>),
}

impl Disk {
    /// A fresh [`Disk::Directory`].
    #[cfg(any(test, feature = "testing"))]
    pub fn scratch() -> Result<Disk> {
        Ok(Disk::Directory(Arc::new(tempfile::tempdir()?)))
    }
}

/// One ZFS pool: its device, its anchor chain, its last-anchor lock.
struct Pool {
    /// Held so a [`Disk::Directory`] lives as long as the pool on it.
    #[allow(dead_code)]
    disk: Disk,
    keys: Arc<KeyMaterial>,
    roots: Arc<dyn Backend>,
    /// The global bucket prefix, under which the generation chain lives.
    prefix: String,
    /// This pool's anchor-chain prefix in the bucket; `{prefix}zfs/` for the
    /// one pool today, `{prefix}zfs/pools/<id>/` once there is a pool per
    /// tenant. Anchors hang off it, generations do not: they are global.
    anchor_prefix: String,
    retention: Duration,
    /// The zpool's name, e.g. `enclave`.
    name: String,
    /// The dm-crypt device the pool sits on, e.g. `/dev/mapper/zcrypt`.
    mapped: String,
    /// Which pool this is, and its identity, signed into every anchor.
    kind: PoolKind,
    pool_id: [u8; 16],
    tenant_id: [u8; 16],
    /// `/` on the pool; a directory for [`Disk::Directory`].
    root: PathBuf,
    pool: bool,
    pool_guid: u64,
    genesis: Hash256,
    /// This boot's generation. An anchor refuses to publish once generation
    /// `+ 1` exists, so a superseded enclave cannot acknowledge anything.
    generation: u64,
    /// The newest published anchor, or why anchoring stopped. Held for the
    /// whole of an anchor, so they run one at a time.
    // ponytail: one lock for every tenant; group waiting callers onto one
    // sync and one PUT if throughput matters.
    last: Mutex<std::result::Result<Anchor, String>>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("root", &self.root)
            .field("pool_guid", &self.pool_guid)
            .finish()
    }
}

impl Pool {
    /// Genesis: create the pool on a blank disk and publish anchor 0. Refuses a
    /// disk that already holds a pool, and a bucket that already has anchors.
    async fn create(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        master: &MasterSecret,
        prefix: &str,
        retention: Duration,
    ) -> Result<Arc<Pool>> {
        let mut zfs = Pool::attach(disk, roots, keys, master, prefix, retention).await?;
        ensure!(
            zfs.find_tip().await?.is_none(),
            "the roots bucket already has anchors; genesis would start a second history"
        );
        zfs.generation = zfs
            .claim_generation()
            .await
            .context("claiming the first enclave generation")?;
        if zfs.pool {
            // `zpool import` with no pool name lists what it could import.
            let listed = Command::new("zpool")
                .args(["import", "-d", "/dev/mapper"])
                .output()
                .await
                .context("running zpool")?;
            if String::from_utf8_lossy(&listed.stdout).contains("pool:") {
                bail!("the disk holds a pool but no anchor names it; refusing to guess");
            }
            run(
                "zpool",
                &[
                    "create",
                    "-f",
                    "-o",
                    "ashift=12",
                    "-o",
                    "cachefile=none",
                    "-o",
                    "failmode=panic",
                    "-O",
                    "checksum=sha256",
                    "-O",
                    "atime=off",
                    "-O",
                    "sync=disabled",
                    "-O",
                    "mountpoint=none",
                    &zfs.name,
                    &zfs.mapped,
                ],
            )
            .await?;
            for name in ["tenants", "runtime"] {
                run(
                    "zfs",
                    &[
                        "create",
                        "-o",
                        &format!("mountpoint=/{name}"),
                        &format!("{}/{name}", zfs.name),
                    ],
                )
                .await?;
            }
            zfs.pool_guid = pool_guid(&zfs.name).await?;
        } else {
            for name in ["tenants", "runtime"] {
                tokio::fs::create_dir_all(zfs.root.join(name)).await?;
            }
        }
        let genesis = zfs.seal_and_publish(None).await?;
        zfs.genesis = genesis.hash();
        tracing::info!(
            pool_guid = zfs.pool_guid,
            txg = genesis.txg,
            "zfs genesis: created the pool"
        );
        zfs.last = Mutex::new(Ok(genesis));
        Ok(Arc::new(zfs))
    }

    /// Resume: import the pool as it is, and refuse it unless the newest
    /// anchor vouches for what ZFS loaded (see [`admit`]). `min_seq` is a floor
    /// from outside the store.
    async fn open(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        master: &MasterSecret,
        prefix: &str,
        retention: Duration,
        min_seq: Option<u64>,
    ) -> Result<Arc<Pool>> {
        let mut zfs = Pool::attach(disk, roots, keys, master, prefix, retention).await?;
        // Before the read-write import below, so a second enclave the host
        // starts cannot both fork this disk and let the enclave it forked from
        // go on to publish — the fence in `seal_and_publish` refuses that.
        zfs.generation = zfs
            .claim_generation()
            .await
            .context("claiming an enclave generation")?;
        let seq = zfs
            .find_tip()
            .await?
            .context("the roots bucket has no anchors; there is no pool to resume")?;
        if let Some(min) = min_seq {
            ensure!(seq >= min, "the newest anchor is {seq}, below the floor of {min}: refusing a rolled-back store");
        }
        let tip = zfs.load(seq).await?;
        if seq > 0 && zfs.load(seq - 1).await?.hash() != tip.prev {
            bail!("the anchor chain is broken at seq {seq}");
        }
        zfs.genesis = if seq == 0 {
            tip.hash()
        } else {
            zfs.load(0).await?.hash()
        };
        if zfs.pool {
            // The newest state on the disk, not `-T` the anchored txg: that
            // takes the newest uberblock at or below it with no exact match,
            // and falls back further when one fails to load. Which txg it got
            // comes from the kernel's own notes on this import, so the log is
            // emptied first. Unmounted until it is admitted.
            tokio::fs::write(DBGMSG, "0")
                .await
                .context("clearing the ZFS debug log")?;
            run(
                "zpool",
                &[
                    "import",
                    "-f",
                    "-N",
                    "-d",
                    &zfs.mapped,
                    "-o",
                    "cachefile=none",
                    &tip.pool_guid.to_string(),
                    &zfs.name,
                ],
            )
            .await
            .context("importing the pool")?;
            #[cfg(feature = "testing")]
            log_loaded_state(&zfs.name).await;
            let loaded = loaded_txg(&tokio::fs::read_to_string(DBGMSG).await?, &zfs.name);
            let marker = run("zfs", &["get", "-Hp", "-o", "value", PROPERTY, &zfs.name]).await?;
            let guid = pool_guid(&zfs.name).await?;
            if let Err(why) = admit(&tip, loaded, marker.trim(), guid) {
                let _ = run("zpool", &["export", &zfs.name]).await;
                bail!("refusing the pool: {why}");
            }
            run("zfs", &["mount", "-a"]).await?;
            tracing::info!(
                loaded_txg = loaded,
                marker = marker.trim(),
                "zfs pool admitted"
            );
        }
        zfs.pool_guid = tip.pool_guid;
        tracing::info!(
            seq,
            txg = tip.txg,
            pool_guid = zfs.pool_guid,
            "zfs pool resumed at its anchor"
        );
        zfs.last = Mutex::new(Ok(tip));
        Ok(Arc::new(zfs))
    }

    /// Bring up the disk under the pool, without touching the pool.
    async fn attach(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        master: &MasterSecret,
        prefix: &str,
        retention: Duration,
    ) -> Result<Pool> {
        let (root, pool) = match disk {
            Disk::Parent => {
                insmod("/lib/zfs/spl.ko", "")?;
                insmod("/lib/zfs/zfs.ko", ZFS_PARAMS)?;
                let size = nbd_attach(NBD_PORT)?;
                dmcrypt(master, keys.fs_uuid(), size).await?;
                (PathBuf::from("/"), true)
            }
            #[cfg(any(test, feature = "testing"))]
            Disk::Directory(dir) => (dir.path().to_path_buf(), false),
        };
        Ok(Pool {
            disk: disk.clone(),
            keys,
            roots,
            prefix: prefix.to_string(),
            anchor_prefix: format!("{prefix}zfs/"),
            retention,
            name: POOL.to_string(),
            mapped: MAPPED.to_string(),
            kind: PoolKind::Control,
            pool_id: CONTROL_POOL_ID,
            tenant_id: [0u8; 16],
            root,
            pool,
            pool_guid: 0,
            genesis: Hash256::ZERO,
            generation: 0,
            last: Mutex::new(Err("not opened".into())),
        })
    }

    /// A pool in a temporary directory with its anchors in memory: what
    /// in-process tests run on.
    #[cfg(any(test, feature = "testing"))]
    async fn scratch_pool() -> Arc<Pool> {
        let master = MasterSecret::from_bytes([7u8; 32]);
        let keys = Arc::new(KeyMaterial::derive(&master, [0u8; 16]).expect("deriving keys"));
        Pool::create(
            &Disk::scratch().expect("a temporary directory"),
            Arc::new(crate::store::backend::memory::MemoryBackend::new()),
            keys,
            &master,
            "",
            Duration::from_secs(3600),
        )
        .await
        .expect("a scratch pool")
    }

    /// The hash of anchor 0: which history this pool is, for the boot receipt.
    pub fn genesis_hash(&self) -> [u8; 32] {
        *self.genesis.as_bytes()
    }

    /// Make everything written so far survive the host. Call before telling
    /// anyone a write happened, and tell nobody if it fails.
    ///
    /// It runs in a task of its own, so a caller that is dropped — a deadline,
    /// an abort, a client that went away — cannot stop it between writing the
    /// marker and publishing the anchor, and leave the next one to collide
    /// with an anchor it does not know was published.
    ///
    /// Before the marker is written a failure changes nothing and is only
    /// returned. From the marker on it stops anchoring for good, an uncertain
    /// publish included: retrying could publish over a lost race, or past a
    /// state the host has since rewritten.
    pub async fn anchor(self: &Arc<Self>) -> Result<()> {
        if !self.pool {
            return Ok(());
        }
        let zfs = self.clone();
        tokio::spawn(async move { zfs.anchor_now().await })
            .await
            .context("the anchor's task died")?
    }

    async fn anchor_now(&self) -> Result<()> {
        #[cfg(feature = "testing")]
        if self.last.try_lock().is_err() {
            hook("anchor-wait", String::new()).await;
        }
        let mut last = self.last.lock().await;
        let prev = last
            .as_ref()
            .map_err(|e| anyhow!("zfs anchoring stopped after a failure: {e}"))?
            .clone();
        let start = Instant::now();
        run("zpool", &["sync", &self.name]).await?;
        let synced = synced_txg(&self.name).await?;
        if synced == prev.txg {
            return Ok(()); // nothing has reached the disk since
        }
        let sync_ms = start.elapsed().as_millis();
        match self.seal_and_publish(Some(&prev)).await {
            Ok(anchor) => {
                tracing::info!(
                    seq = anchor.seq,
                    txg = anchor.txg,
                    written_txgs_since = synced - prev.txg,
                    sync_ms,
                    total_ms = start.elapsed().as_millis(),
                    "zfs anchored"
                );
                *last = Ok(anchor);
                Ok(())
            }
            Err(e) => {
                *last = Err(format!("{e:#}"));
                Err(e)
            }
        }
    }

    async fn seal_and_publish(&self, prev: Option<&Anchor>) -> Result<Anchor> {
        let seq = prev.map_or(0, |p| p.seq + 1);
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|e| anyhow!("getrandom: {e}"))?;
        let txg = if self.pool {
            // Anchor::property, before there is an anchor. A sync task: back
            // once the txg holding it, and everything written before it, is
            // on the disk.
            let value = marker(seq, &nonce, &prev.map_or(Hash256::ZERO, Anchor::hash));
            run("zfs", &["set", &format!("{PROPERTY}={value}"), &self.name]).await?;
            #[cfg(feature = "testing")]
            hook("after-marker", format!("seq={seq}")).await;
            // Its frees are deferred two txgs, and would otherwise reach the
            // disk on the next sync: every later call would see a write and
            // anchor again, read-only ones included.
            run("zpool", &["sync", &self.name]).await?;
            let txg = synced_txg(&self.name).await?;
            if let Some(p) = prev {
                ensure!(
                    txg > p.txg,
                    "zfs set reached txg {txg}, not past the anchor at {}",
                    p.txg
                );
            }
            txg
        } else {
            0
        };
        #[cfg(feature = "testing")]
        hook("after-sync", format!("seq={seq} txg={txg}")).await;
        // The fence, checked as late as possible before the publish that would
        // acknowledge these writes: if a newer enclave has booted, this one is
        // superseded and must not publish. The marker is already on the disk,
        // which is harmless — nothing was acknowledged, and the next boot's
        // admission handles an unpublished marker. Only a real anchor fences;
        // genesis is guarded by the sealed-key lease instead.
        if prev.is_some() && self.generation_exists(self.generation + 1).await? {
            bail!(
                "a newer enclave generation ({}) exists; this one is superseded and will not anchor",
                self.generation + 1
            );
        }
        let anchor = Anchor::seal(
            &self.keys,
            prev,
            self.kind,
            self.pool_id,
            self.tenant_id,
            self.pool_guid,
            txg,
            nonce,
        );
        self.publish(seq, anchor.encoded()).await?;
        #[cfg(feature = "testing")]
        hook("after-publish", format!("seq={seq} txg={txg}")).await;
        Ok(anchor)
    }

    /// A tenant's directory: its own dataset, created on first use and
    /// anchored with whatever created it.
    pub async fn tenant_dir(&self, tenant_id: [u8; 16]) -> Result<(PathBuf, Arrival)> {
        let dir = self.tenant_path(tenant_id);
        if tokio::fs::try_exists(&dir).await? {
            return Ok((dir, Arrival::Returning));
        }
        if self.pool {
            run(
                "zfs",
                &[
                    "create",
                    &format!("{}/tenants/{}", self.name, hex::encode(tenant_id)),
                ],
            )
            .await?;
        } else {
            tokio::fs::create_dir(&dir).await?;
        }
        Ok((dir, Arrival::New))
    }

    /// A tenant's directory, which must already exist. For work that runs on
    /// a tenant's behalf without them, and so must never bring one back.
    pub async fn existing_tenant_dir(&self, tenant_id: [u8; 16]) -> Result<PathBuf> {
        let dir = self.tenant_path(tenant_id);
        ensure!(
            tokio::fs::try_exists(&dir).await?,
            "tenant {} has no directory",
            hex::encode(tenant_id)
        );
        Ok(dir)
    }

    /// Where a tenant's directory is, whether or not it exists yet.
    pub fn tenant_path(&self, tenant_id: [u8; 16]) -> PathBuf {
        self.root.join("tenants").join(hex::encode(tenant_id))
    }

    /// A directory of runtime state under `/runtime`, out of every guest's
    /// reach: no preopen names anything above a tenant's own directory.
    pub async fn runtime_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.root.join("runtime").join(name);
        tokio::fs::create_dir_all(&dir).await?;
        Ok(dir)
    }

    // ---- the anchor chain, in the roots bucket -----------------------------

    fn anchor_key(&self, seq: u64) -> String {
        format!("{}anchors/{seq:016x}", self.anchor_prefix)
    }

    fn generation_key(&self, generation: u64) -> String {
        format!("{}zfs/generations/{generation:016x}", self.prefix)
    }

    /// The retained version of a key: a delete marker hides an Object-Locked
    /// object from a plain GET while leaving it there, so a plain GET would let
    /// the host roll a chain back with one legal call.
    async fn retained(&self, key: &str) -> StoreResult<Bytes> {
        Ok(self.roots.get_retained_blob(key).await?.body)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        match self.retained(key).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn load(&self, seq: u64) -> Result<Anchor> {
        Ok(Anchor::decode_and_verify(
            &self.retained(&self.anchor_key(seq)).await?,
            &self.keys,
            seq,
            self.pool_id,
        )?)
    }

    async fn generation_exists(&self, generation: u64) -> Result<bool> {
        let key = self.generation_key(generation);
        if self.exists(&key).await? {
            // Verify it, so a host cannot fence this enclave out with a record
            // it forged for another filesystem.
            verify_generation(&self.retained(&key).await?, &self.keys, generation)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// The newest existing number of a contiguous, never-deleted chain:
    /// existence is monotone, so gallop then bisect.
    async fn chain_tip(&self, key: impl Fn(u64) -> String) -> Result<Option<u64>> {
        if !self.exists(&key(0)).await? {
            return Ok(None);
        }
        let (mut lo, mut step) = (0u64, 1u64);
        while let Some(next) = lo.checked_add(step) {
            if !self.exists(&key(next)).await? {
                break;
            }
            lo = next;
            step = step.saturating_mul(2);
        }
        let mut hi = lo.saturating_add(step);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.exists(&key(mid)).await? {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        Ok(Some(lo))
    }

    async fn find_tip(&self) -> Result<Option<u64>> {
        self.chain_tip(|seq| self.anchor_key(seq)).await
    }

    /// Claim the first unused generation, racing other boots for it. Each win
    /// is read back, since a delete marker could otherwise let a second PUT
    /// through, as for an anchor.
    async fn claim_generation(&self) -> Result<u64> {
        for _ in 0..1024 {
            let generation = self
                .chain_tip(|g| self.generation_key(g))
                .await?
                .map_or(0, |t| t + 1);
            let key = self.generation_key(generation);
            let body = seal_generation(&self.keys, generation);
            let input = PutBlobInput::new(key.clone(), body.clone()).with_object_lock(ObjectLock {
                mode: ObjectLockMode::Compliance,
                retain_until: std::time::SystemTime::now() + self.retention,
            });
            match self.roots.put_blob_if_not_exists(input).await {
                Ok(_) if self.retained(&key).await? == body => {
                    tracing::info!(generation, "claimed an enclave generation");
                    return Ok(generation);
                }
                Ok(_) | Err(StoreError::AlreadyExists) => continue, // lost the race; try the next
                Err(e) => return Err(e.into()),
            }
        }
        bail!("could not claim an enclave generation after 1024 tries; the store is being raced")
    }

    /// Publish `seq`, winning or losing the race for it. `If-None-Match`
    /// alone does not decide that race — a delete marker over the winner lets
    /// a second conditional PUT through — the retained version does, so it is
    /// read back.
    async fn publish(&self, seq: u64, body: Bytes) -> Result<()> {
        let key = self.anchor_key(seq);
        let input = PutBlobInput::new(key.clone(), body.clone()).with_object_lock(ObjectLock {
            mode: ObjectLockMode::Compliance,
            retain_until: std::time::SystemTime::now() + self.retention,
        });
        match self.roots.put_blob_if_not_exists(input).await {
            Ok(_) => {}
            Err(StoreError::AlreadyExists) => bail!("another writer published anchor {seq}"),
            Err(e) => return Err(e.into()),
        }
        ensure!(
            self.retained(&key).await? == body,
            "another writer published anchor {seq} first"
        );
        Ok(())
    }
}

/// The enclave's storage: the control pool, and a tenant's pool imported as it
/// is used. One disk underneath, cut into equal regions (see [`region_bounds`]),
/// each its own dm-crypt device and its own pool with its own anchor chain.
///
/// The public type the rest of the runtime holds. It routes a tenant's writes
/// to that tenant's pool and the runtime's own records to the control pool, and
/// anchors each independently.
pub struct Zfs {
    control: Arc<Pool>,
}

impl std::fmt::Debug for Zfs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Zfs")
            .field("control", &self.control)
            .finish()
    }
}

impl Zfs {
    /// Genesis: bring up the disk, create the control pool, publish its anchor
    /// 0. Tenant pools are created as tenants arrive.
    pub async fn create(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        master: &MasterSecret,
        prefix: &str,
        retention: Duration,
    ) -> Result<Arc<Zfs>> {
        let control = Pool::create(disk, roots, keys, master, prefix, retention).await?;
        Ok(Arc::new(Zfs { control }))
    }

    /// Resume: bring up the disk and import the control pool at its anchor.
    pub async fn open(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        master: &MasterSecret,
        prefix: &str,
        retention: Duration,
        min_seq: Option<u64>,
    ) -> Result<Arc<Zfs>> {
        let control = Pool::open(disk, roots, keys, master, prefix, retention, min_seq).await?;
        Ok(Arc::new(Zfs { control }))
    }

    /// In-process test storage: a control pool in a temporary directory.
    #[cfg(any(test, feature = "testing"))]
    pub async fn scratch() -> Arc<Zfs> {
        Arc::new(Zfs {
            control: Pool::scratch_pool().await,
        })
    }

    /// The hash of the control pool's anchor 0: which history this enclave is,
    /// for the boot receipt.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.control.genesis_hash()
    }

    /// A directory of runtime records on the control pool, out of every guest's
    /// reach: credentials, tasks, streams, devices, the tenant catalog.
    pub async fn runtime_dir(&self, name: &str) -> Result<PathBuf> {
        self.control.runtime_dir(name).await
    }

    /// A tenant's data directory, created on first use.
    pub async fn tenant_dir(&self, tenant_id: [u8; 16]) -> Result<(PathBuf, Arrival)> {
        self.control.tenant_dir(tenant_id).await
    }

    /// A tenant's data directory, which must already exist. For work that runs
    /// on a tenant's behalf without them, and so must never bring one back.
    pub async fn existing_tenant_dir(&self, tenant_id: [u8; 16]) -> Result<PathBuf> {
        self.control.existing_tenant_dir(tenant_id).await
    }

    /// Where a tenant's data directory is, whether or not it exists yet.
    pub fn tenant_path(&self, tenant_id: [u8; 16]) -> PathBuf {
        self.control.tenant_path(tenant_id)
    }

    /// Anchor a tenant's writes: its own pool, then the control pool for any
    /// record a request of theirs left there. Both before anyone is told.
    pub async fn anchor_tenant(&self, _tenant_id: [u8; 16]) -> Result<()> {
        self.control.anchor().await
    }

    /// Anchor the control pool: a credential, a catalog entry.
    pub async fn anchor_control(&self) -> Result<()> {
        self.control.anchor().await
    }
}

/// `<seq>-<nonce>-<previous anchor's hash>`, as the pool's `enclave:anchor`.
/// The hash is what lets a boot recognise the marker of an anchor that was
/// never published as the successor of the one that was.
fn marker(seq: u64, nonce: &[u8; 32], prev: &Hash256) -> String {
    format!(
        "{seq}-{}-{}",
        hex::encode(nonce),
        hex::encode(prev.as_bytes())
    )
}

/// Whether the newest anchor vouches for a loaded pool state: the txg ZFS
/// loaded, the marker it holds and its guid.
///
/// The marker's nonce first reaches the disk a txg or more before the txg the
/// anchor names, and a write that lands between the two is acknowledged by the
/// anchor. So holding the anchor's marker is not enough; the state must also be
/// no older than the anchored txg. One that is newer descends from it: nothing
/// but the enclave writes the marker, and a nonce is written once.
///
/// A state may also hold the marker of the next anchor, one the enclave wrote
/// and died before publishing, naming this one as its predecessor. Either way
/// everything the anchor covered is there, and anything after it was never
/// acknowledged, so the boot goes on from it rather than rewinding: a rewind
/// to a txg some way back can find its blocks already reused.
fn admit(
    tip: &Anchor,
    loaded_txg: Option<u64>,
    marker: &str,
    guid: u64,
) -> std::result::Result<(), String> {
    let loaded = loaded_txg.ok_or("the kernel did not say which txg it loaded")?;
    if guid != tip.pool_guid {
        return Err(format!(
            "it is pool {guid}, not the anchored pool {}",
            tip.pool_guid
        ));
    }
    if loaded < tip.txg {
        return Err(format!(
            "it loaded txg {loaded}, older than the anchored txg {}",
            tip.txg
        ));
    }
    // Pools anchored before the marker named its predecessor.
    let legacy = format!("{}-{}", tip.seq, hex::encode(tip.nonce));
    if marker == tip.property() || marker == legacy {
        return Ok(());
    }
    if let [seq, nonce, prev] = marker.split('-').collect::<Vec<_>>()[..] {
        if seq == (tip.seq + 1).to_string()
            && nonce.len() == 64
            && prev == hex::encode(tip.hash().as_bytes())
        {
            return Ok(());
        }
    }
    Err(format!(
        "it holds anchor {marker:?}, but the newest anchor is {:?}",
        tip.property()
    ))
}

/// Where the kernel keeps its debug log, `zfs_dbgmsg`.
const DBGMSG: &str = "/proc/spl/kstat/zfs/dbgmsg";

/// The txg of the uberblock an import of `pool` loaded, from the kernel's own
/// notes on it in the debug log: the `using uberblock with txg=` of the load
/// that ended `LOADED` with nothing after it. `zpool import` loads the pool
/// more than once — a trial load, a reload with the trusted config, a retry
/// at an older txg — and only the last is the pool as imported.
fn loaded_txg(dbgmsg: &str, pool: &str) -> Option<u64> {
    let tag = format!("spa_load({pool}, config ");
    let (mut using, mut loaded) = (None, None);
    for line in dbgmsg.lines() {
        let Some((_, rest)) = line.split_once(&tag) else {
            continue;
        };
        let Some((_, note)) = rest.split_once("): ") else {
            continue;
        };
        let note = note.trim();
        if let Some(txg) = note.strip_prefix("using uberblock with txg=") {
            using = txg.parse().ok();
        } else if note == "LOADED" {
            loaded = using;
        } else if note == "LOADING" || note == "UNLOADING" || note.starts_with("FAILED") {
            using = None;
            loaded = None;
        }
    }
    loaded
}

/// The newest txg that reached the disk: the last committed row of the pool's
/// txg history that wrote anything. A txg that changes nothing writes no
/// uberblock, so "last committed" alone can name one the disk never held.
fn witness(kstat: &str) -> Option<u64> {
    let mut lines = kstat.lines().skip_while(|l| !l.starts_with("txg"));
    let cols: Vec<&str> = lines.next()?.split_whitespace().collect();
    let col = |name| cols.iter().position(|c| *c == name);
    let (txg, state, written) = (col("txg")?, col("state")?, col("nwritten")?);
    lines
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let wrote = f.get(written)?.parse::<u64>().ok()? > 0;
            (*f.get(state)? == "C" && wrote).then(|| f.get(txg)?.parse().ok())?
        })
        .max()
}

async fn synced_txg(pool: &str) -> Result<u64> {
    let kstat = tokio::fs::read_to_string(format!("/proc/spl/kstat/zfs/{pool}/txgs")).await?;
    witness(&kstat).context("the pool's txg history shows nothing written")
}

/// Testing only: what the kernel says it loaded, as evidence for the rollback
/// legs of `run-zfs-spike.sh` — the import's own notes from the debug log, and
/// the first txgs the pool opened after it.
#[cfg(feature = "testing")]
async fn log_loaded_state(pool: &str) {
    let dbgmsg = tokio::fs::read_to_string("/proc/spl/kstat/zfs/dbgmsg")
        .await
        .unwrap_or_default();
    for line in dbgmsg.lines().filter(|l| l.contains("spa_load(")) {
        tracing::info!(line, "zfs import: dbgmsg");
    }
    let txgs = tokio::fs::read_to_string(format!("/proc/spl/kstat/zfs/{pool}/txgs"))
        .await
        .unwrap_or_default();
    for line in txgs.lines().skip(1).take(4) {
        tracing::info!(line, "zfs import: txgs");
    }
}

/// Testing only: the vsock port `deploy/qemu-nitro/test-hooks.py` answers on.
#[cfg(feature = "testing")]
const TEST_HOOK_PORT: u32 = 9101;

/// Testing only: stop at a named point in an anchor until the host says to go
/// on, or die there, so a test can copy the disk at an exact moment or kill the
/// enclave between two steps. With nothing listening on the port it returns at
/// once.
#[cfg(feature = "testing")]
async fn hook(point: &'static str, detail: String) {
    let line = format!("{point} {detail}\n");
    let reply = tokio::task::spawn_blocking(move || -> io::Result<String> {
        let mut v = vsock_connect(PARENT_CID, TEST_HOOK_PORT)?;
        v.write_all(line.as_bytes())?;
        let mut reply = String::new();
        io::BufRead::read_line(&mut io::BufReader::new(v), &mut reply)?;
        Ok(reply)
    })
    .await;
    if let Ok(Ok(reply)) = reply {
        if reply.trim() == "abort" {
            tracing::error!(point, detail, "test hook: dying here");
            std::process::abort();
        }
    }
}

async fn pool_guid(pool: &str) -> Result<u64> {
    let out = run("zpool", &["get", "-Hp", "-o", "value", "guid", pool]).await?;
    out.trim().parse().context("parsing the pool guid")
}

async fn run(program: &str, args: &[&str]) -> Result<String> {
    run_with_input(program, args, None).await
}

/// Runs a ZFS or device-mapper tool. `input` goes on stdin, never argv, which
/// any process can read from /proc.
async fn run_with_input(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        // No udev in an enclave: libdevmapper makes its own /dev/mapper node.
        .env("DM_DISABLE_UDEV", "1")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {program}"))?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(input.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    ensure!(
        out.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn insmod(path: &str, params: &str) -> Result<()> {
    let module = File::open(path).with_context(|| format!("opening {path}"))?;
    match rustix::system::finit_module(&module, &std::ffi::CString::new(params)?, 0) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("loading {path}")),
    }
}

async fn dmcrypt(master: &MasterSecret, fs_uuid: &[u8; 16], size: u64) -> Result<()> {
    let mut key = [0u8; 64]; // two AES-256 keys, for XTS
    hkdf(master, fs_uuid, b"zfs/dmcrypt/v1", &mut key)?;
    let mut table = format!(
        "0 {} crypt aes-xts-plain64 {} 0 {NBD_DEVICE} 0 1 sector_size:4096\n",
        size / 512,
        hex::encode(key)
    );
    key.zeroize();
    let r = run_with_input(
        "dmsetup",
        &["create", "zcrypt", "--noudevsync"],
        Some(&table),
    )
    .await;
    table.zeroize();
    r.map(drop)
}

const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;

/// Attach `/dev/nbd0` to the parent's NBD export on vsock `port`.
///
/// The kernel takes only TCP and UNIX sockets for NBD ("Unsupported socket:
/// should be TCP or UNIX"), so it is given one end of a socketpair and two
/// threads copy between the other end and the vsock connection.
// ponytail: those copies go through userspace; splice(2) them if disk
// throughput is ever what limits a request.
fn nbd_attach(port: u32) -> Result<u64> {
    let mut v = vsock_connect(PARENT_CID, port)
        .with_context(|| format!("connecting to the parent's NBD server on vsock port {port}"))?;

    // Fixed-newstyle handshake, default export.
    let mut hello = [0u8; 18];
    v.read_exact(&mut hello)?;
    ensure!(
        hello[..8] == NBDMAGIC.to_be_bytes() && hello[8..16] == IHAVEOPT.to_be_bytes(),
        "the parent's NBD server does not speak fixed-newstyle"
    );
    let no_zeroes = u16::from_be_bytes([hello[16], hello[17]]) & 2;
    v.write_all(&(1 | u32::from(no_zeroes)).to_be_bytes())?;
    let mut export_name = IHAVEOPT.to_be_bytes().to_vec();
    export_name.extend(1u32.to_be_bytes()); // NBD_OPT_EXPORT_NAME
    export_name.extend(0u32.to_be_bytes()); // "", the default
    v.write_all(&export_name)?;
    let mut reply = [0u8; 10];
    v.read_exact(&mut reply)?;
    let size = u64::from_be_bytes(reply[..8].try_into().expect("8 bytes"));
    let flags = u16::from_be_bytes([reply[8], reply[9]]);
    if no_zeroes == 0 {
        v.read_exact(&mut [0u8; 124])?;
    }

    let (kernel_end, bridge) = UnixStream::pair()?;
    pump(bridge.try_clone()?, v.try_clone()?, "enclave to parent");
    pump(v, bridge, "parent to enclave");

    let dev = File::options().read(true).write(true).open(NBD_DEVICE)?;
    // SAFETY: the NBD ioctls are _IO(0xab, n), each taking the integer below.
    unsafe {
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 1) }>::new_usize(4096),
        )?; // SET_BLKSIZE
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 7) }>::new_usize((size / 4096) as usize),
        )?; // SET_SIZE_BLOCKS
            // Without the server's flags the kernel never sends FLUSH, and nothing
            // written would be asked to reach the parent's disk.
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 10) }>::new_usize(flags.into()),
        )?; // SET_FLAGS
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 0) }>::new_usize(kernel_end.as_raw_fd() as usize),
        )?; // SET_SOCK
    }
    std::thread::spawn(move || {
        let _socket = kernel_end;
        // SAFETY: NBD_DO_IT takes no argument; it serves until the device goes.
        let r = unsafe { ioctl::ioctl(&dev, NoArg::<{ opcode::none(0xab, 3) }>::new()) };
        tracing::error!(?r, "the NBD device stopped; the pool has no disk");
        std::process::exit(71);
    });
    // The device starts inside NBD_DO_IT, on that thread. Until then it has
    // no size and dm-crypt would map nothing. Started is when this appears.
    for _ in 0..100 {
        if Path::new("/sys/block/nbd0/pid").exists() {
            return Ok(size);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("/dev/nbd0 did not start within 5s of NBD_DO_IT")
}

fn pump(
    mut from: impl Read + Send + 'static,
    mut to: impl Write + Send + 'static,
    way: &'static str,
) {
    std::thread::spawn(move || {
        let r = io::copy(&mut from, &mut to);
        tracing::error!(way, ?r, "the NBD bridge closed; the pool has no disk");
        std::process::exit(71);
    });
}

/// `struct sockaddr_vm`, which rustix has no type for.
#[repr(C)]
struct VsockAddr {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}

// SAFETY: a complete sockaddr_vm, readable for its whole size for the call.
unsafe impl SocketAddrArg for VsockAddr {
    unsafe fn with_sockaddr<R>(
        &self,
        f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R,
    ) -> R {
        f(
            (self as *const Self).cast(),
            std::mem::size_of::<Self>() as SocketAddrLen,
        )
    }
}

fn vsock_connect(cid: u32, port: u32) -> io::Result<File> {
    let fd = rustix::net::socket(AddressFamily::VSOCK, SocketType::STREAM, None)?;
    let addr = VsockAddr {
        family: AddressFamily::VSOCK.as_raw(),
        reserved: 0,
        port,
        cid,
        zero: [0; 4],
    };
    rustix::net::connect(&fd, &addr)?;
    Ok(File::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::crypto::MasterSecret;

    fn keys(master: u8) -> KeyMaterial {
        KeyMaterial::derive(&MasterSecret::from_bytes([master; 32]), [1u8; 16]).unwrap()
    }

    /// A tenant-pool anchor, for the codec and admission tests. `guid` stands
    /// in for the pool guid; the pool id is fixed so chaining can be checked.
    const TEST_POOL_ID: [u8; 16] = [0x7c; 16];
    fn tseal(
        k: &KeyMaterial,
        prev: Option<&Anchor>,
        guid: u64,
        txg: u64,
        nonce: [u8; 32],
    ) -> Anchor {
        Anchor::seal(
            k,
            prev,
            PoolKind::Tenant,
            TEST_POOL_ID,
            [0x7a; 16],
            guid,
            txg,
            nonce,
        )
    }

    #[test]
    fn witness_is_the_newest_committed_txg_that_wrote() {
        // As /proc/spl/kstat/zfs/<pool>/txgs prints it: a raw kstat header,
        // the column names, then one row per txg.
        let kstat = "\
13 0 0x01 6 672 1234 5678
txg      birth            state ndirty       nread        nwritten     reads    writes   otime        qtime        wtime        stime
26       100              C     0            0            90112        0        12       10           10           10           10
27       200              C     0            0            0            0        0        10           10           10           10
28       300              C     0            0            0            0        0        10           10           10           10
29       400              C     4096         0            86016        0        11       10           10           10           10
30       500              S     4096         0            0            0        0        10           10           0            0
31       600              O     0            0            0            0        0        0            0            0            0
";
        assert_eq!(witness(kstat), Some(29));
        assert_eq!(witness("txg birth state ndirty nread nwritten\n"), None);
    }

    /// Shaped as the emulator's kernel logged a boot: a trial load, then the
    /// load with the trusted config. The two name different txgs here, which
    /// a host serving two reads differently could make happen; the last is
    /// the pool as imported. `$import` is a trial under its own name.
    const PLAIN_IMPORT: &str = "\
timestamp    message
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load($import, config untrusted): using uberblock with txg=900
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADING
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=845
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADED
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): UNLOADING
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADING
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=846
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): Read 9 log space maps (9 total blocks - blksz = 131072 bytes) in 1 ms
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADED
";

    /// And a load that failed at one txg and was retried at an older one.
    const RETRIED_IMPORT: &str = "\
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADING
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=810
1791607707   ffff888003fe2080 spa_misc.c:417:spa_load_failed(): spa_load(enclave, config untrusted): FAILED: couldn't get 'config' value in MOS directory [error=5]
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): UNLOADING
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): spa_load_retry: rewind, max txg: 809
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): LOADING
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=809
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADED
";

    #[test]
    fn the_loaded_txg_is_the_last_load_that_finished() {
        assert_eq!(loaded_txg(PLAIN_IMPORT, "enclave"), Some(846));
        assert_eq!(loaded_txg(RETRIED_IMPORT, "enclave"), Some(809));
        assert_eq!(
            loaded_txg(PLAIN_IMPORT, "encl"),
            None,
            "another pool's name"
        );
        // Anything after the last LOADED means it is not the pool as imported.
        for after in ["UNLOADING", "FAILED: no valid uberblock found", "LOADING"] {
            let later = format!("{PLAIN_IMPORT}1 x spa_load(enclave, config trusted): {after}\n");
            assert_eq!(loaded_txg(&later, "enclave"), None, "{after} after LOADED");
        }
        // LOADED with no uberblock named since the load began.
        let unnamed = "1 x spa_load(enclave, config trusted): LOADING\n\
                       1 x spa_load(enclave, config trusted): LOADED\n";
        assert_eq!(loaded_txg(unnamed, "enclave"), None);
        assert_eq!(loaded_txg("", "enclave"), None);
    }

    #[test]
    fn only_the_anchored_state_and_its_descendants_are_admitted() {
        let k = keys(7);
        let a0 = tseal(&k, None, 42, 100, [9u8; 32]);
        let tip = tseal(&k, Some(&a0), 42, 846, [8u8; 32]);
        let mine = tip.property();
        assert!(
            admit(&tip, Some(846), &mine, 42).is_ok(),
            "the anchored txg"
        );
        assert!(admit(&tip, Some(900), &mine, 42).is_ok(), "synced past it");
        // The leg-7 disk: the marker's txg, holding the right nonce.
        let early = admit(&tip, Some(845), &mine, 42).unwrap_err();
        assert!(early.contains("older than the anchored txg"), "{early}");
        assert!(
            admit(&tip, None, &mine, 42).is_err(),
            "no word from the kernel"
        );
        assert!(admit(&tip, Some(846), &mine, 43).is_err(), "another pool");
        // Rolled back: the anchor before, at an older txg or not.
        assert!(admit(&tip, Some(846), &a0.property(), 42).is_err());
        // The marker of an anchor that died unpublished, naming this one.
        let next = marker(tip.seq + 1, &[5u8; 32], &tip.hash());
        assert!(admit(&tip, Some(860), &next, 42).is_ok());
        // ... but not one naming another predecessor, or two seqs on.
        assert!(admit(
            &tip,
            Some(860),
            &marker(tip.seq + 1, &[5u8; 32], &a0.hash()),
            42
        )
        .is_err());
        assert!(admit(
            &tip,
            Some(860),
            &marker(tip.seq + 2, &[5u8; 32], &tip.hash()),
            42
        )
        .is_err());
        // A pool marked before markers named their predecessor.
        let legacy = format!("{}-{}", tip.seq, hex::encode(tip.nonce));
        assert!(admit(&tip, Some(846), &legacy, 42).is_ok());
        assert!(admit(&tip, Some(845), &legacy, 42).is_err());
    }

    #[test]
    fn a_generation_round_trips_and_refuses_tampering_and_strangers() {
        let k = keys(7);
        let g = seal_generation(&k, 5);
        assert_eq!(g.len(), GEN_LEN);
        assert!(verify_generation(&g, &k, 5).is_ok());
        assert!(
            verify_generation(&g, &k, 6).is_err(),
            "number from another key"
        );
        assert!(
            verify_generation(&g, &keys(8), 5).is_err(),
            "another master"
        );
        let mut flipped = g.to_vec();
        flipped[GEN_OFF_G + 7] ^= 1;
        assert!(verify_generation(&flipped, &k, 5).is_err());
        assert!(
            verify_generation(&g[..GEN_LEN - 1], &k, 5).is_err(),
            "truncated"
        );
    }

    /// Each boot claims the next generation, and the fence it leaves behind is
    /// verifiable. Directory-backed, so this is the claim logic, not the pool.
    #[tokio::test]
    async fn boots_claim_generations_in_order() {
        use crate::store::backend::memory::MemoryBackend;
        let backend = Arc::new(MemoryBackend::new());
        let master = MasterSecret::from_bytes([7; 32]);
        let km = Arc::new(KeyMaterial::derive(&master, [1u8; 16]).unwrap());
        let disk = Disk::scratch().unwrap();
        let day = Duration::from_secs(86_400);

        let first = Zfs::create(&disk, backend.clone(), km.clone(), &master, "", day)
            .await
            .unwrap();
        assert_eq!(first.control.generation, 0);
        for expected in 1..=2 {
            let next = Zfs::open(&disk, backend.clone(), km.clone(), &master, "", day, None)
                .await
                .unwrap();
            assert_eq!(next.control.generation, expected);
            assert!(next.control.generation_exists(expected).await.unwrap());
            assert!(!next.control.generation_exists(expected + 1).await.unwrap());
        }
    }

    #[test]
    fn anchor_round_trips_and_chains() {
        let k = keys(7);
        let a0 = tseal(&k, None, 42, 4, [9u8; 32]);
        let a1 = tseal(&k, Some(&a0), 42, 9, [8u8; 32]);
        assert_eq!(a1.encoded().len(), ANCHOR_LEN);
        assert_eq!(
            Anchor::decode_and_verify(&a0.encoded(), &k, 0, TEST_POOL_ID).unwrap(),
            a0
        );
        let back = Anchor::decode_and_verify(&a1.encoded(), &k, 1, TEST_POOL_ID).unwrap();
        assert_eq!((back.seq, back.txg, back.prev), (1, 9, a0.hash()));
        assert_eq!(
            (back.kind, back.pool_id, back.tenant_id),
            (PoolKind::Tenant, TEST_POOL_ID, [0x7a; 16])
        );
    }

    #[test]
    fn anchor_refuses_tampering_replay_and_strangers() {
        let k = keys(7);
        let a = tseal(&k, None, 42, 4, [9u8; 32]);
        let mut flipped = a.encoded().to_vec();
        flipped[OFF_TXG + 7] ^= 1;
        assert!(Anchor::decode_and_verify(&flipped, &k, 0, TEST_POOL_ID).is_err());
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &k, 1, TEST_POOL_ID).is_err(),
            "replayed at another seq"
        );
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &keys(8), 0, TEST_POOL_ID).is_err(),
            "another master"
        );
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &k, 0, [0x99; 16]).is_err(),
            "another pool's id"
        );
    }
}
