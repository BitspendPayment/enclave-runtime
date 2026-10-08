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
//! pinned by its uberblock. But a txg number does not name one: after a
//! rewound import ZFS hands out the abandoned txgs again, and the abandoned
//! uberblocks are still on the disk for the host to serve.
//!
//! So each anchor writes a fresh random value into the pool itself,
//! `zfs set enclave:anchor=<seq>-<nonce>`, which also syncs everything written
//! before it. The txg that reached and the nonce are signed, chained to the
//! anchor before, and published to the roots bucket under Object Lock. Nothing
//! is acknowledged — a response, a registration, a finished task — until the
//! anchor covering it exists.
//!
//! Boot imports the pool as of the anchored txg (`zpool import -T`), which
//! rewinds a pool the enclave synced but died before anchoring, and then reads
//! the property back from what ZFS actually loaded. A rolled-back disk or an
//! abandoned fork cannot carry the newest anchor's nonce, so it is refused.
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
const ZFS_PARAMS: &str = "zfs_txg_timeout=3600 zfs_txg_history=4096 \
    zfs_arc_max=268435456 zfs_dirty_data_max=268435456 zfs_dirty_data_sync_percent=90 \
    spa_load_verify_data=0";

const ANCHOR_MAGIC: &[u8; 8] = b"ZFSANCH1";

// magic | seq | prev | fs_uuid | pool_guid | txg | nonce | pubkey | sig
const OFF_SEQ: usize = 8;
const OFF_PREV: usize = OFF_SEQ + 8;
const OFF_FS_UUID: usize = OFF_PREV + 32;
const OFF_POOL_GUID: usize = OFF_FS_UUID + 16;
const OFF_TXG: usize = OFF_POOL_GUID + 8;
const OFF_NONCE: usize = OFF_TXG + 8;
const OFF_PUBKEY: usize = OFF_NONCE + 32;
const SIGNED_LEN: usize = OFF_PUBKEY + ED25519_PUBLIC_KEY_LEN;
pub const ANCHOR_LEN: usize = SIGNED_LEN + ED25519_SIGNATURE_LEN;

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

/// One anchored pool state, chained to the one before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub prev: Hash256,
    pub pool_guid: u64,
    pub txg: u64,
    /// Also in the pool, as `enclave:anchor`: what tells this state apart
    /// from another that reached the same txg.
    pub nonce: [u8; 32],
    encoded: Bytes,
}

impl Anchor {
    pub fn seal(
        keys: &KeyMaterial,
        prev: Option<&Anchor>,
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
        b.extend_from_slice(&pool_guid.to_be_bytes());
        b.extend_from_slice(&txg.to_be_bytes());
        b.extend_from_slice(&nonce);
        b.extend_from_slice(keys.public_key());
        let sig = sign::sign(keys.signing_key(), &b);
        b.extend_from_slice(&sig);
        Anchor {
            seq,
            prev: prev_hash,
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
        format!("{}-{}", self.seq, hex::encode(self.nonce))
    }

    /// The checks `RootRecord::decode_and_verify` makes, for the same
    /// reasons: our key and not the one the record names, our filesystem, and
    /// a sequence that matches the key it was read from.
    pub fn decode_and_verify(
        bytes: &[u8],
        keys: &KeyMaterial,
        expected_seq: u64,
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
        if &bytes[OFF_FS_UUID..OFF_POOL_GUID] != keys.fs_uuid() {
            return Err(StoreError::Integrity(
                "zfs anchor: belongs to another filesystem",
            ));
        }
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
            pool_guid: u64_at(bytes, OFF_POOL_GUID),
            txg: u64_at(bytes, OFF_TXG),
            nonce: bytes[OFF_NONCE..OFF_PUBKEY].try_into().expect("32 bytes"),
            encoded: Bytes::copy_from_slice(bytes),
        })
    }
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

/// The pool, opened and anchored.
pub struct Zfs {
    /// Held so a [`Disk::Directory`] lives as long as the pool on it.
    #[allow(dead_code)]
    disk: Disk,
    keys: Arc<KeyMaterial>,
    roots: Arc<dyn Backend>,
    prefix: String,
    retention: Duration,
    /// `/` on the pool; a directory for [`Disk::Directory`].
    root: PathBuf,
    pool: bool,
    pool_guid: u64,
    genesis: Hash256,
    /// The newest published anchor, or why anchoring stopped. Held for the
    /// whole of an anchor, so they run one at a time.
    // ponytail: one lock for every tenant; group waiting callers onto one
    // sync and one PUT if throughput matters.
    last: Mutex<std::result::Result<Anchor, String>>,
}

impl std::fmt::Debug for Zfs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Zfs")
            .field("root", &self.root)
            .field("pool_guid", &self.pool_guid)
            .finish()
    }
}

impl Zfs {
    /// Genesis: create the pool on a blank disk and publish anchor 0. Refuses a
    /// disk that already holds a pool, and a bucket that already has anchors.
    pub async fn create(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        master: &MasterSecret,
        prefix: &str,
        retention: Duration,
    ) -> Result<Arc<Zfs>> {
        let mut zfs = Zfs::attach(disk, roots, keys, master, prefix, retention).await?;
        ensure!(
            zfs.find_tip().await?.is_none(),
            "the roots bucket already has anchors; genesis would start a second history"
        );
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
                    POOL,
                    MAPPED,
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
                        &format!("{POOL}/{name}"),
                    ],
                )
                .await?;
            }
            zfs.pool_guid = pool_guid().await?;
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

    /// Resume: import the pool as of the newest anchor, and refuse it unless
    /// what ZFS loaded is that anchor's state. `min_seq` is a floor from
    /// outside the store.
    pub async fn open(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        master: &MasterSecret,
        prefix: &str,
        retention: Duration,
        min_seq: Option<u64>,
    ) -> Result<Arc<Zfs>> {
        let mut zfs = Zfs::attach(disk, roots, keys, master, prefix, retention).await?;
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
            // As of the anchored txg: rewinds a pool synced past it by an
            // enclave that died before publishing, and fails on one that never
            // got there. On a disk without txg A it silently takes the newest
            // txg below it, which is why the property check is not optional.
            run(
                "zpool",
                &[
                    "import",
                    "-f",
                    "-d",
                    "/dev/mapper",
                    "-o",
                    "cachefile=none",
                    "-T",
                    &tip.txg.to_string(),
                    POOL,
                ],
            )
            .await
            .context("importing the pool at the anchored txg")?;
            let loaded = run("zfs", &["get", "-Hp", "-o", "value", PROPERTY, POOL]).await?;
            let guid = pool_guid().await?;
            if loaded.trim() != tip.property() || guid != tip.pool_guid {
                let _ = run("zpool", &["export", POOL]).await;
                bail!(
                    "refusing the pool: it holds anchor {:?} in pool {guid}, but the newest anchor is {:?} in pool {}",
                    loaded.trim(),
                    tip.property(),
                    tip.pool_guid
                );
            }
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
    ) -> Result<Zfs> {
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
        Ok(Zfs {
            disk: disk.clone(),
            keys,
            roots,
            prefix: prefix.to_string(),
            retention,
            root,
            pool,
            pool_guid: 0,
            genesis: Hash256::ZERO,
            last: Mutex::new(Err("not opened".into())),
        })
    }

    /// A pool in a temporary directory with its anchors in memory: what
    /// in-process tests run on.
    #[cfg(any(test, feature = "testing"))]
    pub async fn scratch() -> Arc<Zfs> {
        let master = MasterSecret::from_bytes([7u8; 32]);
        let keys = Arc::new(KeyMaterial::derive(&master, [0u8; 16]).expect("deriving keys"));
        Zfs::create(
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
    /// anyone a write happened.
    pub async fn anchor(&self) -> Result<()> {
        if !self.pool {
            return Ok(());
        }
        let mut last = self.last.lock().await;
        let prev = last
            .as_ref()
            .map_err(|e| anyhow!("zfs anchoring stopped after a failure: {e}"))?
            .clone();
        let start = Instant::now();
        run("zpool", &["sync", POOL]).await?;
        let synced = synced_txg().await?;
        if synced == prev.txg {
            return Ok(()); // nothing has reached the disk since
        }
        let sync_ms = start.elapsed().as_millis();
        // Every failure stops anchoring for good: retrying could publish over
        // a lost race, or past a state the host has since rewritten.
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
            let value = format!("{seq}-{}", hex::encode(nonce)); // Anchor::property, before there is one
                                                                 // A sync task: back once the txg holding it, and everything
                                                                 // written before it, is on the disk.
            run("zfs", &["set", &format!("{PROPERTY}={value}"), POOL]).await?;
            // Its frees are deferred two txgs, and would otherwise reach the
            // disk on the next sync: every later call would see a write and
            // anchor again, read-only ones included.
            run("zpool", &["sync", POOL]).await?;
            let txg = synced_txg().await?;
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
        if prev.is_some() && std::env::var_os("ENCLAVE_ZFS_CRASH_BEFORE_ANCHOR").is_some() {
            tracing::error!(
                seq,
                txg,
                "ENCLAVE_ZFS_CRASH_BEFORE_ANCHOR: dying between sync and publish"
            );
            std::process::abort();
        }
        let anchor = Anchor::seal(&self.keys, prev, self.pool_guid, txg, nonce);
        self.publish(seq, anchor.encoded()).await?;
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
                    &format!("{POOL}/tenants/{}", hex::encode(tenant_id)),
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
        format!("{}zfs/anchors/{seq:016x}", self.prefix)
    }

    /// The retained version: a delete marker hides an Object-Locked object
    /// from a plain GET while leaving it there, so a plain GET would let the
    /// host roll the chain back with one legal call.
    async fn retained(&self, seq: u64) -> StoreResult<Bytes> {
        Ok(self
            .roots
            .get_retained_blob(&self.anchor_key(seq))
            .await?
            .body)
    }

    async fn load(&self, seq: u64) -> Result<Anchor> {
        Ok(Anchor::decode_and_verify(
            &self.retained(seq).await?,
            &self.keys,
            seq,
        )?)
    }

    async fn exists(&self, seq: u64) -> Result<bool> {
        match self.retained(seq).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// The newest anchor. Anchors are contiguous and never deleted, so
    /// existence is monotone in `seq`: gallop, then bisect.
    async fn find_tip(&self) -> Result<Option<u64>> {
        if !self.exists(0).await? {
            return Ok(None);
        }
        let (mut lo, mut step) = (0u64, 1u64);
        while let Some(next) = lo.checked_add(step) {
            if !self.exists(next).await? {
                break;
            }
            lo = next;
            step = step.saturating_mul(2);
        }
        let mut hi = lo.saturating_add(step);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.exists(mid).await? {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        Ok(Some(lo))
    }

    /// Publish `seq`, winning or losing the race for it. `If-None-Match`
    /// alone does not decide that race — a delete marker over the winner lets
    /// a second conditional PUT through — the retained version does, so it is
    /// read back.
    async fn publish(&self, seq: u64, body: Bytes) -> Result<()> {
        let key = self.anchor_key(seq);
        let input = PutBlobInput::new(key, body.clone()).with_object_lock(ObjectLock {
            mode: ObjectLockMode::Compliance,
            retain_until: std::time::SystemTime::now() + self.retention,
        });
        match self.roots.put_blob_if_not_exists(input).await {
            Ok(_) => {}
            Err(StoreError::AlreadyExists) => bail!("another writer published anchor {seq}"),
            Err(e) => return Err(e.into()),
        }
        ensure!(
            self.retained(seq).await? == body,
            "another writer published anchor {seq} first"
        );
        Ok(())
    }
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

async fn synced_txg() -> Result<u64> {
    let kstat = tokio::fs::read_to_string(format!("/proc/spl/kstat/zfs/{POOL}/txgs")).await?;
    witness(&kstat).context("the pool's txg history shows nothing written")
}

async fn pool_guid() -> Result<u64> {
    let out = run("zpool", &["get", "-Hp", "-o", "value", "guid", POOL]).await?;
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

    #[test]
    fn anchor_round_trips_and_chains() {
        let k = keys(7);
        let a0 = Anchor::seal(&k, None, 42, 4, [9u8; 32]);
        let a1 = Anchor::seal(&k, Some(&a0), 42, 9, [8u8; 32]);
        assert_eq!(a1.encoded().len(), ANCHOR_LEN);
        assert_eq!(Anchor::decode_and_verify(&a0.encoded(), &k, 0).unwrap(), a0);
        let back = Anchor::decode_and_verify(&a1.encoded(), &k, 1).unwrap();
        assert_eq!((back.seq, back.txg, back.prev), (1, 9, a0.hash()));
    }

    #[test]
    fn anchor_refuses_tampering_replay_and_strangers() {
        let k = keys(7);
        let a = Anchor::seal(&k, None, 42, 4, [9u8; 32]);
        let mut flipped = a.encoded().to_vec();
        flipped[OFF_TXG + 7] ^= 1;
        assert!(Anchor::decode_and_verify(&flipped, &k, 0).is_err());
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &k, 1).is_err(),
            "replayed at another seq"
        );
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &keys(8), 0).is_err(),
            "another master"
        );
    }
}
