//! Root records — the signed, hash-chained anchor that makes rollback
//! detectable.
//!
//! A root record is the only thing in the store that is signed, and the only
//! thing S3 Object Lock protects. Everything else derives its trust from it:
//! the record carries the meta-dnode, whose block pointer's checksum covers
//! every dnode, every indirect block, and every byte of data beneath.
//!
//! ## What each mechanism actually buys
//!
//! | Threat | Defence |
//! |---|---|
//! | Forge a root | Ed25519 signature over the whole record, verified against the key we derived — not the key the record names |
//! | Alter data under a valid root | The signed `meta_dnode` pointer's BLAKE3 checksum |
//! | Replay an old root at its own key | `seq` is checked against the key it was read from, and against an in-session floor |
//! | Delete a root to hide history | Object Lock COMPLIANCE: undeletable by every principal, including the account root |
//! | Splice two histories together | `prev_root_hash`, which the signature covers |
//! | Two writers racing | `If-None-Match: *`, so exactly one wins `seq + 1` |
//!
//! ## The residual risk
//!
//! A cold mount cannot distinguish "the tip is N" from "the tip is N, and the
//! store is hiding N+1". Object Lock means roots past N cannot be *deleted*,
//! so hiding them requires S3 itself to lie about `HEAD` — but nothing here
//! excludes that cryptographically. Closing it needs an anchor outside S3 (a
//! conditional counter in another service, or a floor supplied through the
//! enclave's KMS encryption context, which [`RootStore::mount`] accepts as
//! `min_seq`).
//!
//! Within a session the gap does not exist: `expected_seq` only ever rises, so
//! a root older than one already accepted is rejected outright.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;

use crate::backend::{Backend, PutBlobInput};
use crate::crypto::{sign, Hash256, KeyMaterial, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
use crate::errors::{FsError, FsResult};

use super::config::StoreConfig;
use super::dnode::{Dnode, DNODE_LEN};

/// On-disk format version. A mount refuses anything else rather than guessing.
pub const FORMAT_VERSION: u32 = 1;

const ROOT_MAGIC: &[u8; 8] = b"S3FSROOT";

// Field offsets. Derived rather than written out, because hand-computed
// offsets are exactly the sort of thing that silently reads the wrong field —
// a mis-sited `signer_pubkey` would compare the wrong 32 bytes and reject
// every valid record. `field_offsets_are_stable` pins them against the encoder.
const OFF_MAGIC: usize = 0;
const OFF_FORMAT: usize = OFF_MAGIC + 8;
const OFF_SEQ: usize = OFF_FORMAT + 4;
const OFF_PREV_HASH: usize = OFF_SEQ + 8;
const OFF_TXG: usize = OFF_PREV_HASH + 32;
const OFF_TIMESTAMP: usize = OFF_TXG + 8;
const OFF_NEXT_OBJID: usize = OFF_TIMESTAMP + 8;
const OFF_FS_UUID: usize = OFF_NEXT_OBJID + 8;
const OFF_PUBKEY: usize = OFF_FS_UUID + 16;
const OFF_META_DNODE: usize = OFF_PUBKEY + ED25519_PUBLIC_KEY_LEN;

/// Bytes covered by the signature.
const SIGNED_LEN: usize = OFF_META_DNODE + DNODE_LEN;
/// Total encoded length.
pub const ROOT_LEN: usize = SIGNED_LEN + ED25519_SIGNATURE_LEN;

fn u64_at(bytes: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(bytes[off..off + 8].try_into().expect("8 bytes"))
}

/// A committed state of the entire filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecord {
    pub format_version: u32,
    /// Sequence number. Also the object key this record lives at, so a replay
    /// to a different key is caught by comparing the two.
    pub seq: u64,
    /// BLAKE3 of the previous record's full encoding. Zero at genesis.
    pub prev_root_hash: Hash256,
    pub txg: u64,
    pub timestamp_nanos: u64,
    pub next_objid: u64,
    pub fs_uuid: [u8; 16],
    pub signer_pubkey: [u8; ED25519_PUBLIC_KEY_LEN],
    /// The dnode array. Its `blkptr` checksum is the Merkle root.
    pub meta_dnode: Dnode,
    pub signature: [u8; ED25519_SIGNATURE_LEN],
}

impl RootRecord {
    /// Build and sign a record.
    pub fn seal(
        keys: &KeyMaterial,
        seq: u64,
        prev: Option<&RootRecord>,
        txg: u64,
        timestamp_nanos: u64,
        meta_dnode: Dnode,
        next_objid: u64,
    ) -> FsResult<RootRecord> {
        let mut record = RootRecord {
            format_version: FORMAT_VERSION,
            seq,
            prev_root_hash: prev.map(RootRecord::hash).unwrap_or(Hash256::ZERO),
            txg,
            timestamp_nanos,
            next_objid,
            fs_uuid: *keys.fs_uuid(),
            signer_pubkey: *keys.public_key(),
            meta_dnode,
            signature: [0u8; ED25519_SIGNATURE_LEN],
        };
        record.signature = sign::sign(keys.signing_key(), &record.signed_bytes()?);
        Ok(record)
    }

    fn signed_bytes(&self) -> FsResult<Vec<u8>> {
        let mut b = Vec::with_capacity(SIGNED_LEN);
        b.extend_from_slice(ROOT_MAGIC);
        b.extend_from_slice(&self.format_version.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(self.prev_root_hash.as_bytes());
        b.extend_from_slice(&self.txg.to_be_bytes());
        b.extend_from_slice(&self.timestamp_nanos.to_be_bytes());
        b.extend_from_slice(&self.next_objid.to_be_bytes());
        b.extend_from_slice(&self.fs_uuid);
        b.extend_from_slice(&self.signer_pubkey);
        b.extend_from_slice(&self.meta_dnode.encode()?);
        debug_assert_eq!(b.len(), SIGNED_LEN);
        Ok(b)
    }

    pub fn encode(&self) -> FsResult<Vec<u8>> {
        let mut b = self.signed_bytes()?;
        b.extend_from_slice(&self.signature);
        Ok(b)
    }

    /// Identity of this record for chaining. Covers the signature too, so a
    /// link commits to one exact set of bytes.
    pub fn hash(&self) -> Hash256 {
        Hash256::of(&self.encode().expect("a sealed record always encodes"))
    }

    /// The Merkle root: one checksum covering the whole filesystem.
    pub fn merkle_root(&self) -> &Hash256 {
        &self.meta_dnode.blkptr.checksum
    }

    /// Decode and fully verify.
    ///
    /// `expected_seq` is the key the bytes were read from. Checking it against
    /// the record's own `seq` is what stops a valid old record being replayed
    /// at a newer key — the signature alone would happily accept that.
    pub fn decode_and_verify(
        bytes: &[u8],
        keys: &KeyMaterial,
        expected_seq: u64,
    ) -> FsResult<RootRecord> {
        if bytes.len() != ROOT_LEN {
            return Err(FsError::Integrity("root: wrong length"));
        }
        if &bytes[OFF_MAGIC..OFF_MAGIC + 8] != ROOT_MAGIC {
            return Err(FsError::Integrity("root: bad magic"));
        }
        let format_version = u32::from_be_bytes(
            bytes[OFF_FORMAT..OFF_FORMAT + 4]
                .try_into()
                .expect("4 bytes"),
        );
        if format_version != FORMAT_VERSION {
            return Err(FsError::Integrity("root: unsupported format version"));
        }

        let mut signer_pubkey = [0u8; ED25519_PUBLIC_KEY_LEN];
        signer_pubkey.copy_from_slice(&bytes[OFF_PUBKEY..OFF_PUBKEY + ED25519_PUBLIC_KEY_LEN]);
        // Verify against the key *we* derived, never the one the record names.
        // Otherwise an attacker signs a forged record with their own key and
        // ships the matching public key alongside it.
        if &signer_pubkey != keys.public_key() {
            return Err(FsError::Integrity("root: signed by an unexpected key"));
        }
        let mut signature = [0u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[SIGNED_LEN..]);
        sign::verify(keys.public_key(), &bytes[..SIGNED_LEN], &signature)?;

        let mut fs_uuid = [0u8; 16];
        fs_uuid.copy_from_slice(&bytes[OFF_FS_UUID..OFF_FS_UUID + 16]);
        if &fs_uuid != keys.fs_uuid() {
            return Err(FsError::Integrity("root: belongs to another filesystem"));
        }

        let seq = u64_at(bytes, OFF_SEQ);
        if seq != expected_seq {
            return Err(FsError::Integrity("root: sequence does not match its key"));
        }

        let record = RootRecord {
            format_version,
            seq,
            prev_root_hash: Hash256::from_bytes(
                bytes[OFF_PREV_HASH..OFF_PREV_HASH + 32]
                    .try_into()
                    .expect("32 bytes"),
            ),
            txg: u64_at(bytes, OFF_TXG),
            timestamp_nanos: u64_at(bytes, OFF_TIMESTAMP),
            next_objid: u64_at(bytes, OFF_NEXT_OBJID),
            fs_uuid,
            signer_pubkey,
            meta_dnode: Dnode::decode(&bytes[OFF_META_DNODE..SIGNED_LEN])?,
            signature,
        };
        if seq == 0 && !record.prev_root_hash.is_zero() {
            return Err(FsError::Integrity("root: genesis record has a predecessor"));
        }
        Ok(record)
    }
}

/// Reads and publishes root records against the locked bucket.
#[derive(Debug)]
pub struct RootStore {
    backend: Arc<dyn Backend>,
    keys: Arc<KeyMaterial>,
    config: Arc<StoreConfig>,
    /// Floor for this session. Only ever rises, so a root older than one we
    /// have already accepted can never be served to us again.
    expected_seq: AtomicU64,
}

impl RootStore {
    pub fn new(
        backend: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        config: Arc<StoreConfig>,
    ) -> Self {
        RootStore {
            backend,
            keys,
            config,
            expected_seq: AtomicU64::new(0),
        }
    }

    /// Highest sequence accepted in this session.
    pub fn expected_seq(&self) -> u64 {
        self.expected_seq.load(Ordering::SeqCst)
    }

    async fn exists(&self, seq: u64) -> FsResult<bool> {
        match self.backend.head_blob(&self.config.root_key(seq)).await {
            Ok(_) => Ok(true),
            Err(FsError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Fetch and verify the record at `seq`.
    pub async fn load(&self, seq: u64) -> FsResult<RootRecord> {
        let got = self
            .backend
            .get_blob(&self.config.root_key(seq), None)
            .await?;
        let record = RootRecord::decode_and_verify(&got.body, &self.keys, seq)?;
        let floor = self.expected_seq();
        if record.seq < floor {
            return Err(FsError::Rollback {
                expected: floor,
                found: record.seq,
            });
        }
        Ok(record)
    }

    /// Fetch and verify a *historical* root, bypassing the session floor.
    ///
    /// Only for read-only access to a past state. The floor exists to stop the
    /// store rewinding the filesystem under us, so nothing that establishes
    /// the live state may use this — and nothing here raises the floor either,
    /// so reading an old snapshot cannot be turned into accepting one.
    ///
    /// Every other check still applies: signature, key, filesystem id, and
    /// that the record's own sequence matches the key it was read from.
    pub async fn load_snapshot(&self, seq: u64) -> FsResult<RootRecord> {
        self.verify_at(seq).await
    }

    /// Locate the newest root.
    ///
    /// Roots are contiguous — every commit takes `seq + 1` and none can be
    /// deleted — so existence is monotone in `seq` and a galloping search
    /// finds the tip in O(log n) HEADs. A full LIST is not an option: after
    /// years of commits there may be millions of keys, and none of them ever
    /// go away.
    ///
    /// The `roots/latest` hint only chooses where the search starts, and it is
    /// verified before being trusted, so a stale or hostile hint costs a round
    /// trip and nothing else.
    pub async fn find_tip(&self) -> FsResult<Option<u64>> {
        if !self.exists(0).await? {
            return Ok(None); // not formatted
        }

        let mut lo = 0u64;
        if let Some(hint) = self.read_hint().await {
            if hint > 0 && self.verify_at(hint).await.is_ok() {
                lo = hint;
            }
        }

        let mut step = 1u64;
        loop {
            match lo.checked_add(step) {
                Some(next) if self.exists(next).await? => {
                    lo = next;
                    step = step.saturating_mul(2);
                }
                _ => break,
            }
        }

        let mut hi = lo.saturating_add(step); // known absent
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

    async fn verify_at(&self, seq: u64) -> FsResult<RootRecord> {
        let got = self
            .backend
            .get_blob(&self.config.root_key(seq), None)
            .await?;
        RootRecord::decode_and_verify(&got.body, &self.keys, seq)
    }

    async fn read_hint(&self) -> Option<u64> {
        let got = self
            .backend
            .get_blob(&self.config.root_hint_key(), None)
            .await
            .ok()?;
        std::str::from_utf8(&got.body).ok()?.trim().parse().ok()
    }

    /// Open the filesystem at its newest root.
    ///
    /// `min_seq` is an externally supplied floor — from a KMS encryption
    /// context, a configuration flag, or anywhere else outside the store's
    /// control. It is the only thing that can close the cold-mount gap
    /// described in this module's documentation.
    ///
    /// Returns `None` if the bucket holds no filesystem at all.
    pub async fn mount(&self, min_seq: Option<u64>) -> FsResult<Option<RootRecord>> {
        let Some(tip) = self.find_tip().await? else {
            return Ok(None);
        };
        if let Some(min) = min_seq {
            if tip < min {
                return Err(FsError::Rollback {
                    expected: min,
                    found: tip,
                });
            }
        }
        let record = self.verify_at(tip).await?;
        self.verify_chain(&record, self.config.root_chain_verify_depth)
            .await?;
        self.raise_floor(record.seq);
        Ok(Some(record))
    }

    /// Walk `depth` links back, checking each `prev_root_hash`.
    ///
    /// Depth 1 catches a spliced history at the tip, which is the live attack.
    /// Walking the whole chain costs one GET per root and is an audit
    /// operation, not something a mount should pay for.
    pub async fn verify_chain(&self, tip: &RootRecord, depth: u32) -> FsResult<()> {
        let mut current = tip.clone();
        for _ in 0..depth {
            if current.seq == 0 {
                return Ok(()); // reached genesis
            }
            let prev = self.verify_at(current.seq - 1).await?;
            if prev.hash() != current.prev_root_hash {
                return Err(FsError::Integrity("root: broken hash chain"));
            }
            current = prev;
        }
        Ok(())
    }

    /// Publish a record, winning or losing the race for its sequence number.
    ///
    /// `If-None-Match: *` means exactly one writer can ever take a given
    /// sequence. Losing is [`FsError::Conflict`], and the caller must treat
    /// that as fatal for the mount rather than retrying: a retry would reuse
    /// the transaction group number, and with it every AEAD nonce in the
    /// commit.
    pub async fn publish(&self, record: &RootRecord) -> FsResult<()> {
        let mut input = PutBlobInput::new(
            self.config.root_key(record.seq),
            Bytes::from(record.encode()?),
        );
        input.object_lock = self.root_retention();

        match self.backend.put_blob_if_not_exists(input).await {
            Ok(_) => {}
            Err(FsError::AlreadyExists) => return Err(FsError::Conflict),
            Err(e) => return Err(e),
        }
        self.raise_floor(record.seq);
        self.write_hint(record.seq).await;
        Ok(())
    }

    fn root_retention(&self) -> Option<crate::backend::ObjectLock> {
        self.config
            .root_retention
            .map(|d| crate::backend::ObjectLock {
                mode: crate::backend::ObjectLockMode::Compliance,
                retain_until: std::time::SystemTime::now() + d,
            })
    }

    /// Best-effort tip hint. Never trusted on read, so a failure here costs a
    /// slower mount and nothing more.
    async fn write_hint(&self, seq: u64) {
        let _ = self
            .backend
            .put_blob(PutBlobInput::new(
                self.config.root_hint_key(),
                Bytes::from(seq.to_string()),
            ))
            .await;
    }

    fn raise_floor(&self, seq: u64) {
        self.expected_seq.fetch_max(seq, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::crypto::MasterSecret;
    use crate::store::dnode::{DnodeKind, META_OBJID};

    fn keys_for(master: u8) -> Arc<KeyMaterial> {
        Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([master; 32]), [1u8; 16]).unwrap())
    }

    fn setup() -> (Arc<MemoryBackend>, Arc<KeyMaterial>, RootStore) {
        let backend = Arc::new(MemoryBackend::new());
        let keys = keys_for(11);
        let config = Arc::new(StoreConfig {
            // Short retention: the tests need to be able to demonstrate that a
            // committed root is refused, not to keep one for a decade.
            root_retention: Some(std::time::Duration::from_secs(3600)),
            ..Default::default()
        });
        let rs = RootStore::new(backend.clone(), keys.clone(), config);
        (backend, keys, rs)
    }

    fn meta() -> Dnode {
        Dnode::new(META_OBJID, DnodeKind::DnodeArray, 17, 0)
    }

    fn seal(keys: &KeyMaterial, seq: u64, prev: Option<&RootRecord>) -> RootRecord {
        RootRecord::seal(keys, seq, prev, seq + 1, 1_000 + seq, meta(), 2).unwrap()
    }

    /// Publish a chain of `n` roots, seq 0..n-1.
    async fn publish_chain(rs: &RootStore, keys: &KeyMaterial, n: u64) -> Vec<RootRecord> {
        let mut out: Vec<RootRecord> = Vec::new();
        for seq in 0..n {
            let r = seal(keys, seq, out.last());
            rs.publish(&r).await.unwrap();
            out.push(r);
        }
        out
    }

    // ---- encoding ----------------------------------------------------------

    #[test]
    fn round_trips() {
        let keys = keys_for(11);
        let r = seal(&keys, 5, None);
        assert_eq!(r.encode().unwrap().len(), ROOT_LEN);
        assert_eq!(
            RootRecord::decode_and_verify(&r.encode().unwrap(), &keys, 5).unwrap(),
            r
        );
    }

    /// The decoder reads by offset; the encoder writes in order. Pin every
    /// boundary so a field added or resized cannot silently shift the ones
    /// after it into reading the wrong bytes.
    #[test]
    fn field_offsets_are_stable() {
        let keys = keys_for(11);
        let r = RootRecord::seal(&keys, 0x1122, None, 0x3344, 0x5566, meta(), 0x7788).unwrap();
        let b = r.encode().unwrap();

        assert_eq!(&b[OFF_MAGIC..OFF_MAGIC + 8], ROOT_MAGIC);
        assert_eq!(
            &b[OFF_FORMAT..OFF_FORMAT + 4],
            &FORMAT_VERSION.to_be_bytes()
        );
        assert_eq!(u64_at(&b, OFF_SEQ), 0x1122);
        assert_eq!(
            &b[OFF_PREV_HASH..OFF_PREV_HASH + 32],
            Hash256::ZERO.as_bytes()
        );
        assert_eq!(u64_at(&b, OFF_TXG), 0x3344);
        assert_eq!(u64_at(&b, OFF_TIMESTAMP), 0x5566);
        assert_eq!(u64_at(&b, OFF_NEXT_OBJID), 0x7788);
        assert_eq!(&b[OFF_FS_UUID..OFF_FS_UUID + 16], keys.fs_uuid());
        assert_eq!(&b[OFF_PUBKEY..OFF_PUBKEY + 32], keys.public_key());
        assert_eq!(&b[OFF_META_DNODE..SIGNED_LEN], &meta().encode().unwrap());
        assert_eq!(&b[SIGNED_LEN..], &r.signature);
        assert_eq!(b.len(), ROOT_LEN);
    }

    #[test]
    fn every_field_survives_the_round_trip() {
        let keys = keys_for(11);
        let prev = seal(&keys, 0, None);
        let r = seal(&keys, 1, Some(&prev));
        let decoded = RootRecord::decode_and_verify(&r.encode().unwrap(), &keys, 1).unwrap();

        assert_eq!(decoded.seq, 1);
        assert_eq!(decoded.txg, 2);
        assert_eq!(decoded.timestamp_nanos, 1001);
        assert_eq!(decoded.next_objid, 2);
        assert_eq!(decoded.prev_root_hash, prev.hash());
        assert_eq!(&decoded.fs_uuid, keys.fs_uuid());
        assert_eq!(&decoded.signer_pubkey, keys.public_key());
        assert_eq!(decoded.meta_dnode, meta());
    }

    // ---- verification failures ---------------------------------------------

    #[test]
    fn a_tampered_record_fails_its_signature() {
        let keys = keys_for(11);
        let r = seal(&keys, 3, None);
        let mut bytes = r.encode().unwrap();
        // Move the Merkle root: the single most valuable field to an attacker.
        bytes[SIGNED_LEN - 40] ^= 0x01;
        assert!(matches!(
            RootRecord::decode_and_verify(&bytes, &keys, 3),
            Err(FsError::Integrity(_))
        ));
    }

    /// The forged-record case: an attacker signs their own record and ships
    /// the matching public key. Verifying against the key in the record would
    /// accept it; verifying against the key we derived does not.
    #[test]
    fn a_record_signed_by_another_key_is_refused() {
        let ours = keys_for(11);
        let theirs = keys_for(22);
        let forged = seal(&theirs, 3, None);
        assert!(matches!(
            RootRecord::decode_and_verify(&forged.encode().unwrap(), &ours, 3),
            Err(FsError::Integrity("root: signed by an unexpected key"))
        ));
    }

    /// A perfectly valid record replayed to a different key.
    #[test]
    fn a_record_replayed_to_another_key_is_refused() {
        let keys = keys_for(11);
        let r = seal(&keys, 3, None);
        assert!(matches!(
            RootRecord::decode_and_verify(&r.encode().unwrap(), &keys, 7),
            Err(FsError::Integrity("root: sequence does not match its key"))
        ));
    }

    #[test]
    fn malformed_records_are_refused() {
        let keys = keys_for(11);
        let r = seal(&keys, 0, None);

        assert!(RootRecord::decode_and_verify(&[], &keys, 0).is_err());
        assert!(RootRecord::decode_and_verify(&[0u8; ROOT_LEN], &keys, 0).is_err());

        let mut short = r.encode().unwrap();
        short.pop();
        assert!(RootRecord::decode_and_verify(&short, &keys, 0).is_err());

        let mut bad_magic = r.encode().unwrap();
        bad_magic[0] ^= 0xff;
        assert!(matches!(
            RootRecord::decode_and_verify(&bad_magic, &keys, 0),
            Err(FsError::Integrity("root: bad magic"))
        ));

        let mut bad_version = r.encode().unwrap();
        bad_version[11] = 99;
        assert!(matches!(
            RootRecord::decode_and_verify(&bad_version, &keys, 0),
            Err(FsError::Integrity("root: unsupported format version"))
        ));
    }

    #[test]
    fn a_record_from_another_filesystem_is_refused() {
        let master = MasterSecret::from_bytes([11u8; 32]);
        let ours = KeyMaterial::derive(&master, [1u8; 16]).unwrap();
        let theirs = KeyMaterial::derive(&master, [2u8; 16]).unwrap();
        let r = seal(&theirs, 0, None);
        // Same master secret, different filesystem: the derived signing key
        // differs, so this is caught at the signature.
        assert!(RootRecord::decode_and_verify(&r.encode().unwrap(), &ours, 0).is_err());
    }

    // ---- publishing --------------------------------------------------------

    #[tokio::test]
    async fn publish_then_load() {
        let (_b, keys, rs) = setup();
        let r = seal(&keys, 0, None);
        rs.publish(&r).await.unwrap();
        assert_eq!(rs.load(0).await.unwrap(), r);
    }

    /// Exactly one writer can take a sequence number. The loser must fail, not
    /// retry: a retry would reuse the transaction group number and with it
    /// every AEAD nonce in the commit.
    #[tokio::test]
    async fn only_one_writer_can_claim_a_sequence() {
        let (_b, keys, rs) = setup();
        let first = seal(&keys, 0, None);
        rs.publish(&first).await.unwrap();

        // A different record competing for the same sequence.
        let second = RootRecord::seal(&keys, 0, None, 1, 9999, meta(), 2).unwrap();
        assert!(matches!(rs.publish(&second).await, Err(FsError::Conflict)));

        // The winner's record is what remains.
        assert_eq!(rs.load(0).await.unwrap(), first);
    }

    #[tokio::test]
    async fn a_published_root_cannot_be_deleted_or_overwritten() {
        let (backend, keys, rs) = setup();
        let r = seal(&keys, 0, None);
        rs.publish(&r).await.unwrap();

        let key = rs.config.root_key(0);
        assert!(matches!(
            backend.delete_blob(&key).await,
            Err(FsError::AccessDenied)
        ));
        assert!(matches!(
            backend
                .put_blob(PutBlobInput::new(key, Bytes::from_static(b"forged")))
                .await,
            Err(FsError::AccessDenied)
        ));
        assert_eq!(rs.load(0).await.unwrap(), r);
    }

    // ---- tip discovery -----------------------------------------------------

    #[tokio::test]
    async fn an_unformatted_bucket_has_no_tip() {
        let (_b, _k, rs) = setup();
        assert_eq!(rs.find_tip().await.unwrap(), None);
        assert_eq!(rs.mount(None).await.unwrap(), None);
    }

    #[tokio::test]
    async fn tip_is_found_at_every_chain_length() {
        for n in [1u64, 2, 3, 7, 8, 9, 33, 64] {
            let (_b, keys, rs) = setup();
            publish_chain(&rs, &keys, n).await;
            assert_eq!(rs.find_tip().await.unwrap(), Some(n - 1), "chain of {n}");
        }
    }

    #[tokio::test]
    async fn tip_is_found_without_any_hint() {
        let (backend, keys, rs) = setup();
        publish_chain(&rs, &keys, 20).await;
        backend
            .delete_blob(&rs.config.root_hint_key())
            .await
            .unwrap();
        assert_eq!(rs.find_tip().await.unwrap(), Some(19));
    }

    /// The hint chooses where the search starts and nothing else. A lie can
    /// slow a mount down; it cannot change which root is accepted.
    #[tokio::test]
    async fn a_lying_hint_does_not_change_the_tip() {
        let (backend, keys, rs) = setup();
        publish_chain(&rs, &keys, 20).await;
        let hint_key = rs.config.root_hint_key();

        for lie in ["0", "5", "999999", "garbage", ""] {
            backend
                .put_blob(PutBlobInput::new(
                    hint_key.clone(),
                    Bytes::from(lie.to_string()),
                ))
                .await
                .unwrap();
            assert_eq!(
                rs.find_tip().await.unwrap(),
                Some(19),
                "hint {lie:?} changed the tip"
            );
        }
    }

    // ---- mounting ----------------------------------------------------------

    #[tokio::test]
    async fn mount_returns_the_newest_root() {
        let (_b, keys, rs) = setup();
        let chain = publish_chain(&rs, &keys, 5).await;
        let mounted = rs.mount(None).await.unwrap().unwrap();
        assert_eq!(mounted, chain[4]);
        assert_eq!(rs.expected_seq(), 4);
    }

    #[tokio::test]
    async fn mount_verifies_the_chain() {
        let (_b, keys, rs) = setup();
        publish_chain(&rs, &keys, 3).await;

        // A record whose predecessor link is wrong: individually valid, and
        // correctly signed, but not a continuation of this history.
        let spliced = RootRecord::seal(&keys, 3, None, 99, 0, meta(), 2).unwrap();
        rs.publish(&spliced).await.unwrap();

        assert!(matches!(
            rs.mount(None).await,
            Err(FsError::Integrity("root: broken hash chain"))
        ));
    }

    #[tokio::test]
    async fn mount_honours_an_external_floor() {
        let (_b, keys, rs) = setup();
        publish_chain(&rs, &keys, 5).await;

        assert!(rs.mount(Some(4)).await.is_ok());
        assert!(matches!(
            rs.mount(Some(10)).await,
            Err(FsError::Rollback {
                expected: 10,
                found: 4
            })
        ));
    }

    /// The in-session guarantee: once a sequence has been accepted, nothing
    /// older is ever served again, whatever the store offers.
    #[tokio::test]
    async fn an_older_root_is_refused_once_a_newer_one_is_seen() {
        let (_b, keys, rs) = setup();
        publish_chain(&rs, &keys, 5).await;
        rs.mount(None).await.unwrap();
        assert_eq!(rs.expected_seq(), 4);

        assert!(matches!(
            rs.load(2).await,
            Err(FsError::Rollback {
                expected: 4,
                found: 2
            })
        ));
        assert!(rs.load(4).await.is_ok());
    }

    #[tokio::test]
    async fn the_floor_never_falls() {
        let (_b, keys, rs) = setup();
        publish_chain(&rs, &keys, 5).await;
        rs.mount(None).await.unwrap();
        rs.raise_floor(2);
        assert_eq!(rs.expected_seq(), 4, "the floor must only ever rise");
    }

    #[tokio::test]
    async fn publishing_raises_the_floor() {
        let (_b, keys, rs) = setup();
        let chain = publish_chain(&rs, &keys, 3).await;
        assert_eq!(rs.expected_seq(), 2);
        assert!(
            rs.load(1).await.is_err(),
            "our own history is now behind us"
        );
        assert_eq!(rs.load(2).await.unwrap(), chain[2]);
    }

    #[tokio::test]
    async fn a_full_chain_walk_verifies_every_link() {
        let (_b, keys, rs) = setup();
        let chain = publish_chain(&rs, &keys, 10).await;
        rs.verify_chain(&chain[9], 9).await.unwrap();
        // Walking past genesis stops rather than failing.
        rs.verify_chain(&chain[9], 100).await.unwrap();
    }

    #[tokio::test]
    async fn the_merkle_root_is_the_meta_dnode_checksum() {
        let keys = keys_for(11);
        let r = seal(&keys, 0, None);
        assert_eq!(r.merkle_root(), &r.meta_dnode.blkptr.checksum);
    }
}
