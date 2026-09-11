//! The boot machine: which state an enclave will load, and what it records.
//!
//! `Store::open` used to create a filesystem when it found none, so an enclave
//! pointed at an emptied store served a fresh, correctly-signed, completely
//! wrong filesystem. Most of these tests are about the *refusals* that replaced
//! that, because the happy path was never the problem. The rest are about pair
//! records: what a new runtime or guest leaves behind, and what a restart does
//! not.
//!
//! Everything runs over `MemoryBackend`, so there is no Docker and no network:
//! what is under test is the decision, not S3.
//!
//! **Receipts here are unsigned**, and deliberately. `ReceiptTrust::Required`
//! would demand a chain to the real AWS root, which no test can produce.
//! `UnsignedEmulator` skips the *signature* and still applies every
//! expectation — PCR0, PCR16, `user_data` — so the state machine, the identity
//! binding and the pair records are all genuinely exercised. The signature path
//! is `nitro-attestation`'s own tests, against real ES384 chains.
//!
//! The NSM here keeps registers the way the device does: 0–15 locked from the
//! start, 16 free until the guest is measured, and **only locked registers in a
//! document**. The fake it replaced put an unlocked register into every
//! document, which is how a successor handoff that could never have worked on
//! hardware passed here.

use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use enclave_runtime::boot::{BootConfig, BootMode, Pair, ReceiptTrust};
use enclave_runtime::{Backends, MasterKeySource, MountConfig, SealedKey, StaticKey};
use nitro_attestation::testing::TestChain;
use nitro_attestation::AttestationDocument;
use nitro_nsm::{AttestationRequest, Nsm, Pcr, PCR_GUEST, PCR_ZERO};
use s3fs_core::backend::{
    memory::MemoryBackend, Backend, BlobMeta, Capabilities, CompletedPart, CopyBlobInput,
    GetBlobOutput, ListBlobsInput, ListBlobsOutput, MultipartId, PartUploadOutput, PutBlobInput,
};
use s3fs_core::{FsError, MasterSecret};

const GUEST_A: &[u8] = b"guest component A";
const GUEST_B: &[u8] = b"guest component B";
const FS_ID: [u8; 16] = [3u8; 16];

/// An NSM that keeps registers like the device, and signs documents listing
/// the locked ones.
struct TestNsm {
    chain: TestChain,
    pcrs: Mutex<Vec<Pcr>>,
    attestations: AtomicUsize,
}

impl std::fmt::Debug for TestNsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestNsm")
    }
}

impl TestNsm {
    /// A fresh enclave running image `pcr0`, before its runtime has measured
    /// anything.
    fn unmeasured(pcr0: u8) -> Arc<Self> {
        Arc::new(TestNsm {
            chain: TestChain::new().expect("chain"),
            pcrs: Mutex::new(
                (0..32)
                    .map(|i| Pcr {
                        locked: i < 16,
                        value: if i == 0 {
                            vec![pcr0; 48]
                        } else {
                            PCR_ZERO.to_vec()
                        },
                    })
                    .collect(),
            ),
            attestations: AtomicUsize::new(0),
        })
    }

    /// A fresh enclave running image `pcr0`, with `guest` measured the way the
    /// runtime measures it. A restart is one of these, not the same one again.
    fn running(pcr0: u8, guest: &[u8]) -> Arc<Self> {
        let nsm = Self::unmeasured(pcr0);
        enclave_runtime::measure_guest(nsm.as_ref(), guest).expect("measuring the guest");
        nsm
    }

    fn attestations(&self) -> usize {
        self.attestations.load(Ordering::SeqCst)
    }
}

impl Nsm for TestNsm {
    fn get_random(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        buf.fill(0x5a);
        Ok(())
    }

    fn attest(&self, request: &AttestationRequest) -> anyhow::Result<Vec<u8>> {
        self.attestations.fetch_add(1, Ordering::SeqCst);
        let pcrs = self
            .pcrs
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, pcr)| pcr.locked)
            .map(|(index, pcr)| (index as u32, pcr.value.clone()))
            .collect();
        self.chain
            .document_with_pcrs(request.user_data.clone(), request.nonce.clone(), pcrs)
    }

    fn describe_pcr(&self, index: u16) -> anyhow::Result<Pcr> {
        self.pcrs
            .lock()
            .unwrap()
            .get(index as usize)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))
    }

    fn extend_pcr(&self, index: u16, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.value = nitro_nsm::pcr_extend(&pcr.value, data);
        Ok(pcr.value.clone())
    }

    fn lock_pcr(&self, index: u16) -> anyhow::Result<()> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.locked = true;
        Ok(())
    }

    fn describe(&self) -> String {
        "test NSM".into()
    }
}

/// One store, reused across boots, so "resume" means what it says.
struct Store {
    data: Arc<dyn Backend>,
    roots: Arc<dyn Backend>,
}

impl Store {
    fn new() -> Self {
        Store {
            data: Arc::new(MemoryBackend::new()),
            roots: Arc::new(MemoryBackend::new()),
        }
    }

    fn backends(&self) -> Backends {
        Backends {
            data: self.data.clone(),
            roots: self.roots.clone(),
        }
    }

    /// Write an object with no retention, to construct a store in a shape a
    /// completed genesis never produces.
    async fn put(&self, key: &str, body: Vec<u8>) {
        self.roots
            .put_blob(PutBlobInput::new(key, body.into()))
            .await
            .expect("write");
    }

    /// Every origin record, sorted. What a boot wrote is the difference
    /// between two of these.
    async fn origin_records(&self) -> Vec<String> {
        let listed = self
            .roots
            .list_blobs(ListBlobsInput {
                prefix: "origin/",
                max_keys: Some(1000),
                start_after: None,
                continuation_token: None,
                delimiter: None,
            })
            .await
            .expect("list");
        let mut keys: Vec<String> = listed.items.into_iter().map(|item| item.key).collect();
        keys.sort();
        keys
    }

    async fn pair_records(&self) -> Vec<String> {
        self.origin_records()
            .await
            .into_iter()
            .filter(|key| key.contains(".pair."))
            .collect()
    }

    async fn document(&self, key: &str) -> AttestationDocument {
        let body = self
            .roots
            .get_retained_blob(key)
            .await
            .expect("the record")
            .body;
        nitro_attestation::parse(&body).expect("a document")
    }
}

fn config() -> MountConfig {
    MountConfig {
        bucket: "data".into(),
        roots_bucket: Some("roots".into()),
        region: "us-east-1".into(),
        endpoint: None,
        access_key_id: None,
        secret_access_key: None,
        session_token: None,
        force_path_style: false,
        bucket_prefix: String::new(),
        mount_path: "/".into(),
        fs_id: FS_ID,
        min_root_seq: None,
        skip_bucket_probe: true,
        request_timeout: std::time::Duration::from_secs(30),
    }
}

fn boot_config() -> BootConfig {
    BootConfig {
        trust: ReceiptTrust::UnsignedEmulator,
    }
}

fn key() -> StaticKey {
    StaticKey::new(MasterSecret::from_bytes([8u8; 32]))
}

fn pair_of(pcr0: u8, guest: &[u8]) -> Pair {
    Pair {
        pcr0: [pcr0; 48],
        pcr16: nitro_attestation::guest_pcr(guest),
    }
}

fn record_key(pair: &Pair) -> String {
    pair.record_key("", &FS_ID)
}

async fn boot(store: &Store, nsm: &Arc<TestNsm>) -> anyhow::Result<enclave_runtime::Booted> {
    boot_on(store.backends(), nsm).await
}

async fn boot_on(
    backends: Backends,
    nsm: &Arc<TestNsm>,
) -> anyhow::Result<enclave_runtime::Booted> {
    let nsm: Arc<dyn Nsm> = nsm.clone();
    enclave_runtime::boot(&backends, &config(), &boot_config(), &nsm, &key()).await
}

#[tokio::test]
async fn an_empty_store_becomes_a_filesystem_with_an_attested_origin() {
    let store = Store::new();
    let booted = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");
    assert_eq!(booted.mode, BootMode::Genesis);
    assert_eq!(booted.pair, pair_of(0xaa, GUEST_A));

    // The receipt, the sealed key, and the record of who ran genesis.
    let pair_key = record_key(&booted.pair);
    let mut expected = vec![
        format!("origin/{}.key", hex::encode(FS_ID)),
        format!("origin/{}.receipt", hex::encode(FS_ID)),
        pair_key.clone(),
    ];
    expected.sort();
    assert_eq!(store.origin_records().await, expected);

    // It says who, in registers a document carries only once they are locked.
    let record = store.document(&pair_key).await;
    assert_eq!(record.pcr(0), Some(&[0xaa; 48][..]));
    assert_eq!(
        record.pcr(PCR_GUEST as u32),
        Some(&nitro_attestation::guest_pcr(GUEST_A)[..])
    );

    // And it stays said.
    assert!(
        store
            .roots
            .put_blob(PutBlobInput::new(&pair_key, b"rewritten".to_vec().into()))
            .await
            .is_err(),
        "COMPLIANCE retention must refuse to overwrite a pair record"
    );
}

/// The property the whole milestone is for: a second boot recognises the state
/// as its own, rather than making a new one. And a plain restart leaves no
/// trace — records accumulate per pair, not per boot.
#[tokio::test]
async fn a_restart_resumes_the_same_state_and_writes_nothing() {
    let store = Store::new();
    let first = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");
    let before = store.origin_records().await;

    let restarted = TestNsm::running(0xaa, GUEST_A);
    let second = boot(&store, &restarted).await.expect("resume");

    assert_eq!(second.mode, BootMode::Resume);
    assert_eq!(
        second.state_root, first.state_root,
        "the same filesystem must hash to the same state_root"
    );
    assert_eq!(
        store.origin_records().await,
        before,
        "a restart wrote an origin record"
    );
    assert_eq!(
        restarted.attestations(),
        0,
        "a restart asked the NSM for a record it already had"
    );
}

/// **The delete marker.** Object Lock protects a *version*; it does not stop a
/// `DeleteObject` without a version id, which writes a marker that hides the
/// object from every ordinary read while the bytes stay undeletable underneath.
///
/// That gap is only dangerous where absence means something. Hide the receipt
/// *and* the sealed key and the naive reading is `(None, None)` — create a
/// filesystem — while the real one sits in the same bucket. Hide the pair
/// record and the naive reading is "first boot of this pair". The enclave reads
/// the retained versions instead, so the records are still found, and the boot
/// is still a plain resume.
#[tokio::test]
async fn hiding_the_origin_records_behind_a_delete_marker_does_not_work() {
    let store = Store::new();
    let first = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let hidden = [
        format!("origin/{}.receipt", hex::encode(FS_ID)),
        format!("origin/{}.key", hex::encode(FS_ID)),
        record_key(&first.pair),
    ];
    for key in &hidden {
        // Succeeds, as S3 does. Refusing would be the comfortable answer and
        // is not the true one.
        store
            .roots
            .delete_blob(key)
            .await
            .expect("S3 allows a delete marker");
        assert!(
            store.roots.get_blob(key, None).await.is_err(),
            "{key} should be gone as far as an ordinary read can tell"
        );
    }

    let second = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("the records are still there");
    assert_eq!(second.mode, BootMode::Resume);
    assert_eq!(
        second.state_root, first.state_root,
        "a hidden origin must not become a new one"
    );
}

/// The same attack against a store that reads the *current* version, to show
/// the test above is not passing for an unrelated reason. This is what the
/// enclave used to do, and it ends in a second filesystem.
#[tokio::test]
async fn reading_the_current_version_is_what_made_hiding_work() {
    let store = Store::new();
    boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let receipt = format!("origin/{}.receipt", hex::encode(FS_ID));
    store.roots.delete_blob(&receipt).await.unwrap();

    // What `get_blob` — the old read — would have reported.
    assert!(
        store.roots.get_blob(&receipt, None).await.is_err(),
        "the marker hides it"
    );
    // What the conditional PUT would then have allowed: the genesis lease is
    // free again, so a second enclave could take it.
    let retaken = store
        .roots
        .put_blob_if_not_exists(PutBlobInput::new(
            receipt.clone(),
            Bytes::from_static(b"a forged origin"),
        ))
        .await;
    assert!(
        retaken.is_ok(),
        "the lease is retakeable over a marker — this is why absence must be \
         read from the retained version, not the current one"
    );

    // And the retained version is still the real one underneath.
    let retained = store.roots.get_retained_blob(&receipt).await.unwrap();
    assert_ne!(
        retained.body.as_ref(),
        b"a forged origin",
        "Object Lock kept the original version"
    );
}

/// **The state substitution.** A receipt with no filesystem under it: either
/// the store is hiding everything, or it is not the store the receipt
/// describes. Either way there is nothing here this enclave may serve, and the
/// old code would have made a fresh empty filesystem instead.
///
/// Written directly rather than by hiding, because the test above shows hiding
/// no longer produces this state — this is the shape, not the route to it.
#[tokio::test]
async fn a_receipt_without_a_filesystem_is_refused() {
    let store = Store::new();
    let nsm = TestNsm::running(0xaa, GUEST_A);

    store
        .put(
            &format!("origin/{}.receipt", hex::encode(FS_ID)),
            nsm.attest(&AttestationRequest::with_user_data(b"anything".to_vec()))
                .unwrap(),
        )
        .await;

    let err = boot(&store, &nsm).await.expect_err("must refuse");
    let text = format!("{err:#}");
    assert!(text.contains("no sealed key"), "{text}");
    assert!(
        text.contains("Refusing to boot"),
        "the refusal must be explicit about what it is not doing: {text}"
    );
}

/// The mirror: a sealed key with no receipt. That is what an interrupted
/// genesis leaves — the receipt is written last, on purpose — and it is also
/// what hiding the receipt leaves. Nothing on this side can tell those apart,
/// so the only safe answer is to refuse both.
#[tokio::test]
async fn a_sealed_key_without_a_receipt_is_refused() {
    let store = Store::new();
    let (_, sealed) = key().mint().await.unwrap();
    store
        .put(
            &format!("origin/{}.key", hex::encode(FS_ID)),
            sealed.as_bytes().to_vec(),
        )
        .await;

    let err = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect_err("must refuse");
    let text = format!("{err:#}");
    assert!(text.contains("no state-origin receipt"), "{text}");
    assert!(text.contains("Refusing to boot"), "{text}");
}

/// A key source that counts what it was asked for.
#[derive(Debug)]
struct CountingKey {
    inner: StaticKey,
    asked: AtomicUsize,
}

#[async_trait::async_trait]
impl MasterKeySource for CountingKey {
    fn describe(&self) -> &'static str {
        "counting test key"
    }

    async fn mint(&self) -> anyhow::Result<(MasterSecret, SealedKey)> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.mint().await
    }

    async fn open(&self, sealed: &SealedKey) -> anyhow::Result<MasterSecret> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.open(sealed).await
    }
}

/// **The ordering.** A guest that was never measured must not get as far as
/// KMS: the attestation it presented would carry no guest, and nothing would
/// stop the register being extended after a key was released.
#[tokio::test]
async fn an_unmeasured_guest_is_refused_before_any_key_is_asked_for() {
    let store = Store::new();
    let nsm: Arc<dyn Nsm> = TestNsm::unmeasured(0xaa);
    let keys = CountingKey {
        inner: key(),
        asked: AtomicUsize::new(0),
    };

    let err = enclave_runtime::boot(&store.backends(), &config(), &boot_config(), &nsm, &keys)
        .await
        .expect_err("must refuse");
    assert!(
        format!("{err:#}").contains("PCR16 is not locked"),
        "{err:#}"
    );
    assert_eq!(
        keys.asked.load(Ordering::SeqCst),
        0,
        "a key was asked for on behalf of an unmeasured guest"
    );
    assert!(
        store.origin_records().await.is_empty(),
        "nothing may be written for it either"
    );
}

/// **A new guest.** The key policy was edited to name it, so the boot machine
/// does not refuse it. What it does is leave a record — exactly one — carrying
/// the new guest's measurement against this state, and nothing on the restarts
/// after.
#[tokio::test]
async fn a_new_guest_is_an_upgrade_and_is_recorded_once() {
    let store = Store::new();
    let genesis = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let upgraded = TestNsm::running(0xaa, GUEST_B);
    let first = boot(&store, &upgraded).await.expect("upgrade");
    assert_eq!(first.mode, BootMode::Upgrade);
    assert_eq!(
        first.state_root, genesis.state_root,
        "an upgrade must not change what the state is"
    );
    assert_eq!(
        upgraded.attestations(),
        1,
        "one document, for the one record"
    );

    let records = store.pair_records().await;
    assert_eq!(records.len(), 2, "{records:?}");
    let record = store.document(&record_key(&pair_of(0xaa, GUEST_B))).await;
    assert_eq!(record.pcr(0), Some(&[0xaa; 48][..]));
    assert_eq!(
        record.pcr(PCR_GUEST as u32),
        Some(&nitro_attestation::guest_pcr(GUEST_B)[..])
    );

    let before = store.origin_records().await;
    let again = boot(&store, &TestNsm::running(0xaa, GUEST_B))
        .await
        .expect("resume");
    assert_eq!(
        again.mode,
        BootMode::Resume,
        "a restart after an upgrade is not another upgrade"
    );
    assert_eq!(store.origin_records().await, before);
}

/// **A new runtime image.** This used to be refused unless the outgoing image
/// had authorised the incoming one. The key policy decides that now, and the
/// boot machine records it exactly as it records a new guest.
#[tokio::test]
async fn a_new_runtime_image_is_an_upgrade_too() {
    let store = Store::new();
    let genesis = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let upgraded = boot(&store, &TestNsm::running(0xbb, GUEST_A))
        .await
        .expect("upgrade");
    assert_eq!(upgraded.mode, BootMode::Upgrade);
    assert_eq!(upgraded.state_root, genesis.state_root);
    assert_eq!(store.pair_records().await.len(), 2);
}

/// **Set, not sequence.** Returning to a pair that has held the state before
/// finds its record and writes nothing, so the store cannot show that a
/// rollback happened — only that both pairs have held the state. The order is
/// in CloudTrail's record of key-policy edits. Pinned here so the trade-off is
/// visible where it is made.
#[tokio::test]
async fn returning_to_an_earlier_pair_adds_no_record() {
    let store = Store::new();
    boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");
    boot(&store, &TestNsm::running(0xaa, GUEST_B))
        .await
        .expect("upgrade");

    let back = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("back again");
    assert_eq!(back.mode, BootMode::Resume);
    assert_eq!(store.pair_records().await.len(), 2);
}

/// **A copied record.** A genuine record from another pair, copied to this
/// pair's key ahead of its first boot. It is signed; it is simply about someone
/// else. Found rather than written, and still refused, because a record is
/// checked for what it says and not only for being there.
#[tokio::test]
async fn a_record_copied_from_another_pair_is_refused() {
    let store = Store::new();
    boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let genuine = store
        .roots
        .get_retained_blob(&record_key(&pair_of(0xaa, GUEST_A)))
        .await
        .unwrap()
        .body;
    store
        .put(&record_key(&pair_of(0xaa, GUEST_B)), genuine.to_vec())
        .await;

    let err = boot(&store, &TestNsm::running(0xaa, GUEST_B))
        .await
        .expect_err("must refuse");
    let text = format!("{err:#}");
    assert!(text.contains("PCR16 mismatch"), "{text}");
}

/// Plants an object at a pair record's key a moment before the enclave's own
/// conditional write lands — the shape of another first boot of the same pair
/// winning the race, or of something less friendly doing the same.
#[derive(Debug)]
struct Interloper {
    inner: Arc<dyn Backend>,
    plant: Mutex<Option<Planted>>,
}

#[derive(Debug)]
enum Planted {
    /// A copy of the record the enclave is about to write: what a concurrent
    /// boot of the same pair would have written.
    TheSameRecord,
    /// These bytes instead.
    Bytes(Vec<u8>),
}

impl Interloper {
    fn planting(inner: Arc<dyn Backend>, planted: Planted) -> Arc<dyn Backend> {
        Arc::new(Interloper {
            inner,
            plant: Mutex::new(Some(planted)),
        })
    }
}

#[async_trait::async_trait]
impl Backend for Interloper {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn head_blob(&self, key: &str) -> Result<BlobMeta, FsError> {
        self.inner.head_blob(key).await
    }

    async fn get_blob(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<GetBlobOutput, FsError> {
        self.inner.get_blob(key, range).await
    }

    async fn get_retained_blob(&self, key: &str) -> Result<GetBlobOutput, FsError> {
        self.inner.get_retained_blob(key).await
    }

    async fn put_blob(&self, input: PutBlobInput) -> Result<BlobMeta, FsError> {
        self.inner.put_blob(input).await
    }

    async fn put_blob_if_not_exists(&self, input: PutBlobInput) -> Result<BlobMeta, FsError> {
        if input.key.contains(".pair.") {
            let planted = self.plant.lock().unwrap().take();
            if let Some(planted) = planted {
                let body = match planted {
                    Planted::TheSameRecord => input.body.clone(),
                    Planted::Bytes(bytes) => bytes.into(),
                };
                self.inner
                    .put_blob_if_not_exists(PutBlobInput::new(input.key.clone(), body))
                    .await?;
            }
        }
        self.inner.put_blob_if_not_exists(input).await
    }

    async fn delete_blob(&self, key: &str) -> Result<(), FsError> {
        self.inner.delete_blob(key).await
    }

    async fn list_blobs(&self, input: ListBlobsInput<'_>) -> Result<ListBlobsOutput, FsError> {
        self.inner.list_blobs(input).await
    }

    async fn copy_blob(&self, input: CopyBlobInput) -> Result<BlobMeta, FsError> {
        self.inner.copy_blob(input).await
    }

    async fn multipart_begin(&self, input: PutBlobInput) -> Result<MultipartId, FsError> {
        self.inner.multipart_begin(input).await
    }

    async fn multipart_upload_part(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        body: Bytes,
    ) -> Result<PartUploadOutput, FsError> {
        self.inner
            .multipart_upload_part(key, upload_id, part_number, body)
            .await
    }

    async fn multipart_upload_part_copy(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        source_key: &str,
        source_range: Range<u64>,
    ) -> Result<PartUploadOutput, FsError> {
        self.inner
            .multipart_upload_part_copy(key, upload_id, part_number, source_key, source_range)
            .await
    }

    async fn multipart_complete(
        &self,
        key: &str,
        upload_id: &MultipartId,
        parts: Vec<CompletedPart>,
    ) -> Result<BlobMeta, FsError> {
        self.inner.multipart_complete(key, upload_id, parts).await
    }

    async fn multipart_abort(&self, key: &str, upload_id: &MultipartId) -> Result<(), FsError> {
        self.inner.multipart_abort(key, upload_id).await
    }
}

/// **The race.** Two first boots of one pair both find no record, both attest,
/// and one conditional write wins. The loser boots on the winner's record — it
/// says the same thing — rather than failing, and there is still one record.
#[tokio::test]
async fn a_first_boot_that_loses_the_race_boots_on_the_winners_record() {
    let store = Store::new();
    boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let backends = Backends {
        data: store.data.clone(),
        roots: Interloper::planting(store.roots.clone(), Planted::TheSameRecord),
    };
    let booted = boot_on(backends, &TestNsm::running(0xaa, GUEST_B))
        .await
        .expect("the loser boots");
    assert_eq!(
        booted.mode,
        BootMode::Upgrade,
        "it is still this pair's first boot"
    );
    assert_eq!(store.pair_records().await.len(), 2, "one record per pair");
}

/// **The pre-emption.** Junk lands at the key between the check and the write.
/// The enclave's own record can no longer be stored there, so the junk would
/// stand as the pair's only record — and it is refused rather than accepted as
/// one.
#[tokio::test]
async fn junk_that_wins_the_race_is_refused() {
    let store = Store::new();
    boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let backends = Backends {
        data: store.data.clone(),
        roots: Interloper::planting(
            store.roots.clone(),
            Planted::Bytes(b"not a record".to_vec()),
        ),
    };
    let err = boot_on(backends, &TestNsm::running(0xaa, GUEST_B))
        .await
        .expect_err("must refuse");
    assert!(format!("{err:#}").contains("does not describe"), "{err:#}");
}

/// The receipt commits to `sha256(sealed key)`, so a swapped key would be
/// caught — but Object Lock means it cannot be swapped in the first place.
/// Both halves are worth pinning: the retention that prevents it, and the
/// binding that would catch it if retention were ever misconfigured.
#[tokio::test]
async fn the_sealed_key_cannot_be_substituted() {
    let store = Store::new();
    let booted = boot(&store, &TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("genesis");

    let (_, other) = StaticKey::new(MasterSecret::from_bytes([77u8; 32]))
        .mint()
        .await
        .unwrap();
    let key_object = format!("origin/{}.key", hex::encode(FS_ID));

    assert!(
        store
            .roots
            .put_blob(PutBlobInput::new(
                &key_object,
                other.as_bytes().to_vec().into(),
            ))
            .await
            .is_err(),
        "COMPLIANCE retention must refuse to overwrite the sealed key"
    );

    // Unchanged, so the state is still the state the receipt names.
    assert_eq!(
        boot(&store, &TestNsm::running(0xaa, GUEST_A))
            .await
            .unwrap()
            .state_root,
        booted.state_root
    );
}
