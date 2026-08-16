//! The boot machine: which enclaves may load which state.
//!
//! `Store::open` used to create a filesystem when it found none, so an enclave
//! pointed at an emptied store served a fresh, correctly-signed, completely
//! wrong filesystem. These tests are mostly about the *refusals* that replaced
//! that, because the happy path was never the problem.
//!
//! Everything runs over `MemoryBackend`, so there is no Docker and no network:
//! what is under test is the decision, not S3.
//!
//! **Receipts here are unsigned**, and deliberately. `ReceiptTrust::Required`
//! would demand a chain to the real AWS root, which no test can produce.
//! `UnsignedEmulator` skips the *signature* and still applies every
//! expectation — PCR0, PCR31, `user_data` — so the state machine, the identity
//! binding and the handoff are all genuinely exercised. The signature path is
//! `nitro-attestation`'s own twenty tests, against real ES384 chains.

use std::sync::{Arc, Mutex};

use enclave_runtime::boot::{BootConfig, BootMode, ReceiptTrust};
use enclave_runtime::{Backends, MountConfig, StaticKey};
use nitro_attestation::testing::TestChain;
use nitro_attestation::AttestationDocument;
use nitro_nsm::{AttestationRequest, Nsm, Pcr, PCR_SUCCESSOR, PCR_ZERO};
use s3fs_core::backend::{memory::MemoryBackend, Backend};

/// An NSM that produces parseable documents with the PCRs it is told to have,
/// and models extension so a handoff can be rehearsed.
struct TestNsm {
    chain: TestChain,
    pcr0: Vec<u8>,
    pcrs: Mutex<Vec<Vec<u8>>>,
}

impl std::fmt::Debug for TestNsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestNsm")
    }
}

impl TestNsm {
    fn with_pcr0(byte: u8) -> Arc<Self> {
        Arc::new(TestNsm {
            chain: TestChain::new().expect("chain"),
            pcr0: vec![byte; 48],
            pcrs: Mutex::new(vec![PCR_ZERO.to_vec(); 32]),
        })
    }
}

impl Nsm for TestNsm {
    fn get_random(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        buf.fill(0x5a);
        Ok(())
    }

    fn attest(&self, request: &AttestationRequest) -> anyhow::Result<Vec<u8>> {
        let mut pcrs = std::collections::BTreeMap::new();
        pcrs.insert(0u32, self.pcr0.clone());
        pcrs.insert(
            PCR_SUCCESSOR as u32,
            self.pcrs.lock().unwrap()[PCR_SUCCESSOR as usize].clone(),
        );

        self.chain.document_from(AttestationDocument {
            module_id: "i-0test".into(),
            timestamp_ms: 1_700_000_000_000,
            digest: "SHA384".into(),
            pcrs,
            certificate: self.chain.leaf.clone(),
            cabundle: self.chain.cabundle.clone(),
            public_key: None,
            user_data: request.user_data.clone(),
            nonce: request.nonce.clone(),
        })
    }

    fn describe_pcr(&self, index: u16) -> anyhow::Result<Pcr> {
        Ok(Pcr {
            locked: index < 3,
            value: if index == 0 {
                self.pcr0.clone()
            } else {
                self.pcrs.lock().unwrap()[index as usize].clone()
            },
        })
    }

    fn extend_pcr(&self, index: u16, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut pcrs = self.pcrs.lock().unwrap();
        pcrs[index as usize] = nitro_nsm::pcr_extend(&pcrs[index as usize], data);
        Ok(pcrs[index as usize].clone())
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
            .put_blob(s3fs_core::backend::PutBlobInput::new(key, body.into()))
            .await
            .expect("write");
    }

    #[allow(dead_code)]
    async fn delete(&self, prefix: &str) {
        let listed = self
            .roots
            .list_blobs(s3fs_core::backend::ListBlobsInput {
                prefix,
                max_keys: Some(1000),
                start_after: None,
                continuation_token: None,
                delimiter: None,
            })
            .await
            .expect("list");
        for item in listed.items {
            if item.key.starts_with(prefix) {
                let _ = self.roots.delete_blob(&item.key).await;
            }
        }
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
        fs_id: [3u8; 16],
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
    StaticKey::new(s3fs_core::MasterSecret::from_bytes([8u8; 32]))
}

async fn boot(store: &Store, nsm: &Arc<dyn Nsm>) -> anyhow::Result<enclave_runtime::Booted> {
    enclave_runtime::boot(&store.backends(), &config(), &boot_config(), nsm, &key()).await
}

#[tokio::test]
async fn an_empty_store_becomes_a_filesystem_with_an_attested_origin() {
    let store = Store::new();
    let nsm: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);

    let booted = boot(&store, &nsm).await.expect("genesis");
    assert_eq!(booted.mode, BootMode::Genesis);
    assert_eq!(booted.pcr0, vec![0xaa; 48]);
}

/// The property the whole milestone is for: a second boot recognises the state
/// as its own, rather than making a new one.
#[tokio::test]
async fn a_second_boot_resumes_the_same_state() {
    let store = Store::new();
    let nsm: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);

    let first = boot(&store, &nsm).await.expect("genesis");
    let second = boot(&store, &nsm).await.expect("resume");

    assert_eq!(second.mode, BootMode::Resume);
    assert_eq!(
        second.state_root, first.state_root,
        "the same filesystem must hash to the same state_root"
    );
}

/// **The delete marker.** Object Lock protects a *version*; it does not stop a
/// `DeleteObject` without a version id, which writes a marker that hides the
/// object from every ordinary read while the bytes stay undeletable underneath.
///
/// That gap is only dangerous here, where absence is what authorises genesis:
/// hide the receipt *and* the sealed key and the naive reading is
/// `(None, None)` — create a filesystem — while the real one sits in the same
/// bucket. The enclave reads the retained version instead, so the records are
/// still found and the boot still resumes.
#[tokio::test]
async fn hiding_the_origin_records_behind_a_delete_marker_does_not_work() {
    let store = Store::new();
    let nsm: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);
    let first = boot(&store, &nsm).await.expect("genesis");

    let receipt = format!("origin/{}.receipt", hex::encode([3u8; 16]));
    let sealed = format!("origin/{}.key", hex::encode([3u8; 16]));

    // Both succeed, as S3 does. Refusing would be the comfortable answer and
    // is not the true one.
    store
        .roots
        .delete_blob(&receipt)
        .await
        .expect("S3 allows a delete marker");
    store
        .roots
        .delete_blob(&sealed)
        .await
        .expect("S3 allows a delete marker");

    // Gone, as far as an ordinary read can tell.
    assert!(store.roots.get_blob(&receipt, None).await.is_err());
    assert!(store.roots.get_blob(&sealed, None).await.is_err());

    // And the enclave resumes the filesystem it already had, rather than
    // starting a second one beside it.
    let second = boot(&store, &nsm)
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
    let nsm: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);
    boot(&store, &nsm).await.expect("genesis");

    let receipt = format!("origin/{}.receipt", hex::encode([3u8; 16]));
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
        .put_blob_if_not_exists(s3fs_core::backend::PutBlobInput::new(
            receipt.clone(),
            bytes::Bytes::from_static(b"a forged origin"),
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
    let nsm: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);

    store
        .put(
            &format!("origin/{}.receipt", hex::encode([3u8; 16])),
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
    let nsm: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);

    let (_, sealed) = {
        use enclave_runtime::MasterKeySource;
        key().mint().await.unwrap()
    };
    store
        .put(
            &format!("origin/{}.key", hex::encode([3u8; 16])),
            sealed.as_bytes().to_vec(),
        )
        .await;

    let err = boot(&store, &nsm).await.expect_err("must refuse");
    let text = format!("{err:#}");
    assert!(text.contains("no state-origin receipt"), "{text}");
    assert!(text.contains("Refusing to boot"), "{text}");
}

/// A different image may not simply pick up someone else's filesystem.
#[tokio::test]
async fn another_enclave_image_is_refused_without_a_handoff() {
    let store = Store::new();
    let incumbent: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);
    boot(&store, &incumbent).await.expect("genesis");

    let newcomer: Arc<dyn Nsm> = TestNsm::with_pcr0(0xbb);
    let err = boot(&store, &newcomer).await.expect_err("must refuse");
    let text = format!("{err:#}");
    assert!(text.contains("transition receipt"), "{text}");
    assert!(
        text.contains("authorise-successor"),
        "the refusal must say how to proceed: {text}"
    );
}

/// And may, once the incumbent has said so — in two independent places, the
/// payload and PCR31.
#[tokio::test]
async fn an_authorised_successor_migrates() {
    let store = Store::new();
    let incumbent: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);
    let genesis = boot(&store, &incumbent).await.expect("genesis");

    let successor_pcr0 = vec![0xbb; 48];
    enclave_runtime::authorise_successor(
        &store.backends(),
        &config(),
        &incumbent,
        &key(),
        &successor_pcr0,
    )
    .await
    .expect("handoff");

    let newcomer: Arc<dyn Nsm> = TestNsm::with_pcr0(0xbb);
    let migrated = boot(&store, &newcomer).await.expect("migration");

    assert_eq!(migrated.mode, BootMode::Migration);
    assert_eq!(
        migrated.state_root, genesis.state_root,
        "a handoff must not change what the state is"
    );
}

/// A handoff authorises *one* successor. The register the predecessor extended
/// commits to that image and no other, so a third image cannot ride in on a
/// receipt written for someone else.
#[tokio::test]
async fn a_handoff_does_not_authorise_a_third_image() {
    let store = Store::new();
    let incumbent: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);
    boot(&store, &incumbent).await.expect("genesis");

    enclave_runtime::authorise_successor(
        &store.backends(),
        &config(),
        &incumbent,
        &key(),
        &[0xbb; 48],
    )
    .await
    .expect("handoff");

    let interloper: Arc<dyn Nsm> = TestNsm::with_pcr0(0xcc);
    assert!(
        boot(&store, &interloper).await.is_err(),
        "a receipt naming 0xbb must not admit 0xcc"
    );
}

/// The receipt commits to `sha256(sealed key)`, so a swapped key would be
/// caught — but Object Lock means it cannot be swapped in the first place.
/// Both halves are worth pinning: the retention that prevents it, and the
/// binding that would catch it if retention were ever misconfigured.
#[tokio::test]
async fn the_sealed_key_cannot_be_substituted() {
    let store = Store::new();
    let nsm: Arc<dyn Nsm> = TestNsm::with_pcr0(0xaa);
    let booted = boot(&store, &nsm).await.expect("genesis");

    let (_, other) = {
        use enclave_runtime::MasterKeySource;
        StaticKey::new(s3fs_core::MasterSecret::from_bytes([77u8; 32]))
            .mint()
            .await
            .unwrap()
    };
    let key_object = format!("origin/{}.key", hex::encode([3u8; 16]));

    assert!(
        store
            .roots
            .put_blob(s3fs_core::backend::PutBlobInput::new(
                &key_object,
                other.as_bytes().to_vec().into(),
            ))
            .await
            .is_err(),
        "COMPLIANCE retention must refuse to overwrite the sealed key"
    );

    // Unchanged, so the state is still the state the receipt names.
    assert_eq!(
        boot(&store, &nsm).await.unwrap().state_root,
        booted.state_root
    );
}
