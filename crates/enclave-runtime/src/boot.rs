//! Deciding whether this enclave is entitled to the state it is about to load.
//!
//! `Store::open` used to end with `None => Store::format(…)`: an enclave
//! pointed at an empty store made a fresh filesystem and served it. It was
//! correctly signed, correctly hash-chained, and completely wrong — every
//! check the design makes passed, because they all attested to the *new*
//! filesystem while the guest saw an empty database where its data should have
//! been.
//!
//! `store/root.rs` already documents the neighbouring risk, rollback: *"a cold
//! mount cannot distinguish 'the tip is N' from 'the tip is N, and the store is
//! hiding N+1'"*. This is the worse one it does not name — a cold mount cannot
//! distinguish "this filesystem is new" from "everything has been hidden".
//!
//! ## The receipt
//!
//! Genesis writes a **state-origin receipt**: an NSM attestation document
//! whose `user_data` commits to a hash over this filesystem's identity. The
//! host cannot forge one, because AWS signs it. Following
//! [ArkLabsHQ/enclave#151](https://github.com/ArkLabsHQ/enclave/pull/151),
//! whose `runtime/boot.go` puts it exactly right:
//!
//! > Committing to it in an NSM attestation is what lets a later boot — or a
//! > successor across a migration — prove the state it loaded is the state
//! > some enclave of a known PCR0 actually wrote, rather than something the
//! > host substituted.
//!
//! ## Three things make a missing receipt mean something
//!
//! The receipt is self-authenticating, so the host cannot forge one. It can
//! still *delete* or *hide* one, and "no receipt" is what authorises genesis —
//! so the absence has to be as trustworthy as the presence:
//!
//! - **Object Lock COMPLIANCE** on the roots bucket: nobody, including the
//!   account root, can delete the receipt once written.
//! - **Attested bucket identity**: the bucket names are baked into the enclave
//!   image, so PCR0 covers them. Without this the host simply points the
//!   enclave at an empty bucket and every other check passes.
//! - **TLS to S3, validated inside the enclave**: the parent proxies the
//!   bytes but cannot substitute them. It can block, which fails closed.
//!
//! What remains out of scope, unchanged from `root.rs`: S3 lying about `HEAD`.
//! That is AWS, whom we already trust for the signature on the receipt itself.
//!
//! ## Which code may hold the state
//!
//! Not this module's decision. An enclave that gets past opening the key was
//! released it by KMS, against a policy naming one runtime image (PCR0) and one
//! guest (PCR16), and changing either is an edit to that policy by whoever
//! controls the key. A boot machine that also refused pairs would be a second
//! copy of that decision, able only to disagree with the real one.
//!
//! What boot adds is a **record**. The first time a runtime and guest hold this
//! state, the enclave attests a *pair record* — a document carrying its PCR0
//! and PCR16 and committing to this `state_root` — and stores it undeletably
//! under a key derived from the pair. Later boots of that pair find it and
//! write nothing. The store therefore holds one signed record for each distinct
//! pair that has ever held the state.
//!
//! It records *which* pairs, not *in what order*: returning to an earlier pair
//! finds that pair's record and adds nothing. The order approvals were given in
//! lives where they were given, in CloudTrail's record of key-policy edits.
//!
//! Under the static development key source there is no policy at all, so
//! nothing decides which pair may boot. That source protects nothing, and the
//! image environment that selects it is measured.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use nitro_attestation::{Expectations, Trust, VerifyOptions, AWS_NITRO_ROOT_G1_PEM};
use nitro_nsm::{AttestationRequest, Nsm, PCR_GUEST, PCR_ZERO};
use s3fs_core::backend::{Backend, ObjectLock, PutBlobInput};
use s3fs_core::{FsError, MasterSecret};

use crate::keys::{MasterKeySource, SealedKey};
use crate::mount::{Backends, MountConfig, Mounted};

/// `user_data` purpose for the receipt genesis writes.
const PURPOSE_STATE_ORIGIN: &str = "s3fs-state-origin";
/// `user_data` purpose for the record a runtime and guest leave the first time
/// they hold this state.
const PURPOSE_PAIR: &str = "s3fs-pair";

/// Schema string inside the `state_root` pre-image. Bump it and every existing
/// receipt stops verifying, which is the intended effect of changing what a
/// receipt means.
const STATE_ROOT_SCHEMA: &str = "s3fs/state-origin/v1";

/// Which boot this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// No receipt and no filesystem: create both.
    Genesis,
    /// This runtime and guest have held this state before.
    Resume,
    /// The first boot of this runtime and guest on this state: a new guest, a
    /// new runtime image, or both. Recorded rather than refused — the key
    /// policy is what allowed it.
    ///
    /// Derived from whether this pair's record exists, not by comparing with
    /// whoever ran genesis, which would call every restart after an upgrade
    /// another upgrade.
    Upgrade,
}

/// The two measurements that say what an enclave is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// The runtime image, measured by the hypervisor.
    pub pcr0: [u8; 48],
    /// The guest component, measured by that runtime into [`PCR_GUEST`] and
    /// locked before it asked for a key.
    pub pcr16: [u8; 48],
}

impl Pair {
    /// Read both from the device, refusing if the guest was never measured.
    ///
    /// The first thing [`boot`] does, before anything is read from the store or
    /// asked of KMS. An enclave that reached KMS with PCR16 unlocked would
    /// present an attestation with no guest in it, and could still extend the
    /// register after being released a key.
    pub fn read(nsm: &dyn Nsm) -> Result<Self> {
        let pcr0 = nsm
            .describe_pcr(0)
            .context("reading PCR0; the boot machine cannot record what it cannot read")?;
        let guest = nsm
            .describe_pcr(PCR_GUEST)
            .context("reading PCR16, where the guest is measured")?;
        if !guest.locked {
            bail!(
                "PCR16 is not locked, so this enclave has not measured its guest. It must be \
                 measured and locked before any key is asked for: an attestation carries only \
                 locked registers, so a key policy pinning the guest would see none. Refusing \
                 to boot."
            );
        }
        if guest.value == PCR_ZERO {
            bail!(
                "PCR16 is locked but was never extended, so it names no guest. Refusing to boot."
            );
        }
        Ok(Pair {
            pcr0: register(&pcr0.value, 0)?,
            pcr16: register(&guest.value, PCR_GUEST)?,
        })
    }

    /// Where this pair's record lives.
    ///
    /// Derived, like the receipt and the sealed key, so "no record" is an
    /// answer rather than a failure to look in the right place. Both registers
    /// are SHA-384 and so always 48 bytes, which keeps the concatenation
    /// unambiguous.
    pub fn record_key(&self, prefix: &str, fs_uuid: &[u8; 16]) -> String {
        let mut both = [0u8; 96];
        both[..48].copy_from_slice(&self.pcr0);
        both[48..].copy_from_slice(&self.pcr16);
        format!(
            "{prefix}origin/{}.pair.{}",
            hex::encode(fs_uuid),
            hex::encode(nitro_attestation::sha256(&both))
        )
    }
}

fn register(value: &[u8], index: u16) -> Result<[u8; 48]> {
    value.try_into().with_context(|| {
        format!(
            "PCR{index} is {} bytes; a SHA-384 register is 48",
            value.len()
        )
    })
}

/// What a boot established, for logging and for the health endpoint.
#[derive(Debug)]
pub struct Booted {
    pub mode: BootMode,
    pub mounted: Mounted,
    pub state_root: [u8; 32],
    /// The runtime image and guest this enclave is running.
    pub pair: Pair,
    /// The recovered master secret.
    ///
    /// Returned rather than dropped because per-client filesystems derive
    /// their key material from it, and there is nowhere else to get it: the
    /// runtime's own `KeyMaterial` holds only what was derived *for* the
    /// runtime filesystem.
    ///
    /// It zeroizes on drop and never prints. It is already resident in this
    /// process either way; what this changes is that it stays reachable, and
    /// the alternative was re-opening the key source per client.
    pub master: MasterSecret,
}

/// The identity a receipt commits to.
///
/// Every field is something an attacker could otherwise vary while leaving the
/// rest of the design intact: the filesystem, the store it lives in, the
/// history it descends from, and the key that reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateIdentity {
    pub fs_uuid: [u8; 16],
    pub data_bucket: String,
    pub roots_bucket: String,
    pub bucket_prefix: String,
    /// Hash of the seq-0 record: *which* history, not merely which bucket.
    pub genesis_root_hash: [u8; 32],
    /// SHA-256 of the **sealed** key. Never the key: a receipt is readable by
    /// anyone who can read the bucket it sits in.
    pub sealed_key_sha256: [u8; 32],
}

impl StateIdentity {
    /// The value a receipt's `user_data` commits to.
    ///
    /// Deterministic: CBOR with fields in a fixed order, hashed. Two enclaves
    /// looking at the same filesystem must compute the same 32 bytes or the
    /// receipt is useless.
    pub fn state_root(&self) -> [u8; 32] {
        let value = ciborium::Value::Array(vec![
            ciborium::Value::Text(STATE_ROOT_SCHEMA.into()),
            ciborium::Value::Bytes(self.fs_uuid.to_vec()),
            ciborium::Value::Text(self.data_bucket.clone()),
            ciborium::Value::Text(self.roots_bucket.clone()),
            ciborium::Value::Text(self.bucket_prefix.clone()),
            ciborium::Value::Bytes(self.genesis_root_hash.to_vec()),
            ciborium::Value::Bytes(self.sealed_key_sha256.to_vec()),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).expect("writing to a Vec cannot fail");
        *blake3::hash(&encoded).as_bytes()
    }
}

/// `user_data` payload of a receipt or a pair record.
///
/// Every receipt already written commits to this encoding, so changing it
/// would make every existing filesystem unmountable.
fn receipt_payload(purpose: &str, state_root: &[u8; 32]) -> Vec<u8> {
    let fields = vec![
        (
            ciborium::Value::Text("purpose".into()),
            ciborium::Value::Text(purpose.to_string()),
        ),
        (
            ciborium::Value::Text("state_root".into()),
            ciborium::Value::Bytes(state_root.to_vec()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(fields), &mut out)
        .expect("writing to a Vec cannot fail");
    out
}

/// Object keys, derived from the filesystem id alone.
///
/// Derivable without reading anything, which is what makes a 404 meaningful:
/// the enclave knows exactly where to look, so "not there" is an answer rather
/// than a failure to find the right place.
fn receipt_key(prefix: &str, fs_uuid: &[u8; 16]) -> String {
    format!("{prefix}origin/{}.receipt", hex::encode(fs_uuid))
}

fn sealed_key_key(prefix: &str, fs_uuid: &[u8; 16]) -> String {
    format!("{prefix}origin/{}.key", hex::encode(fs_uuid))
}

/// How a receipt is checked. QEMU's NSM does not sign, so the harness needs a
/// concession that production must never have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptTrust {
    /// Signature and chain to the AWS Nitro root.
    Required,
    /// Contents only, because the emulated NSM produces unsigned documents.
    ///
    /// Set by the emulator image and never by a production one — and because
    /// the image's environment is measured, PCR0 itself tells a client which
    /// kind it is talking to.
    UnsignedEmulator,
}

impl ReceiptTrust {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "required" | "signed" => Ok(ReceiptTrust::Required),
            "unsigned-emulator" | "unsigned" => Ok(ReceiptTrust::UnsignedEmulator),
            other => Err(format!(
                "expected one of required, unsigned-emulator; got {other:?}"
            )),
        }
    }
}

/// Everything the boot machine needs that is not already in [`MountConfig`].
///
/// There is deliberately no "adopt this existing filesystem" escape hatch. One
/// would authorise whatever state happened to be present — the single thing
/// this module exists to refuse — and it could only ever be justified by a
/// deployment that predates receipts. None does: receipts were here before the
/// first enclave was. Anything that needs adopting is, by construction, state
/// of unknown origin.
pub struct BootConfig {
    pub trust: ReceiptTrust,
}

/// Read an origin record, distinguishing "absent" from "could not read" — and
/// both of those from "hidden".
///
/// [`Backend::get_retained_blob`] rather than `get_blob`, because this is the
/// one place in the system where **absence is a decision**. Object Lock makes
/// these records indestructible but not unhideable: a `DeleteObject` without a
/// version id writes a delete marker, an ordinary `GetObject` then answers
/// `NoSuchKey`, and a conditional PUT over the marker succeeds because the
/// current version is no longer an object. Hide the receipt and the sealed key
/// together and this function would report `(None, None)` — genesis — and the
/// enclave would create a second filesystem beside the one it was hiding,
/// with every signature along the way valid.
///
/// Every other record here is content-verified, so hiding is the only attack
/// that has no signature to fail. Reading the retained version is what makes it
/// fail instead.
async fn maybe_get(backend: &Arc<dyn Backend>, key: &str) -> Result<Option<Vec<u8>>> {
    match backend.get_retained_blob(key).await {
        Ok(out) => Ok(Some(out.body.to_vec())),
        Err(FsError::NotFound) => Ok(None),
        Err(e) => Err(anyhow::Error::msg(e.to_string())).with_context(|| format!("reading {key}")),
    }
}

/// Verify a receipt and return what it committed to.
fn open_receipt(
    document: &[u8],
    trust: ReceiptTrust,
    purpose: &str,
    expected: &Expectations,
) -> Result<nitro_attestation::Verified> {
    let verified = match trust {
        ReceiptTrust::Required => verify_as_signed(document, AWS_NITRO_ROOT_G1_PEM.as_bytes())?,
        // The emulator's NSM does not sign, so there is nothing to verify and
        // the contents are read as-is. Only an image built for the emulator
        // reaches here, and because the image's environment is measured, PCR0
        // says which kind of image a client is talking to.
        ReceiptTrust::UnsignedEmulator => nitro_attestation::Verified {
            document: nitro_attestation::parse(document).context("parsing the receipt")?,
            trust: Trust::Unsigned,
        },
    };
    // `max_age` is deliberately unset: a state-origin receipt is a statement
    // about an origin, not a proof of liveness. It is *supposed* to be old,
    // and expiring one would make a filesystem unmountable by the passage of
    // time.
    verified
        .expect(expected, std::time::SystemTime::now())
        .with_context(|| format!("the {purpose} receipt does not say what it must"))?;
    Ok(verified)
}

/// Verify a stored document's signature and chain **as of when it was signed**.
///
/// Not as of now. The certificates in an attestation document's chain are
/// short-lived — far shorter than a filesystem's life — so a receipt checked
/// against the current time stops verifying soon after it is written, and the
/// filesystem it guards becomes unmountable by the passage of time: the failure
/// `max_age` is left unset to avoid, arriving by another route.
///
/// The timestamp is part of the signed payload. It is read before the signature
/// is checked only to choose the moment to check at; `verify` then fails unless
/// the chain was valid at that moment *and* the signature covers that
/// timestamp.
fn verify_as_signed(document: &[u8], trust_root: &[u8]) -> Result<nitro_attestation::Verified> {
    let signed_at = nitro_attestation::parse(document)
        .context("parsing the receipt")?
        .timestamp();
    let verified = nitro_attestation::verify(
        document,
        &VerifyOptions {
            trust_root: trust_root.to_vec(),
            now: signed_at,
            allow_untrusted_root: false,
        },
    )
    .context("verifying the receipt")?;
    if verified.trust != Trust::ChainVerified {
        bail!(
            "receipt is {:?} rather than chain-verified; this image requires a receipt \
             signed by AWS",
            verified.trust
        );
    }
    Ok(verified)
}

/// Decide the mode, resolve the key, and mount or create.
pub async fn boot(
    backends: &Backends,
    mount_config: &MountConfig,
    boot_config: &BootConfig,
    nsm: &Arc<dyn Nsm>,
    key_source: &dyn MasterKeySource,
) -> Result<Booted> {
    let prefix = &mount_config.bucket_prefix;
    let fs_uuid = &mount_config.fs_id;
    let roots = &backends.roots;

    // Before anything is read from the store or asked of KMS.
    let pair = Pair::read(nsm.as_ref())?;

    let receipt = maybe_get(roots, &receipt_key(prefix, fs_uuid)).await?;
    let sealed = maybe_get(roots, &sealed_key_key(prefix, fs_uuid))
        .await?
        .map(SealedKey::from_bytes);

    match (receipt, sealed) {
        // ---- resume or upgrade ---------------------------------------------
        (Some(receipt), Some(sealed)) => {
            // Under `kms` this is where the key policy decides which runtime
            // and guest may hold this state, and the only place: a pair it does
            // not name gets no key and goes no further.
            let master = key_source
                .open(&sealed)
                .await
                .context("opening this filesystem's master key")?;
            let mounted = crate::mount::mount_existing(backends, mount_config, &master).await?;

            let identity = identity_of(&mounted, mount_config, &sealed).await?;
            let state_root = identity.state_root();

            verify_origin(&receipt, boot_config.trust, &state_root)?;
            let first = record_pair(
                backends,
                mount_config,
                boot_config.trust,
                nsm.as_ref(),
                &pair,
                &state_root,
            )
            .await?;

            Ok(Booted {
                mode: if first {
                    BootMode::Upgrade
                } else {
                    BootMode::Resume
                },
                mounted,
                state_root,
                pair,
                master,
            })
        }

        // ---- genesis -------------------------------------------------------
        (None, None) => {
            genesis(
                backends,
                mount_config,
                boot_config.trust,
                nsm,
                key_source,
                pair,
            )
            .await
        }

        // ---- the attack ----------------------------------------------------
        (Some(_), None) => bail!(
            "this filesystem has a state-origin receipt but no sealed key. \
             Either the key was deleted — which Object Lock should have \
             prevented — or the store is not the one the receipt describes. \
             Refusing to boot rather than creating a second filesystem."
        ),
        (None, Some(_)) => bail!(
            "this filesystem has a sealed key but no state-origin receipt. \
             Genesis writes the receipt last, so this is either a genesis \
             interrupted between the two, or a store with its receipt hidden. \
             Nothing here can tell those apart, and treating it as the first \
             would serve state no enclave ever accounted for. Refusing to boot."
        ),
    }
}

/// Recompute the identity of a filesystem that is already mounted.
async fn identity_of(
    mounted: &Mounted,
    config: &MountConfig,
    sealed: &SealedKey,
) -> Result<StateIdentity> {
    // The seq-0 record, read past the session floor because it is history
    // rather than the live tip.
    let genesis_root = mounted
        .fs
        .store()
        .snapshot_root(0)
        .await
        .map_err(|e| anyhow::anyhow!("reading the genesis root record: {e}"))?;

    Ok(StateIdentity {
        fs_uuid: config.fs_id,
        data_bucket: config.bucket.clone(),
        roots_bucket: config
            .roots_bucket
            .clone()
            .unwrap_or_else(|| config.bucket.clone()),
        bucket_prefix: config.bucket_prefix.clone(),
        genesis_root_hash: *genesis_root.hash().as_bytes(),
        sealed_key_sha256: sealed.sha256(),
    })
}

/// Check the origin receipt names the state that was just loaded.
///
/// Not who wrote it. Any runtime and guest may have run genesis, because by
/// this point KMS has released the key to *this* pair, and that is the decision
/// that matters — see the module docs. What KMS cannot say is whether the state
/// loaded is the state genesis recorded, and that is the question here.
fn verify_origin(receipt: &[u8], trust: ReceiptTrust, state_root: &[u8; 32]) -> Result<()> {
    open_receipt(
        receipt,
        trust,
        "state-origin",
        &Expectations::default().user_data(receipt_payload(PURPOSE_STATE_ORIGIN, state_root)),
    )?;
    Ok(())
}

/// Check a pair record says this runtime and guest held this state.
fn verify_pair_record(
    document: &[u8],
    trust: ReceiptTrust,
    pair: &Pair,
    state_root: &[u8; 32],
) -> Result<()> {
    open_receipt(
        document,
        trust,
        "pair",
        &Expectations::default()
            .pcr0(pair.pcr0.to_vec())
            .pcr(PCR_GUEST as u32, pair.pcr16.to_vec())
            .user_data(receipt_payload(PURPOSE_PAIR, state_root)),
    )?;
    Ok(())
}

/// Make sure this pair has a record against this state, returning whether this
/// boot is the pair's first.
///
/// A record that is already there is **verified, not merely found**. Its key
/// is derivable by anyone who can write to the roots bucket — the parent
/// included — so an object planted there ahead of a pair's first boot would
/// otherwise stand in for the real record for good, Object Lock keeping it as
/// faithfully as it would the genuine one.
async fn record_pair(
    backends: &Backends,
    config: &MountConfig,
    trust: ReceiptTrust,
    nsm: &dyn Nsm,
    pair: &Pair,
    state_root: &[u8; 32],
) -> Result<bool> {
    let key = pair.record_key(&config.bucket_prefix, &config.fs_id);

    if let Some(existing) = maybe_get(&backends.roots, &key).await? {
        verify_pair_record(&existing, trust, pair, state_root).with_context(|| {
            format!(
                "the record at {key} does not describe this runtime and guest holding this \
                 state. Refusing to boot rather than leave it standing as this pair's record."
            )
        })?;
        return Ok(false);
    }

    let document = nsm
        .attest(&AttestationRequest::with_user_data(receipt_payload(
            PURPOSE_PAIR,
            state_root,
        )))
        .context("asking the NSM for a pair record")?;
    // Before it is stored. A document that did not carry both registers would
    // be a record of nothing, locked in place for the retention period — and on
    // real hardware, this is where a guest register missing from documents
    // would first show.
    verify_pair_record(&document, trust, pair, state_root)
        .context("the NSM's own document does not carry this runtime and guest")?;

    match backends
        .roots
        .put_blob_if_not_exists(locked(&key, document, config))
        .await
    {
        Ok(_) => {}
        // Another first boot of this pair got there first. Its record stands,
        // provided it says what this one would have.
        Err(FsError::AlreadyExists) => {
            let theirs = maybe_get(&backends.roots, &key)
                .await?
                .with_context(|| format!("{key} was reported present and then was not"))?;
            verify_pair_record(&theirs, trust, pair, state_root).with_context(|| {
                format!(
                    "another writer's record at {key} does not describe this runtime and \
                     guest holding this state. Refusing to boot."
                )
            })?;
        }
        Err(other) => bail!("writing the pair record {key}: {other}"),
    }

    tracing::info!(
        pcr0 = %hex::encode(pair.pcr0),
        pcr16 = %hex::encode(pair.pcr16),
        record = %key,
        "first boot of this runtime and guest on this state; recorded"
    );
    Ok(true)
}

/// Create a filesystem, the receipt that authorises every later boot, and the
/// first pair record.
///
/// The ordering is load-bearing and only the last steps are atomic: mint, seal,
/// persist the key, create the filesystem, then write the receipt with a
/// conditional PUT. A crash before the receipt leaves a filesystem with no
/// receipt, which the next boot refuses — deliberately, because that state is
/// indistinguishable from a store whose receipt has been hidden.
///
/// The pair record comes after the receipt, so the receipt stays the last thing
/// whose absence means "unfinished". A genesis interrupted between the two
/// leaves a store the next boot resumes; that boot writes the record and
/// reports an upgrade, which for once is not one.
async fn genesis(
    backends: &Backends,
    config: &MountConfig,
    trust: ReceiptTrust,
    nsm: &Arc<dyn Nsm>,
    key_source: &dyn MasterKeySource,
    pair: Pair,
) -> Result<Booted> {
    tracing::info!(
        pcr0 = %hex::encode(pair.pcr0),
        pcr16 = %hex::encode(pair.pcr16),
        "no filesystem here: creating one and recording its origin"
    );

    let (master, sealed) = key_source.mint().await.context("minting a master key")?;

    // Written first and *conditionally*: this is the genesis lease. Two cold
    // boots race here and exactly one wins, so they cannot create divergent
    // filesystems under different keys.
    let key_object = sealed_key_key(&config.bucket_prefix, &config.fs_id);
    backends
        .roots
        .put_blob_if_not_exists(locked(&key_object, sealed.as_bytes().to_vec(), config))
        .await
        .map_err(|e| match e {
            // `AlreadyExists`, not `Conflict`: that is what both backends
            // return from a failed conditional PUT (`backend/mod.rs`), and
            // matching `Conflict` here meant this arm never fired — a genesis
            // race reported the generic message instead of the specific one.
            FsError::AlreadyExists => anyhow::anyhow!(
                "another enclave is performing genesis on this filesystem right now"
            ),
            other => anyhow::anyhow!("storing the sealed master key: {other}"),
        })?;

    let mounted = crate::mount::create(backends, config, &master).await?;
    let identity = identity_of(&mounted, config, &sealed).await?;
    let state_root = identity.state_root();

    let document = nsm
        .attest(&AttestationRequest::with_user_data(receipt_payload(
            PURPOSE_STATE_ORIGIN,
            &state_root,
        )))
        .context("asking the NSM for a state-origin receipt")?;

    let receipt_object = receipt_key(&config.bucket_prefix, &config.fs_id);
    backends
        .roots
        .put_blob_if_not_exists(locked(&receipt_object, document, config))
        .await
        .map_err(|e| anyhow::anyhow!("writing the state-origin receipt: {e}"))?;

    record_pair(backends, config, trust, nsm.as_ref(), &pair, &state_root).await?;

    tracing::info!(
        state_root = %hex::encode(state_root),
        "genesis complete; this filesystem now has an attested origin"
    );

    Ok(Booted {
        mode: BootMode::Genesis,
        mounted,
        state_root,
        pair,
        master,
    })
}

/// Everything the boot machine writes goes under the same retention as the
/// anchor chain: undeletable is the whole point.
fn locked(key: &str, body: Vec<u8>, _config: &MountConfig) -> PutBlobInput {
    let mut input = PutBlobInput::new(key, body.into());
    if let Some(retention) = s3fs_core::store::StoreConfig::default().root_retention {
        input = input.with_object_lock(ObjectLock {
            mode: s3fs_core::backend::ObjectLockMode::Compliance,
            retain_until: std::time::SystemTime::now() + retention,
        });
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use nitro_nsm::fake::FakeNsm;

    fn identity() -> StateIdentity {
        StateIdentity {
            fs_uuid: [1u8; 16],
            data_bucket: "data".into(),
            roots_bucket: "roots".into(),
            bucket_prefix: String::new(),
            genesis_root_hash: [2u8; 32],
            sealed_key_sha256: [3u8; 32],
        }
    }

    fn pair(pcr0: u8, pcr16: u8) -> Pair {
        Pair {
            pcr0: [pcr0; 48],
            pcr16: [pcr16; 48],
        }
    }

    #[test]
    fn the_state_root_is_deterministic() {
        assert_eq!(identity().state_root(), identity().state_root());
    }

    /// Every field is something an attacker could otherwise vary while leaving
    /// the rest of the design intact, so every field must change the hash.
    #[test]
    fn every_field_changes_the_state_root() {
        let base = identity().state_root();

        let mut a = identity();
        a.fs_uuid = [9u8; 16];
        assert_ne!(a.state_root(), base, "filesystem id");

        let mut b = identity();
        b.data_bucket = "elsewhere".into();
        assert_ne!(b.state_root(), base, "data bucket");

        let mut c = identity();
        c.roots_bucket = "elsewhere".into();
        assert_ne!(c.state_root(), base, "roots bucket");

        let mut d = identity();
        d.bucket_prefix = "other/".into();
        assert_ne!(d.state_root(), base, "prefix");

        let mut e = identity();
        e.genesis_root_hash = [9u8; 32];
        assert_ne!(e.state_root(), base, "history");

        let mut f = identity();
        f.sealed_key_sha256 = [9u8; 32];
        assert_ne!(f.state_root(), base, "key");
    }

    /// Swapping two string fields must not produce the same pre-image. CBOR
    /// length-prefixes each, so it does not — worth pinning, because a
    /// concatenation-based encoding would.
    #[test]
    fn swapping_fields_is_not_the_same_state() {
        let mut swapped = identity();
        std::mem::swap(&mut swapped.data_bucket, &mut swapped.roots_bucket);
        assert_ne!(swapped.state_root(), identity().state_root());
    }

    #[test]
    fn the_payload_distinguishes_its_purposes() {
        let root = [4u8; 32];
        assert_ne!(
            receipt_payload(PURPOSE_STATE_ORIGIN, &root),
            receipt_payload(PURPOSE_PAIR, &root),
            "a pair record must not verify as a state-origin receipt"
        );
    }

    /// Byte for byte, what state-origin receipts have always carried. Every
    /// receipt already written commits to this, so it cannot move without
    /// making every existing filesystem unmountable.
    #[test]
    fn the_state_origin_payload_has_not_changed() {
        let root = [4u8; 32];
        let mut expected = vec![0xa2];
        expected.push(0x67);
        expected.extend_from_slice(b"purpose");
        expected.push(0x71);
        expected.extend_from_slice(b"s3fs-state-origin");
        expected.push(0x6a);
        expected.extend_from_slice(b"state_root");
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&root);
        assert_eq!(receipt_payload(PURPOSE_STATE_ORIGIN, &root), expected);
    }

    /// Keys must be derivable from what the enclave already knows — that is
    /// what makes a 404 an answer rather than a failure to look in the right
    /// place.
    #[test]
    fn object_keys_are_derived_and_distinct() {
        let uuid = [7u8; 16];
        let r = receipt_key("p/", &uuid);
        let k = sealed_key_key("p/", &uuid);
        let p = pair(1, 2).record_key("p/", &uuid);
        assert_ne!(r, k);
        assert_ne!(r, p);
        assert_ne!(k, p);
        assert!(r.starts_with("p/"));
        assert!(p.starts_with("p/origin/"));
        assert_eq!(r, receipt_key("p/", &uuid), "must be deterministic");
        assert_eq!(
            p,
            pair(1, 2).record_key("p/", &uuid),
            "must be deterministic"
        );
    }

    /// One record per pair, so the key has to change with either register —
    /// and with which register holds which value.
    #[test]
    fn a_pair_record_key_names_both_measurements() {
        let uuid = [7u8; 16];
        let base = pair(1, 2).record_key("", &uuid);
        assert_ne!(pair(9, 2).record_key("", &uuid), base, "another runtime");
        assert_ne!(pair(1, 9).record_key("", &uuid), base, "another guest");
        assert_ne!(pair(2, 1).record_key("", &uuid), base, "registers swapped");
        assert_ne!(
            pair(1, 2).record_key("", &[8u8; 16]),
            base,
            "another filesystem"
        );
    }

    #[test]
    fn a_measured_guest_is_read_back_as_the_pair() {
        let nsm = FakeNsm::new();
        let pcr16 = crate::guest::measure_guest(&nsm, b"a guest").unwrap();
        let read = Pair::read(&nsm).unwrap();
        assert_eq!(read.pcr16, pcr16);
        assert_eq!(read.pcr0, [0x10; 48], "the fake's PCR0");
    }

    /// Boot's first refusal, and the one that keeps an unmeasured guest from
    /// ever reaching KMS.
    #[test]
    fn an_unmeasured_guest_is_not_a_pair() {
        let err = Pair::read(&FakeNsm::new()).unwrap_err();
        assert!(
            format!("{err:#}").contains("PCR16 is not locked"),
            "{err:#}"
        );
    }

    #[test]
    fn a_locked_but_empty_guest_register_is_not_a_pair() {
        let nsm = FakeNsm::new();
        nsm.lock_pcr(PCR_GUEST).unwrap();
        let err = Pair::read(&nsm).unwrap_err();
        assert!(format!("{err:#}").contains("never extended"), "{err:#}");
    }

    /// A signed document stamped at `signed_at`, from a chain valid only for
    /// the hour after `valid_from`.
    fn stamped(
        valid_from: std::time::SystemTime,
        signed_at: std::time::SystemTime,
    ) -> (nitro_attestation::testing::TestChain, Vec<u8>) {
        use std::time::{Duration, UNIX_EPOCH};
        let chain = nitro_attestation::testing::TestChain::with_validity(
            valid_from,
            valid_from + Duration::from_secs(3600),
        )
        .unwrap();
        let mut document = nitro_attestation::parse(
            &chain
                .document(Some(b"payload".to_vec()), None, [0xab; 48])
                .unwrap(),
        )
        .unwrap();
        document.timestamp_ms = signed_at.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let receipt = chain.document_from(document).unwrap();
        (chain, receipt)
    }

    /// A receipt outlives the certificates that signed it. Judged against the
    /// current time it would stop verifying soon after it was written, and the
    /// filesystem it guards with it.
    #[test]
    fn a_receipt_is_judged_as_of_when_it_was_signed() {
        use std::time::{Duration, SystemTime};
        let long_ago = SystemTime::now() - Duration::from_secs(3600 * 24 * 90);
        let (chain, receipt) = stamped(long_ago, long_ago + Duration::from_secs(60));

        assert!(
            nitro_attestation::verify(
                &receipt,
                &VerifyOptions {
                    trust_root: chain.root_der().to_vec(),
                    now: SystemTime::now(),
                    allow_untrusted_root: false,
                },
            )
            .is_err(),
            "the chain has expired, so a check against now must refuse it"
        );
        let verified =
            verify_as_signed(&receipt, chain.root_der()).expect("valid when it was signed");
        assert_eq!(
            verified.document.user_data.as_deref(),
            Some(&b"payload"[..])
        );
    }

    /// And the moment a receipt claims has to be one its chain was valid at. A
    /// document stamped outside that window is refused, whatever the time now.
    #[test]
    fn a_receipt_stamped_outside_its_chain_is_refused() {
        use std::time::{Duration, SystemTime};
        let long_ago = SystemTime::now() - Duration::from_secs(3600 * 24 * 90);
        let (chain, receipt) = stamped(long_ago, SystemTime::now());
        assert!(verify_as_signed(&receipt, chain.root_der()).is_err());
    }

    #[test]
    fn trust_parses_the_documented_values() {
        assert_eq!(ReceiptTrust::parse("required"), Ok(ReceiptTrust::Required));
        assert_eq!(
            ReceiptTrust::parse("unsigned-emulator"),
            Ok(ReceiptTrust::UnsignedEmulator)
        );
        assert!(ReceiptTrust::parse("none").is_err());
    }
}
