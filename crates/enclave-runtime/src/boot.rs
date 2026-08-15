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

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use nitro_attestation::{Expectations, Trust, VerifyOptions};
use nitro_nsm::{AttestationRequest, Nsm, PCR_SUCCESSOR, PCR_ZERO};
use s3fs_core::backend::{Backend, ObjectLock, PutBlobInput};
use s3fs_core::FsError;

use crate::keys::{MasterKeySource, SealedKey};
use crate::mount::{Backends, MountConfig, Mounted};

/// `user_data` purpose for the receipt genesis writes.
const PURPOSE_STATE_ORIGIN: &str = "s3fs-state-origin";
/// `user_data` purpose for the receipt a predecessor writes to name a successor.
const PURPOSE_TRANSITION: &str = "s3fs-transition";

/// Schema string inside the `state_root` pre-image. Bump it and every existing
/// receipt stops verifying, which is the intended effect of changing what a
/// receipt means.
const STATE_ROOT_SCHEMA: &str = "s3fs/state-origin/v1";

/// Which boot this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// No receipt and no filesystem: create both.
    Genesis,
    /// A receipt written by an enclave with this PCR0.
    Resume,
    /// A receipt written by a different PCR0, with a transition receipt from
    /// that PCR0 naming this one.
    Migration,
}

/// What a boot established, for logging and for the health endpoint.
#[derive(Debug)]
pub struct Booted {
    pub mode: BootMode,
    pub mounted: Mounted,
    pub state_root: [u8; 32],
    /// The PCR0 this enclave is running under.
    pub pcr0: Vec<u8>,
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

/// `user_data` payload of a receipt.
fn receipt_payload(purpose: &str, state_root: &[u8; 32], successor: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![
        (
            ciborium::Value::Text("purpose".into()),
            ciborium::Value::Text(purpose.to_string()),
        ),
        (
            ciborium::Value::Text("state_root".into()),
            ciborium::Value::Bytes(state_root.to_vec()),
        ),
    ];
    if let Some(pcr0) = successor {
        fields.push((
            ciborium::Value::Text("successor_pcr0".into()),
            ciborium::Value::Bytes(pcr0.to_vec()),
        ));
    }
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

fn transition_key(prefix: &str, fs_uuid: &[u8; 16], successor_pcr0: &[u8]) -> String {
    format!(
        "{prefix}origin/{}.transition.{}",
        hex::encode(fs_uuid),
        hex::encode(successor_pcr0)
    )
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

/// Read an object, distinguishing "absent" from "could not read".
async fn maybe_get(backend: &Arc<dyn Backend>, key: &str) -> Result<Option<Vec<u8>>> {
    match backend.get_blob(key, None).await {
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
        ReceiptTrust::Required => {
            let verified = nitro_attestation::verify(document, &VerifyOptions::default())
                .context("verifying the receipt")?;
            if verified.trust != Trust::ChainVerified {
                bail!(
                    "receipt is {:?} rather than chain-verified; this image \
                     requires a receipt signed by AWS",
                    verified.trust
                );
            }
            verified
        }
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

    let pcr0 = nsm
        .describe_pcr(0)
        .context("reading PCR0; the boot machine cannot compare what it cannot read")?
        .value;

    let receipt = maybe_get(roots, &receipt_key(prefix, fs_uuid)).await?;
    let sealed = maybe_get(roots, &sealed_key_key(prefix, fs_uuid))
        .await?
        .map(SealedKey::from_bytes);

    match (receipt, sealed) {
        // ---- resume or migration -------------------------------------------
        (Some(receipt), Some(sealed)) => {
            let master = key_source
                .open(&sealed)
                .await
                .context("opening this filesystem's master key")?;
            let mounted = crate::mount::mount_existing(backends, mount_config, &master).await?;

            let identity = identity_of(&mounted, mount_config, &sealed).await?;
            let state_root = identity.state_root();

            let mode = verify_origin(
                &receipt,
                boot_config.trust,
                &state_root,
                &pcr0,
                roots,
                prefix,
                fs_uuid,
            )
            .await?;

            Ok(Booted {
                mode,
                mounted,
                state_root,
                pcr0,
            })
        }

        // ---- genesis -------------------------------------------------------
        (None, None) => genesis(backends, mount_config, nsm, key_source, pcr0).await,

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

/// Check the receipt, falling through to the migration path if it was written
/// by a different image.
async fn verify_origin(
    receipt: &[u8],
    trust: ReceiptTrust,
    state_root: &[u8; 32],
    pcr0: &[u8],
    roots: &Arc<dyn Backend>,
    prefix: &str,
    fs_uuid: &[u8; 16],
) -> Result<BootMode> {
    let payload = receipt_payload(PURPOSE_STATE_ORIGIN, state_root, None);

    // Whose receipt is it? Parse before verifying so the error can say
    // "written by another image" rather than "PCR0 mismatch".
    let parsed = nitro_attestation::parse(receipt).context("parsing the state-origin receipt")?;
    let author = parsed
        .pcr(0)
        .context("the receipt carries no PCR0")?
        .to_vec();

    if author == pcr0 {
        open_receipt(
            receipt,
            trust,
            "state-origin",
            &Expectations::default()
                .pcr0(pcr0.to_vec())
                .user_data(payload),
        )?;
        return Ok(BootMode::Resume);
    }

    // A different image wrote this filesystem. It may boot here only if that
    // image said so, and said so about *this* image specifically.
    let key = transition_key(prefix, fs_uuid, pcr0);
    let transition = maybe_get(roots, &key).await?.with_context(|| {
        format!(
            "this filesystem was created by enclave image {} and this one is {}. \
             No transition receipt at {key} authorises the handoff — the \
             predecessor must run `--authorise-successor {}` first.",
            hex::encode(&author[..8.min(author.len())]),
            hex::encode(&pcr0[..8.min(pcr0.len())]),
            hex::encode(pcr0),
        )
    })?;

    // Written by the incumbent, committing to this successor in two
    // independent places: PCR31, which it had to extend before attesting and
    // cannot undo, and the payload.
    open_receipt(
        &transition,
        trust,
        "transition",
        &Expectations::default()
            .pcr0(author.clone())
            .pcr(PCR_SUCCESSOR as u32, nitro_nsm::pcr_extend(&PCR_ZERO, pcr0))
            .user_data(receipt_payload(PURPOSE_TRANSITION, state_root, Some(pcr0))),
    )?;

    tracing::warn!(
        predecessor = %hex::encode(&author),
        successor = %hex::encode(pcr0),
        "migrating: this filesystem was created by a different enclave image"
    );
    Ok(BootMode::Migration)
}

/// Create a filesystem and the receipt that authorises every later boot.
///
/// The ordering is load-bearing and only the last step is atomic: mint, seal,
/// persist the key, create the filesystem, then write the receipt with a
/// conditional PUT. A crash before the last step leaves a filesystem with no
/// receipt, which the next boot refuses — deliberately, because that state is
/// indistinguishable from a store whose receipt has been hidden.
async fn genesis(
    backends: &Backends,
    config: &MountConfig,
    nsm: &Arc<dyn Nsm>,
    key_source: &dyn MasterKeySource,
    pcr0: Vec<u8>,
) -> Result<Booted> {
    tracing::info!(
        pcr0 = %hex::encode(&pcr0),
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
            FsError::Conflict => anyhow::anyhow!(
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
            None,
        )))
        .context("asking the NSM for a state-origin receipt")?;

    let receipt_object = receipt_key(&config.bucket_prefix, &config.fs_id);
    backends
        .roots
        .put_blob_if_not_exists(locked(&receipt_object, document, config))
        .await
        .map_err(|e| anyhow::anyhow!("writing the state-origin receipt: {e}"))?;

    tracing::info!(
        state_root = %hex::encode(state_root),
        "genesis complete; this filesystem now has an attested origin"
    );

    Ok(Booted {
        mode: BootMode::Genesis,
        mounted,
        state_root,
        pcr0,
    })
}

/// Authorise a successor image, then stop.
///
/// Extends PCR31 with the successor's PCR0 — irreversibly, for this enclave's
/// life — and attests. The document therefore proves two things a later image
/// can check independently: that the incumbent produced it, and that it had
/// committed to *this* successor before doing so.
pub async fn authorise_successor(
    backends: &Backends,
    config: &MountConfig,
    nsm: &Arc<dyn Nsm>,
    key_source: &dyn MasterKeySource,
    successor_pcr0: &[u8],
) -> Result<()> {
    let sealed = maybe_get(
        &backends.roots,
        &sealed_key_key(&config.bucket_prefix, &config.fs_id),
    )
    .await?
    .map(SealedKey::from_bytes)
    .context("no sealed key here: there is no filesystem to hand over")?;

    let master = key_source.open(&sealed).await?;
    let mounted = crate::mount::mount_existing(backends, config, &master).await?;
    let state_root = identity_of(&mounted, config, &sealed).await?.state_root();

    let extended = nsm
        .extend_pcr(PCR_SUCCESSOR, successor_pcr0)
        .context("extending PCR31 to name the successor")?;
    let expected = nitro_nsm::pcr_extend(&PCR_ZERO, successor_pcr0);
    if extended != expected {
        bail!(
            "PCR{PCR_SUCCESSOR} reads {} after extending, expected {}. It was \
             not zero beforehand, so this enclave has already authorised \
             something. Restart it and authorise once.",
            hex::encode(&extended),
            hex::encode(&expected)
        );
    }

    let document = nsm
        .attest(&AttestationRequest::with_user_data(receipt_payload(
            PURPOSE_TRANSITION,
            &state_root,
            Some(successor_pcr0),
        )))
        .context("asking the NSM for a transition receipt")?;

    let key = transition_key(&config.bucket_prefix, &config.fs_id, successor_pcr0);
    backends
        .roots
        .put_blob(locked(&key, document, config))
        .await
        .map_err(|e| anyhow::anyhow!("writing the transition receipt: {e}"))?;

    tracing::info!(
        successor = %hex::encode(successor_pcr0),
        key = %key,
        "successor authorised; it may now boot this filesystem once"
    );
    Ok(())
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
            receipt_payload(PURPOSE_STATE_ORIGIN, &root, None),
            receipt_payload(PURPOSE_TRANSITION, &root, None),
            "a state-origin receipt must not verify as a transition receipt"
        );
    }

    #[test]
    fn a_transition_payload_names_its_successor() {
        let root = [4u8; 32];
        assert_ne!(
            receipt_payload(PURPOSE_TRANSITION, &root, Some(b"image-a")),
            receipt_payload(PURPOSE_TRANSITION, &root, Some(b"image-b")),
            "a handoff to one image must not authorise another"
        );
    }

    /// Keys must be derivable from the filesystem id alone — that is what
    /// makes a 404 an answer rather than a failure to look in the right place.
    #[test]
    fn object_keys_are_derived_and_distinct() {
        let uuid = [7u8; 16];
        let r = receipt_key("p/", &uuid);
        let k = sealed_key_key("p/", &uuid);
        let t = transition_key("p/", &uuid, b"successor");
        assert_ne!(r, k);
        assert_ne!(r, t);
        assert_ne!(k, t);
        assert!(r.starts_with("p/"));
        assert_eq!(r, receipt_key("p/", &uuid), "must be deterministic");
        assert_ne!(t, transition_key("p/", &uuid, b"other"));
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
