//! The guest component: fetched from outside the image, measured into PCR16,
//! and locked before anything asks for a key.
//!
//! It used to ship inside the enclave image, which put it under PCR0 and made
//! every guest change an image rebuild. Now the image names *where* the guest
//! is — a key in the roots bucket, covered by PCR0 like the rest of the image's
//! configuration — and the runtime measures *what* it finds there:
//!
//! ```text
//!   fetch ──▶ extend PCR16 with sha256(component) ──▶ lock ──▶ boot, and KMS
//! ```
//!
//! ## Why the object does not have to be trusted
//!
//! Whatever bytes arrive are measured before they can matter. A parent that
//! substitutes the object gets an enclave with a different PCR16: one a key
//! policy pinning the approved guest releases no key to, and one a client
//! pinning that guest refuses.
//!
//! That is also why the order cannot be rearranged. A key released before the
//! lock would go to an enclave whose register could still change, and a
//! register that is never locked appears in no attestation document at all.
//!
//! ## What it does not cover
//!
//! PCR16 means something only beside PCR0. The runtime does the extending, so a
//! runtime someone else wrote can put any value in the register while running
//! anything; PCR0 is what says the runtime that extended it is this one.
//!
//! And measuring a guest is not vetting it. An approved guest can still write
//! whatever it reads to stdout, which the runtime ships to CloudWatch. Approving
//! a guest is trusting it with the data, and nothing here changes that.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use nitro_nsm::{Nsm, PCR_GUEST, PCR_ZERO};
use s3fs_core::backend::Backend;
use s3fs_core::FsError;

/// Larger than any guest this runtime has a use for.
///
/// The largest example, the SQLite guest, is about 1.3 MiB. The object comes
/// from a store the parent can write to, and memory is the one thing an enclave
/// cannot get more of once it has started.
pub const MAX_GUEST_BYTES: u64 = 64 * 1024 * 1024;

/// Where the guest component comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestSource {
    /// A key in the roots bucket, used verbatim. What an enclave image uses.
    Object { key: String },
    /// A local file, for development and tests. Measured exactly as an object
    /// is, so a run from a file attests the same PCR16 as one from the store.
    Path(PathBuf),
}

impl std::fmt::Display for GuestSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestSource::Object { key } => write!(f, "roots-bucket object {key}"),
            GuestSource::Path(path) => write!(f, "file {}", path.display()),
        }
    }
}

/// Read the guest component, refusing anything over [`MAX_GUEST_BYTES`].
pub async fn fetch_guest(source: &GuestSource, roots: &Arc<dyn Backend>) -> Result<Vec<u8>> {
    fetch_bounded(source, roots, MAX_GUEST_BYTES).await
}

async fn fetch_bounded(
    source: &GuestSource,
    roots: &Arc<dyn Backend>,
    limit: u64,
) -> Result<Vec<u8>> {
    // One byte past the limit is read and never more, so an oversized component
    // is found out without being held whole.
    let bytes = match source {
        GuestSource::Object { key } => roots
            .get_blob(key, Some(0..limit + 1))
            .await
            .map_err(|e| match e {
                FsError::NotFound => anyhow::anyhow!(
                    "no guest component at {key} in the roots bucket; upload the approved \
                     guest there before starting the enclave"
                ),
                other => anyhow::anyhow!("reading the guest component {key}: {other}"),
            })?
            .body
            .to_vec(),
        GuestSource::Path(path) => {
            use std::io::Read as _;
            let file = std::fs::File::open(path)
                .with_context(|| format!("opening the guest component {}", path.display()))?;
            let mut bytes = Vec::new();
            file.take(limit + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading the guest component {}", path.display()))?;
            bytes
        }
    };
    if bytes.len() as u64 > limit {
        bail!("the guest component from {source} is over the {limit} byte limit");
    }
    if bytes.is_empty() {
        bail!("the guest component from {source} is empty");
    }
    Ok(bytes)
}

/// Extend [`PCR_GUEST`] with `sha256(component)` and lock it, returning the
/// value it now holds.
///
/// Each step is checked against what it should have produced, because each is a
/// place a wrong answer would otherwise pass silently into every attestation
/// this enclave makes:
///
/// 1. The register must be unlocked and zero. Anything else means something
///    measured into it first, and extending on top would attest a value no
///    client could reproduce from the component.
/// 2. Extending must produce exactly what a client computes from the
///    component, [`nitro_attestation::guest_pcr`].
/// 3. Lock it.
/// 4. The register must now read locked, with that same value — the device's
///    word for it, not the lock call's.
pub fn measure_guest(nsm: &dyn Nsm, component: &[u8]) -> Result<[u8; 48]> {
    let before = nsm
        .describe_pcr(PCR_GUEST)
        .context("reading PCR16 before measuring the guest")?;
    if before.locked {
        bail!(
            "PCR16 is already locked, so something measured into it before this runtime \
             could. Refusing to start: every attestation would carry a register that names \
             nothing this runtime loaded."
        );
    }
    if before.value != PCR_ZERO {
        bail!(
            "PCR16 already holds {}; something extended it before the guest was measured, \
             and extending on top would attest a value no client can reproduce from the \
             component. Refusing to start.",
            hex::encode(&before.value)
        );
    }

    let expected = nitro_attestation::guest_pcr(component);
    let extended = nsm
        .extend_pcr(PCR_GUEST, &nitro_attestation::sha256(component))
        .context("extending PCR16 with the guest's hash")?;
    if extended != expected {
        bail!(
            "PCR16 reads {} after extending with the guest's hash, but one extension from \
             zero gives {}. Refusing to start.",
            hex::encode(&extended),
            hex::encode(expected)
        );
    }

    nsm.lock_pcr(PCR_GUEST).context("locking PCR16")?;

    let after = nsm
        .describe_pcr(PCR_GUEST)
        .context("reading PCR16 after locking it")?;
    if !after.locked {
        bail!(
            "PCR16 still reads unlocked after LockPCR succeeded. An unlocked register appears \
             in no attestation document, so no key policy and no client could see this \
             guest. Refusing to start."
        );
    }
    if after.value != expected {
        bail!(
            "PCR16 changed while being locked: it reads {}, expected {}. Refusing to start.",
            hex::encode(&after.value),
            hex::encode(expected)
        );
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nitro_nsm::fake::FakeNsm;
    use nitro_nsm::Pcr;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::backend::PutBlobInput;
    use std::sync::atomic::{AtomicBool, Ordering};

    const GUEST: &[u8] = b"\0asm pretend component";

    #[test]
    fn a_guest_is_measured_into_pcr16_and_locked() {
        let nsm = FakeNsm::new();
        let measured = measure_guest(&nsm, GUEST).expect("measured");
        assert_eq!(
            measured,
            nitro_attestation::guest_pcr(GUEST),
            "the value a client computes from the component"
        );
        let pcr = nsm.describe_pcr(PCR_GUEST).unwrap();
        assert!(pcr.locked);
        assert_eq!(pcr.value, measured.to_vec());
    }

    /// The runtime and every client compute this register with two copies of
    /// the arithmetic, on either side of a crate boundary that exists on
    /// purpose. This is what keeps them the same arithmetic.
    #[test]
    fn the_device_side_and_the_verifier_side_agree() {
        assert_eq!(PCR_GUEST as u32, nitro_attestation::PCR_GUEST);
        let digest = nitro_attestation::sha256(GUEST);
        let cases: [&[u8]; 4] = [b"", b"abc", &[0xff; 32], &digest];
        for data in cases {
            assert_eq!(
                nitro_nsm::pcr_extend(&PCR_ZERO, data),
                nitro_attestation::pcr_after_one_extend(data).to_vec()
            );
        }
    }

    /// Something extended the register first.
    #[test]
    fn a_register_already_extended_is_refused() {
        let nsm = FakeNsm::new();
        nsm.extend_pcr(PCR_GUEST, b"someone else").unwrap();
        let err = measure_guest(&nsm, GUEST).unwrap_err();
        assert!(format!("{err:#}").contains("already holds"), "{err:#}");
    }

    #[test]
    fn a_register_already_locked_is_refused() {
        let nsm = FakeNsm::new();
        nsm.lock_pcr(PCR_GUEST).unwrap();
        let err = measure_guest(&nsm, GUEST).unwrap_err();
        assert!(format!("{err:#}").contains("already locked"), "{err:#}");
    }

    /// A device that misreports, one lie at a time.
    #[derive(Debug, Default)]
    struct Misreporting {
        inner: FakeNsm,
        wrong_extend: AtomicBool,
        lock_ignored: AtomicBool,
    }

    impl Nsm for Misreporting {
        fn get_random(&self, buf: &mut [u8]) -> Result<()> {
            self.inner.get_random(buf)
        }
        fn attest(&self, request: &nitro_nsm::AttestationRequest) -> Result<Vec<u8>> {
            self.inner.attest(request)
        }
        fn describe_pcr(&self, index: u16) -> Result<Pcr> {
            self.inner.describe_pcr(index)
        }
        fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<Vec<u8>> {
            let value = self.inner.extend_pcr(index, data)?;
            if self.wrong_extend.load(Ordering::SeqCst) {
                return Ok(vec![0xee; 48]);
            }
            Ok(value)
        }
        fn lock_pcr(&self, index: u16) -> Result<()> {
            if self.lock_ignored.load(Ordering::SeqCst) {
                return Ok(());
            }
            self.inner.lock_pcr(index)
        }
        fn describe(&self) -> String {
            "misreporting test NSM".into()
        }
    }

    #[test]
    fn an_extension_that_did_not_produce_the_measurement_is_refused() {
        let nsm = Misreporting::default();
        nsm.wrong_extend.store(true, Ordering::SeqCst);
        let err = measure_guest(&nsm, GUEST).unwrap_err();
        assert!(format!("{err:#}").contains("after extending"), "{err:#}");
        assert!(
            !nsm.describe_pcr(PCR_GUEST).unwrap().locked,
            "a bad measurement was locked in"
        );
    }

    /// The lock call returning is not the device saying the register is
    /// locked. An unlocked register is in no document, so this is the
    /// difference between a guest the key policy can see and one it cannot.
    #[test]
    fn a_lock_that_did_not_take_is_refused() {
        let nsm = Misreporting::default();
        nsm.lock_ignored.store(true, Ordering::SeqCst);
        let err = measure_guest(&nsm, GUEST).unwrap_err();
        assert!(format!("{err:#}").contains("unlocked"), "{err:#}");
    }

    async fn roots_with(key: &str, body: &[u8]) -> Arc<dyn Backend> {
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        roots
            .put_blob(PutBlobInput::new(key, body.to_vec().into()))
            .await
            .expect("write");
        roots
    }

    #[tokio::test]
    async fn a_guest_object_is_read_from_the_roots_bucket() {
        let roots = roots_with("guest/guest.wasm", GUEST).await;
        let source = GuestSource::Object {
            key: "guest/guest.wasm".into(),
        };
        assert_eq!(fetch_guest(&source, &roots).await.unwrap(), GUEST);
    }

    #[tokio::test]
    async fn a_missing_guest_object_says_what_to_do() {
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let source = GuestSource::Object {
            key: "guest/guest.wasm".into(),
        };
        let err = fetch_guest(&source, &roots).await.unwrap_err();
        assert!(format!("{err:#}").contains("upload"), "{err:#}");
    }

    #[tokio::test]
    async fn an_oversized_guest_object_is_refused() {
        let roots = roots_with("big", &[7u8; 17]).await;
        let source = GuestSource::Object { key: "big".into() };
        let err = fetch_bounded(&source, &roots, 16).await.unwrap_err();
        assert!(format!("{err:#}").contains("limit"), "{err:#}");
        assert_eq!(
            fetch_bounded(&source, &roots, 17).await.unwrap(),
            vec![7u8; 17],
            "exactly at the limit is allowed"
        );
    }

    #[tokio::test]
    async fn a_guest_file_is_bounded_the_same_way() {
        let path = std::env::temp_dir().join(format!("guest-bound-{}.wasm", std::process::id()));
        std::fs::write(&path, [7u8; 17]).unwrap();
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let source = GuestSource::Path(path.clone());

        let refused = fetch_bounded(&source, &roots, 16).await;
        let accepted = fetch_bounded(&source, &roots, 17).await;
        let _ = std::fs::remove_file(&path);

        assert!(refused.is_err());
        assert_eq!(accepted.unwrap(), vec![7u8; 17]);
    }

    #[tokio::test]
    async fn an_empty_guest_is_refused() {
        let roots = roots_with("empty", b"").await;
        let source = GuestSource::Object {
            key: "empty".into(),
        };
        let err = fetch_guest(&source, &roots).await.unwrap_err();
        assert!(format!("{err:#}").contains("empty"), "{err:#}");
    }
}
