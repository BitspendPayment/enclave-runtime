//! Where the guest's random bytes come from.
//!
//! `wasi:random/random` is what a guest builds keys, nonces and session
//! identifiers from. Inside an enclave those bytes should come from the Nitro
//! Security Module — the same root of trust that signs attestation documents —
//! rather than from a kernel pool that *is* NSM-seeded but says nothing about
//! it and fails silently if it isn't.
//!
//! Bytes come **straight from the device on every call**. There is no DRBG in
//! between, so the trust argument is "the NSM produced these" with nothing
//! else to reason about. The cost is real: the device answers 256 bytes per
//! ioctl, so a large request is a loop of them.
//!
//! ## Why this panics where the clock does not
//!
//! [`cap_rand::RngCore`] has no fallible method. A device failure must become
//! either a panic or silently degraded bytes, and this chooses the panic.
//!
//! That looks inconsistent beside [`crate::clock`], which serves a stale
//! reading rather than failing — so the difference is worth stating. A slightly
//! stale timestamp is still a timestamp, and a caller can notice. Predictable
//! bytes handed to a guest that believes them random are indistinguishable from
//! good ones at the point of use; the guest builds a key and nothing downstream
//! can ever detect it. Stopping is the only safe answer.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use nitro_nsm::{Nsm, NsmDevice};

/// Which entropy source to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RandomSource {
    /// NSM if the device opens, kernel otherwise.
    #[default]
    Auto,
    /// NSM, or refuse to start.
    Nsm,
    /// The kernel's `getrandom(2)`.
    Host,
}

impl RandomSource {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(RandomSource::Auto),
            "nsm" => Ok(RandomSource::Nsm),
            "host" => Ok(RandomSource::Host),
            other => Err(format!("expected one of auto, nsm, host; got {other:?}")),
        }
    }
}

/// The kernel's `getrandom(2)`, for development and CI.
#[derive(Debug, Default)]
pub struct HostEntropy;

impl Nsm for HostEntropy {
    fn get_random(&self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|e| anyhow::anyhow!("kernel getrandom(2): {e}"))
    }

    fn describe(&self) -> String {
        "kernel getrandom(2) (not NSM)".to_string()
    }
}

/// Resolve a source into an entropy provider, saying which one was chosen.
///
/// A fallback here is reported at `error`, not `warn`. Running an enclave on
/// host entropy is not a degraded mode to note and move on from — every key the
/// guest generates afterwards rests on it.
pub fn open_entropy(source: RandomSource, device: &Path) -> Result<Arc<dyn Nsm>> {
    match source {
        RandomSource::Host => {
            tracing::warn!(
                entropy = "host",
                "using kernel entropy; not the Nitro Security Module"
            );
            Ok(Arc::new(HostEntropy))
        }
        RandomSource::Nsm => {
            let nsm = NsmDevice::open(device)
                .context("entropy source 'nsm' was required but the device is unusable")?;
            tracing::info!(entropy = %nsm.describe(), "entropy source");
            Ok(Arc::new(nsm))
        }
        RandomSource::Auto => match NsmDevice::open(device) {
            Ok(nsm) => {
                tracing::info!(entropy = %nsm.describe(), "entropy source");
                Ok(Arc::new(nsm))
            }
            Err(e) => {
                tracing::error!(
                    device = %device.display(),
                    error = format!("{e:#}"),
                    "NSM unavailable, falling back to kernel entropy; \
                     inside an enclave this is a security failure, not a warning"
                );
                Ok(Arc::new(HostEntropy))
            }
        },
    }
}

/// Serves `wasi:random/random` from an entropy source.
pub struct GuestRandom {
    source: Arc<dyn Nsm>,
}

impl GuestRandom {
    pub fn new(source: Arc<dyn Nsm>) -> Self {
        GuestRandom { source }
    }

    /// A seed for `wasi:random/insecure-seed`, drawn once at startup. That
    /// interface is a hash seed, not key material, so one draw is enough.
    pub fn insecure_seed(&self) -> Result<u128> {
        let mut bytes = [0u8; 16];
        self.source.get_random(&mut bytes)?;
        Ok(u128::from_le_bytes(bytes))
    }
}

impl fmt::Debug for GuestRandom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestRandom")
            .field("source", &self.source)
            .finish()
    }
}

impl cap_rand::RngCore for GuestRandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // See the module docs: there is no way to report this, and continuing
        // would hand the guest bytes it would treat as secret.
        self.source
            .get_random(dest)
            .expect("entropy source failed; refusing to hand the guest predictable bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), cap_rand::Error> {
        match self.source.get_random(dest) {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "entropy source failed");
                Err(cap_rand::Error::from(
                    std::num::NonZeroU32::new(cap_rand::Error::CUSTOM_START)
                        .expect("CUSTOM_START is nonzero"),
                ))
            }
        }
    }
}

/// `cap_rand::CryptoRng` is a marker promising the output is suitable for
/// cryptography. That holds: the bytes are the NSM's, or the kernel CSPRNG's.
impl cap_rand::CryptoRng for GuestRandom {}

#[cfg(test)]
mod tests {
    use super::*;
    use nitro_nsm::fake::FakeNsm;
    use cap_rand::RngCore;
    use std::sync::atomic::Ordering;

    fn fake() -> Arc<FakeNsm> {
        Arc::new(FakeNsm::new())
    }

    #[test]
    fn source_parses_the_documented_values() {
        assert_eq!(RandomSource::parse("auto"), Ok(RandomSource::Auto));
        assert_eq!(RandomSource::parse("NSM"), Ok(RandomSource::Nsm));
        assert_eq!(RandomSource::parse(" host "), Ok(RandomSource::Host));
        assert_eq!(RandomSource::default(), RandomSource::Auto);
        assert!(RandomSource::parse("urandom").is_err());
    }

    #[test]
    fn bytes_come_from_the_source() {
        let nsm = fake();
        let mut rng = GuestRandom::new(nsm.clone());
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);

        assert!(buf.iter().any(|&b| b != 0));
        assert!(
            nsm.calls.load(Ordering::SeqCst) > 0,
            "the device was not consulted"
        );
    }

    /// Every draw must hit the device: that is the whole point of choosing
    /// direct-from-NSM over a seeded generator.
    #[test]
    fn every_draw_consults_the_device() {
        let nsm = fake();
        let mut rng = GuestRandom::new(nsm.clone());
        for _ in 0..5 {
            let _ = rng.next_u64();
        }
        assert_eq!(nsm.calls.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn successive_draws_differ() {
        let nsm = fake();
        let mut rng = GuestRandom::new(nsm);
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn a_large_request_is_filled_completely() {
        let nsm = fake();
        let mut rng = GuestRandom::new(nsm.clone());
        let mut buf = vec![0u8; 4096];
        rng.fill_bytes(&mut buf);

        assert_eq!(
            nsm.calls.load(Ordering::SeqCst),
            16,
            "4096 / 256 byte chunks"
        );
        assert!(!buf.iter().all(|&b| b == buf[0]), "output is constant");
    }

    /// A guest must never receive predictable bytes believing them random, so
    /// a dead entropy source stops the process rather than degrading.
    #[test]
    #[should_panic(expected = "entropy source failed")]
    fn a_dead_source_panics_rather_than_degrading() {
        let nsm = fake();
        nsm.empty.store(true, Ordering::SeqCst);
        let mut rng = GuestRandom::new(nsm);
        rng.fill_bytes(&mut [0u8; 16]);
    }

    #[test]
    fn the_fallible_path_reports_rather_than_panicking() {
        let nsm = fake();
        nsm.empty.store(true, Ordering::SeqCst);
        let mut rng = GuestRandom::new(nsm);
        assert!(rng.try_fill_bytes(&mut [0u8; 16]).is_err());
    }

    #[test]
    fn the_insecure_seed_is_drawn_from_the_source() {
        let nsm = fake();
        let rng = GuestRandom::new(nsm.clone());
        let seed = rng.insecure_seed().unwrap();
        assert_ne!(seed, 0);
        assert!(nsm.calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn the_host_source_produces_usable_entropy() {
        let host = HostEntropy;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        host.get_random(&mut a).unwrap();
        host.get_random(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(a.iter().any(|&x| x != 0));
        assert!(host.describe().contains("not NSM"));
    }

    /// `auto` degrades; `nsm` refuses. Same asymmetry as the clock.
    #[test]
    fn auto_falls_back_but_nsm_does_not() {
        let missing = Path::new("/dev/definitely-not-nsm");
        let fallback = open_entropy(RandomSource::Auto, missing).expect("auto must fall back");
        assert!(fallback.describe().contains("not NSM"));
        assert!(open_entropy(RandomSource::Nsm, missing).is_err());
    }
}
