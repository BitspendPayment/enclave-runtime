//! Where the guest's idea of "now" comes from.
//!
//! An enclave's system clock is not its own. It is seeded by the hypervisor at
//! boot, has no NTP, and drifts — and the party that sets it is the parent
//! instance, which is exactly the party the enclave exists to distrust. AWS
//! addresses this by exposing the Nitro card's PTP hardware clock, synchronised
//! to the Amazon Time Sync Service, at `/dev/ptp0`.
//!
//! Reading it uses the POSIX *dynamic clock* mechanism: open the character
//! device, then derive a clock id from the file descriptor and call
//! `clock_gettime` on that. The encoding is `((~fd) << 3) | 3`, which
//! [`rustix::time::clock_gettime_dynamic`] performs for us — worth using rather
//! than open-coding, since getting the bit twiddle wrong yields a valid-looking
//! clock id for some *other* clock rather than an error.

use std::fmt;
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rustix::time::{clock_gettime_dynamic, DynamicClockId};

/// The conventional device for the Nitro PTP hardware clock.
pub const DEFAULT_PTP_DEVICE: &str = "/dev/ptp0";

/// A source of wall-clock time.
pub trait TrustedClock: Send + Sync + fmt::Debug {
    /// Time since the Unix epoch.
    fn now(&self) -> Result<Duration>;

    /// Granularity of this clock.
    fn resolution(&self) -> Duration;

    /// Short description for the startup log. A deployment reading its own
    /// logs must be able to tell which clock it actually got.
    fn describe(&self) -> String;
}

/// The PTP hardware clock, read through its character device.
pub struct PtpClock {
    device: PathBuf,
    fd: OwnedFd,
}

impl PtpClock {
    /// Open the device and take one reading, so a device that exists but
    /// cannot be read fails here rather than on the guest's first call.
    pub fn open(device: impl AsRef<Path>) -> Result<Self> {
        let device = device.as_ref().to_path_buf();
        let file = File::open(&device)
            .with_context(|| format!("opening PTP clock device {}", device.display()))?;
        let clock = PtpClock {
            device,
            fd: OwnedFd::from(file),
        };
        clock
            .now()
            .with_context(|| format!("reading PTP clock device {}", clock.device.display()))?;
        Ok(clock)
    }

    pub fn device(&self) -> &Path {
        &self.device
    }
}

impl fmt::Debug for PtpClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtpClock")
            .field("device", &self.device)
            .finish()
    }
}

impl TrustedClock for PtpClock {
    fn now(&self) -> Result<Duration> {
        let ts = clock_gettime_dynamic(DynamicClockId::Dynamic(self.fd.as_fd()))
            .context("clock_gettime on the PTP dynamic clock id")?;
        // A PHC counts from the Unix epoch like CLOCK_REALTIME, so a negative
        // reading means the device is not what we think it is.
        let secs = u64::try_from(ts.tv_sec)
            .map_err(|_| anyhow::anyhow!("PTP clock returned a pre-epoch time"))?;
        Ok(Duration::new(secs, ts.tv_nsec as u32))
    }

    fn resolution(&self) -> Duration {
        // A PHC is nanosecond-granular in its interface. The underlying
        // oscillator is coarser, but nothing here can measure that.
        Duration::from_nanos(1)
    }

    fn describe(&self) -> String {
        format!("PTP hardware clock ({})", self.device.display())
    }
}

/// The host's `CLOCK_REALTIME`.
///
/// Fine for development. Inside an enclave it is whatever the hypervisor last
/// set, which is why using it there is worth a warning.
#[derive(Debug, Default)]
pub struct HostClock;

impl TrustedClock for HostClock {
    fn now(&self) -> Result<Duration> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("host clock is before the Unix epoch")
    }

    fn resolution(&self) -> Duration {
        Duration::from_nanos(1)
    }

    fn describe(&self) -> String {
        "host system clock (untrusted)".to_string()
    }
}

/// Which clock to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockSource {
    /// PTP if the device opens, host clock otherwise.
    #[default]
    Auto,
    /// PTP, or refuse to start.
    Ptp,
    /// Host clock, unconditionally.
    Host,
}

impl ClockSource {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(ClockSource::Auto),
            "ptp" => Ok(ClockSource::Ptp),
            "host" => Ok(ClockSource::Host),
            other => Err(format!("expected one of auto, ptp, host; got {other:?}")),
        }
    }
}

/// Resolve a clock source into a clock, logging which one was chosen.
///
/// `Auto` falls back at `warn` rather than silently: a misconfigured enclave
/// running on host time must not look identical in the logs to a correctly
/// configured one.
pub fn open_clock(source: ClockSource, device: &Path) -> Result<Box<dyn TrustedClock>> {
    match source {
        ClockSource::Host => {
            tracing::warn!(clock = "host", "using the host clock; time is untrusted");
            Ok(Box::new(HostClock))
        }
        ClockSource::Ptp => {
            let clock = PtpClock::open(device)
                .context("clock source 'ptp' was required but the device could not be opened")?;
            tracing::info!(clock = %clock.describe(), "clock source");
            Ok(Box::new(clock))
        }
        ClockSource::Auto => match PtpClock::open(device) {
            Ok(clock) => {
                tracing::info!(clock = %clock.describe(), "clock source");
                Ok(Box::new(clock))
            }
            Err(e) => {
                tracing::warn!(
                    device = %device.display(),
                    error = format!("{e:#}"),
                    "PTP clock unavailable, falling back to the host clock; time is untrusted"
                );
                Ok(Box::new(HostClock))
            }
        },
    }
}

/// Adapts a [`TrustedClock`] to what `wasmtime-wasi` wants for
/// `wasi:clocks/wall-clock`.
///
/// `HostWallClock::now` cannot fail, so this has to decide what a failed device
/// read means mid-run. It returns the last good reading and logs once. A guest
/// should not trap because a driver hiccuped, and a zero timestamp would be far
/// more damaging downstream — expired certificates, rejected tokens, dates in
/// 1970 — than one that is a few milliseconds stale.
pub struct WallClockAdapter {
    clock: Box<dyn TrustedClock>,
    last_good: Mutex<Duration>,
}

impl WallClockAdapter {
    pub fn new(clock: Box<dyn TrustedClock>) -> Result<Self> {
        let initial = clock.now()?;
        Ok(WallClockAdapter {
            clock,
            last_good: Mutex::new(initial),
        })
    }
}

impl fmt::Debug for WallClockAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WallClockAdapter")
            .field("clock", &self.clock)
            .finish()
    }
}

impl wasmtime_wasi::HostWallClock for WallClockAdapter {
    fn resolution(&self) -> Duration {
        self.clock.resolution()
    }

    fn now(&self) -> Duration {
        match self.clock.now() {
            Ok(now) => {
                *self.last_good.lock().expect("clock mutex poisoned") = now;
                now
            }
            Err(e) => {
                let stale = *self.last_good.lock().expect("clock mutex poisoned");
                tracing::warn!(
                    error = format!("{e:#}"),
                    "clock read failed; serving the last good reading"
                );
                stale
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use wasmtime_wasi::HostWallClock;

    /// A clock that can be made to fail on demand.
    #[derive(Debug)]
    struct FakeClock {
        nanos: AtomicU64,
        fail: AtomicBool,
    }

    impl FakeClock {
        fn new(nanos: u64) -> Arc<Self> {
            Arc::new(FakeClock {
                nanos: AtomicU64::new(nanos),
                fail: AtomicBool::new(false),
            })
        }
    }

    // Implemented on the handle so a test can keep one and still hand the
    // adapter ownership.
    impl TrustedClock for Arc<FakeClock> {
        fn now(&self) -> Result<Duration> {
            if self.fail.load(Ordering::SeqCst) {
                anyhow::bail!("device read failed");
            }
            Ok(Duration::from_nanos(self.nanos.load(Ordering::SeqCst)))
        }
        fn resolution(&self) -> Duration {
            Duration::from_nanos(7)
        }
        fn describe(&self) -> String {
            "fake".into()
        }
    }

    #[test]
    fn clock_source_parses_the_documented_values() {
        assert_eq!(ClockSource::parse("auto"), Ok(ClockSource::Auto));
        assert_eq!(ClockSource::parse("PTP"), Ok(ClockSource::Ptp));
        assert_eq!(ClockSource::parse(" host "), Ok(ClockSource::Host));
        assert_eq!(ClockSource::default(), ClockSource::Auto);

        let err = ClockSource::parse("gps").unwrap_err();
        assert!(err.contains("gps"), "{err}");
        assert!(err.contains("auto"), "{err}");
    }

    #[test]
    fn the_adapter_passes_readings_and_resolution_through() {
        let fake = FakeClock::new(1_700_000_000_000_000_000);
        let adapter = WallClockAdapter::new(Box::new(fake)).unwrap();
        assert_eq!(
            adapter.now(),
            Duration::from_nanos(1_700_000_000_000_000_000)
        );
        assert_eq!(adapter.resolution(), Duration::from_nanos(7));
    }

    /// The property that matters when a device read fails mid-run: a guest gets
    /// a slightly stale answer, never a zero one, and never a trap.
    #[test]
    fn a_failed_read_serves_the_last_good_value() {
        let fake = FakeClock::new(1_000);
        let adapter = WallClockAdapter::new(Box::new(fake.clone())).unwrap();

        // Advance, read, then break the device.
        fake.nanos.store(5_000, Ordering::SeqCst);
        assert_eq!(adapter.now(), Duration::from_nanos(5_000));

        fake.fail.store(true, Ordering::SeqCst);
        assert_eq!(
            adapter.now(),
            Duration::from_nanos(5_000),
            "must serve the last good reading, not zero"
        );
        assert_ne!(adapter.now(), Duration::ZERO);

        // Recovery restores live readings.
        fake.fail.store(false, Ordering::SeqCst);
        fake.nanos.store(9_000, Ordering::SeqCst);
        assert_eq!(adapter.now(), Duration::from_nanos(9_000));
    }

    #[test]
    fn a_clock_that_cannot_be_read_at_all_fails_to_construct() {
        let fake = FakeClock::new(0);
        fake.fail.store(true, Ordering::SeqCst);
        assert!(WallClockAdapter::new(Box::new(fake.clone())).is_err());
    }

    #[test]
    fn opening_a_missing_device_names_it() {
        let err = PtpClock::open("/dev/definitely-not-a-ptp-device").unwrap_err();
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("/dev/definitely-not-a-ptp-device"),
            "{rendered}"
        );
    }

    /// `auto` must degrade rather than refuse; `ptp` must refuse rather than
    /// degrade. That asymmetry is the whole point of having both.
    #[test]
    fn auto_falls_back_but_ptp_does_not() {
        let missing = Path::new("/dev/definitely-not-a-ptp-device");
        let fallback = open_clock(ClockSource::Auto, missing).expect("auto must fall back");
        assert!(fallback.describe().contains("host"));

        assert!(open_clock(ClockSource::Ptp, missing).is_err());
    }

    #[test]
    fn the_host_clock_is_sane_and_labelled_untrusted() {
        let clock = HostClock;
        let now = clock.now().unwrap();
        // Somewhere after 2020 and before 2100, i.e. a real wall clock.
        assert!(now.as_secs() > 1_577_836_800, "{now:?}");
        assert!(now.as_secs() < 4_102_444_800, "{now:?}");
        assert!(clock.describe().contains("untrusted"));
    }
}
