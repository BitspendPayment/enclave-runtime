//! The Nitro Security Module, through `/dev/nsm`.
//!
//! The NSM is the enclave's root of trust. It produces attestation documents,
//! holds the PCRs, and — the part used here — generates random bytes. Its
//! userspace interface is one ioctl carrying a CBOR request and returning a
//! CBOR response, defined by `uapi/linux/nsm.h`:
//!
//! ```c
//! struct nsm_iovec { __u64 addr; __u64 len; };
//! struct nsm_raw   { struct nsm_iovec request; struct nsm_iovec response; };
//! #define NSM_IOCTL_RAW _IOWR(0x0A, 0x0, struct nsm_raw)
//! ```
//!
//! Only [`NsmDevice::request`] knows about the ioctl; everything above it deals
//! in CBOR payloads. That is the seam attestation will reuse — its requests are
//! different bytes through the same call.
//!
//! ## Two things worth knowing before debugging this
//!
//! The raw ioctl requires **`CAP_SYS_ADMIN`**, per the comment in the kernel
//! header. An unprivileged process gets `EPERM` from a device that exists and
//! is readable, which is a confusing failure if you are not expecting it.
//!
//! `response.len` is **in/out**: the caller sets the buffer capacity and the
//! driver overwrites it with how much it actually wrote. Passing a fresh
//! `nsm_raw` per call rather than reusing one is deliberate.

use std::fmt;
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustix::ioctl;

/// The conventional device node for the NSM.
pub const DEFAULT_NSM_DEVICE: &str = "/dev/nsm";

/// `NSM_REQUEST_MAX_SIZE`.
const REQUEST_MAX: usize = 0x1000;
/// `NSM_RESPONSE_MAX_SIZE`.
const RESPONSE_MAX: usize = 0x3000;

/// `struct nsm_iovec`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NsmIovec {
    addr: u64,
    len: u64,
}

/// `struct nsm_raw`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NsmRaw {
    request: NsmIovec,
    response: NsmIovec,
}

/// `_IOWR(NSM_MAGIC, 0x0, struct nsm_raw)`.
const NSM_IOCTL_RAW: ioctl::Opcode = ioctl::opcode::read_write::<NsmRaw>(0x0A, 0x0);

/// What an NSM can do, so tests can substitute a fake.
pub trait Nsm: Send + Sync + fmt::Debug {
    /// Fill `buf` with random bytes.
    fn get_random(&self, buf: &mut [u8]) -> Result<()>;
    /// Short description for logs.
    fn describe(&self) -> String;
}

/// The real device.
pub struct NsmDevice {
    device: PathBuf,
    fd: OwnedFd,
}

impl NsmDevice {
    /// Open the device and prove it answers, so a device that exists but is
    /// unusable fails here rather than on the guest's first request for
    /// randomness.
    pub fn open(device: impl AsRef<Path>) -> Result<Self> {
        let device = device.as_ref().to_path_buf();
        let file = File::open(&device)
            .with_context(|| format!("opening NSM device {}", device.display()))?;
        let nsm = NsmDevice {
            device,
            fd: OwnedFd::from(file),
        };

        let mut probe = [0u8; 32];
        nsm.get_random(&mut probe).with_context(|| {
            format!(
                "NSM device {} did not answer GetRandom (the raw ioctl needs CAP_SYS_ADMIN)",
                nsm.device.display()
            )
        })?;
        Ok(nsm)
    }

    pub fn device(&self) -> &Path {
        &self.device
    }

    /// One raw NSM round trip: CBOR in, CBOR out.
    ///
    /// This is the whole device interface. Attestation is the same call with a
    /// different payload.
    pub fn request(&self, cbor: &[u8]) -> Result<Vec<u8>> {
        if cbor.len() > REQUEST_MAX {
            bail!(
                "NSM request is {} bytes, over the {REQUEST_MAX} limit",
                cbor.len()
            );
        }
        let mut response = vec![0u8; RESPONSE_MAX];

        let mut raw = NsmRaw {
            request: NsmIovec {
                addr: cbor.as_ptr() as u64,
                len: cbor.len() as u64,
            },
            response: NsmIovec {
                addr: response.as_mut_ptr() as u64,
                // In/out: capacity going in, bytes written coming back.
                len: response.len() as u64,
            },
        };

        // SAFETY: the opcode matches `struct nsm_raw`, both iovecs point at
        // live allocations that outlive the call, and the lengths describe
        // them exactly.
        unsafe {
            let control = ioctl::Updater::<NSM_IOCTL_RAW, NsmRaw>::new(&mut raw);
            ioctl::ioctl(self.fd.as_fd(), control)
                .with_context(|| format!("NSM ioctl on {}", self.device.display()))?;
        }

        let written = raw.response.len as usize;
        if written == 0 {
            bail!("NSM returned an empty response");
        }
        if written > response.len() {
            bail!(
                "NSM reported {written} bytes into a {} byte buffer",
                response.len()
            );
        }
        response.truncate(written);
        Ok(response)
    }
}

impl fmt::Debug for NsmDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NsmDevice")
            .field("device", &self.device)
            .finish()
    }
}

impl Nsm for NsmDevice {
    fn get_random(&self, buf: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let response = self.request(&encode_get_random())?;
            let bytes = decode_get_random(&response)?;
            if bytes.is_empty() {
                // Retrying would spin forever against a source that has
                // stopped producing. An entropy failure must be loud.
                bail!("NSM GetRandom returned no bytes");
            }
            let take = bytes.len().min(buf.len() - filled);
            buf[filled..filled + take].copy_from_slice(&bytes[..take]);
            filled += take;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("Nitro Security Module ({})", self.device.display())
    }
}

/// The `GetRandom` request: a bare CBOR text string.
///
/// The NSM has two request shapes — a plain string for parameterless requests
/// like `GetRandom` and `DescribeNSM`, and a single-entry map for the rest.
fn encode_get_random() -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&"GetRandom", &mut out).expect("writing to a Vec cannot fail");
    out
}

/// Pull the bytes out of `{"GetRandom": {"random": <bytes>}}`.
fn decode_get_random(cbor: &[u8]) -> Result<Vec<u8>> {
    let value: ciborium::Value =
        ciborium::from_reader(cbor).context("decoding the NSM GetRandom response")?;

    // The NSM reports its own failures as {"Error": "..."} rather than by
    // failing the ioctl, so an unexpected shape deserves the real text.
    let outer = value
        .as_map()
        .with_context(|| format!("NSM response is not a map: {value:?}"))?;
    let (key, inner) = outer.first().context("NSM response map is empty")?;
    let key = key.as_text().unwrap_or("<non-text>");
    if key != "GetRandom" {
        bail!("NSM answered {key:?} instead of GetRandom: {inner:?}");
    }

    let inner = inner
        .as_map()
        .with_context(|| format!("GetRandom value is not a map: {inner:?}"))?;
    for (k, v) in inner {
        if k.as_text() == Some("random") {
            return v
                .as_bytes()
                .cloned()
                .context("GetRandom 'random' field is not a byte string");
        }
    }
    bail!("GetRandom response has no 'random' field")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Encodes a GetRandom response the way the device does, so the decoder is
    /// tested against the real wire shape rather than against itself.
    pub(crate) fn encode_response(bytes: &[u8]) -> Vec<u8> {
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("GetRandom".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("random".into()),
                ciborium::Value::Bytes(bytes.to_vec()),
            )]),
        )]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    /// A stand-in device: counts calls, and can be made to return nothing.
    #[derive(Debug)]
    pub(crate) struct FakeNsm {
        pub calls: AtomicU64,
        pub empty: AtomicBool,
        /// Bytes returned per call, mirroring the device's 256-byte chunk.
        pub chunk: usize,
    }

    impl FakeNsm {
        pub(crate) fn new() -> Self {
            FakeNsm {
                calls: AtomicU64::new(0),
                empty: AtomicBool::new(false),
                chunk: 256,
            }
        }
    }

    impl Nsm for FakeNsm {
        fn get_random(&self, buf: &mut [u8]) -> Result<()> {
            if self.empty.load(Ordering::SeqCst) {
                bail!("NSM GetRandom returned no bytes");
            }
            let mut filled = 0;
            while filled < buf.len() {
                let n = self.calls.fetch_add(1, Ordering::SeqCst);
                let take = self.chunk.min(buf.len() - filled);
                // Distinct per call, so a test can tell chunks apart.
                for (i, b) in buf[filled..filled + take].iter_mut().enumerate() {
                    *b = (n as u8)
                        .wrapping_mul(31)
                        .wrapping_add(i as u8)
                        .wrapping_add(1);
                }
                filled += take;
            }
            Ok(())
        }
        fn describe(&self) -> String {
            "fake NSM".into()
        }
    }

    #[test]
    fn the_request_is_a_bare_cbor_text_string() {
        // 0x69 = text string of length 9, then "GetRandom". This is the exact
        // shape the device's dispatcher looks for (CBOR_ROOT_TYPE_STRING).
        let encoded = encode_get_random();
        assert_eq!(encoded[0], 0x69);
        assert_eq!(&encoded[1..], b"GetRandom");
        assert_eq!(encoded.len(), 10);
    }

    #[test]
    fn a_response_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode_get_random(&encode_response(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn an_empty_random_field_decodes_to_nothing() {
        // Distinct from a malformed response: the caller turns this into a
        // hard error rather than looping.
        assert!(decode_get_random(&encode_response(&[])).unwrap().is_empty());
    }

    /// The NSM reports its own failures in-band, as a response rather than an
    /// ioctl error, so the decoder must surface them rather than say "not a
    /// map" and lose the reason.
    #[test]
    fn an_error_response_names_what_came_back() {
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("Error".into()),
            ciborium::Value::Text("InvalidOperation".into()),
        )]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&value, &mut cbor).unwrap();

        let err = format!("{:#}", decode_get_random(&cbor).unwrap_err());
        assert!(err.contains("Error"), "{err}");
        assert!(err.contains("InvalidOperation"), "{err}");
    }

    #[test]
    fn malformed_responses_are_rejected() {
        assert!(decode_get_random(&[]).is_err());
        assert!(decode_get_random(&[0xff, 0xff, 0xff]).is_err());

        // Right shape, wrong field.
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("GetRandom".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("entropy".into()),
                ciborium::Value::Bytes(vec![1, 2, 3]),
            )]),
        )]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&value, &mut cbor).unwrap();
        assert!(decode_get_random(&cbor).is_err());
    }

    /// The device returns 256 bytes per call, so a larger request must loop
    /// and stitch the chunks together rather than truncating.
    #[test]
    fn a_large_request_loops_over_several_calls() {
        let fake = FakeNsm::new();
        let mut buf = vec![0u8; 1000];
        fake.get_random(&mut buf).unwrap();

        assert_eq!(fake.calls.load(Ordering::SeqCst), 4, "1000 bytes / 256");
        assert!(buf.iter().any(|&b| b != 0));
        // Chunks differ from one another, so nothing was copied twice.
        assert_ne!(&buf[0..256], &buf[256..512]);
    }

    #[test]
    fn a_source_that_stops_producing_is_an_error_not_a_spin() {
        let fake = FakeNsm::new();
        fake.empty.store(true, Ordering::SeqCst);
        assert!(fake.get_random(&mut [0u8; 16]).is_err());
    }

    #[test]
    fn opening_a_missing_device_names_it() {
        let err = NsmDevice::open("/dev/definitely-not-nsm").unwrap_err();
        assert!(format!("{err:#}").contains("/dev/definitely-not-nsm"));
    }
}
