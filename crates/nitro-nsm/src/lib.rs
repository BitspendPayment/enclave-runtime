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

/// What goes into an attestation document, beyond what the NSM puts there
/// itself (the PCRs, the module id, the timestamp, the signing certificate).
///
/// All three fields are optional and all three are attacker-visible; none is a
/// secret. Their value is that the NSM copies them verbatim into a document it
/// signs, so a verifier who trusts the signature can trust that *this enclave*
/// asserted them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AttestationRequest {
    /// Application-chosen bytes. This is where a TLS certificate hash goes, so
    /// a client can tie the connection it holds to the code it attested.
    pub user_data: Option<Vec<u8>>,
    /// Caller-chosen bytes, echoed back. A verifier supplies a fresh one so a
    /// replayed document from an earlier boot cannot be passed off as current.
    pub nonce: Option<Vec<u8>>,
    /// A public key the enclave generated, for a verifier to encrypt to. Used
    /// by KMS `Decrypt` with `Recipient`; unused here.
    pub public_key: Option<Vec<u8>>,
}

impl AttestationRequest {
    /// An attestation binding `user_data`, with a caller-supplied `nonce`.
    pub fn with_user_data(user_data: Vec<u8>) -> Self {
        AttestationRequest {
            user_data: Some(user_data),
            ..Default::default()
        }
    }

    pub fn nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

/// What an NSM can do, so tests can substitute a fake.
pub trait Nsm: Send + Sync + fmt::Debug {
    /// Fill `buf` with random bytes.
    fn get_random(&self, buf: &mut [u8]) -> Result<()>;

    /// Ask for an attestation document.
    ///
    /// Returns the raw COSE_Sign1 bytes, unparsed and unverified. Parsing
    /// belongs to `nitro-attestation`, which a *client* needs without this
    /// crate's Linux device layer — the whole point of a document is that it
    /// is checked somewhere else.
    fn attest(&self, request: &AttestationRequest) -> Result<Vec<u8>>;

    /// Read a Platform Configuration Register.
    ///
    /// Returns the value and whether it is locked. PCRs 0–15 are locked by the
    /// hypervisor at boot — 0–2 hold the image measurements — and 16–31 are the
    /// enclave's to extend and then lock.
    fn describe_pcr(&self, index: u16) -> Result<Pcr>;

    /// Extend a PCR, returning its new value.
    ///
    /// `new = SHA384(old ‖ data)`, and it cannot be undone for the life of the
    /// enclave — which is the property that makes it useful. An enclave that
    /// extends a register has permanently committed to whatever it extended
    /// with.
    ///
    /// Fails with a read-only error on a locked register.
    fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<Vec<u8>>;

    /// Lock a PCR, so nothing extends it again for the life of the enclave.
    ///
    /// Not a formality. An attestation document carries **only locked**
    /// registers, so a register that was extended and never locked appears in
    /// no document, and no key policy or client can see it. Locking is also
    /// what makes the value final: until then, code running later could extend
    /// it again.
    ///
    /// Fails with a read-only error on a register that is already locked.
    fn lock_pcr(&self, index: u16) -> Result<()>;

    /// Short description for logs.
    fn describe(&self) -> String;
}

/// A Platform Configuration Register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcr {
    pub locked: bool,
    pub value: Vec<u8>,
}

/// The register the runtime measures its guest component into.
///
/// The first one the enclave may use: 0–15 are locked by the hypervisor at
/// boot. The runtime extends it exactly once, with `sha256(component)`, and
/// locks it before asking for any key, so it is reserved — anything else
/// extending it makes the runtime refuse to start rather than attest a value
/// that means something different.
///
/// `nitro_attestation::PCR_GUEST` is the verifier's copy of this number.
pub const PCR_GUEST: u16 = 16;

/// What a PCR holds before anything extends it: 48 zero bytes.
pub const PCR_ZERO: [u8; 48] = [0u8; 48];

/// The value a register would hold after extending `current` with `data`.
///
/// Lets the runtime check what the device reported without trusting anything
/// but the arithmetic.
pub fn pcr_extend(current: &[u8], data: &[u8]) -> Vec<u8> {
    use aws_lc_rs::digest;
    let mut ctx = digest::Context::new(&digest::SHA384);
    ctx.update(current);
    ctx.update(data);
    ctx.finish().as_ref().to_vec()
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

    fn attest(&self, request: &AttestationRequest) -> Result<Vec<u8>> {
        let response = self.request(&encode_attestation(request))?;
        decode_attestation(&response)
    }

    fn describe_pcr(&self, index: u16) -> Result<Pcr> {
        let response = self.request(&encode_pcr_request("DescribePCR", index, None))?;
        decode_describe_pcr(&response)
    }

    fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<Vec<u8>> {
        let response = self.request(&encode_pcr_request("ExtendPCR", index, Some(data)))?;
        decode_extend_pcr(&response)
    }

    fn lock_pcr(&self, index: u16) -> Result<()> {
        let response = self.request(&encode_pcr_request("LockPCR", index, None))?;
        decode_lock_pcr(&response)
    }

    fn describe(&self) -> String {
        format!("Nitro Security Module ({})", self.device.display())
    }
}

/// `{"DescribePCR": {"index": n}}`, `{"LockPCR": {"index": n}}`, or
/// `{"ExtendPCR": {"index": n, "data": …}}`.
fn encode_pcr_request(name: &str, index: u16, data: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![(
        ciborium::Value::Text("index".into()),
        ciborium::Value::Integer(index.into()),
    )];
    if let Some(data) = data {
        fields.push((
            ciborium::Value::Text("data".into()),
            ciborium::Value::Bytes(data.to_vec()),
        ));
    }
    let value = ciborium::Value::Map(vec![(
        ciborium::Value::Text(name.to_string()),
        ciborium::Value::Map(fields),
    )]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("writing to a Vec cannot fail");
    out
}

/// Pull the single value out of `{"<name>": {…}}`, surfacing `{"Error": …}`.
fn pcr_response_fields(cbor: &[u8], name: &str) -> Result<Vec<(ciborium::Value, ciborium::Value)>> {
    let value: ciborium::Value =
        ciborium::from_reader(cbor).with_context(|| format!("decoding the NSM {name} response"))?;
    let outer = value
        .as_map()
        .with_context(|| format!("NSM response is not a map: {value:?}"))?;
    let (key, inner) = outer.first().context("NSM response map is empty")?;
    let key = key.as_text().unwrap_or("<non-text>");
    if key != name {
        bail!("NSM answered {key:?} instead of {name}: {inner:?}");
    }
    inner
        .as_map()
        .cloned()
        .with_context(|| format!("{name} value is not a map: {inner:?}"))
}

fn field<'a>(
    fields: &'a [(ciborium::Value, ciborium::Value)],
    name: &str,
) -> Option<&'a ciborium::Value> {
    fields
        .iter()
        .find(|(k, _)| k.as_text() == Some(name))
        .map(|(_, v)| v)
}

fn decode_describe_pcr(cbor: &[u8]) -> Result<Pcr> {
    let fields = pcr_response_fields(cbor, "DescribePCR")?;
    Ok(Pcr {
        locked: field(&fields, "lock")
            .and_then(|v| match v {
                ciborium::Value::Bool(b) => Some(*b),
                _ => None,
            })
            .context("DescribePCR has no boolean 'lock'")?,
        value: field(&fields, "data")
            .and_then(|v| v.as_bytes())
            .cloned()
            .context("DescribePCR has no 'data'")?,
    })
}

fn decode_extend_pcr(cbor: &[u8]) -> Result<Vec<u8>> {
    let fields = pcr_response_fields(cbor, "ExtendPCR")?;
    field(&fields, "data")
        .and_then(|v| v.as_bytes())
        .cloned()
        .context("ExtendPCR has no 'data'")
}

/// A successful `LockPCR` is the bare text string `"LockPCR"`.
///
/// It has nothing to return, and the device encodes a variant with no fields as
/// its name alone — the shape of the `GetRandom` *request* — so this cannot
/// share [`pcr_response_fields`], which wants a map. A failure is still a map,
/// `{"Error": "ReadOnlyIndex"}`, and its text is what gets reported.
fn decode_lock_pcr(cbor: &[u8]) -> Result<()> {
    let value: ciborium::Value =
        ciborium::from_reader(cbor).context("decoding the NSM LockPCR response")?;
    match &value {
        ciborium::Value::Text(name) if name == "LockPCR" => Ok(()),
        ciborium::Value::Map(outer) => {
            let (key, inner) = outer.first().context("NSM response map is empty")?;
            let key = key.as_text().unwrap_or("<non-text>");
            bail!("NSM answered {key:?} instead of LockPCR: {inner:?}")
        }
        other => bail!("NSM answered {other:?} instead of LockPCR"),
    }
}

/// `{"Attestation": {"user_data": <bytes>, ...}}`, with absent fields
/// **omitted rather than set to null**.
///
/// This is not a style choice. The device parses each present key by pulling a
/// byte string out of it; a CBOR `null` is not a byte string, so a request
/// carrying `"nonce": null` is rejected outright — and the rejection arrives
/// as `InvalidOperation` for the whole request, naming nothing. Omitting the
/// key leaves the field at its default, which is null anyway.
fn encode_attestation(request: &AttestationRequest) -> Vec<u8> {
    let mut fields = Vec::new();
    let mut push = |name: &str, value: &Option<Vec<u8>>| {
        if let Some(bytes) = value {
            fields.push((
                ciborium::Value::Text(name.to_string()),
                ciborium::Value::Bytes(bytes.clone()),
            ));
        }
    };
    push("user_data", &request.user_data);
    push("nonce", &request.nonce);
    push("public_key", &request.public_key);

    let value = ciborium::Value::Map(vec![(
        ciborium::Value::Text("Attestation".into()),
        ciborium::Value::Map(fields),
    )]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("writing to a Vec cannot fail");
    out
}

/// Pull the COSE_Sign1 out of `{"Attestation": {"document": <bytes>}}`.
fn decode_attestation(cbor: &[u8]) -> Result<Vec<u8>> {
    let value: ciborium::Value =
        ciborium::from_reader(cbor).context("decoding the NSM Attestation response")?;

    let outer = value
        .as_map()
        .with_context(|| format!("NSM response is not a map: {value:?}"))?;
    let (key, inner) = outer.first().context("NSM response map is empty")?;
    let key = key.as_text().unwrap_or("<non-text>");
    if key != "Attestation" {
        // The device reports its own failures as {"Error": "..."} rather than
        // by failing the ioctl, so the real text matters here.
        bail!("NSM answered {key:?} instead of Attestation: {inner:?}");
    }

    let inner = inner
        .as_map()
        .with_context(|| format!("Attestation value is not a map: {inner:?}"))?;
    for (k, v) in inner {
        if k.as_text() == Some("document") {
            let doc = v
                .as_bytes()
                .cloned()
                .context("Attestation 'document' field is not a byte string")?;
            if doc.is_empty() {
                bail!("NSM returned an empty attestation document");
            }
            return Ok(doc);
        }
    }
    bail!("Attestation response has no 'document' field")
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

#[cfg(any(test, feature = "testing"))]
pub mod fake {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;

    /// Encodes a GetRandom response the way the device does, so the decoder is
    /// tested against the real wire shape rather than against itself.
    pub fn encode_response(bytes: &[u8]) -> Vec<u8> {
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

    /// Encodes an Attestation response the way the device does.
    pub fn encode_attestation_response(document: &[u8]) -> Vec<u8> {
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("Attestation".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("document".into()),
                ciborium::Value::Bytes(document.to_vec()),
            )]),
        )]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    /// A stand-in device: counts calls, and can be made to return nothing.
    #[derive(Debug)]
    pub struct FakeNsm {
        pub calls: AtomicU64,
        pub empty: AtomicBool,
        /// Bytes returned per call, mirroring the device's 256-byte chunk.
        pub chunk: usize,
        /// Document [`Nsm::attest`] hands back, and the last request that
        /// asked for one.
        ///
        /// It is *not* a signed COSE_Sign1 by default — this crate has no
        /// signing stack and should not grow one. Tests that need a verifiable
        /// document build it in `nitro-attestation` and set it here, so a fake
        /// can never accidentally satisfy a real verifier.
        pub attestation: Mutex<Vec<u8>>,
        pub last_attestation_request: Mutex<Option<AttestationRequest>>,
        /// Real registers, so extend arithmetic and the locked-register
        /// refusal can be exercised without a device.
        pub pcrs: Mutex<Vec<Pcr>>,
    }

    impl Default for FakeNsm {
        fn default() -> Self {
            FakeNsm {
                calls: AtomicU64::new(0),
                empty: AtomicBool::new(false),
                chunk: 256,
                attestation: Mutex::new(b"not-a-signed-attestation-document".to_vec()),
                last_attestation_request: Mutex::new(None),
                // 0–15 locked, as the hypervisor leaves them, with 0–2 carrying
                // non-zero image measurements; 16 upwards free and zeroed.
                pcrs: Mutex::new(
                    (0..32)
                        .map(|i| Pcr {
                            locked: i < 16,
                            value: if i < 3 {
                                vec![0x10 + i as u8; 48]
                            } else {
                                PCR_ZERO.to_vec()
                            },
                        })
                        .collect(),
                ),
            }
        }
    }

    impl FakeNsm {
        pub fn new() -> Self {
            Self::default()
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
        fn attest(&self, request: &AttestationRequest) -> Result<Vec<u8>> {
            if self.empty.load(Ordering::SeqCst) {
                bail!("NSM returned an empty attestation document");
            }
            *self.last_attestation_request.lock().unwrap() = Some(request.clone());
            Ok(self.attestation.lock().unwrap().clone())
        }

        fn describe_pcr(&self, index: u16) -> Result<Pcr> {
            self.pcrs
                .lock()
                .unwrap()
                .get(index as usize)
                .cloned()
                .context("no such PCR")
        }

        fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<Vec<u8>> {
            let mut pcrs = self.pcrs.lock().unwrap();
            let pcr = pcrs.get_mut(index as usize).context("no such PCR")?;
            if pcr.locked {
                bail!("PCR {index} is read-only");
            }
            pcr.value = pcr_extend(&pcr.value, data);
            Ok(pcr.value.clone())
        }

        fn lock_pcr(&self, index: u16) -> Result<()> {
            let mut pcrs = self.pcrs.lock().unwrap();
            let pcr = pcrs.get_mut(index as usize).context("no such PCR")?;
            if pcr.locked {
                bail!("PCR {index} is read-only");
            }
            pcr.locked = true;
            Ok(())
        }

        fn describe(&self) -> String {
            "fake NSM".into()
        }
    }

    #[cfg(test)]
    fn cbor(value: ciborium::Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    #[test]
    fn extending_is_the_documented_arithmetic() {
        let nsm = FakeNsm::new();
        let after = nsm.extend_pcr(PCR_GUEST, b"a guest").unwrap();
        assert_eq!(after, pcr_extend(&PCR_ZERO, b"a guest"));
        assert_eq!(nsm.describe_pcr(PCR_GUEST).unwrap().value, after);
    }

    /// Extension accumulates. Checking `extend(0, x)` is checking that the
    /// register was extended exactly once, with `x` — twice, or with anything
    /// else first, does not match.
    #[test]
    fn extending_twice_does_not_look_like_extending_once() {
        let nsm = FakeNsm::new();
        nsm.extend_pcr(PCR_GUEST, b"a").unwrap();
        let twice = nsm.extend_pcr(PCR_GUEST, b"b").unwrap();
        assert_ne!(twice, pcr_extend(&PCR_ZERO, b"b"));
    }

    /// The fake has to lock what the hypervisor locks, or a test could extend a
    /// register no real enclave can touch and pass for the wrong reason.
    #[test]
    fn the_registers_the_hypervisor_locks_cannot_be_extended() {
        let nsm = FakeNsm::new();
        for index in 0..16 {
            assert!(nsm.describe_pcr(index).unwrap().locked, "PCR{index}");
            assert!(nsm.extend_pcr(index, b"anything").is_err(), "PCR{index}");
        }
        assert!(!nsm.describe_pcr(PCR_GUEST).unwrap().locked);
    }

    #[test]
    fn a_locked_register_can_be_neither_extended_nor_locked_again() {
        let nsm = FakeNsm::new();
        let value = nsm.extend_pcr(PCR_GUEST, b"measured").unwrap();
        nsm.lock_pcr(PCR_GUEST).unwrap();

        let pcr = nsm.describe_pcr(PCR_GUEST).unwrap();
        assert!(pcr.locked);
        assert_eq!(pcr.value, value, "locking must not change the value");
        assert!(nsm.extend_pcr(PCR_GUEST, b"more").is_err());
        assert!(nsm.lock_pcr(PCR_GUEST).is_err());
        assert!(nsm.lock_pcr(32).is_err(), "there is no PCR32");
    }

    /// `{"LockPCR": {"index": 16}}` — a map like the other register requests,
    /// and with no `data`, which a lock does not take.
    #[test]
    fn a_lock_request_names_the_register_and_nothing_else() {
        let value: ciborium::Value =
            ciborium::from_reader(&encode_pcr_request("LockPCR", PCR_GUEST, None)[..]).unwrap();
        let outer = value.as_map().unwrap();
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].0.as_text(), Some("LockPCR"));
        let fields = outer[0].1.as_map().unwrap();
        assert_eq!(fields.len(), 1, "a lock carries only the index: {fields:?}");
        assert_eq!(fields[0].0.as_text(), Some("index"));
        assert_eq!(
            fields[0].1.as_integer(),
            Some(ciborium::value::Integer::from(PCR_GUEST))
        );
    }

    #[test]
    fn a_bare_lock_response_is_success() {
        assert!(decode_lock_pcr(&cbor(ciborium::Value::Text("LockPCR".into()))).is_ok());
    }

    /// Locking an already-locked register is the failure worth reading: it
    /// means something got to the register first.
    #[test]
    fn an_error_response_to_a_lock_names_what_came_back() {
        let err = decode_lock_pcr(&cbor(ciborium::Value::Map(vec![(
            ciborium::Value::Text("Error".into()),
            ciborium::Value::Text("ReadOnlyIndex".into()),
        )])))
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("ReadOnlyIndex"), "{text}");
    }

    #[test]
    fn an_answer_to_some_other_request_is_not_a_lock() {
        assert!(decode_lock_pcr(&cbor(ciborium::Value::Text("LockPCRs".into()))).is_err());
        assert!(decode_lock_pcr(&[]).is_err());
    }

    /// The device rejects a `null` field outright — `fill_attestation_property`
    /// wants a byte string — and answers `InvalidOperation` for the whole
    /// request without naming which field was at fault. Omitting absent fields
    /// is what keeps that from happening, so it is worth a test.
    #[test]
    fn absent_attestation_fields_are_omitted_not_nulled() {
        let encoded = encode_attestation(&AttestationRequest::with_user_data(vec![1, 2, 3]));
        let value: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
        let inner = value.as_map().unwrap()[0].1.as_map().unwrap();

        let names: Vec<&str> = inner.iter().filter_map(|(k, _)| k.as_text()).collect();
        assert_eq!(names, ["user_data"], "only the supplied field may appear");
        assert!(
            !inner
                .iter()
                .any(|(_, v)| matches!(v, ciborium::Value::Null)),
            "a null field makes the device reject the whole request"
        );
    }

    #[test]
    fn every_supplied_attestation_field_is_carried() {
        let request = AttestationRequest {
            user_data: Some(vec![0xaa]),
            nonce: Some(vec![0xbb]),
            public_key: Some(vec![0xcc]),
        };
        let value: ciborium::Value =
            ciborium::from_reader(&encode_attestation(&request)[..]).unwrap();
        let outer = value.as_map().unwrap();
        assert_eq!(outer[0].0.as_text(), Some("Attestation"));

        let inner = outer[0].1.as_map().unwrap();
        let get = |name: &str| {
            inner
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v.as_bytes().unwrap().clone())
        };
        assert_eq!(get("user_data"), Some(vec![0xaa]));
        assert_eq!(get("nonce"), Some(vec![0xbb]));
        assert_eq!(get("public_key"), Some(vec![0xcc]));
    }

    #[test]
    fn an_attestation_document_round_trips() {
        let doc = b"\x84pretend COSE_Sign1".to_vec();
        assert_eq!(
            decode_attestation(&encode_attestation_response(&doc)).unwrap(),
            doc
        );
    }

    /// An empty document is a failure, not an empty success: everything
    /// downstream would otherwise try to parse zero bytes and report a
    /// confusing parse error instead of "the device gave us nothing".
    #[test]
    fn an_empty_attestation_document_is_an_error() {
        let err = decode_attestation(&encode_attestation_response(&[])).unwrap_err();
        assert!(format!("{err:#}").contains("empty"), "{err:#}");
    }

    #[test]
    fn an_error_response_to_attestation_names_what_came_back() {
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("Error".into()),
            ciborium::Value::Text("InvalidOperation".into()),
        )]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&value, &mut cbor).unwrap();

        let err = decode_attestation(&cbor).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("Error"), "{text}");
        assert!(text.contains("InvalidOperation"), "{text}");
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
