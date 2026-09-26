//! An NSM that signs what the emulator will not.
//!
//! QEMU's `nitro-enclave` machine implements the NSM protocol but not the
//! signing. Its source says so — *"we don't actually sign the data, so we use
//! -1 as the 'alg' value"* — and -1 is not a COSE algorithm identifier. So the
//! documents it produces carry genuine contents, the real PCR0 of the image
//! that booted and the PCR16 the runtime measured its guest into, inside an
//! envelope no client can check. Every client run against the emulator has had
//! to pass `--unsigned-emulator`, which skips the signature, the certificate
//! chain and the validity windows — the part of a client most worth exercising
//! before it meets hardware, and the only part the emulator could never reach.
//!
//! This wraps the device instead of replacing it. [`CosigningNsm::attest`] asks
//! the emulator for a document, parses it, and re-signs *that same payload*
//! with a chain minted at boot. Contents stay the device's answers; only the
//! envelope becomes real. Nothing else is intercepted — entropy and every PCR
//! operation go straight through — so a client comparing PCR0 against what
//! `nix build` printed is still comparing against the hardware's own report.
//!
//! # What this does not do
//!
//! It does not make a document mean anything. The key is minted inside the same
//! image whoever runs it controls, so a document proves only that its producer
//! had that key, which is everyone who can boot the image. That is the whole
//! difference from real Nitro, where the key lives in hardware and the chain
//! goes back to a root AWS publishes.
//!
//! Two things keep that from being mistaken for the real property. The root is
//! fresh every boot, so there is no long-lived value to paste into an app and
//! forget; and a client still has to set `allow_untrusted_root` to accept a
//! non-AWS root at all, which [`nitro_attestation::verify`] reports back as
//! [`Trust::SelfSigned`](nitro_attestation::Trust::SelfSigned) rather than
//! letting it pass as the real thing.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

/// How long the minted chain is good for.
///
/// A real Nitro leaf is valid for about three hours, which costs AWS nothing
/// because it mints another whenever an enclave asks. This chain is minted once
/// at boot and never again, so its window has to outlast however long the
/// enclave runs — and a development enclave stays up for as long as somebody is
/// working against it. Long enough for that, short enough that a root scraped
/// out of a log is useless next quarter.
const CHAIN_VALIDITY: Duration = Duration::from_secs(30 * 24 * 3600);

/// Backdating, for the same reason certificate issuers backdate: the enclave's
/// clock and the verifying client's need not agree to the second, and a leaf
/// that is not valid *yet* fails exactly like one that was never valid.
const CHAIN_BACKDATE: Duration = Duration::from_secs(3600);

/// An [`Nsm`](nitro_nsm::Nsm) that delegates everything and re-signs documents.
#[derive(Debug)]
pub struct CosigningNsm {
    inner: Arc<dyn nitro_nsm::Nsm>,
    chain: nitro_attestation::testing::TestChain,
}

impl CosigningNsm {
    /// Wrap a device, minting the chain its documents will be signed with.
    pub fn wrap(inner: Arc<dyn nitro_nsm::Nsm>) -> Result<Self> {
        let now = SystemTime::now();
        let chain = nitro_attestation::testing::TestChain::with_validity(
            now - CHAIN_BACKDATE,
            now + CHAIN_VALIDITY,
        )
        .context("minting the attestation signing chain")?;
        Ok(CosigningNsm { inner, chain })
    }

    /// DER of the root a client must pin to verify what this signs.
    ///
    /// Not a secret and not a credential: it is the public half, and publishing
    /// it is the only way anything can check a document. The *private* key
    /// never leaves this process, which is not a security property here — see
    /// the module documentation — but does mean the root is all a client needs.
    pub fn trust_root(&self) -> Vec<u8> {
        self.chain.root_der().to_vec()
    }
}

impl nitro_nsm::Nsm for CosigningNsm {
    fn get_random(&self, buf: &mut [u8]) -> Result<()> {
        self.inner.get_random(buf)
    }

    /// Ask the device, then re-sign what it said.
    ///
    /// The payload is the device's, field for field — module id, timestamp,
    /// every locked register, and the `user_data`/`nonce`/`public_key` this
    /// request asked it to bind. Only `certificate` and `cabundle` are
    /// replaced, and they have to be: the signature is made with the leaf's
    /// key, so a document carrying the device's placeholder certificate would
    /// name a key that did not sign it and fail verification for a reason that
    /// looks nothing like the cause.
    fn attest(&self, request: &nitro_nsm::AttestationRequest) -> Result<Vec<u8>> {
        let unsigned = self.inner.attest(request)?;
        let mut document = nitro_attestation::parse(&unsigned)
            .context("the device produced a document this build cannot parse")?;
        document.certificate = self.chain.leaf.clone();
        document.cabundle = self.chain.cabundle.clone();
        self.chain.document_from(document)
    }

    fn describe_pcr(&self, index: u16) -> Result<nitro_nsm::Pcr> {
        self.inner.describe_pcr(index)
    }

    fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<Vec<u8>> {
        self.inner.extend_pcr(index, data)
    }

    fn lock_pcr(&self, index: u16) -> Result<()> {
        self.inner.lock_pcr(index)
    }

    fn describe(&self) -> String {
        format!("{} (documents re-signed at boot)", self.inner.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nitro_nsm::Nsm as _;
    use std::collections::BTreeMap;

    /// A device shaped like QEMU's: a real payload in an envelope with `alg =
    /// -1` and no signature.
    ///
    /// Written out rather than borrowed from `nitro_nsm::fake`, whose `attest`
    /// deliberately returns a fixed byte string that is not a document at all.
    /// What is under test here is what happens *to a document*, so the stand-in
    /// has to produce one.
    #[derive(Debug)]
    struct EmulatorNsm {
        inner: nitro_nsm::fake::FakeNsm,
    }

    impl EmulatorNsm {
        fn new() -> Self {
            EmulatorNsm {
                inner: nitro_nsm::fake::FakeNsm::new(),
            }
        }
    }

    impl nitro_nsm::Nsm for EmulatorNsm {
        fn get_random(&self, buf: &mut [u8]) -> Result<()> {
            self.inner.get_random(buf)
        }
        fn describe_pcr(&self, index: u16) -> Result<nitro_nsm::Pcr> {
            self.inner.describe_pcr(index)
        }
        fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<Vec<u8>> {
            self.inner.extend_pcr(index, data)
        }
        fn lock_pcr(&self, index: u16) -> Result<()> {
            self.inner.lock_pcr(index)
        }
        fn describe(&self) -> String {
            "emulated NSM".to_string()
        }

        fn attest(&self, request: &nitro_nsm::AttestationRequest) -> Result<Vec<u8>> {
            // Locked registers only, as a real document lists.
            let mut pcrs = BTreeMap::new();
            for index in 0..32u16 {
                let pcr = self.inner.describe_pcr(index)?;
                if pcr.locked {
                    pcrs.insert(u32::from(index), pcr.value);
                }
            }
            let payload = nitro_attestation::testing::encode_payload(
                &nitro_attestation::AttestationDocument {
                    module_id: "i-0emulated000000000".to_string(),
                    timestamp_ms: 1_700_000_000_000,
                    digest: "SHA384".to_string(),
                    pcrs,
                    // No certificate and no chain, which is consistent of it:
                    // it has no key to name one for.
                    certificate: Vec::new(),
                    cabundle: Vec::new(),
                    public_key: request.public_key.clone(),
                    user_data: request.user_data.clone(),
                    nonce: request.nonce.clone(),
                },
            );
            // A COSE_Sign1 by shape only: protected headers say `alg = -1`
            // (`a1 01 20`) and the signature is empty.
            let mut out = Vec::new();
            ciborium::into_writer(
                &ciborium::Value::Array(vec![
                    ciborium::Value::Bytes(vec![0xa1, 0x01, 0x20]),
                    ciborium::Value::Map(vec![]),
                    ciborium::Value::Bytes(payload),
                    ciborium::Value::Bytes(Vec::new()),
                ]),
                &mut out,
            )
            .unwrap();
            Ok(out)
        }
    }

    fn wrapped() -> (Arc<EmulatorNsm>, CosigningNsm) {
        let device = Arc::new(EmulatorNsm::new());
        let cosigning = CosigningNsm::wrap(device.clone()).expect("minting the chain");
        (device, cosigning)
    }

    /// The strict check, which is the whole reason for co-signing.
    ///
    /// `allow_untrusted_root` stays **false**: with it on, `verify` accepts
    /// whatever root the document arrived with and reports
    /// [`Trust::SelfSigned`](nitro_attestation::Trust::SelfSigned), so a
    /// "pinned" root pins nothing. Off, the presented root must equal this one
    /// — the same comparison a client makes against AWS's.
    fn options(trust_root: Vec<u8>) -> nitro_attestation::VerifyOptions {
        nitro_attestation::VerifyOptions {
            trust_root,
            now: SystemTime::now(),
            allow_untrusted_root: false,
        }
    }

    /// The whole point. Both halves are asserted together because either alone
    /// could pass while the feature does nothing: a verifier that accepted the
    /// emulator's own document would make the second half meaningless.
    #[test]
    fn a_document_the_emulator_would_not_sign_verifies_once_co_signed() {
        let (device, cosigning) = wrapped();
        let request = nitro_nsm::AttestationRequest::with_user_data(b"cert-hash".to_vec());

        let bare = device.attest(&request).unwrap();
        nitro_attestation::verify(&bare, &options(cosigning.trust_root()))
            .expect_err("the emulator's unsigned document must not verify");

        let signed = cosigning.attest(&request).unwrap();
        let verified = nitro_attestation::verify(&signed, &options(cosigning.trust_root()))
            .expect("the co-signed document must verify");
        assert_eq!(
            verified.document.user_data.as_deref(),
            Some(&b"cert-hash"[..])
        );
    }

    /// Re-signing must not become re-authoring. The registers a client pins are
    /// the device's answers, so they have to survive the round trip byte for
    /// byte — including one the runtime extended and locked, which is how PCR16
    /// reaches a document at all.
    #[test]
    fn the_co_signed_document_carries_the_devices_own_registers() {
        let (device, cosigning) = wrapped();
        let pcr16 = device.extend_pcr(16, b"a guest component").unwrap();
        device.lock_pcr(16).unwrap();

        let signed = cosigning
            .attest(&nitro_nsm::AttestationRequest::default())
            .unwrap();
        let verified =
            nitro_attestation::verify(&signed, &options(cosigning.trust_root())).unwrap();

        assert_eq!(
            verified.document.pcr(0),
            Some(&device.describe_pcr(0).unwrap().value[..]),
            "PCR0 must be the device's measurement, not one this wrapper invented"
        );
        assert_eq!(verified.document.pcr(16), Some(&pcr16[..]));
        assert_eq!(verified.document.module_id, "i-0emulated000000000");
    }

    /// A nonce is what stops a document from an earlier boot being passed off
    /// as current, so it has to be the *caller's* bytes that come back.
    #[test]
    fn the_nonce_the_caller_asked_to_bind_comes_back_unchanged() {
        let (_device, cosigning) = wrapped();
        let request = nitro_nsm::AttestationRequest::with_user_data(b"cert-hash".to_vec())
            .nonce(b"a fresh nonce".to_vec());

        let signed = cosigning.attest(&request).unwrap();
        let verified =
            nitro_attestation::verify(&signed, &options(cosigning.trust_root())).unwrap();
        assert_eq!(
            verified.document.nonce.as_deref(),
            Some(&b"a fresh nonce"[..])
        );
    }

    /// Otherwise the chain check is decorative: a client that would accept a
    /// document signed by anybody has gained nothing over `--unsigned-emulator`.
    #[test]
    fn a_client_pinning_a_different_root_refuses_it() {
        let (_device, cosigning) = wrapped();
        let stranger = nitro_attestation::testing::TestChain::new().unwrap();

        let signed = cosigning
            .attest(&nitro_nsm::AttestationRequest::default())
            .unwrap();
        nitro_attestation::verify(&signed, &options(stranger.root_der().to_vec()))
            .expect_err("a document must not verify against a root that did not issue it");
    }

    /// The claim worth making about the whole feature: pinning the minted root
    /// is the *same* check a client runs against AWS, reported the same way —
    /// so the code path under development is the production one, not a relaxed
    /// variant of it. And a client that pins nothing else still refuses this:
    /// the default options carry the AWS root, and they must say no.
    #[test]
    fn pinning_the_minted_root_is_the_check_a_client_makes_against_aws() {
        let (_device, cosigning) = wrapped();
        let signed = cosigning
            .attest(&nitro_nsm::AttestationRequest::default())
            .unwrap();

        let verified =
            nitro_attestation::verify(&signed, &options(cosigning.trust_root())).unwrap();
        assert_eq!(
            verified.trust,
            nitro_attestation::Trust::ChainVerified,
            "a pinned root that matches must verify as a chain, not as self-signed"
        );

        nitro_attestation::verify(&signed, &nitro_attestation::VerifyOptions::default())
            .expect_err("nothing minted here may pass against the AWS root");
    }

    /// Everything except `attest` is the device's. Stated as a test because the
    /// tempting next change — caching PCRs in the wrapper — would break the
    /// property that a client comparing PCR0 against `nix build` is comparing
    /// against the hardware's own report.
    #[test]
    fn nothing_but_the_signature_is_intercepted() {
        let (device, cosigning) = wrapped();

        assert_eq!(
            cosigning.extend_pcr(16, b"x").unwrap(),
            device.describe_pcr(16).unwrap().value,
            "an extend through the wrapper must land on the device"
        );
        cosigning.lock_pcr(16).unwrap();
        assert!(device.describe_pcr(16).unwrap().locked);
        cosigning
            .extend_pcr(16, b"y")
            .expect_err("the device's own refusal must come through");

        let mut buf = [0u8; 8];
        cosigning.get_random(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 8], "entropy must come from the device");
        assert!(cosigning.describe().contains("emulated NSM"));
    }
}
