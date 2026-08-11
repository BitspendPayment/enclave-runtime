//! Parsing and verifying AWS Nitro Enclaves attestation documents.
//!
//! An attestation document is a COSE_Sign1 signed by a key the Nitro
//! hypervisor holds, carrying the enclave's PCR measurements and up to three
//! caller-supplied fields. Verifying one answers a question a TLS handshake
//! cannot: *is the thing I am talking to an enclave running the code I
//! expect?*
//!
//! ```text
//!   COSE_Sign1
//!   ├── protected   {1: -35}          ES384
//!   ├── payload     CBOR map
//!   │   ├── pcrs        0..15         what code is running
//!   │   ├── certificate leaf DER      signs this document
//!   │   ├── cabundle    [DER, …]      root first, chains to AWS
//!   │   ├── user_data   opt bytes     ← the TLS certificate hash
//!   │   └── nonce       opt bytes     ← the verifier's freshness challenge
//!   └── signature   r‖s, 96 bytes
//! ```
//!
//! This crate deliberately does **not** depend on `nitro-nsm`. Verification
//! happens on the client, which has no `/dev/nsm`, is often not Linux at all,
//! and should not need a device layer to check a signature.
//!
//! ## What [`verify`] checks, and what it does not
//!
//! Checks: the COSE signature against the leaf certificate's key; the leaf
//! chains to the trust root through `cabundle`, each link's signature
//! verified; every certificate's validity window against a supplied time;
//! that intermediates are CAs; and that the root is the one pinned.
//!
//! Does not check: revocation, name constraints, or extended key usage. The
//! chain is linear and its root is pinned by the caller, so path *building* —
//! where most X.509 complexity lives — does not arise. Revocation would need a
//! network fetch from inside a verifier that may have no network.
//!
//! Confirming the document is authentic is only half the job. It says nothing
//! about *what* was attested: a valid document from an enclave running
//! something else is still valid. [`Verified::expect`] is where the caller
//! states what it required — PCR0, the nonce it sent, the certificate it is
//! talking to — and those comparisons are the point.

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use aws_lc_rs::{digest, signature};
use x509_parser::prelude::*;

/// The AWS Nitro Enclaves root, `CN = aws.nitro-enclaves`, valid to 2049.
///
/// From <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>,
/// whose published SHA-256 is
/// `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`. The
/// certificate's own SHA-256 fingerprint is asserted in the tests below, so a
/// careless edit to this file fails the build rather than silently moving the
/// trust anchor.
pub const AWS_NITRO_ROOT_G1_PEM: &str = include_str!("aws-nitro-root-g1.pem");

/// A parsed attestation document payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationDocument {
    pub module_id: String,
    /// Milliseconds since the Unix epoch, as the *enclave* saw it.
    pub timestamp_ms: u64,
    pub digest: String,
    /// Platform Configuration Registers. PCR0 measures the enclave image.
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    /// DER of the certificate whose key signed this document.
    pub certificate: Vec<u8>,
    /// DER certificates from the root down to the leaf's issuer.
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl AttestationDocument {
    pub fn pcr(&self, index: u32) -> Option<&[u8]> {
        self.pcrs.get(&index).map(|v| v.as_slice())
    }

    /// PCR0 as lowercase hex — the value a KMS key policy pins.
    pub fn pcr0_hex(&self) -> Option<String> {
        self.pcr(0).map(hex::encode)
    }

    pub fn timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.timestamp_ms)
    }
}

/// How much of the document was checked, so a caller cannot mistake one for
/// the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Signature and certificate chain verified against the pinned root.
    ChainVerified,
    /// Signature verified against the document's own leaf certificate, but the
    /// chain was checked against a caller-supplied root that is not AWS's — so
    /// the document is cryptographically self-consistent while proving nothing
    /// about AWS hardware.
    SelfSigned,
    /// Nothing was verified: the contents were read and no signature was
    /// checked, because there was none to check.
    ///
    /// QEMU's emulated NSM produces documents in this state — it does not sign
    /// them, and uses an invalid COSE algorithm identifier to say so. A
    /// document at this level is worth exactly what the connection it arrived
    /// over is worth.
    Unsigned,
}

/// A document that passed [`verify`].
#[derive(Debug, Clone)]
pub struct Verified {
    pub document: AttestationDocument,
    pub trust: Trust,
}

/// What the caller requires the document to say.
///
/// Every field is optional and every field left `None` is a check *not*
/// performed. A verifier that only calls [`verify`] has established that some
/// enclave signed something; these are what turn that into a statement about
/// this enclave and this connection.
#[derive(Debug, Default, Clone)]
pub struct Expectations {
    /// Required PCR0, hex or raw. Pins the enclave image.
    pub pcr0: Option<Vec<u8>>,
    /// The nonce the verifier sent. Rejects a replayed document.
    pub nonce: Option<Vec<u8>>,
    /// Required `user_data`, byte for byte.
    pub user_data: Option<Vec<u8>>,
    /// Maximum age, against the document's own timestamp.
    pub max_age: Option<Duration>,
}

impl Verified {
    /// Apply [`Expectations`], failing on the first that does not hold.
    pub fn expect(&self, expectations: &Expectations, now: SystemTime) -> Result<()> {
        if let Some(want) = &expectations.pcr0 {
            let got = self
                .document
                .pcr(0)
                .context("document carries no PCR0 to compare")?;
            if got != want.as_slice() {
                bail!(
                    "PCR0 mismatch: enclave is running {}, expected {}",
                    hex::encode(got),
                    hex::encode(want)
                );
            }
        }

        if let Some(want) = &expectations.nonce {
            match &self.document.nonce {
                // Without this the document could be one captured earlier from
                // the same enclave, which says nothing about now.
                None => bail!("document carries no nonce, so it cannot be shown to be fresh"),
                Some(got) if got != want => bail!(
                    "nonce mismatch: document echoes {}, sent {}",
                    hex::encode(got),
                    hex::encode(want)
                ),
                Some(_) => {}
            }
        }

        if let Some(want) = &expectations.user_data {
            match &self.document.user_data {
                None => bail!("document carries no user_data"),
                Some(got) if got != want => bail!(
                    "user_data mismatch: document binds {}, expected {}",
                    hex::encode(got),
                    hex::encode(want)
                ),
                Some(_) => {}
            }
        }

        if let Some(max_age) = expectations.max_age {
            let stamped = self.document.timestamp();
            let age = now.duration_since(stamped).unwrap_or_else(|e| e.duration());
            if age > max_age {
                bail!("document is {age:?} old, over the {max_age:?} limit");
            }
        }

        Ok(())
    }
}

/// Options for [`verify`].
pub struct VerifyOptions {
    /// PEM or DER of the trust anchor. Defaults to the AWS Nitro root.
    pub trust_root: Vec<u8>,
    /// Time to judge certificate validity windows against.
    pub now: SystemTime,
    /// Treat a non-AWS root as acceptable, reporting [`Trust::SelfSigned`].
    ///
    /// Exists for the QEMU harness, which has no AWS signing key. It must be
    /// set deliberately: a verifier that silently accepted whatever root the
    /// document arrived with would be checking nothing at all.
    pub allow_untrusted_root: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            trust_root: AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(),
            now: SystemTime::now(),
            allow_untrusted_root: false,
        }
    }
}

/// Parse a COSE_Sign1 attestation document **without verifying anything**.
///
/// For inspection only. Nothing a document says is worth acting on until
/// [`verify`] has run: the payload is attacker-controlled until its signature
/// is checked.
///
/// Deliberately more tolerant than [`verify`], because one producer needs it:
/// QEMU's emulated NSM does not sign at all. Its source says so —
/// *"we don't actually sign the data, so we use -1 as the 'alg' value"* — and
/// -1 is not a COSE algorithm identifier, so a strict COSE parser rejects the
/// document before reaching the payload. Reading the payload anyway is what
/// lets the emulator harness check the *contents* the runtime asked for, while
/// [`verify`] keeps refusing it.
pub fn parse(cose: &[u8]) -> Result<AttestationDocument> {
    if let Ok(sign1) = parse_cose(cose) {
        let payload = sign1
            .payload
            .as_ref()
            .context("COSE_Sign1 has no payload")?;
        return decode_payload(payload);
    }
    decode_payload(&payload_from_raw_cose(cose)?)
}

/// Pull the payload out of a COSE_Sign1 without interpreting its headers.
///
/// The structure is a 4-element array — protected, unprotected, payload,
/// signature — and the payload is element 2 whatever the headers claim.
fn payload_from_raw_cose(cose: &[u8]) -> Result<Vec<u8>> {
    let value: ciborium::Value = ciborium::from_reader(cose).context("document is not CBOR")?;
    // Tagged (18) or bare.
    let value = match value {
        ciborium::Value::Tag(_, inner) => *inner,
        other => other,
    };
    let array = value.as_array().context("COSE_Sign1 is not a CBOR array")?;
    if array.len() != 4 {
        bail!("COSE_Sign1 has {} elements, expected 4", array.len());
    }
    array[2]
        .as_bytes()
        .cloned()
        .context("COSE_Sign1 payload is not a byte string")
}

/// Parse and verify a COSE_Sign1 attestation document.
pub fn verify(cose: &[u8], options: &VerifyOptions) -> Result<Verified> {
    let sign1 = parse_cose(cose)?;
    let payload = sign1
        .payload
        .as_ref()
        .context("COSE_Sign1 has no payload")?;
    let document = decode_payload(payload)?;

    // Order matters: establish that the leaf is trusted *before* trusting the
    // key it carries to check the document's own signature. The other way
    // round, a forged document could nominate its own signing certificate.
    let trust = verify_chain(&document, options)?;

    let leaf = X509Certificate::from_der(&document.certificate)
        .context("parsing the leaf certificate")?
        .1;
    let key = leaf.public_key().subject_public_key.data.as_ref();

    // COSE signatures are fixed-width r‖s, not the ASN.1 SEQUENCE that X.509
    // uses. Passing the wrong one here fails on every valid document, which is
    // an unhelpfully quiet way to be wrong.
    sign1
        .verify_signature(b"", |sig, data| {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, key)
                .verify(data, sig)
        })
        .map_err(|_| anyhow::anyhow!("attestation document signature is not valid"))?;

    Ok(Verified { document, trust })
}

fn parse_cose(cose: &[u8]) -> Result<coset::CoseSign1> {
    use coset::{CborSerializable, TaggedCborSerializable};
    // Documents appear both tagged (18) and bare depending on the producer.
    coset::CoseSign1::from_tagged_slice(cose)
        .or_else(|_| coset::CoseSign1::from_slice(cose))
        .map_err(|e| anyhow::anyhow!("parsing COSE_Sign1: {e:?}"))
}

fn decode_payload(payload: &[u8]) -> Result<AttestationDocument> {
    let value: ciborium::Value =
        ciborium::from_reader(payload).context("decoding the attestation payload")?;
    let map = value
        .as_map()
        .context("attestation payload is not a CBOR map")?;

    let get = |name: &str| -> Option<&ciborium::Value> {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .map(|(_, v)| v)
    };

    let text = |v: Option<&ciborium::Value>, name: &str| -> Result<String> {
        v.and_then(|v| v.as_text())
            .map(str::to_string)
            .with_context(|| format!("attestation payload field {name:?} is missing or not text"))
    };
    let bytes = |v: Option<&ciborium::Value>, name: &str| -> Result<Vec<u8>> {
        v.and_then(|v| v.as_bytes())
            .cloned()
            .with_context(|| format!("attestation payload field {name:?} is missing or not bytes"))
    };
    let optional_bytes =
        |v: Option<&ciborium::Value>| -> Option<Vec<u8>> { v.and_then(|v| v.as_bytes()).cloned() };

    let module_id = text(get("module_id"), "module_id")?;
    let digest = text(get("digest"), "digest")?;
    let timestamp_ms = get("timestamp")
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .context("attestation payload field \"timestamp\" is missing or not an integer")?;

    let mut pcrs = BTreeMap::new();
    let pcr_map = get("pcrs")
        .and_then(|v| v.as_map())
        .context("attestation payload field \"pcrs\" is missing or not a map")?;
    for (k, v) in pcr_map {
        let index = k
            .as_integer()
            .and_then(|i| u32::try_from(i).ok())
            .context("PCR index is not an integer")?;
        let value = v.as_bytes().cloned().context("PCR value is not bytes")?;
        pcrs.insert(index, value);
    }

    let certificate = bytes(get("certificate"), "certificate")?;
    let cabundle = get("cabundle")
        .and_then(|v| v.as_array())
        .context("attestation payload field \"cabundle\" is missing or not an array")?
        .iter()
        .map(|v| {
            v.as_bytes()
                .cloned()
                .context("cabundle entry is not a byte string")
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(AttestationDocument {
        module_id,
        timestamp_ms,
        digest,
        pcrs,
        certificate,
        cabundle,
        public_key: optional_bytes(get("public_key")),
        user_data: optional_bytes(get("user_data")),
        nonce: optional_bytes(get("nonce")),
    })
}

/// Verify `cabundle` chains from the pinned root down to the leaf.
///
/// `cabundle` is ordered root first. The chain to check is therefore
/// `cabundle` in order, then the leaf.
fn verify_chain(document: &AttestationDocument, options: &VerifyOptions) -> Result<Trust> {
    if document.cabundle.is_empty() {
        bail!("attestation document has an empty cabundle, so nothing chains to a root");
    }

    let expected_root = decode_certificate(&options.trust_root)?;
    let presented_root = &document.cabundle[0];

    let trust = if presented_root.as_slice() == expected_root.as_slice() {
        Trust::ChainVerified
    } else if options.allow_untrusted_root {
        Trust::SelfSigned
    } else {
        bail!(
            "attestation document does not chain to the expected root \
             (presented root sha256 {}, expected {})",
            sha256_hex(presented_root),
            sha256_hex(&expected_root)
        );
    };

    // Root, intermediates, then the leaf: each verified against the one before.
    let mut chain: Vec<&[u8]> = document.cabundle.iter().map(|c| c.as_slice()).collect();
    chain.push(&document.certificate);

    for (depth, der) in chain.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der)
            .with_context(|| format!("parsing certificate at depth {depth}"))?;

        let seconds = options
            .now
            .duration_since(UNIX_EPOCH)
            .context("verification time is before the Unix epoch")?
            .as_secs();
        let asn1_now =
            ASN1Time::from_timestamp(seconds as i64).context("converting the verification time")?;
        if !cert.validity().is_valid_at(asn1_now) {
            bail!(
                "certificate at depth {depth} ({}) is not valid at the given time: {} to {}",
                cert.subject(),
                cert.validity().not_before,
                cert.validity().not_after
            );
        }

        // Every certificate except the leaf must be allowed to issue. Without
        // this, a leaf could be presented as an intermediate and sign others.
        let is_leaf = depth == chain.len() - 1;
        if !is_leaf {
            let is_ca = cert
                .basic_constraints()
                .ok()
                .flatten()
                .map(|bc| bc.value.ca)
                .unwrap_or(false);
            if !is_ca {
                bail!(
                    "certificate at depth {depth} ({}) is not a CA but has one below it",
                    cert.subject()
                );
            }
        }

        if depth == 0 {
            // The root is self-signed; its authority comes from being pinned,
            // which was settled above.
            continue;
        }
        let (_, issuer) = X509Certificate::from_der(chain[depth - 1])
            .with_context(|| format!("parsing issuer at depth {}", depth - 1))?;
        if cert.issuer() != issuer.subject() {
            bail!(
                "certificate at depth {depth} names issuer {} but follows {}",
                cert.issuer(),
                issuer.subject()
            );
        }
        verify_certificate_signature(&cert, &issuer)
            .with_context(|| format!("verifying certificate at depth {depth}"))?;
    }

    Ok(trust)
}

/// Check `cert`'s signature against `issuer`'s public key.
///
/// X.509 ECDSA signatures are DER-encoded `SEQUENCE { r, s }` — the ASN.1
/// variant — unlike the fixed-width form COSE uses.
fn verify_certificate_signature(cert: &X509Certificate, issuer: &X509Certificate) -> Result<()> {
    let algorithm = match cert.signature_algorithm.algorithm.to_id_string().as_str() {
        // ecdsa-with-SHA384
        "1.2.840.10045.4.3.3" => &signature::ECDSA_P384_SHA384_ASN1,
        // ecdsa-with-SHA256
        "1.2.840.10045.4.3.2" => &signature::ECDSA_P256_SHA256_ASN1,
        other => bail!("unsupported certificate signature algorithm {other}"),
    };

    let key = issuer.public_key().subject_public_key.data.as_ref();
    signature::UnparsedPublicKey::new(algorithm, key)
        .verify(cert.tbs_certificate.as_ref(), &cert.signature_value.data)
        .map_err(|_| anyhow::anyhow!("signature does not verify against the issuer's key"))
}

/// Accept a trust root as PEM or DER, returning DER.
fn decode_certificate(bytes: &[u8]) -> Result<Vec<u8>> {
    let looks_like_pem = bytes.starts_with(b"-----BEGIN");
    if !looks_like_pem {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes).context("PEM certificate is not UTF-8")?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .context("decoding the PEM certificate body")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}

/// The `user_data` layout nitriding uses, and this runtime follows.
///
/// Two multihash-prefixed SHA-256 digests, 68 bytes: the TLS certificate the
/// client is talking to, and the guest component being served. Together they
/// answer "is this connection terminated by the code I attested?" — the
/// certificate hash ties the TLS session to the document, and the guest hash
/// says which application was behind it.
///
/// ```text
///   0x12 0x20 ‖ sha256(tls leaf DER) ‖ 0x12 0x20 ‖ sha256(guest component)
///     │    └── length, 32 bytes
///     └── multihash code for sha2-256
/// ```
///
/// The prefixes are what make it self-describing: a bare 64-byte blob could
/// not later gain a third hash, or move to SHA-384, without every existing
/// verifier silently misreading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationHashes {
    pub tls_certificate: [u8; 32],
    pub guest: [u8; 32],
}

/// Multihash prefix for sha2-256 with a 32-byte digest.
const MULTIHASH_SHA256: [u8; 2] = [0x12, 0x20];
/// Two prefixed digests.
pub const ATTESTATION_HASHES_LEN: usize = 2 * (2 + 32);

impl AttestationHashes {
    pub fn new(tls_certificate_der: &[u8], guest_component: &[u8]) -> Self {
        AttestationHashes {
            tls_certificate: sha256(tls_certificate_der),
            guest: sha256(guest_component),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTESTATION_HASHES_LEN);
        out.extend_from_slice(&MULTIHASH_SHA256);
        out.extend_from_slice(&self.tls_certificate);
        out.extend_from_slice(&MULTIHASH_SHA256);
        out.extend_from_slice(&self.guest);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ATTESTATION_HASHES_LEN {
            bail!(
                "user_data is {} bytes, expected {ATTESTATION_HASHES_LEN}",
                bytes.len()
            );
        }
        if bytes[0..2] != MULTIHASH_SHA256 || bytes[34..36] != MULTIHASH_SHA256 {
            bail!("user_data does not carry two sha2-256 multihash prefixes");
        }
        let mut hashes = AttestationHashes {
            tls_certificate: [0u8; 32],
            guest: [0u8; 32],
        };
        hashes.tls_certificate.copy_from_slice(&bytes[2..34]);
        hashes.guest.copy_from_slice(&bytes[36..68]);
        Ok(hashes)
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published fingerprint of the AWS Nitro Enclaves root. If the
    /// embedded PEM is ever edited, this fails rather than quietly moving the
    /// trust anchor for every verification.
    #[test]
    fn the_embedded_root_is_the_published_one() {
        let der = decode_certificate(AWS_NITRO_ROOT_G1_PEM.as_bytes()).unwrap();
        assert_eq!(
            sha256_hex(&der),
            "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
        );

        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert_eq!(
            cert.subject().to_string(),
            "C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves"
        );
        assert_eq!(cert.subject(), cert.issuer(), "the root is self-signed");
    }

    #[test]
    fn hashes_round_trip() {
        let hashes = AttestationHashes::new(b"a certificate", b"a guest");
        let parsed = AttestationHashes::parse(&hashes.serialize()).unwrap();
        assert_eq!(parsed, hashes);
    }

    /// The 68-byte layout is a wire format shared with nitriding. Pin it.
    #[test]
    fn the_hash_layout_is_the_nitriding_one() {
        let hashes = AttestationHashes::new(b"cert", b"guest");
        let bytes = hashes.serialize();

        assert_eq!(bytes.len(), 68);
        assert_eq!(&bytes[0..2], &[0x12, 0x20], "sha2-256 multihash prefix");
        assert_eq!(&bytes[2..34], &sha256(b"cert"));
        assert_eq!(&bytes[34..36], &[0x12, 0x20]);
        assert_eq!(&bytes[36..68], &sha256(b"guest"));
    }

    #[test]
    fn a_wrong_length_user_data_is_refused() {
        assert!(AttestationHashes::parse(&[0u8; 67]).is_err());
        assert!(AttestationHashes::parse(&[0u8; 69]).is_err());
    }

    /// A 68-byte blob with the right length but no prefixes is not ours.
    #[test]
    fn user_data_without_multihash_prefixes_is_refused() {
        let err = AttestationHashes::parse(&[0u8; 68]).unwrap_err();
        assert!(format!("{err:#}").contains("multihash"), "{err:#}");
    }

    #[test]
    fn parsing_garbage_is_an_error_not_a_panic() {
        assert!(parse(b"").is_err());
        assert!(parse(b"\x84not cose").is_err());
        assert!(parse(&[0u8; 64]).is_err());
    }

    #[test]
    fn pem_and_der_roots_decode_alike() {
        let der = decode_certificate(AWS_NITRO_ROOT_G1_PEM.as_bytes()).unwrap();
        assert_eq!(decode_certificate(&der).unwrap(), der);
    }

    // ---- verification, against genuinely signed documents -------------------
    //
    // These use `testing::TestChain`, which mints a real P-384 chain and signs
    // a real ES384 COSE_Sign1. A verifier that skipped the signature, the
    // chain, or the root pin would pass the happy-path test and fail the rest,
    // which is the reason the rest exist.

    use crate::testing::TestChain;

    fn options_for(chain: &TestChain) -> VerifyOptions {
        VerifyOptions {
            trust_root: chain.root_der().to_vec(),
            now: SystemTime::now(),
            allow_untrusted_root: false,
        }
    }

    #[test]
    fn a_well_formed_document_verifies() {
        let chain = TestChain::new().unwrap();
        let cose = chain
            .document(Some(b"bound".to_vec()), Some(b"fresh".to_vec()), [0xab; 48])
            .unwrap();

        let verified = verify(&cose, &options_for(&chain)).unwrap();
        assert_eq!(verified.trust, Trust::ChainVerified);
        assert_eq!(verified.document.user_data.as_deref(), Some(&b"bound"[..]));
        assert_eq!(verified.document.nonce.as_deref(), Some(&b"fresh"[..]));
        assert_eq!(verified.document.pcr(0).unwrap(), [0xab; 48]);
        assert_eq!(verified.document.pcr0_hex().unwrap(), "ab".repeat(48));
    }

    /// The single most important negative test: swapping the payload for
    /// another must not verify. If it does, every other check is decoration.
    #[test]
    fn a_tampered_payload_does_not_verify() {
        let chain = TestChain::new().unwrap();
        let honest = chain
            .document(Some(b"honest".to_vec()), None, [0x01; 48])
            .unwrap();
        let forged_payload = testing::encode_payload(&AttestationDocument {
            user_data: Some(b"forged".to_vec()),
            ..parse(&honest).unwrap()
        });

        // Same signature, different payload.
        let mut sign1 = parse_cose(&honest).unwrap();
        sign1.payload = Some(forged_payload);
        use coset::CborSerializable;
        let tampered = sign1.to_vec().unwrap();

        let err = verify(&tampered, &options_for(&chain)).unwrap_err();
        assert!(format!("{err:#}").contains("signature"), "{err:#}");
    }

    /// A document signed by a chain rooted somewhere else must not verify
    /// against our root, however well formed it is. This is the check that
    /// stops anyone with a certificate generator from minting attestations.
    #[test]
    fn a_document_from_another_root_is_refused() {
        let ours = TestChain::new().unwrap();
        let theirs = TestChain::new().unwrap();
        let cose = theirs.document(None, None, [0x02; 48]).unwrap();

        let err = verify(&cose, &options_for(&ours)).unwrap_err();
        assert!(format!("{err:#}").contains("root"), "{err:#}");
    }

    /// The escape hatch the QEMU harness needs, and the reason it reports a
    /// different `Trust`: the document is self-consistent but proves nothing
    /// about AWS.
    #[test]
    fn an_untrusted_root_is_accepted_only_when_asked_and_is_labelled() {
        let theirs = TestChain::new().unwrap();
        let cose = theirs.document(None, None, [0x03; 48]).unwrap();

        let options = VerifyOptions {
            trust_root: AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(),
            now: SystemTime::now(),
            allow_untrusted_root: true,
        };
        let verified = verify(&cose, &options).unwrap();
        assert_eq!(
            verified.trust,
            Trust::SelfSigned,
            "a non-AWS root must never be reported as chain-verified"
        );
    }

    #[test]
    fn an_expired_chain_is_refused() {
        let long_ago = SystemTime::now() - Duration::from_secs(3600 * 24 * 30);
        let chain = TestChain::with_validity(
            long_ago,
            long_ago + Duration::from_secs(3600), // expired 30 days ago
        )
        .unwrap();
        let cose = chain.document(None, None, [0x04; 48]).unwrap();

        let err = verify(&cose, &options_for(&chain)).unwrap_err();
        assert!(format!("{err:#}").contains("not valid at"), "{err:#}");
    }

    /// The leaf's own certificate replaced by one from a different chain: the
    /// signature would verify against the substituted key, so only the chain
    /// check catches it.
    #[test]
    fn a_leaf_from_another_chain_is_refused() {
        let ours = TestChain::new().unwrap();
        let theirs = TestChain::new().unwrap();

        let cose = ours
            .document_from(AttestationDocument {
                certificate: theirs.leaf.clone(),
                ..parse(&ours.document(None, None, [0x05; 48]).unwrap()).unwrap()
            })
            .unwrap();

        assert!(verify(&cose, &options_for(&ours)).is_err());
    }

    #[test]
    fn an_empty_cabundle_is_refused() {
        let chain = TestChain::new().unwrap();
        let cose = chain
            .document_from(AttestationDocument {
                cabundle: vec![],
                ..parse(&chain.document(None, None, [0x06; 48]).unwrap()).unwrap()
            })
            .unwrap();

        let err = verify(&cose, &options_for(&chain)).unwrap_err();
        assert!(format!("{err:#}").contains("cabundle"), "{err:#}");
    }

    // ---- expectations -------------------------------------------------------

    fn verified_with(
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        pcr0: [u8; 48],
    ) -> Verified {
        let chain = TestChain::new().unwrap();
        let cose = chain.document(user_data, nonce, pcr0).unwrap();
        verify(&cose, &options_for(&chain)).unwrap()
    }

    #[test]
    fn expectations_hold_when_the_document_matches() {
        let verified = verified_with(Some(b"ud".to_vec()), Some(b"n".to_vec()), [0x07; 48]);
        verified
            .expect(
                &Expectations {
                    pcr0: Some(vec![0x07; 48]),
                    nonce: Some(b"n".to_vec()),
                    user_data: Some(b"ud".to_vec()),
                    max_age: Some(Duration::from_secs(60)),
                },
                SystemTime::now(),
            )
            .unwrap();
    }

    #[test]
    fn a_different_pcr0_is_rejected() {
        let verified = verified_with(None, None, [0x08; 48]);
        let err = verified
            .expect(
                &Expectations {
                    pcr0: Some(vec![0x09; 48]),
                    ..Default::default()
                },
                SystemTime::now(),
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("PCR0 mismatch"), "{err:#}");
    }

    /// A document with no nonce cannot be shown to be fresh, and must not pass
    /// as though the check were simply skipped.
    #[test]
    fn a_missing_nonce_fails_a_nonce_expectation() {
        let verified = verified_with(None, None, [0x0a; 48]);
        let err = verified
            .expect(
                &Expectations {
                    nonce: Some(b"sent".to_vec()),
                    ..Default::default()
                },
                SystemTime::now(),
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("no nonce"), "{err:#}");
    }

    #[test]
    fn a_replayed_nonce_is_rejected() {
        let verified = verified_with(None, Some(b"old".to_vec()), [0x0b; 48]);
        assert!(verified
            .expect(
                &Expectations {
                    nonce: Some(b"new".to_vec()),
                    ..Default::default()
                },
                SystemTime::now(),
            )
            .is_err());
    }

    #[test]
    fn a_stale_document_is_rejected() {
        let verified = verified_with(None, None, [0x0c; 48]);
        let err = verified
            .expect(
                &Expectations {
                    max_age: Some(Duration::from_secs(1)),
                    ..Default::default()
                },
                SystemTime::now() + Duration::from_secs(600),
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("old"), "{err:#}");
    }

    /// The end-to-end shape this milestone exists for: a client holding a TLS
    /// certificate checks that the enclave bound *that* certificate.
    #[test]
    fn a_certificate_binding_round_trips_through_user_data() {
        let tls_cert = b"the DER a client saw in the handshake";
        let guest = b"the guest component";
        let hashes = AttestationHashes::new(tls_cert, guest);

        let verified = verified_with(Some(hashes.serialize()), None, [0x0d; 48]);
        verified
            .expect(
                &Expectations {
                    user_data: Some(hashes.serialize()),
                    ..Default::default()
                },
                SystemTime::now(),
            )
            .unwrap();

        // And a client seeing a *different* certificate must not be satisfied.
        let other = AttestationHashes::new(b"a certificate from a proxy", guest);
        assert!(verified
            .expect(
                &Expectations {
                    user_data: Some(other.serialize()),
                    ..Default::default()
                },
                SystemTime::now(),
            )
            .is_err());
    }
}
