//! Building genuinely signed attestation documents.
//!
//! Not a stub. This mints a real P-384 certificate chain and a real ES384
//! COSE_Sign1 over a real CBOR payload, so a verifier cannot pass against it
//! by skipping a step — the way it would against a hand-written blob. That
//! matters because [`crate::verify`] is the one function here whose failure
//! mode is silent acceptance.
//!
//! What it cannot do is sign with AWS's key. Documents from here chain to a
//! root generated on the spot, so verifying one requires
//! [`crate::VerifyOptions::allow_untrusted_root`] and reports
//! [`crate::Trust::SelfSigned`]. That is the same footing the QEMU harness is
//! on, and the reason [`crate::Trust`] distinguishes the two cases at all.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair as RcgenKeyPair, KeyUsagePurpose,
};

use crate::AttestationDocument;

/// A certificate chain plus the leaf's signing key.
#[derive(Debug)]
pub struct TestChain {
    /// DER, root first — the `cabundle` layout.
    pub cabundle: Vec<Vec<u8>>,
    /// DER of the leaf that signs documents.
    pub leaf: Vec<u8>,
    leaf_key_pkcs8: Vec<u8>,
}

impl TestChain {
    /// A root → intermediate → leaf chain, mirroring what a real NSM presents.
    pub fn new() -> Result<Self> {
        Self::with_validity(
            SystemTime::now() - Duration::from_secs(3600),
            SystemTime::now() + Duration::from_secs(3600 * 24),
        )
    }

    pub fn with_validity(not_before: SystemTime, not_after: SystemTime) -> Result<Self> {
        let root_key = RcgenKeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;
        let mut root_params = ca_params("test-nitro-root", not_before, not_after);
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key)?;
        let root_issuer = Issuer::new(root_params, root_key);

        let inter_key = RcgenKeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;
        let mut inter_params = ca_params("test-nitro-intermediate", not_before, not_after);
        inter_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let intermediate = inter_params.signed_by(&inter_key, &root_issuer)?;
        let inter_issuer = Issuer::new(inter_params, inter_key);

        let leaf_key = RcgenKeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;
        let mut leaf_params = ca_params("test-enclave-leaf", not_before, not_after);
        leaf_params.is_ca = IsCa::NoCa;
        let leaf = leaf_params.signed_by(&leaf_key, &inter_issuer)?;

        Ok(TestChain {
            cabundle: vec![root.der().to_vec(), intermediate.der().to_vec()],
            leaf: leaf.der().to_vec(),
            leaf_key_pkcs8: leaf_key.serialize_der(),
        })
    }

    /// PEM of the root, for [`crate::VerifyOptions::trust_root`].
    pub fn root_der(&self) -> &[u8] {
        &self.cabundle[0]
    }

    /// Build a document with these fields and sign it with the leaf key.
    pub fn document(
        &self,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        pcr0: [u8; 48],
    ) -> Result<Vec<u8>> {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0u32, pcr0.to_vec());
        pcrs.insert(1u32, vec![0x11; 48]);
        pcrs.insert(2u32, vec![0x22; 48]);

        self.document_from(AttestationDocument {
            module_id: "i-0test-enc0000000000".to_string(),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            digest: "SHA384".to_string(),
            pcrs,
            certificate: self.leaf.clone(),
            cabundle: self.cabundle.clone(),
            public_key: None,
            user_data,
            nonce,
        })
    }

    /// Sign an arbitrary document, so tests can build malformed ones.
    pub fn document_from(&self, document: AttestationDocument) -> Result<Vec<u8>> {
        let payload = encode_payload(&document);

        let key = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &self.leaf_key_pkcs8,
        )
        .map_err(|e| anyhow::anyhow!("loading the leaf key: {e}"))?;
        let rng = SystemRandom::new();

        // ES384. The `_FIXED_` algorithm produces r‖s, which is what COSE
        // wants — the ASN.1 variant would verify nowhere.
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES384)
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(b"", |data| {
                key.sign(&rng, data)
                    .map(|s| s.as_ref().to_vec())
                    .map_err(|e| anyhow::anyhow!("signing: {e}"))
            })?
            .build();

        sign1
            .to_vec()
            .map_err(|e| anyhow::anyhow!("serialising COSE_Sign1: {e:?}"))
    }

    /// The leaf's public key, for tests that need to check it directly.
    pub fn leaf_public_key(&self) -> Result<Vec<u8>> {
        let key = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &self.leaf_key_pkcs8,
        )
        .map_err(|e| anyhow::anyhow!("loading the leaf key: {e}"))?;
        Ok(key.public_key().as_ref().to_vec())
    }
}

fn ca_params(name: &str, not_before: SystemTime, not_after: SystemTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.not_before = to_offset(not_before);
    params.not_after = to_offset(not_after);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
}

fn to_offset(t: SystemTime) -> time::OffsetDateTime {
    let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    time::OffsetDateTime::from_unix_timestamp(secs).expect("representable timestamp")
}

/// Encode a document the way the NSM does, so the decoder is tested against
/// the real wire shape rather than against itself.
pub fn encode_payload(document: &AttestationDocument) -> Vec<u8> {
    let mut fields = vec![
        (
            ciborium::Value::Text("module_id".into()),
            ciborium::Value::Text(document.module_id.clone()),
        ),
        (
            ciborium::Value::Text("digest".into()),
            ciborium::Value::Text(document.digest.clone()),
        ),
        (
            ciborium::Value::Text("timestamp".into()),
            ciborium::Value::Integer(document.timestamp_ms.into()),
        ),
        (
            ciborium::Value::Text("pcrs".into()),
            ciborium::Value::Map(
                document
                    .pcrs
                    .iter()
                    .map(|(k, v)| {
                        (
                            ciborium::Value::Integer((*k).into()),
                            ciborium::Value::Bytes(v.clone()),
                        )
                    })
                    .collect(),
            ),
        ),
        (
            ciborium::Value::Text("certificate".into()),
            ciborium::Value::Bytes(document.certificate.clone()),
        ),
        (
            ciborium::Value::Text("cabundle".into()),
            ciborium::Value::Array(
                document
                    .cabundle
                    .iter()
                    .map(|c| ciborium::Value::Bytes(c.clone()))
                    .collect(),
            ),
        ),
    ];

    // The real device emits these as null when absent rather than omitting
    // them; the decoder must tolerate either.
    for (name, value) in [
        ("public_key", &document.public_key),
        ("user_data", &document.user_data),
        ("nonce", &document.nonce),
    ] {
        fields.push((
            ciborium::Value::Text(name.into()),
            match value {
                Some(bytes) => ciborium::Value::Bytes(bytes.clone()),
                None => ciborium::Value::Null,
            },
        ));
    }

    let mut out = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(fields), &mut out)
        .expect("writing to a Vec cannot fail");
    out
}

/// Read a document's payload without verifying it, for tests that tamper.
pub fn payload_of(cose: &[u8]) -> Result<Vec<u8>> {
    let sign1 = coset::CoseSign1::from_slice(cose)
        .map_err(|e| anyhow::anyhow!("parsing COSE_Sign1: {e:?}"))?;
    sign1.payload.context("COSE_Sign1 has no payload")
}
