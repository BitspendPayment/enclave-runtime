//! A passkey in software, for tests.
//!
//! Every property the gate has — origin, RP ID, user verification, the
//! signature, the binding to one request — can only be tested against
//! something that produces real assertions. A phone cannot be driven from a
//! test suite, so this is a P-256 key that emits exactly the bytes a phone
//! would: the same `clientDataJSON`, the same authenticator-data layout, the
//! same ECDSA signature over the same message.
//!
//! It is a fixture, not a fake. Nothing here is more permissive than a real
//! authenticator — the runtime's verification does not know the difference and
//! is not told. What it *can* do that a phone cannot is misbehave on purpose:
//! sign the wrong challenge, clear the user-verification flag, claim another
//! origin. Those are the tests worth having, and they need an authenticator
//! that will do as it is told.
//!
//! Compiled into the crate rather than a test file so the QEMU harness can use
//! it too — its self-signed certificate means no real platform authenticator
//! will ever attest against it, so this is the only way that leg exercises the
//! gate at all.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use base64::Engine as _;

/// Authenticator-data flags, as the spec names them.
pub mod flags {
    /// User present — someone touched it.
    pub const UP: u8 = 0x01;
    /// User verified — biometric or PIN, not merely presence.
    pub const UV: u8 = 0x04;
    /// Attested credential data follows. Registration only.
    pub const AT: u8 = 0x40;
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A software passkey bound to one relying party.
pub struct SoftwareAuthenticator {
    key: EcdsaKeyPair,
    /// The private key in PKCS#8, kept so a caller can persist and restore the
    /// passkey. A real authenticator's key never leaves its hardware; this one
    /// has to, because a shell script invokes the client afresh for every
    /// request and a passkey that vanished between them could not be used at
    /// all. It is a test fixture — it is behind a feature for exactly this
    /// kind of reason.
    key_pkcs8: Vec<u8>,
    credential_id: Vec<u8>,
    rp_id: String,
    /// Atomic rather than a `Cell`: a real authenticator can be asked for two
    /// assertions at once, and a fixture that could not be shared across tasks
    /// would rule out testing exactly that.
    counter: std::sync::atomic::AtomicU32,
}

impl SoftwareAuthenticator {
    pub fn new(rp_id: &str) -> Self {
        let key_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generating a P-256 key");
        let mut credential_id = vec![0u8; 32];
        aws_lc_rs::rand::fill(&mut credential_id).expect("credential id");
        Self::restore(rp_id, &credential_id, key_pkcs8.as_ref(), 0)
            .expect("a key we just generated parses")
    }

    /// Rebuild a passkey from a credential id, its private key, and the
    /// signature counter it had reached.
    ///
    /// The counter has to come back too. An authenticator that restarted at
    /// zero would present a count no higher than the one registration
    /// recorded, and a relying party is entitled to read that as a cloned
    /// credential — which is exactly what it is protecting against.
    pub fn restore(
        rp_id: &str,
        credential_id: &[u8],
        key_pkcs8: &[u8],
        counter: u32,
    ) -> anyhow::Result<Self> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_pkcs8)
            .map_err(|e| anyhow::anyhow!("restoring a passkey: {e}"))?;
        Ok(SoftwareAuthenticator {
            key,
            key_pkcs8: key_pkcs8.to_vec(),
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.to_string(),
            counter: std::sync::atomic::AtomicU32::new(counter),
        })
    }

    /// The counter this passkey has reached, for a caller that persists it.
    pub fn counter(&self) -> u32 {
        self.counter.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The private key, for a caller that has to persist this passkey.
    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.key_pkcs8
    }

    /// The credential public key, as the COSE_Key an authenticator reports.
    ///
    /// `{1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}`, which is
    /// what `attestedCredentialData` carries and what the relying party stores.
    fn cose_key(&self) -> Vec<u8> {
        let point = self.key.public_key().as_ref();
        assert_eq!(point.len(), 65, "expected an uncompressed P-256 point");
        assert_eq!(point[0], 0x04, "expected an uncompressed P-256 point");
        let value = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-7).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(point[1..33].to_vec()),
            ),
            (
                ciborium::Value::Integer((-3).into()),
                ciborium::Value::Bytes(point[33..65].to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).expect("encoding a COSE key");
        out
    }

    /// `rpIdHash ‖ flags ‖ counter`, plus attested credential data when
    /// registering.
    fn authenticator_data(&self, flags: u8, attested: bool) -> Vec<u8> {
        let mut data = nitro_attestation::sha256(self.rp_id.as_bytes()).to_vec();
        data.push(flags);
        let counter = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        data.extend_from_slice(&counter.to_be_bytes());
        if attested {
            data.extend_from_slice(&[0u8; 16]); // AAGUID: zero, as platform authenticators report
            data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(&self.cose_key());
        }
        data
    }

    fn client_data(&self, kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        // Field order is the authenticator's to choose and the relying party
        // must not depend on it, so this is not the same order webauthn-rs
        // writes. That is deliberate: it is one more thing the verifier is
        // being checked for not assuming.
        format!(
            r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        )
        .into_bytes()
    }

    fn sign(&self, authenticator_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let mut message = authenticator_data.to_vec();
        message.extend_from_slice(&nitro_attestation::sha256(client_data));
        self.key
            .sign(&SystemRandom::new(), &message)
            .expect("signing")
            .as_ref()
            .to_vec()
    }

    /// A registration response, attestation format `none`.
    ///
    /// `none` is what a platform authenticator produces for a passkey unless
    /// the relying party asks otherwise, so it is what the runtime has to
    /// accept.
    pub fn register(&self, challenge: &str, origin: &str) -> serde_json::Value {
        let client_data = self.client_data("webauthn.create", challenge, origin);
        let auth_data = self.authenticator_data(flags::UP | flags::UV | flags::AT, true);

        let attestation = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".into()),
                ciborium::Value::Text("none".into()),
            ),
            (
                ciborium::Value::Text("attStmt".into()),
                ciborium::Value::Map(vec![]),
            ),
            (
                ciborium::Value::Text("authData".into()),
                ciborium::Value::Bytes(auth_data),
            ),
        ]);
        let mut attestation_object = Vec::new();
        ciborium::into_writer(&attestation, &mut attestation_object).expect("attestation object");

        serde_json::json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "extensions": {},
            "response": {
                "attestationObject": b64(&attestation_object),
                "clientDataJSON": b64(&client_data),
            }
        })
    }

    /// An assertion, exactly as a phone would produce one.
    pub fn assert(&self, challenge: &str, origin: &str) -> serde_json::Value {
        self.assert_with(challenge, origin, flags::UP | flags::UV)
    }

    /// An assertion with the flags chosen by the caller.
    ///
    /// Clearing [`flags::UV`] is how a test asks "what if the user merely had
    /// an unlocked phone in their pocket" — which must be refused, because a
    /// cosigner's approval is supposed to mean a person did something.
    pub fn assert_with(&self, challenge: &str, origin: &str, flags: u8) -> serde_json::Value {
        let client_data = self.client_data("webauthn.get", challenge, origin);
        let auth_data = self.authenticator_data(flags, false);
        let signature = self.sign(&auth_data, &client_data);

        serde_json::json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": b64(&auth_data),
                "clientDataJSON": b64(&client_data),
                "signature": b64(&signature),
                "userHandle": null,
            }
        })
    }
}
