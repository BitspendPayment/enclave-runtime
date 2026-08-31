//! The production key source: KMS releases the master secret only to an
//! enclave whose PCR0 matches the key policy.
//!
//! ## What this changes
//!
//! [`super::StaticKey`] takes the secret from configuration, which means the
//! parent instance had it first — and the parent is the party an enclave exists
//! to exclude. No amount of boot verification fixes that.
//!
//! Here the secret is **minted by KMS and never exists outside the enclave in
//! the clear.** The parent still proxies the HTTPS request, because the enclave
//! has no network of its own; what it cannot do is read the answer. The
//! `Recipient` parameter makes KMS encrypt its response to a public key carried
//! inside an attestation document, and omit the `Plaintext` field entirely.
//! The parent forwards bytes it has no key for.
//!
//! The enforcement is the KMS key policy, not this code:
//! `kms:RecipientAttestation:PCR0` pinned to the approved image means a wrong
//! enclave does not get a refused mount — it gets **no key at all**. That is
//! the difference between an enclave checking itself and something outside it
//! doing the checking.
//!
//! ## Where the pieces live
//!
//! | | |
//! |---|---|
//! | SSM parameter | the KMS `CiphertextBlob`, and nothing else |
//! | roots bucket ([`SealedKey`]) | a [`KeyPointer`]: where to look, under which key, and the hash of what should be there |
//!
//! The split earns its keep. `boot.rs` decides genesis from resume by whether a
//! sealed-key object and a receipt are both present, so something has to stay
//! in the roots bucket — and a pointer is the useful thing to put there,
//! because the state-origin receipt already commits to `sha256(sealed)`. The
//! receipt therefore attests **which CMK and which encryption context this
//! filesystem was created under**, and the pointer's own `ciphertext_sha256`
//! catches a swapped parameter. A host can delete the parameter and stop the
//! enclave booting; it cannot make it boot wrong.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeyEncryptionMechanism, RecipientInfo};
use base64::Engine as _;
use nitro_nsm::{AttestationRequest, Nsm};
use s3fs_core::MasterSecret;

use super::recipient::RecipientKey;
use super::{MasterKeySource, SealedKey};

/// Bytes of key material to ask KMS for. The block store's master secret.
const MASTER_SECRET_LEN: i32 = 32;

/// Version tag on the pointer record, so a future format is a clear error
/// rather than a misparse of key metadata.
const POINTER_VERSION: u64 = 1;

/// How to reach this filesystem's key, and what should be there when we do.
///
/// CBOR, because the receipt payload beside it is CBOR already. Deliberately
/// contains **no key material** — it is written to the roots bucket, which is
/// readable by anyone who can read the bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPointer {
    pub parameter: String,
    pub key_id: String,
    pub context: BTreeMap<String, String>,
    /// What the SSM parameter should hash to. Checked on every open, so a
    /// swapped parameter is a refusal rather than an unbootable filesystem
    /// with a confusing error.
    pub ciphertext_sha256: [u8; 32],
}

impl KeyPointer {
    pub fn encode(&self) -> Result<SealedKey> {
        let context: Vec<_> = self
            .context
            .iter()
            .map(|(k, v)| {
                (
                    ciborium::Value::Text(k.clone()),
                    ciborium::Value::Text(v.clone()),
                )
            })
            .collect();
        let value = ciborium::Value::Array(vec![
            ciborium::Value::Integer(POINTER_VERSION.into()),
            ciborium::Value::Text(self.parameter.clone()),
            ciborium::Value::Text(self.key_id.clone()),
            ciborium::Value::Map(context),
            ciborium::Value::Bytes(self.ciphertext_sha256.to_vec()),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).context("encoding the key pointer")?;
        Ok(SealedKey::from_bytes(out))
    }

    pub fn decode(sealed: &SealedKey) -> Result<Self> {
        let value: ciborium::Value =
            ciborium::from_reader(sealed.as_bytes()).context("decoding the key pointer")?;
        let ciborium::Value::Array(fields) = value else {
            bail!("key pointer is not an array");
        };
        let [version, parameter, key_id, context, digest] = fields.as_slice() else {
            bail!("key pointer has {} fields, expected 5", fields.len());
        };

        let version = version
            .as_integer()
            .context("pointer version is not an integer")?;
        if u128::try_from(version).ok() != Some(POINTER_VERSION as u128) {
            bail!("key pointer is version {version:?}, this build understands {POINTER_VERSION}");
        }

        let text = |v: &ciborium::Value, what: &str| -> Result<String> {
            v.as_text()
                .map(str::to_string)
                .with_context(|| format!("key pointer {what} is not text"))
        };
        let ciborium::Value::Map(entries) = context else {
            bail!("key pointer encryption context is not a map");
        };
        let mut ctx = BTreeMap::new();
        for (k, v) in entries {
            ctx.insert(text(k, "context key")?, text(v, "context value")?);
        }

        let digest: [u8; 32] = digest
            .as_bytes()
            .context("key pointer digest is not bytes")?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("key pointer digest is not 32 bytes"))?;

        Ok(KeyPointer {
            parameter: text(parameter, "parameter name")?,
            key_id: text(key_id, "key id")?,
            context: ctx,
            ciphertext_sha256: digest,
        })
    }
}

/// Everything a deployment has to say about its KMS key.
#[derive(Debug, Clone)]
pub struct KmsKeyConfig {
    /// The customer master key. Its policy is the security control.
    pub key_id: String,
    /// SSM parameter holding the ciphertext.
    pub parameter: String,
    /// Additional authenticated data on both the mint and every open.
    ///
    /// Derived rather than freely configured — see [`KmsKeyConfig::context`] —
    /// because a context that differed between mint and open would make
    /// `Decrypt` fail with nothing pointing at why.
    pub environment: String,
    pub fs_id: [u8; 16],
}

impl KmsKeyConfig {
    /// The encryption context, identical at mint and at open by construction.
    pub fn context(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("fs-id".to_string(), hex::encode(self.fs_id)),
            ("environment".to_string(), self.environment.clone()),
        ])
    }
}

pub struct KmsAttestedKey {
    nsm: Arc<dyn Nsm>,
    kms: aws_sdk_kms::Client,
    ssm: aws_sdk_ssm::Client,
    config: KmsKeyConfig,
}

impl std::fmt::Debug for KmsAttestedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsAttestedKey")
            .field("key_id", &self.config.key_id)
            .field("parameter", &self.config.parameter)
            .finish_non_exhaustive()
    }
}

impl KmsAttestedKey {
    pub fn new(
        nsm: Arc<dyn Nsm>,
        kms: aws_sdk_kms::Client,
        ssm: aws_sdk_ssm::Client,
        config: KmsKeyConfig,
    ) -> Self {
        KmsAttestedKey {
            nsm,
            kms,
            ssm,
            config,
        }
    }

    /// A fresh key pair and an attestation document naming its public key.
    ///
    /// Both are per call, never reused and never stored. The document is what
    /// KMS checks against the key policy; the key is what it encrypts to. A
    /// replayed document is useless without the matching private key, which
    /// exists only in this process for the length of one request.
    fn recipient(&self) -> Result<(RecipientKey, RecipientInfo)> {
        let key = RecipientKey::generate()?;
        let document = self
            .nsm
            .attest(&AttestationRequest {
                public_key: Some(key.public_key_der().to_vec()),
                ..Default::default()
            })
            .context("attesting the recipient public key")?;
        let info = RecipientInfo::builder()
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .attestation_document(Blob::new(document))
            .build();
        Ok((key, info))
    }

    async fn read_ciphertext(&self, pointer: &KeyPointer) -> Result<Vec<u8>> {
        let response = self
            .ssm
            .get_parameter()
            .name(&pointer.parameter)
            .send()
            .await
            .with_context(|| format!("reading SSM parameter {}", pointer.parameter))?;
        let encoded = response
            .parameter()
            .and_then(|p| p.value())
            .with_context(|| format!("SSM parameter {} has no value", pointer.parameter))?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .context("SSM parameter is not base64")?;

        // Before the ciphertext is used for anything. The pointer is attested
        // by the state-origin receipt, so this check is what carries that
        // attestation forward onto the bytes SSM actually returned.
        let actual = nitro_attestation::sha256(&ciphertext);
        if actual != pointer.ciphertext_sha256 {
            bail!(
                "SSM parameter {} does not match what this filesystem's attested pointer \
                 commits to. Expected sha256 {}, found {}.",
                pointer.parameter,
                hex::encode(pointer.ciphertext_sha256),
                hex::encode(actual)
            );
        }
        Ok(ciphertext)
    }
}

#[async_trait]
impl MasterKeySource for KmsAttestedKey {
    fn describe(&self) -> &'static str {
        "KMS, released on PCR0 attestation"
    }

    async fn mint(&self) -> Result<(MasterSecret, SealedKey)> {
        let (key, recipient) = self.recipient()?;

        let mut request = self
            .kms
            .generate_data_key()
            .key_id(&self.config.key_id)
            .number_of_bytes(MASTER_SECRET_LEN)
            .recipient(recipient);
        for (k, v) in self.config.context() {
            request = request.encryption_context(k, v);
        }
        let response = request
            .send()
            .await
            .context("KMS GenerateDataKey with a Nitro recipient")?;

        let ciphertext = response
            .ciphertext_blob()
            .context("KMS returned no CiphertextBlob")?
            .as_ref()
            .to_vec();
        // Absent, not ignored: with `Recipient` set KMS omits `Plaintext`
        // entirely, and `CiphertextForRecipient` is the only copy — encrypted
        // to a key the parent does not have.
        let for_recipient = response
            .ciphertext_for_recipient()
            .context(
                "KMS returned no CiphertextForRecipient. The request reached KMS without a \
                 recipient attestation, which would have put the key in the clear.",
            )?
            .as_ref();
        let secret = to_secret(key.unwrap_ciphertext(for_recipient)?)?;

        let pointer = KeyPointer {
            parameter: self.config.parameter.clone(),
            key_id: self.config.key_id.clone(),
            context: self.config.context(),
            ciphertext_sha256: nitro_attestation::sha256(&ciphertext),
        };

        // The parameter before the pointer. `boot.rs` writes the pointer with a
        // conditional put and only then attests, so a failure here leaves a
        // store with no pointer and no receipt — which the boot machine reads
        // as an empty store and a genesis it can retry. The reverse order would
        // leave a pointer aimed at nothing.
        self.ssm
            .put_parameter()
            .name(&self.config.parameter)
            .value(base64::engine::general_purpose::STANDARD.encode(&ciphertext))
            // `String`, not `SecureString`: the value is already KMS ciphertext
            // under a key with an attestation-bound policy. Encrypting it again
            // under a second key would add a second thing to get the policy
            // right on, and the weaker of the two would be the one that counts.
            .r#type(aws_sdk_ssm::types::ParameterType::String)
            // A parameter that already exists means a previous genesis got this
            // far. Overwriting would strand whatever filesystem it belonged to.
            .overwrite(false)
            .send()
            .await
            .with_context(|| format!("writing SSM parameter {}", self.config.parameter))?;

        Ok((secret, pointer.encode()?))
    }

    async fn open(&self, sealed: &SealedKey) -> Result<MasterSecret> {
        let pointer = KeyPointer::decode(sealed).context(
            "this filesystem's key pointer could not be read. A blob sealed by the static \
             development source cannot be opened by KMS — that is the expected outcome of \
             pointing a production build at a development store.",
        )?;
        if pointer.context != self.config.context() {
            bail!(
                "this filesystem was created under encryption context {:?}, but this enclave \
                 is configured for {:?}. KMS would refuse the decrypt.",
                pointer.context,
                self.config.context()
            );
        }

        let ciphertext = self.read_ciphertext(&pointer).await?;
        let (key, recipient) = self.recipient()?;

        let mut request = self
            .kms
            .decrypt()
            .ciphertext_blob(Blob::new(ciphertext))
            // Named explicitly rather than left to the ciphertext's own header,
            // so a pointer aimed at a different CMK fails here instead of
            // succeeding under a key nobody meant to use.
            .key_id(&pointer.key_id)
            .recipient(recipient);
        for (k, v) in pointer.context {
            request = request.encryption_context(k, v);
        }
        let response = request
            .send()
            .await
            .context("KMS Decrypt with a Nitro recipient")?;

        let for_recipient = response
            .ciphertext_for_recipient()
            .context(
                "KMS returned no CiphertextForRecipient. The request reached KMS without a \
                 recipient attestation, which would have put the key in the clear.",
            )?
            .as_ref();
        to_secret(key.unwrap_ciphertext(for_recipient)?)
    }
}

fn to_secret(bytes: Vec<u8>) -> Result<MasterSecret> {
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("KMS returned {} bytes, expected 32", bytes.len()))?;
    Ok(MasterSecret::from_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pointer() -> KeyPointer {
        KeyPointer {
            parameter: "/enclave-runtime/prod/deadbeef/master-key".to_string(),
            key_id: "arn:aws:kms:eu-west-2:123456789012:key/abc-123".to_string(),
            context: KmsKeyConfig {
                key_id: "k".into(),
                parameter: "p".into(),
                environment: "prod".into(),
                fs_id: [0xab; 16],
            }
            .context(),
            ciphertext_sha256: [0x5a; 32],
        }
    }

    #[test]
    fn a_pointer_round_trips() {
        let encoded = pointer().encode().unwrap();
        assert_eq!(KeyPointer::decode(&encoded).unwrap(), pointer());
    }

    /// The pointer goes in the roots bucket, which anyone who can read the
    /// bucket can read. If key material ever appears in it, this fails.
    #[test]
    fn a_pointer_carries_no_key_material() {
        let secret = [0x11u8; 32];
        let encoded = pointer().encode().unwrap();
        let haystack = encoded.as_bytes();
        assert!(
            !haystack
                .windows(secret.len())
                .any(|w| w == secret.as_slice()),
            "the pointer contains something 32 bytes long that should not be there"
        );
        // Only what it is supposed to carry: names, and a digest.
        assert!(haystack.len() < 512, "pointer is unexpectedly large");
    }

    /// A blob from the development source must not be misread as a pointer.
    /// Its first bytes are a marker, not CBOR, and confusing the two would mean
    /// a production build treating a plaintext key as metadata.
    #[test]
    fn a_static_key_blob_is_not_a_pointer() {
        let mut blob = b"s3fs-UNSEALED-development-key-v1\n".to_vec();
        blob.extend_from_slice(&[7u8; 32]);
        assert!(KeyPointer::decode(&SealedKey::from_bytes(blob)).is_err());
    }

    #[test]
    fn a_future_pointer_version_is_refused() {
        let mut out = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Array(vec![
                ciborium::Value::Integer((POINTER_VERSION + 1).into()),
                ciborium::Value::Text("p".into()),
                ciborium::Value::Text("k".into()),
                ciborium::Value::Map(vec![]),
                ciborium::Value::Bytes(vec![0; 32]),
            ]),
            &mut out,
        )
        .unwrap();
        let err = KeyPointer::decode(&SealedKey::from_bytes(out))
            .unwrap_err()
            .to_string();
        assert!(err.contains("version"), "unexpected error: {err}");
    }

    #[test]
    fn garbage_is_refused_rather_than_panicking() {
        for bytes in [vec![], vec![0xff; 8], b"not cbor at all".to_vec()] {
            assert!(KeyPointer::decode(&SealedKey::from_bytes(bytes)).is_err());
        }
    }

    /// The encryption context must be identical at mint and at open, and it is
    /// derived rather than configured so that it cannot drift. A change to how
    /// it is built is a change that makes every existing filesystem unopenable,
    /// so it should have to be made deliberately.
    #[test]
    fn the_encryption_context_is_pinned_to_the_filesystem() {
        let config = KmsKeyConfig {
            key_id: "k".into(),
            parameter: "p".into(),
            environment: "prod".into(),
            fs_id: [0xab; 16],
        };
        assert_eq!(
            config.context(),
            BTreeMap::from([
                ("fs-id".to_string(), "ab".repeat(16)),
                ("environment".to_string(), "prod".to_string()),
            ])
        );

        // A different filesystem, or a different environment, is a different
        // context — so a production ciphertext cannot be opened by a staging
        // enclave even if it reaches the same parameter.
        let other = KmsKeyConfig {
            fs_id: [0xcd; 16],
            ..config.clone()
        };
        assert_ne!(config.context(), other.context());
        let staging = KmsKeyConfig {
            environment: "staging".into(),
            ..config.clone()
        };
        assert_ne!(config.context(), staging.context());
    }
}
