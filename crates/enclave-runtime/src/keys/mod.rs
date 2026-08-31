//! Where the master secret comes from, and where it goes.
//!
//! Two operations, not one, because genesis and resume are different
//! questions. Genesis **mints** a secret that has never existed before and
//! hands back the sealed form for the caller to persist; resume **opens** the
//! blob that a previous genesis wrote. A single `master_secret()` could not
//! express the difference, and the difference is the point: a filesystem's key
//! is created once, with it, and recovered every time after.
//!
//! ## Why the secret belongs to the stored state
//!
//! It used to arrive as `S3FS_MASTER_KEY`, from the parent instance. A parent
//! that supplies the key *has* the key, and can decrypt the whole filesystem —
//! so the party an enclave exists to exclude held the only thing that mattered.
//! No amount of boot verification fixes that: an enclave could prove perfectly
//! that it had loaded genuine state while the host read that state over its
//! shoulder.
//!
//! Minting inside the enclave and persisting only the sealed form is what
//! closes it. The plaintext exists in enclave memory and nowhere else.
//!
//! ## Two sources
//!
//! [`KmsAttestedKey`] is the real one: KMS releases the secret only to an
//! enclave whose PCR0 matches the key policy, encrypted to a key that exists
//! only inside that enclave for that boot. The host proxies the call and never
//! sees plaintext.
//!
//! [`StaticKey`] seals by *not* sealing. It exists because the QEMU harness
//! cannot use the real one — an emulated NSM does not sign its attestations,
//! and KMS will not accept an unsigned document — and because it exercises
//! every boot mode without hardware. It is not protection, and the image
//! environment that selects it is measured, so PCR0 says which an enclave runs.

mod kms;
mod recipient;
mod static_key;

pub use kms::{KeyPointer, KmsAttestedKey, KmsKeyConfig};
pub use static_key::StaticKey;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use nitro_nsm::Nsm;
use s3fs_core::MasterSecret;

/// A master secret in the form that is safe to store.
///
/// Opaque bytes: what is inside depends on which [`MasterKeySource`] produced
/// it, and no caller should look. A state-origin receipt commits to
/// `sha256(bytes)` — never the plaintext, because the receipt is readable by
/// anyone who can read the bucket it sits in.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedKey(Vec<u8>);

impl SealedKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        SealedKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// What a receipt commits to.
    pub fn sha256(&self) -> [u8; 32] {
        nitro_attestation::sha256(&self.0)
    }
}

/// Never print the blob. For [`StaticKey`] it *is* the secret, and a `Debug`
/// that rendered it would put a master key in any log line that formats a
/// struct containing one.
impl std::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SealedKey({} bytes, sha256 {})",
            self.0.len(),
            hex::encode(&self.sha256()[..8])
        )
    }
}

#[async_trait]
pub trait MasterKeySource: Send + Sync + std::fmt::Debug {
    /// A short description for startup logging. Must not reveal key material.
    fn describe(&self) -> &'static str;

    /// Create a secret that has never existed before, and return it with the
    /// form the caller must persist.
    ///
    /// Only genesis calls this. Calling it against a filesystem that already
    /// exists would produce a key that cannot read it.
    async fn mint(&self) -> Result<(MasterSecret, SealedKey)>;

    /// Recover the secret from a blob a previous genesis wrote.
    async fn open(&self, sealed: &SealedKey) -> Result<MasterSecret>;
}

/// So a boxed source can be passed where `&dyn MasterKeySource` is wanted.
///
/// [`open_key_source`] returns a box because the two implementations are
/// different types, and `boot()` takes `&dyn` — without this, every call site
/// would have to write `&*keys`, which reads like a mistake rather than a
/// deref.
#[async_trait]
impl<T: MasterKeySource + ?Sized> MasterKeySource for Box<T> {
    fn describe(&self) -> &'static str {
        (**self).describe()
    }

    async fn mint(&self) -> Result<(MasterSecret, SealedKey)> {
        (**self).mint().await
    }

    async fn open(&self, sealed: &SealedKey) -> Result<MasterSecret> {
        (**self).open(sealed).await
    }
}

/// Which implementation of [`MasterKeySource`] a deployment runs.
///
/// No default anywhere. An enclave's key handling is the one setting that
/// should never be inherited by omission, and because the value comes from the
/// image environment, PCR0 records which of the two an enclave was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeySourceKind {
    /// [`KmsAttestedKey`] — the production path.
    Kms,
    /// [`StaticKey`] — development and the QEMU harness, which cannot use KMS
    /// because an emulated NSM does not sign its attestations and KMS will not
    /// accept an unsigned one.
    Static,
}

impl MasterKeySourceKind {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "kms" | "kms-attested" => Ok(MasterKeySourceKind::Kms),
            "static" | "unsealed" => Ok(MasterKeySourceKind::Static),
            other => Err(format!("expected one of kms, static; got {other:?}")),
        }
    }
}

/// Everything needed to build a key source, from either branch.
#[derive(Debug, Clone)]
pub struct MasterKeyConfig {
    pub kind: MasterKeySourceKind,
    /// Hex secret. `static` only, and **refused** under `kms`.
    pub master_key: Option<String>,
    pub kms_key_id: Option<String>,
    pub parameter: Option<String>,
    /// Part of the encryption context, so a staging enclave cannot open a
    /// production filesystem even if it is pointed at the same parameter.
    pub environment: String,
    pub fs_id: [u8; 16],
    pub region: String,
    /// Endpoint overrides, separate from S3's. A MinIO endpoint is not a KMS
    /// endpoint, and pointing one at the other fails in a way that reads like
    /// a credentials problem.
    pub kms_endpoint: Option<String>,
    pub ssm_endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
}

/// Build the configured key source, refusing combinations that cannot mean
/// what they appear to.
///
/// The refusals matter more than the construction. A production image that
/// still carried `S3FS_MASTER_KEY` would work perfectly — silently using a key
/// the parent instance holds, giving up the whole point of KMS release — so
/// supplying both is an error rather than a precedence rule. There is no
/// ordering of "both were given" that is safe to guess at.
pub fn open_key_source(
    config: &MasterKeyConfig,
    nsm: Arc<dyn Nsm>,
) -> Result<Box<dyn MasterKeySource>> {
    match config.kind {
        MasterKeySourceKind::Static => {
            if config.kms_key_id.is_some() || config.parameter.is_some() {
                bail!(
                    "--master-key-source=static was given alongside KMS settings. One of the \
                     two is not what was meant, and guessing which would mean an enclave \
                     silently taking its key from configuration."
                );
            }
            let hex = config
                .master_key
                .as_deref()
                .context("--master-key-source=static needs --master-key (S3FS_MASTER_KEY)")?;
            Ok(Box::new(StaticKey::from_hex(hex)?))
        }
        MasterKeySourceKind::Kms => {
            if config.master_key.is_some() {
                bail!(
                    "--master-key was given alongside --master-key-source=kms. A key from \
                     configuration is a key the parent instance holds, which is exactly what \
                     KMS release exists to prevent — so this is refused, not ignored."
                );
            }
            let key_id = config
                .kms_key_id
                .as_deref()
                .context("--master-key-source=kms needs --kms-key-id (S3FS_KMS_KEY_ID)")?;
            let parameter = config.parameter.as_deref().context(
                "--master-key-source=kms needs --master-key-parameter (S3FS_MASTER_KEY_PARAMETER)",
            )?;

            Ok(Box::new(KmsAttestedKey::new(
                nsm,
                kms_client(config),
                ssm_client(config),
                KmsKeyConfig {
                    key_id: key_id.to_string(),
                    parameter: parameter.to_string(),
                    environment: config.environment.clone(),
                    fs_id: config.fs_id,
                },
            )))
        }
    }
}

/// Static credentials rather than the default chain, for the same reason
/// [`s3fs_core::backend::aws`] uses them: inside an enclave there is no IMDS to
/// walk to, and a client that quietly tried would hang rather than fail.
fn kms_client(config: &MasterKeyConfig) -> aws_sdk_kms::Client {
    use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};
    let mut builder = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(config.region.clone()));
    if let Some(endpoint) = &config.kms_endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    if let (Some(akid), Some(sak)) = (
        config.access_key_id.as_deref(),
        config.secret_access_key.as_deref(),
    ) {
        builder = builder.credentials_provider(Credentials::new(
            akid,
            sak,
            config.session_token.clone(),
            None,
            "s3fs-static",
        ));
    }
    aws_sdk_kms::Client::from_conf(builder.build())
}

/// The same, for SSM. Written out rather than shared through a generic: the
/// two builders are distinct types with coincidentally identical methods, and
/// the macro that would unify them costs more to read than the repetition.
fn ssm_client(config: &MasterKeyConfig) -> aws_sdk_ssm::Client {
    use aws_sdk_ssm::config::{BehaviorVersion, Credentials, Region};
    let mut builder = aws_sdk_ssm::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(config.region.clone()));
    if let Some(endpoint) = &config.ssm_endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    if let (Some(akid), Some(sak)) = (
        config.access_key_id.as_deref(),
        config.secret_access_key.as_deref(),
    ) {
        builder = builder.credentials_provider(Credentials::new(
            akid,
            sak,
            config.session_token.clone(),
            None,
            "s3fs-static",
        ));
    }
    aws_sdk_ssm::Client::from_conf(builder.build())
}
