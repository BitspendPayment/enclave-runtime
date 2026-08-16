//! Let's Encrypt certificates, obtained and kept inside the enclave.
//!
//! A self-signed certificate is enough for a client that verifies attestation
//! — the binding proves more than a CA signature ever could. It is not enough
//! for a browser, which cannot check attestations and will simply refuse. So
//! the enclave gets a real one, and the private key still never leaves it.
//!
//! ## Why TLS-ALPN-01
//!
//! The challenge arrives on **port 443**, the one the parent already forwards
//! inbound. HTTP-01 would need port 80 forwarded as well, and DNS-01 would
//! need DNS credentials inside the enclave — a standing secret that could
//! mint certificates for the whole zone.
//!
//! ## What this does not prove
//!
//! A publicly trusted certificate says a CA agreed the operator controls the
//! domain. The operator *does* control the domain, and could obtain a second
//! certificate for it outside the enclave and terminate TLS themselves. The
//! attestation binding is what closes that: `user_data` names the certificate
//! this enclave is serving, so a client that checks it will not accept the
//! operator's. Let's Encrypt buys browser compatibility, not trust.
//!
//! ## Where the key is kept
//!
//! rustls-acme hands its cache the account key and the certificate's private
//! key as PEM. Both are sealed with AES-256-GCM under a key derived from the
//! master secret and written as an ordinary object, so the parent instance
//! stores ciphertext it cannot read.
//!
//! Not in the filesystem: [`crate::wasi::host_preopens`] gives the guest a
//! descriptor for the filesystem *root*, so anything kept there is readable by
//! the guest — and a guest holding the TLS private key could impersonate the
//! enclave to every client.
//!
//! Caching is not an optimisation. Let's Encrypt allows five duplicate
//! certificates per week; an enclave that re-issued on every boot would run
//! out and be unable to serve.

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use s3fs_core::backend::{Backend, PutBlobInput};
use s3fs_core::crypto::KeyMaterial;
use s3fs_core::FsError;

/// The certificate currently being served.
///
/// A shared slot rather than a fixed value because ACME issues asynchronously
/// and renews later: the certificate at boot is not necessarily the one in use
/// an hour on. The attestation endpoint reads through this so a renewal
/// changes what gets bound, instead of quietly attesting a certificate that is
/// no longer being presented.
#[derive(Debug, Clone, Default)]
pub struct CertificateSlot(Arc<RwLock<Option<Vec<u8>>>>);

impl CertificateSlot {
    /// A slot holding a certificate that will never change.
    pub fn fixed(leaf_der: Vec<u8>) -> Self {
        CertificateSlot(Arc::new(RwLock::new(Some(leaf_der))))
    }

    pub fn empty() -> Self {
        CertificateSlot::default()
    }

    pub fn set(&self, leaf_der: Vec<u8>) {
        let changed = {
            let mut slot = self.0.write().expect("certificate slot poisoned");
            let changed = slot.as_deref() != Some(leaf_der.as_slice());
            *slot = Some(leaf_der);
            changed
        };
        if changed {
            if let Some(der) = self.get() {
                tracing::info!(
                    certificate_sha256 = %hex::encode(nitro_attestation::sha256(&der)),
                    "serving certificate changed; attestation will bind the new one"
                );
            }
        }
    }

    pub fn get(&self) -> Option<Vec<u8>> {
        self.0.read().expect("certificate slot poisoned").clone()
    }
}

/// Object key for the sealed ACME material.
fn cache_key(prefix: &str, kind: &str, scope: &[String], directory_url: &str) -> String {
    // The directory URL is part of the key: staging and production issue
    // different certificates, and a cached staging certificate served in
    // production would be rejected by every client.
    let mut hasher = blake3::Hasher::new();
    hasher.update(directory_url.as_bytes());
    for item in scope {
        hasher.update(b"\0");
        hasher.update(item.as_bytes());
    }
    let digest = hasher.finalize();
    format!(
        "{prefix}acme/{kind}-{}",
        hex::encode(&digest.as_bytes()[..16])
    )
}

/// rustls-acme cache backed by the object store, sealed under the master key.
pub struct SealedAcmeCache {
    backend: Arc<dyn Backend>,
    prefix: String,
    keys: Arc<KeyMaterial>,
    /// Updated whenever a certificate is loaded or stored.
    certificate: CertificateSlot,
}

impl std::fmt::Debug for SealedAcmeCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedAcmeCache")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl SealedAcmeCache {
    pub fn new(
        backend: Arc<dyn Backend>,
        prefix: String,
        keys: Arc<KeyMaterial>,
        certificate: CertificateSlot,
    ) -> Self {
        SealedAcmeCache {
            backend,
            prefix,
            keys,
            certificate,
        }
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.backend.get_blob(key, None).await {
            Ok(output) => {
                let plaintext = unseal(&self.keys, key, &output.body)
                    .with_context(|| format!("unsealing {key}"))?;
                Ok(Some(plaintext))
            }
            // A first boot has no cache. Everything else is a real failure and
            // must not be mistaken for one.
            Err(FsError::NotFound) => Ok(None),
            Err(e) => {
                Err(anyhow::Error::msg(e.to_string())).with_context(|| format!("reading {key}"))
            }
        }
    }

    async fn store(&self, key: &str, plaintext: &[u8]) -> Result<()> {
        let sealed = seal(&self.keys, key, plaintext).with_context(|| format!("sealing {key}"))?;
        self.backend
            .put_blob(PutBlobInput::new(key, sealed.into()))
            .await
            .map_err(|e| anyhow::Error::msg(e.to_string()))
            .with_context(|| format!("writing {key}"))?;
        Ok(())
    }

    /// Pull the leaf certificate out of rustls-acme's PEM blob.
    ///
    /// The layout is fixed by `AcmeState::parse_cert`: the PKCS#8 private key
    /// first, then the chain, leaf first. So the leaf is the second PEM block —
    /// and the first must never be published, which is why the whole blob is
    /// sealed.
    fn publish_leaf(&self, pem: &[u8]) {
        match leaf_from_pem(pem) {
            Ok(der) => self.certificate.set(der),
            Err(e) => tracing::error!(
                error = %e,
                "could not read the leaf out of the ACME certificate; \
                 attestation cannot bind a certificate it cannot identify"
            ),
        }
    }
}

/// Second PEM block of rustls-acme's cached blob.
pub fn leaf_from_pem(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem).context("ACME cache blob is not UTF-8")?;
    let mut blocks = text
        .split("-----BEGIN ")
        .skip(1)
        .filter_map(|block| block.split_once("-----\n"))
        .map(|(_label, body)| body.split("-----END").next().unwrap_or(""));

    let _private_key = blocks
        .next()
        .context("ACME blob has no private key block")?;
    let leaf = blocks
        .next()
        .context("ACME blob has no certificate after the private key")?;

    use base64::Engine;
    let compact: String = leaf.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .context("leaf certificate is not valid base64")
}

/// AES-256-GCM with the object key as associated data.
///
/// Binding the key means a sealed account blob cannot be moved over a
/// certificate blob, or one filesystem's cache swapped for another's, by
/// anyone who can write to the bucket.
fn seal(keys: &KeyMaterial, object_key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    use aws_lc_rs::aead::{Aad, Nonce, NONCE_LEN};
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("generating a nonce"))?;

    let mut buffer = plaintext.to_vec();
    keys.runtime_seal_key()
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(object_key.as_bytes()),
            &mut buffer,
        )
        .map_err(|_| anyhow::anyhow!("sealing the ACME cache entry"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buffer.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    Ok(out)
}

fn unseal(keys: &KeyMaterial, object_key: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    use aws_lc_rs::aead::{Aad, Nonce, NONCE_LEN};

    if sealed.len() <= NONCE_LEN {
        anyhow::bail!("sealed ACME entry is too short to contain a nonce");
    }
    let (nonce_bytes, body) = sealed.split_at(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    let mut buffer = body.to_vec();
    let plaintext = keys
        .runtime_seal_key()
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(object_key.as_bytes()),
            &mut buffer,
        )
        .map_err(|_| {
            anyhow::anyhow!(
                "the sealed ACME entry did not authenticate — it was written under a \
                 different master key, or it has been tampered with"
            )
        })?;
    Ok(plaintext.to_vec())
}

#[async_trait::async_trait]
impl rustls_acme::CertCache for SealedAcmeCache {
    type EC = anyhow::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let key = cache_key(&self.prefix, "cert", domains, directory_url);
        let loaded = self.load(&key).await?;
        if let Some(pem) = &loaded {
            tracing::info!(?domains, "reusing the cached certificate");
            self.publish_leaf(pem);
        }
        Ok(loaded)
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let key = cache_key(&self.prefix, "cert", domains, directory_url);
        tracing::info!(?domains, "storing a newly issued certificate");
        self.publish_leaf(cert);
        self.store(&key, cert).await
    }
}

#[async_trait::async_trait]
impl rustls_acme::AccountCache for SealedAcmeCache {
    type EA = anyhow::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let key = cache_key(&self.prefix, "account", contact, directory_url);
        self.load(&key).await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let key = cache_key(&self.prefix, "account", contact, directory_url);
        self.store(&key, account).await
    }
}

/// Everything needed to obtain and renew a certificate.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub contacts: Vec<String>,
    /// ACME directory URL. `None` is Let's Encrypt production; point it at
    /// staging or a local Pebble for testing, since production's rate limits
    /// are low and per-domain.
    pub directory: Option<String>,
    /// Key prefix for the sealed cache objects.
    pub prefix: String,
}

/// A running ACME client: the two TLS configurations it needs, and the slot it
/// publishes each certificate to.
pub struct Acme {
    /// For ordinary connections, resolving to the issued certificate.
    pub server_config: Arc<rustls::ServerConfig>,
    /// For TLS-ALPN-01 validation connections, which carry no HTTP at all —
    /// the handshake *is* the proof, and the connection is then closed.
    pub challenge_config: Arc<rustls::ServerConfig>,
    pub certificate: CertificateSlot,
}

impl std::fmt::Debug for Acme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acme").finish_non_exhaustive()
    }
}

/// Start issuance and renewal in the background.
///
/// Returns as soon as the machinery is running, *not* when a certificate
/// exists: issuance needs a round trip to the CA and an inbound challenge
/// connection, so blocking here would mean an enclave that cannot start until
/// the network the parent provides is already working. Until a certificate
/// arrives, TLS handshakes fail and `/enclave/attestation` answers 503 —
/// which is honest, where serving an unbound document would not be.
pub fn start(
    config: &AcmeConfig,
    backend: Arc<dyn Backend>,
    keys: Arc<KeyMaterial>,
) -> Result<Acme> {
    anyhow::ensure!(
        !config.domains.is_empty(),
        "ACME needs at least one --acme-domain: a certificate is issued for names, \
         and the CA reaches those names to verify them"
    );

    let certificate = CertificateSlot::empty();
    let cache = SealedAcmeCache::new(backend, config.prefix.clone(), keys, certificate.clone());

    let mut acme = rustls_acme::AcmeConfig::new(config.domains.clone())
        .contact(config.contacts.iter().map(|c| format!("mailto:{c}")))
        .cache(cache);
    acme = match &config.directory {
        Some(url) => acme.directory(url),
        None => acme.directory_lets_encrypt(true),
    };

    let state = acme.state();
    // Built here rather than taken from `state.default_rustls_config()`, which
    // hardcodes `with_no_client_auth()`. Without this the ACME path would
    // silently never see a client certificate — the identity plumbing would be
    // present, correct, and dead. `state.resolver()` is the supported way to
    // supply the ACME certificate to a configuration you own.
    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions for ACME")?
        .with_client_cert_verifier(crate::serve::client::AnyClientCertificate::new())
        .with_cert_resolver(state.resolver()),
    );
    // The challenge config keeps no client auth: the CA validating
    // TLS-ALPN-01 presents no certificate, and asking for one would be noise
    // on the one handshake that must not fail.
    let challenge_config = state.challenge_rustls_config();
    let mut state = state;

    tracing::info!(
        domains = ?config.domains,
        directory = %config.directory.as_deref().unwrap_or("Let's Encrypt production"),
        "starting ACME; the certificate arrives asynchronously"
    );

    tokio::spawn(async move {
        use futures::StreamExt;
        loop {
            match state.next().await {
                Some(Ok(ok)) => tracing::info!(event = ?ok, "ACME"),
                // Logged at error and *not* fatal: a failed order is often a
                // rate limit or a challenge that has not propagated, and
                // rustls-acme retries with backoff. Killing the runtime would
                // turn a transient CA problem into an outage.
                Some(Err(e)) => tracing::error!(error = ?e, "ACME order failed; will retry"),
                None => {
                    tracing::error!("the ACME state machine stopped; no renewals will happen");
                    break;
                }
            }
        }
    });

    Ok(Acme {
        server_config,
        challenge_config,
        certificate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3fs_core::crypto::MasterSecret;

    fn keys() -> Arc<KeyMaterial> {
        Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([3u8; 32]), [1u8; 16]).unwrap())
    }

    #[test]
    fn sealing_round_trips() {
        let keys = keys();
        let sealed = seal(&keys, "acme/cert-abc", b"the private key and chain").unwrap();
        assert_ne!(sealed, b"the private key and chain");
        let opened = unseal(&keys, "acme/cert-abc", &sealed).unwrap();
        assert_eq!(opened, b"the private key and chain");
    }

    /// Binding the object key stops a sealed blob being moved from one slot to
    /// another by anyone who can write to the bucket.
    #[test]
    fn a_blob_moved_to_another_key_does_not_open() {
        let keys = keys();
        let sealed = seal(&keys, "acme/account-abc", b"account key").unwrap();
        assert!(unseal(&keys, "acme/cert-abc", &sealed).is_err());
    }

    #[test]
    fn another_master_key_cannot_open_it() {
        let sealed = seal(&keys(), "acme/cert-abc", b"secret").unwrap();
        let other =
            Arc::new(KeyMaterial::derive(&MasterSecret::from_bytes([4u8; 32]), [1u8; 16]).unwrap());
        let err = unseal(&other, "acme/cert-abc", &sealed).unwrap_err();
        assert!(format!("{err:#}").contains("authenticate"), "{err:#}");
    }

    #[test]
    fn a_tampered_blob_does_not_open() {
        let keys = keys();
        let mut sealed = seal(&keys, "acme/cert-abc", b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(unseal(&keys, "acme/cert-abc", &sealed).is_err());
    }

    #[test]
    fn a_truncated_blob_is_refused_rather_than_panicking() {
        assert!(unseal(&keys(), "k", &[]).is_err());
        assert!(unseal(&keys(), "k", &[0u8; 8]).is_err());
    }

    /// Staging and production must not share a cache slot: a staging
    /// certificate served in production is rejected by every client.
    #[test]
    fn the_directory_url_changes_the_cache_key() {
        let domains = vec!["enclave.example".to_string()];
        let production = cache_key(
            "",
            "cert",
            &domains,
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        let staging = cache_key(
            "",
            "cert",
            &domains,
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        );
        assert_ne!(production, staging);
    }

    #[test]
    fn different_domains_get_different_keys() {
        let a = cache_key("", "cert", &["a.example".to_string()], "d");
        let b = cache_key("", "cert", &["b.example".to_string()], "d");
        assert_ne!(a, b);
    }

    #[test]
    fn certificates_and_accounts_do_not_collide() {
        let scope = vec!["enclave.example".to_string()];
        assert_ne!(
            cache_key("", "cert", &scope, "d"),
            cache_key("", "account", &scope, "d")
        );
    }

    /// The leaf is the second PEM block. Reading the first would publish the
    /// private key's bytes as the certificate hash — wrong, and alarming.
    #[test]
    fn the_leaf_is_taken_from_after_the_private_key() {
        use base64::Engine;
        let key_der = b"not really a key";
        let leaf_der = b"not really a certificate";
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n\
             -----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(key_der),
            base64::engine::general_purpose::STANDARD.encode(leaf_der),
        );
        assert_eq!(leaf_from_pem(pem.as_bytes()).unwrap(), leaf_der);
    }

    #[test]
    fn a_blob_without_a_certificate_is_an_error() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(leaf_from_pem(pem.as_bytes()).is_err());
    }

    #[test]
    fn a_slot_reports_what_was_last_set() {
        let slot = CertificateSlot::empty();
        assert!(slot.get().is_none());
        slot.set(b"first".to_vec());
        assert_eq!(slot.get().as_deref(), Some(&b"first"[..]));
        slot.set(b"renewed".to_vec());
        assert_eq!(slot.get().as_deref(), Some(&b"renewed"[..]));
    }
}
