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

use crate::serve::tls::TlsIdentity;
use anyhow::{Context, Result};
use s3fs_core::backend::{Backend, PutBlobInput};
use s3fs_core::crypto::KeyMaterial;
use s3fs_core::FsError;

/// The identity currently being served — a rustls config and the leaf that
/// config presents, together.
///
/// A shared slot rather than a fixed value because ACME issues asynchronously
/// and renews later: the certificate at boot is not necessarily the one in use
/// an hour on.
///
/// **The pair is the point.** A connection loads one identity and gets both the
/// configuration it hands to rustls and the certificate that configuration will
/// present, indivisibly. Holding only the leaf — as this did — meant the
/// certificate a connection was attested with came from a global read at
/// response time, which during a renewal is a different certificate from the
/// one the handshake used. There is no rustls API to ask a live connection
/// which certificate it was served, so the answer has to be arranged rather
/// than discovered.
#[derive(Debug, Clone, Default)]
pub struct CertificateSlot(Arc<RwLock<Option<Arc<TlsIdentity>>>>);

impl CertificateSlot {
    /// A slot holding an identity that will never change.
    pub fn fixed(identity: Arc<TlsIdentity>) -> Self {
        CertificateSlot(Arc::new(RwLock::new(Some(identity))))
    }

    pub fn empty() -> Self {
        CertificateSlot::default()
    }

    pub fn set(&self, identity: Arc<TlsIdentity>) {
        let changed = {
            let mut slot = self.0.write().expect("certificate slot poisoned");
            let changed = slot.as_ref().map(|i| i.certificate_der.as_slice())
                != Some(identity.certificate_der.as_slice());
            *slot = Some(identity);
            changed
        };
        if changed {
            if let Some(der) = self.leaf() {
                tracing::info!(
                    certificate_sha256 = %hex::encode(nitro_attestation::sha256(&der)),
                    "serving certificate changed; new connections will use it"
                );
            }
        }
    }

    /// The identity a connection should be served with. Load this **once** per
    /// connection and keep it: reading again later can give a different answer.
    pub fn get(&self) -> Option<Arc<TlsIdentity>> {
        self.0.read().expect("certificate slot poisoned").clone()
    }

    /// The leaf of whatever is current, for reporting only.
    pub fn leaf(&self) -> Option<Vec<u8>> {
        self.get().map(|i| i.certificate_der.clone())
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
        match identity_from_pem(pem) {
            Ok(identity) => self.certificate.set(Arc::new(identity)),
            Err(e) => tracing::error!(
                error = %e,
                "could not build a serving identity from the ACME certificate; \
                 connections will keep using the previous one"
            ),
        }
    }
}

/// Build a complete serving identity from rustls-acme's cached blob.
///
/// The layout is fixed by `AcmeState::parse_cert`: the PKCS#8 private key
/// first, then the chain, leaf first. Taking both halves here is what lets the
/// runtime serve from its own configuration rather than from rustls-acme's
/// resolver — which matters because the resolver is updated before the cache
/// is written, so anything reading the cache would lag what is being served.
/// Serving from the same value we attest removes the divergence rather than
/// narrowing it.
pub fn identity_from_pem(pem: &[u8]) -> Result<TlsIdentity> {
    let blocks = pem_blocks(pem)?;
    let (key, chain) = blocks.split_first().context("ACME blob is empty")?;
    if chain.is_empty() {
        anyhow::bail!("ACME blob has no certificate after the private key");
    }
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key.clone().into());
    TlsIdentity::from_chain(chain.to_vec(), key)
        .context("building a serving configuration from the ACME certificate")
}

/// Every PEM block's DER, in order.
///
/// Delegated to a real PEM parser rather than split on `-----\n`. Only the
/// private key half of rustls-acme's blob is written by rustls-acme; the
/// certificate half is the ACME directory's HTTP response body verbatim
/// (`rustls_acme::state` concatenates the two), so its line endings are the
/// CA's choice. A hand-rolled split on LF drops every CRLF block *without
/// erroring*, which turned a valid issuance into an empty serving slot — and,
/// where a blob mixed the two, into a chain quietly missing its intermediate.
fn pem_blocks(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let blocks = pem::parse_many(pem).context("ACME blob is not valid PEM")?;
    Ok(blocks
        .into_iter()
        .map(|block| block.into_contents())
        .collect())
}

/// Second PEM block of rustls-acme's cached blob.
pub fn leaf_from_pem(pem: &[u8]) -> Result<Vec<u8>> {
    let mut blocks = pem_blocks(pem)?.into_iter();
    let _private_key = blocks
        .next()
        .context("ACME blob has no private key block")?;
    blocks
        .next()
        .context("ACME blob has no certificate after the private key")
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
    /// PEM trust root for the directory's *own* HTTPS certificate.
    ///
    /// `None` uses the public roots rustls-acme is built with, which is what
    /// any real CA needs. A test CA like Pebble serves its API under a
    /// certificate no public root signed, so its root has to be supplied — and
    /// only a `testing` build can supply one, because a production enclave that
    /// would take issuance orders from a CA of the operator's choosing is not
    /// one this runtime offers.
    pub directory_ca: Option<Vec<u8>>,
    /// Key prefix for the sealed cache objects.
    pub prefix: String,
}

/// A running ACME client: the two TLS configurations it needs, and the slot it
/// publishes each certificate to.
pub struct Acme {
    /// For TLS-ALPN-01 validation connections, which carry no HTTP at all —
    /// the handshake *is* the proof, and the connection is then closed.
    pub challenge_config: Arc<rustls::ServerConfig>,
    /// Where each issued certificate is published, and where every connection
    /// takes its serving identity.
    ///
    /// Deliberately not rustls-acme's own resolver: `process_cert` deploys a
    /// renewed certificate to the resolver *before* the cache callback that
    /// would publish it here, so serving from one while attesting the other
    /// would attest a certificate the connection was never served.
    pub certificate: CertificateSlot,
    /// Fired once the listener is accepting, releasing the first order.
    ///
    /// A challenge is a connection *inbound* to :443, so ordering before the
    /// socket exists guarantees the first attempt fails. Against Pebble that
    /// costs a retry; against Let's Encrypt it spends one of five failed
    /// validations per hour on every boot, and a crash-looping enclave would
    /// lock itself out of issuance.
    pub listening: Arc<tokio::sync::Notify>,
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
/// arrives, TLS handshakes fail — which is honest, where serving a document
/// bound to a certificate nobody was served would not be.
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
    // Only when a root was supplied. Left alone, rustls-acme keeps the public
    // roots it was compiled with, so the ordinary path gains no new trust and
    // no new dependency.
    if let Some(pem) = &config.directory_ca {
        let mut roots = rustls::RootCertStore::empty();
        for der in pem_blocks(pem).context("reading the ACME directory's trust root")? {
            roots
                .add(rustls::pki_types::CertificateDer::from(der))
                .context("the ACME directory's trust root is not a usable certificate")?;
        }
        anyhow::ensure!(
            !roots.is_empty(),
            "the ACME directory trust root contains no certificates"
        );
        tracing::warn!(
            certificates = roots.len(),
            "trusting a private root for the ACME directory; this is a test configuration"
        );
        acme = acme.client_tls_config(Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::aws_lc_rs::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .context("selecting TLS protocol versions for the ACME client")?
            .with_root_certificates(roots)
            .with_no_client_auth(),
        ));
    }

    let state = acme.state();
    // The challenge config keeps no client auth: the CA validating
    // TLS-ALPN-01 presents no certificate, and asking for one would be noise
    // on the one handshake that must not fail.
    let challenge_config = state.challenge_rustls_config();
    let mut state = state;

    let listening = Arc::new(tokio::sync::Notify::new());
    let wait_for_listener = listening.clone();

    tracing::info!(
        domains = ?config.domains,
        directory = %config.directory.as_deref().unwrap_or("Let's Encrypt production"),
        "ACME is configured; ordering starts once the listener is up"
    );

    tokio::spawn(async move {
        use futures::StreamExt;
        // Nothing is ordered until something can answer the challenge. The CA
        // validates by connecting *in* on :443, so an order placed before the
        // listener exists is an order that fails — reliably, on every boot.
        //
        // `Notify` and not a flag: it keeps a permit if the server binds first,
        // so this cannot miss the signal by being slow to start.
        wait_for_listener.notified().await;
        tracing::info!("the listener is up; ordering a certificate");
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
        challenge_config,
        certificate,
        listening,
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

    /// PEM is line-ending agnostic, and this blob is not all ours to format.
    ///
    /// rustls-acme concatenates its own LF private key with the ACME
    /// directory's response body verbatim, so a CA that emits CRLF produces a
    /// blob the runtime must still read. Splitting on `-----\n` dropped those
    /// blocks silently: issuance succeeded, the serving slot stayed empty, and
    /// the enclave answered no HTTPS at all.
    #[test]
    fn a_crlf_certificate_is_read_like_any_other() {
        let key_der = vec![9u8; 8];
        let leaf_der = vec![4u8; 12];
        let block = |label: &str, der: &[u8], eol: &str| {
            use base64::Engine;
            let body = base64::engine::general_purpose::STANDARD.encode(der);
            format!("-----BEGIN {label}-----{eol}{body}{eol}-----END {label}-----{eol}")
        };

        for eol in ["\n", "\r\n"] {
            let blob = format!(
                "{}{}",
                block("PRIVATE KEY", &key_der, eol),
                block("CERTIFICATE", &leaf_der, eol)
            );
            assert_eq!(
                pem_blocks(blob.as_bytes()).unwrap(),
                vec![key_der.clone(), leaf_der.clone()],
                "line ending {eol:?} must not change what is read"
            );
            assert_eq!(leaf_from_pem(blob.as_bytes()).unwrap(), leaf_der);
        }
    }

    /// The quiet one: a chain that mixes endings must not lose a link.
    ///
    /// A dropped intermediate still parses and still serves, so nothing fails
    /// until a client that needed it rejects the chain.
    #[test]
    fn a_chain_mixing_line_endings_keeps_every_link() {
        use base64::Engine;
        let der = |b: u8| vec![b; 10];
        let block = |label: &str, d: &[u8], eol: &str| {
            let body = base64::engine::general_purpose::STANDARD.encode(d);
            format!("-----BEGIN {label}-----{eol}{body}{eol}-----END {label}-----{eol}")
        };
        let blob = format!(
            "{}{}{}",
            block("PRIVATE KEY", &der(1), "\n"),
            block("CERTIFICATE", &der(2), "\n"),
            block("CERTIFICATE", &der(3), "\r\n"),
        );
        assert_eq!(
            pem_blocks(blob.as_bytes()).unwrap(),
            vec![der(1), der(2), der(3)],
            "the CRLF intermediate was dropped"
        );
    }

    #[test]
    fn a_blob_without_a_certificate_is_an_error() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(leaf_from_pem(pem.as_bytes()).is_err());
    }

    #[test]
    fn a_slot_reports_what_was_last_set() {
        let first = Arc::new(TlsIdentity::self_signed(&["first.test".into()]).expect("first"));
        let renewed =
            Arc::new(TlsIdentity::self_signed(&["renewed.test".into()]).expect("renewed"));

        let slot = CertificateSlot::empty();
        assert!(slot.get().is_none());
        assert!(slot.leaf().is_none());

        slot.set(first.clone());
        assert_eq!(slot.leaf(), Some(first.certificate_der.clone()));

        slot.set(renewed.clone());
        assert_eq!(slot.leaf(), Some(renewed.certificate_der.clone()));
    }

    /// The property the whole slot exists for: an identity taken out of it is a
    /// configuration *and* the leaf that configuration presents, so a
    /// connection served from one can be attested with the other. Reading them
    /// separately is what let a renewal attest a certificate the connection was
    /// never served.
    #[test]
    fn an_identity_pairs_a_config_with_the_leaf_it_presents() {
        let identity = Arc::new(TlsIdentity::self_signed(&["paired.test".into()]).expect("built"));
        let slot = CertificateSlot::fixed(identity.clone());

        let loaded = slot.get().expect("an identity");
        assert_eq!(loaded.certificate_der, identity.certificate_der);
        assert!(Arc::ptr_eq(&loaded.config, &identity.config));

        // A renewal replaces the pair; a connection holding the old one is
        // unaffected, which is the case that matters.
        let renewed = Arc::new(TlsIdentity::self_signed(&["renewed.test".into()]).expect("built"));
        slot.set(renewed);
        assert_eq!(
            loaded.certificate_der, identity.certificate_der,
            "a loaded identity must not change under a renewal"
        );
    }
}
