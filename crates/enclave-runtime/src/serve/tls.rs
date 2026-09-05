//! The TLS certificate the enclave serves, and where its key comes from.
//!
//! The key is generated **inside** the enclave and never leaves it. That is
//! the property the whole design rests on: a certificate whose private key
//! only ever existed in attested memory, whose hash the NSM then signs into an
//! attestation document. A client that checks the binding knows its TLS
//! session terminates in that enclave — not in the EC2 instance hosting it,
//! and not in a proxy the operator controls.
//!
//! Terminating TLS on the parent instance and forwarding plaintext would be
//! far simpler and would give away the entire point.
//!
//! ## Where the key's randomness comes from
//!
//! `rcgen` generates through `aws-lc-rs`, which draws from the kernel. That
//! deserves a note, because [`crate::random`] goes to some trouble to keep the
//! *guest's* `wasi:random` off the kernel pool and on the NSM directly.
//!
//! The two cases differ. The guest's concern is that the runtime might not be
//! in an enclave at all, and nothing in the kernel pool would say so — a
//! silent downgrade. Here, the enclave kernel has exactly one entropy source,
//! the NSM, which it uses to seed its pool before userspace starts; the boot
//! log shows `NSM RNG: returning rand bytes` immediately followed by
//! `random: crng init done`. So inside an enclave the kernel pool *is* NSM
//! entropy.
//!
//! What makes that argument safe to rely on is that it is checked rather than
//! assumed: an enclave image sets `S3FS_RANDOM_SOURCE=nsm`, which refuses to
//! start without a working `/dev/nsm`. If the runtime got that far, it is in
//! an enclave.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A serving certificate and the rustls configuration built from it.
pub struct TlsIdentity {
    /// DER of the leaf certificate — the bytes a client hashes to check the
    /// attestation binding, and therefore what goes into `user_data`.
    pub certificate_der: Vec<u8>,
    pub config: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field(
                "certificate_sha256",
                &hex::encode(nitro_attestation::sha256(&self.certificate_der)),
            )
            .finish()
    }
}

impl TlsIdentity {
    /// Build from a certificate chain and key already in hand — the ACME path.
    ///
    /// `chain` is leaf first, as rustls and every ACME server present it.
    pub fn from_chain(chain: Vec<Vec<u8>>, key: PrivateKeyDer<'static>) -> Result<Self> {
        let leaf = chain.first().context("certificate chain is empty")?.clone();

        let certs: Vec<CertificateDer<'static>> =
            chain.into_iter().map(CertificateDer::from).collect();
        // The provider is named rather than left to `ServerConfig::builder()`,
        // which resolves it from rustls's compiled-in features and **panics**
        // when more than one is present. That is not hypothetical here: the
        // AWS SDK brings rustls with `ring` while this crate asks for
        // `aws-lc-rs`, so in any build with the `aws` feature both exist and
        // there is no unambiguous default. Naming it also keeps the whole
        // image on one implementation of these primitives.
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        // No client certificates. Authentication is a WebAuthn assertion bound
        // to one request — see `crate::auth` — and a certificate would be a
        // second, weaker way to become a tenant that could not bind an
        // approval to a transaction.
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building the TLS configuration")?;

        // No session resumption. This is what makes "the certificate this
        // connection is using" a well-defined thing to attest.
        //
        // rustls calls the certificate resolver while processing every
        // ClientHello, but sends a Certificate message **only on a full
        // handshake** (`server/tls13.rs`, gated on `full_handshake`). A resumed
        // session is authenticated by whatever the client cached from its
        // original handshake — so after an ACME renewal a resumed connection is
        // running on the old certificate while the server has the new one in
        // hand. Attesting the current certificate there would name one the
        // client's session was never authenticated under: a false binding, in
        // exactly the case per-response attestation exists to get right.
        //
        // rustls exposes no way to ask which certificate an earlier session
        // used, so the only correct answer is to have no earlier session. The
        // cost is one handshake signature per connection, which is nothing
        // beside the per-response attestation this enables.
        let mut config = config;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;

        Ok(TlsIdentity {
            certificate_der: leaf,
            config: Arc::new(config),
        })
    }

    /// Generate a self-signed certificate for `domains`.
    ///
    /// **Not available in a production build.** The runtime serves ACME-issued
    /// certificates and nothing else: a certificate the runtime minted for
    /// itself is one an operator can mint too, so it cannot distinguish this
    /// enclave from a process impersonating it — the attestation binding is
    /// what carries that weight, and it binds whatever certificate is being
    /// served, including one that was forged.
    ///
    /// It survives behind `testing` because the test harnesses and the QEMU
    /// emulator have no domain and no reachable CA. A binary built without that
    /// feature refuses `--tls self-signed` outright rather than quietly
    /// generating one, and `rcgen` is not in it at all.
    #[cfg(any(test, feature = "testing"))]
    pub fn self_signed(domains: &[String]) -> Result<Self> {
        let names: Vec<String> = if domains.is_empty() {
            vec!["localhost".to_string()]
        } else {
            domains.to_vec()
        };

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .context("generating the TLS key")?;
        let certificate = rcgen::CertificateParams::new(names.clone())
            .context("building certificate parameters")?
            .self_signed(&key)
            .context("self-signing the certificate")?;

        let key_der = PrivateKeyDer::try_from(key.serialize_der())
            .map_err(|e| anyhow::anyhow!("encoding the TLS key: {e}"))?;
        let identity = Self::from_chain(vec![certificate.der().to_vec()], key_der)?;

        tracing::info!(
            domains = ?names,
            certificate_sha256 = %hex::encode(nitro_attestation::sha256(&identity.certificate_der)),
            "generated a self-signed TLS certificate inside the enclave"
        );
        Ok(identity)
    }
}

/// Where the serving certificate comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Plaintext HTTP. Development, and behind a trusted terminator only —
    /// which inside an enclave means nowhere.
    Off,
    /// Obtain one from an ACME provider over TLS-ALPN-01.
    Acme,
}

impl TlsMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "plaintext" => Ok(TlsMode::Off),
            // Named explicitly so a deployment that asks for it is told why it
            // cannot have it, rather than "expected one of …". No build has
            // this mode, testing included: the QEMU harness was the last user
            // and it now runs a real ACME order against a local Pebble, which
            // is the path production takes.
            "self-signed" | "selfsigned" => Err(
                "this runtime serves ACME-issued certificates only. A self-signed \
                 certificate is one an operator can mint too, so it cannot tell this \
                 enclave apart from something impersonating it. Use --tls acme, \
                 pointing --acme-directory at a test CA if there is no public one."
                    .to_string(),
            ),
            "acme" | "letsencrypt" => Ok(TlsMode::Acme),
            other => Err(format!("expected one of off, acme; got {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_self_signed_identity_has_a_usable_certificate() {
        let identity = TlsIdentity::self_signed(&["enclave.test".to_string()]).unwrap();
        assert!(!identity.certificate_der.is_empty());

        // It must parse as X.509, or the hash going into the attestation
        // document would bind bytes no client could reproduce.
        use x509_parser::prelude::FromDer;
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(&identity.certificate_der).unwrap();
        assert!(cert
            .subject_alternative_name()
            .unwrap()
            .is_some_and(|san| format!("{:?}", san.value).contains("enclave.test")));
    }

    /// Two enclaves, two keys. A shared certificate would let one enclave's
    /// attestation vouch for another's connections.
    #[test]
    fn each_identity_gets_its_own_key() {
        let a = TlsIdentity::self_signed(&[]).unwrap();
        let b = TlsIdentity::self_signed(&[]).unwrap();
        assert_ne!(a.certificate_der, b.certificate_der);
    }

    #[test]
    fn modes_parse_the_documented_values() {
        assert_eq!(TlsMode::parse("off"), Ok(TlsMode::Off));
        assert_eq!(TlsMode::parse("ACME"), Ok(TlsMode::Acme));
        assert!(TlsMode::parse("maybe").is_err());
    }

    /// No build serves a certificate it minted itself, and the refusal says
    /// what to do instead — a runtime that answered "expected one of off, acme"
    /// would leave an operator guessing at a decision that was deliberate.
    #[test]
    fn a_self_signed_deployment_is_refused_with_a_reason() {
        let err = TlsMode::parse("self-signed").unwrap_err();
        assert!(err.contains("ACME-issued certificates only"), "{err}");
        assert!(err.contains("--acme-directory"), "{err}");
    }

    #[test]
    fn an_empty_chain_is_refused() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        assert!(TlsIdentity::from_chain(vec![], key_der).is_err());
    }
}
