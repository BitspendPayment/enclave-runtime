//! Who is on the other end of a connection.
//!
//! The runtime authenticates; the guest authorises. This module is the first
//! half: it turns a TLS handshake into an identity, and hands that identity to
//! the guest in a form the client cannot have written.
//!
//! ## Why the certificate is not validated against anything
//!
//! There is no CA here, no chain to build and nothing to expire. A client
//! presents a self-signed certificate and the identity *is* that certificate —
//! what makes it meaningful is not who vouched for it but that the handshake
//! proved possession of the matching private key, which rustls checks in
//! `verify_tls13_signature`. Accepting any certificate while verifying that
//! signature is the whole scheme; accepting any certificate *without*
//! verifying it would let anyone claim anyone's identity, which is why the
//! verifier below delegates those two methods rather than answering them.

use std::sync::Arc;

use hyper::header::{HeaderName, HeaderValue};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

/// Header the guest reads to learn who is calling.
///
/// Injected by the runtime and **stripped from every inbound request first**,
/// so a client sending it themselves cannot be believed. See
/// [`apply_to`](ClientIdentity::apply_to).
pub const X_ENCLAVE_CLIENT: HeaderName = HeaderName::from_static("x-enclave-client");

/// A client, as proved by the TLS handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    key: [u8; 32],
    /// Precomputed, because it is written on every request and building it
    /// costs a 64-byte allocation and a validation scan each time.
    header: HeaderValue,
}

impl ClientIdentity {
    /// Identify a client by the **public key** in its certificate.
    ///
    /// SHA-256 over the `SubjectPublicKeyInfo`, which is the construction
    /// certificate pinning uses (RFC 7469). Not over the whole certificate,
    /// and the difference is the point: a certificate carries a validity
    /// period and a serial number that change on every renewal, so hashing all
    /// of it would make a client who rotates a certificate around the *same
    /// key* look like a different client.
    ///
    /// That would be survivable while an identity only picks a session — a
    /// renewed client would lose in-memory state and no more. It stops being
    /// survivable once an identity derives a filesystem, because a routine,
    /// scheduled renewal would point a client at empty storage while their data
    /// stayed encrypted under keys nothing would ever derive again, in a bucket
    /// that retains objects for ten years.
    ///
    /// The parse comes from `webpki`, which rustls has already run over this
    /// exact certificate to check the handshake signature — so nothing new
    /// enters the image, and no DER is parsed by two implementations.
    ///
    /// `None` if the certificate will not parse, which should be unreachable:
    /// the signature check that admitted this client parsed it first. Anonymous
    /// is the safe direction if it ever happens.
    pub fn from_certificate(der: &[u8]) -> Option<Self> {
        let der = rustls::pki_types::CertificateDer::from(der);
        let parsed = match webpki::EndEntityCert::try_from(&der) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!(error = %e, "a verified client certificate would not parse");
                return None;
            }
        };

        let key = nitro_attestation::sha256(parsed.subject_public_key_info().as_ref());
        let header =
            HeaderValue::from_str(&hex::encode(key)).expect("hex is always a valid header value");
        Some(ClientIdentity { key, header })
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Overwrite the client header with the truth, or remove it.
    ///
    /// `insert`, never `append`: `insert` drops every previous value, whereas
    /// `append` would leave a client's own copies in place — and the guest's
    /// `fields.get()` returns a *list*, so `[0]` would be theirs. That is the
    /// forgery this exists to prevent.
    ///
    /// The `None` arm is not optional. Without it an unauthenticated
    /// connection passes the client's own value straight through, which is the
    /// same forgery by a shorter route.
    pub fn apply_to<B>(this: Option<&ClientIdentity>, req: &mut hyper::Request<B>) {
        match this {
            Some(id) => {
                req.headers_mut()
                    .insert(X_ENCLAVE_CLIENT, id.header.clone());
            }
            None => {
                req.headers_mut().remove(X_ENCLAVE_CLIENT);
            }
        }
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientIdentity({})", hex::encode(self.key))
    }
}

/// Accepts any client certificate, and verifies possession of its key.
///
/// Client authentication is **optional**: a browser or `curl` with no
/// certificate still completes the handshake and arrives with no identity,
/// which the routing above refuses rather than defaults. Requiring it here
/// would break the ACME challenge and every ordinary client.
#[derive(Debug)]
pub struct AnyClientCertificate {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AnyClientCertificate {
    pub fn new() -> Arc<Self> {
        Arc::new(AnyClientCertificate {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }
}

impl ClientCertVerifier for AnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Optional, deliberately. See the type documentation.
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    /// No CA, so no subjects to hint at.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Any certificate is acceptable — it is a name, not a credential. The
    /// credential is the signature verified below.
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    /// Delegated, and this is the load-bearing half: it proves the client holds
    /// the private key for the certificate it presented. Answering `Ok` here
    /// would let anyone claim anyone's identity by copying their certificate,
    /// which is public.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An identity from a real certificate, since one cannot be made from
    /// arbitrary bytes any more.
    fn test_identity(name: &str) -> ClientIdentity {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        ClientIdentity::from_certificate(cert.der()).expect("parses")
    }

    /// The forgery, in the form it actually takes: a client sending the header
    /// itself, several times, hoping one survives.
    #[test]
    fn injection_overwrites_every_value_a_client_supplied() {
        let id = test_identity("the real client");
        let mut req = hyper::Request::builder()
            .uri("http://enclave.test/")
            .header(X_ENCLAVE_CLIENT, "deadbeef")
            .header(X_ENCLAVE_CLIENT, "cafebabe")
            .header(X_ENCLAVE_CLIENT, "f00d")
            .body(())
            .unwrap();

        ClientIdentity::apply_to(Some(&id), &mut req);

        let seen: Vec<_> = req.headers().get_all(X_ENCLAVE_CLIENT).iter().collect();
        assert_eq!(seen.len(), 1, "a client-supplied value survived: {seen:?}");
        assert_eq!(seen[0], &id.header);
    }

    /// The same forgery by the shorter route: no identity at all.
    #[test]
    fn an_unauthenticated_request_carries_no_client_header() {
        let mut req = hyper::Request::builder()
            .uri("http://enclave.test/")
            .header(X_ENCLAVE_CLIENT, "deadbeef")
            .body(())
            .unwrap();

        ClientIdentity::apply_to(None, &mut req);

        assert_eq!(req.headers().get_all(X_ENCLAVE_CLIENT).iter().count(), 0);
    }

    /// Two certificates around one key. Different bytes, different serials —
    /// the same client, and so the same identity.
    ///
    /// This is the whole reason the digest is over the public key rather than
    /// the certificate. Hash the certificate instead and this fails, which is
    /// what a client would experience as their data vanishing on a renewal.
    #[test]
    fn renewing_a_certificate_does_not_change_who_you_are() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();

        let mut first = rcgen::CertificateParams::new(vec!["client-a".to_string()]).unwrap();
        first.serial_number = Some(rcgen::SerialNumber::from(1u64));
        let first = first.self_signed(&key).unwrap();

        let mut renewed = rcgen::CertificateParams::new(vec!["client-a".to_string()]).unwrap();
        renewed.serial_number = Some(rcgen::SerialNumber::from(2u64));
        let renewed = renewed.self_signed(&key).unwrap();

        assert_ne!(
            first.der().as_ref(),
            renewed.der().as_ref(),
            "the certificates must actually differ, or this proves nothing"
        );
        assert_eq!(
            ClientIdentity::from_certificate(first.der()).unwrap().key(),
            ClientIdentity::from_certificate(renewed.der())
                .unwrap()
                .key(),
        );
    }

    /// And a different key is a different client, however alike the
    /// certificates look otherwise.
    #[test]
    fn a_different_key_is_a_different_client() {
        assert_ne!(
            test_identity("client-a").key(),
            test_identity("client-a").key(),
            "two independently generated keys produced one identity"
        );
    }

    #[test]
    fn a_certificate_that_does_not_parse_yields_no_identity() {
        assert!(ClientIdentity::from_certificate(b"not a certificate").is_none());
    }
}
