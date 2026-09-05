//! Runtime-owned HTTP endpoints, under `/enclave/`.
//!
//! These are answered by the runtime and never reach the guest. The paths
//! follow nitriding's, so tooling written against that convention works here.
//!
//! | Path | Purpose |
//! |---|---|
//! | `GET /enclave/config` | what this enclave is, in non-secret terms |
//!
//! There is no attestation *endpoint*: every response carries a document in
//! `x-enclave-attestation` (see [`crate::serve::attest`]), so a client never
//! has to correlate one connection's proof with another's. `/enclave/config`
//! is what remains, and it earns its place as the cheap probe route — it needs
//! neither a passkey nor the guest, so a client can verify a connection on it
//! and then reuse that same connection for real work.
//!
//! The prefix is reserved: a guest cannot serve anything under `/enclave/`,
//! because a guest that could would be able to describe the enclave it runs
//! in — with whatever it liked.

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use nitro_attestation::AttestationHashes;
use nitro_nsm::{AttestationRequest, Nsm};

use crate::serve::acme::CertificateSlot;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;

/// Path prefix the runtime answers and the guest never sees.
pub const ENCLAVE_PREFIX: &str = "/enclave/";

/// What this enclave will say about itself.
pub struct EnclaveEndpoints {
    /// Read on every request rather than captured once: with ACME the
    /// certificate arrives after startup and is replaced on renewal, and
    /// attesting a certificate that is no longer being presented would break
    /// the binding for every client at exactly the moment it mattered.
    certificate: CertificateSlot,
    guest: [u8; 32],
    /// Learned at startup from a document with no nonce.
    pcr0: Option<Vec<u8>>,
    module_id: Option<String>,
}

impl EnclaveEndpoints {
    /// Bind a TLS certificate and a guest to this enclave's identity.
    ///
    /// Requests one attestation immediately. That is deliberate: an NSM that
    /// will not attest is a deployment failure, and finding out at boot is far
    /// better than finding out when the first client asks — by which time the
    /// enclave has been serving traffic that nobody could verify.
    pub fn new(
        nsm: Arc<dyn Nsm>,
        certificate: CertificateSlot,
        guest_component: &[u8],
    ) -> Result<Self> {
        let guest = nitro_attestation::sha256(guest_component);

        // Probe with whatever binding exists now. Under ACME there may be no
        // certificate yet, and the probe is still worth making: its purpose is
        // to prove the device answers at all.
        let probe = match certificate.leaf() {
            Some(der) => AttestationRequest::with_user_data(
                AttestationHashes {
                    tls_certificate: nitro_attestation::sha256(&der),
                    guest,
                }
                .serialize(),
            ),
            None => AttestationRequest::default(),
        };
        let document = nsm.attest(&probe).context(
            "the NSM would not produce an attestation document; \
             clients could not verify this enclave",
        )?;

        // Parsed, not verified: we are the enclave that just asked for it, and
        // the point is only to read back the PCRs it reports.
        let (pcr0, module_id) = match nitro_attestation::parse(&document) {
            Ok(parsed) => (parsed.pcr(0).map(<[u8]>::to_vec), Some(parsed.module_id)),
            Err(e) => {
                // Not fatal: serving documents is the job, and a client parses
                // them itself. But it means something is off, so say so.
                tracing::warn!(
                    error = %e,
                    "could not parse our own attestation document; \
                     serving it anyway, but /enclave/config will be thin"
                );
                (None, None)
            }
        };

        tracing::info!(
            tls_certificate_sha256 = %certificate
                .leaf()
                .map(|der| hex::encode(nitro_attestation::sha256(&der)))
                .unwrap_or_else(|| "(not issued yet)".into()),
            guest_sha256 = %hex::encode(guest),
            pcr0 = %pcr0.as_deref().map(hex::encode).unwrap_or_else(|| "(unknown)".into()),
            "attestation is available"
        );

        Ok(EnclaveEndpoints {
            certificate,
            guest,
            pcr0,
            module_id,
        })
    }

    /// What a document would bind right now, or `None` before a certificate
    /// exists.
    pub fn hashes(&self) -> Option<AttestationHashes> {
        self.certificate.leaf().map(|der| AttestationHashes {
            tls_certificate: nitro_attestation::sha256(&der),
            guest: self.guest,
        })
    }

    /// Answer if the path is ours, otherwise `None` so the guest sees it.
    pub async fn handle(&self, path: &str) -> Option<hyper::Response<HyperOutgoingBody>> {
        if !path.starts_with(ENCLAVE_PREFIX) {
            return None;
        }
        Some(match &path[ENCLAVE_PREFIX.len()..] {
            "config" => self.config(),
            other => text(
                hyper::StatusCode::NOT_FOUND,
                format!("no runtime endpoint {other:?}\n"),
            ),
        })
    }

    fn config(&self) -> hyper::Response<HyperOutgoingBody> {
        let mut out = String::new();
        out.push_str("runtime          enclave-runtime ");
        out.push_str(env!("CARGO_PKG_VERSION"));
        out.push('\n');
        if let Some(module) = &self.module_id {
            out.push_str(&format!("module           {module}\n"));
        }
        if let Some(pcr0) = &self.pcr0 {
            out.push_str(&format!("pcr0             {}\n", hex::encode(pcr0)));
        }
        match self.hashes() {
            Some(hashes) => out.push_str(&format!(
                "tls_certificate  sha256:{}\n",
                hex::encode(hashes.tls_certificate)
            )),
            None => out.push_str("tls_certificate  (not issued yet)\n"),
        }
        out.push_str(&format!(
            "guest            sha256:{}\n",
            hex::encode(self.guest)
        ));
        out.push_str("attestation      x-enclave-attestation, on every response\n");
        text(hyper::StatusCode::OK, out)
    }
}

fn full(body: impl Into<Bytes>) -> HyperOutgoingBody {
    Full::new(body.into())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

fn text(status: hyper::StatusCode, body: String) -> hyper::Response<HyperOutgoingBody> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full(body))
        .expect("response is well formed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_the_enclave_prefix_is_claimed() {
        let endpoints = fake_endpoints();
        assert!(endpoints.handle("/").await.is_none());
        assert!(endpoints.handle("/counter").await.is_none());
        // A guest route that merely starts with the same letters is not ours.
        assert!(endpoints.handle("/enclaves/list").await.is_none());
        assert!(endpoints.handle("/enclave/config").await.is_some());
    }

    #[tokio::test]
    async fn config_reports_the_binding_without_secrets() {
        let (endpoints, identity) = fake_endpoints_with();
        let response = endpoints.handle("/enclave/config").await.unwrap();
        assert_eq!(response.status(), 200);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        let hashes = AttestationHashes::new(&identity.certificate_der, b"a guest");
        assert!(
            body.contains(&hex::encode(hashes.tls_certificate)),
            "{body}"
        );
        assert!(body.contains(&hex::encode(hashes.guest)), "{body}");
    }

    /// An NSM that will not attest is a deployment failure, and the runtime
    /// should refuse to start rather than serve traffic nobody can verify.
    #[test]
    fn construction_fails_if_the_device_will_not_attest() {
        let nsm = Arc::new(nitro_nsm::fake::FakeNsm::new());
        nsm.empty.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(EnclaveEndpoints::new(
            nsm,
            CertificateSlot::fixed(std::sync::Arc::new(test_identity())),
            b"guest"
        )
        .is_err());
    }

    /// A real serving identity, because the slot now holds a configuration as
    /// well as a leaf — the pairing is the point.
    fn test_identity() -> crate::serve::tls::TlsIdentity {
        crate::serve::tls::TlsIdentity::self_signed(&["endpoints.test".into()])
            .expect("a self-signed identity")
    }

    /// Endpoints plus the identity in their slot, because a test that asserts
    /// on the binding needs the certificate that was bound.
    fn fake_endpoints_with() -> (
        EnclaveEndpoints,
        std::sync::Arc<crate::serve::tls::TlsIdentity>,
    ) {
        let identity = std::sync::Arc::new(test_identity());
        let endpoints = EnclaveEndpoints::new(
            Arc::new(nitro_nsm::fake::FakeNsm::new()),
            CertificateSlot::fixed(identity.clone()),
            b"a guest",
        )
        .expect("endpoints");
        (endpoints, identity)
    }

    fn fake_endpoints() -> EnclaveEndpoints {
        fake_endpoints_with().0
    }
}
