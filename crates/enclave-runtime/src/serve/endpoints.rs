//! Runtime-owned HTTP endpoints, under `/enclave/`.
//!
//! These are answered by the runtime and never reach the guest. The paths
//! follow nitriding's, so tooling written against that convention works here.
//!
//! | Path | Purpose |
//! |---|---|
//! | `GET /enclave/attestation?nonce=<hex>` | a fresh, signed attestation document |
//! | `GET /enclave/config` | what this enclave is, in non-secret terms |
//!
//! The prefix is reserved: a guest cannot serve anything under `/enclave/`,
//! because a guest that could would be able to answer attestation requests
//! itself — with whatever it liked.

use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use nitro_attestation::AttestationHashes;
use nitro_nsm::{AttestationRequest, Nsm};

use crate::serve::acme::CertificateSlot;
use tokio::sync::Semaphore;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;

/// Path prefix the runtime answers and the guest never sees.
pub const ENCLAVE_PREFIX: &str = "/enclave/";

/// A nonce shorter than this is not worth calling a nonce.
const MIN_NONCE_BYTES: usize = 8;
/// The NSM's own request field limit is far higher; this is a sanity bound.
const MAX_NONCE_BYTES: usize = 64;

/// Attestation requests in flight at once.
///
/// Each one is an NSM round trip that produces an ECDSA P-384 signature —
/// orders of magnitude more expensive than the ~62 µs `GetRandom` measured in
/// the entropy milestone, and reachable by anyone who can open a connection.
/// The cap keeps an unauthenticated endpoint from monopolising the device that
/// the rest of the runtime also depends on.
const CONCURRENT_ATTESTATIONS: usize = 4;

/// What this enclave will say about itself.
pub struct EnclaveEndpoints {
    nsm: Arc<dyn Nsm>,
    /// Read on every request rather than captured once: with ACME the
    /// certificate arrives after startup and is replaced on renewal, and
    /// attesting a certificate that is no longer being presented would break
    /// the binding for every client at exactly the moment it mattered.
    certificate: CertificateSlot,
    guest: [u8; 32],
    /// Learned at startup from a document with no nonce.
    pcr0: Option<Vec<u8>>,
    module_id: Option<String>,
    limit: Semaphore,
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
        let probe = match certificate.get() {
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
                .get()
                .map(|der| hex::encode(nitro_attestation::sha256(&der)))
                .unwrap_or_else(|| "(not issued yet)".into()),
            guest_sha256 = %hex::encode(guest),
            pcr0 = %pcr0.as_deref().map(hex::encode).unwrap_or_else(|| "(unknown)".into()),
            "attestation is available"
        );

        Ok(EnclaveEndpoints {
            nsm,
            certificate,
            guest,
            pcr0,
            module_id,
            limit: Semaphore::new(CONCURRENT_ATTESTATIONS),
        })
    }

    /// What a document would bind right now, or `None` before a certificate
    /// exists.
    pub fn hashes(&self) -> Option<AttestationHashes> {
        self.certificate.get().map(|der| AttestationHashes {
            tls_certificate: nitro_attestation::sha256(&der),
            guest: self.guest,
        })
    }

    /// Answer if the path is ours, otherwise `None` so the guest sees it.
    pub async fn handle(
        &self,
        path: &str,
        query: Option<&str>,
    ) -> Option<hyper::Response<HyperOutgoingBody>> {
        if !path.starts_with(ENCLAVE_PREFIX) {
            return None;
        }
        Some(match &path[ENCLAVE_PREFIX.len()..] {
            "attestation" => self.attestation(query).await,
            "config" => self.config(),
            other => text(
                hyper::StatusCode::NOT_FOUND,
                format!("no runtime endpoint {other:?}\n"),
            ),
        })
    }

    async fn attestation(&self, query: Option<&str>) -> hyper::Response<HyperOutgoingBody> {
        let nonce = match nonce_from_query(query) {
            Ok(nonce) => nonce,
            Err(e) => return text(hyper::StatusCode::BAD_REQUEST, format!("{e:#}\n")),
        };

        let Ok(_permit) = self.limit.acquire().await else {
            return text(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "attestation is shutting down\n".to_string(),
            );
        };

        // No certificate means no binding, and a document without one would
        // let a client believe its connection was attested when it was not.
        let Some(hashes) = self.hashes() else {
            return text(
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "no certificate has been issued yet, so nothing can be bound to it\n".to_string(),
            );
        };
        let request = AttestationRequest::with_user_data(hashes.serialize()).nonce(nonce);
        match self.nsm.attest(&request) {
            Ok(document) => {
                let body = base64::engine::general_purpose::STANDARD.encode(&document);
                hyper::Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header("content-type", "text/plain; charset=utf-8")
                    // A document is bound to the nonce in it; caching one
                    // would serve a stale answer to a different challenge.
                    .header("cache-control", "no-store")
                    .body(full(body))
                    .expect("response is well formed")
            }
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "NSM refused an attestation request");
                text(
                    hyper::StatusCode::INTERNAL_SERVER_ERROR,
                    "the Nitro Security Module did not produce a document\n".to_string(),
                )
            }
        }
    }

    /// Everything here is public by construction — hashes of things a client
    /// can already see, and measurements the attestation document repeats
    /// under signature. Nothing secret belongs on an unauthenticated endpoint.
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
        out.push_str("attestation      GET /enclave/attestation?nonce=<hex>\n");
        text(hyper::StatusCode::OK, out)
    }
}

/// Pull `nonce` out of a query string.
///
/// Required, not optional. A document without a caller-chosen nonce cannot be
/// shown to be fresh, so serving one on request would invite exactly the
/// mistake the nonce exists to prevent — a client accepting a document
/// captured from an earlier boot.
fn nonce_from_query(query: Option<&str>) -> Result<Vec<u8>> {
    let query = query.unwrap_or("");
    let value = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("nonce="))
        .context("missing ?nonce=<hex>; a document without one cannot be shown to be fresh")?;

    let nonce = hex::decode(value).context("nonce is not hex")?;
    if nonce.len() < MIN_NONCE_BYTES || nonce.len() > MAX_NONCE_BYTES {
        anyhow::bail!(
            "nonce is {} bytes, expected between {MIN_NONCE_BYTES} and {MAX_NONCE_BYTES}",
            nonce.len()
        );
    }
    Ok(nonce)
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

    #[test]
    fn a_valid_nonce_decodes() {
        let nonce = nonce_from_query(Some("nonce=00112233445566778899")).unwrap();
        assert_eq!(nonce.len(), 10);
    }

    #[test]
    fn a_nonce_among_other_parameters_is_found() {
        assert!(nonce_from_query(Some("a=1&nonce=0011223344556677&b=2")).is_ok());
    }

    /// Serving an un-nonced document on demand would let a captured one be
    /// replayed indefinitely.
    #[test]
    fn a_missing_nonce_is_refused() {
        let err = nonce_from_query(None).unwrap_err();
        assert!(format!("{err:#}").contains("fresh"), "{err:#}");
        assert!(nonce_from_query(Some("other=1")).is_err());
    }

    #[test]
    fn a_short_or_oversized_nonce_is_refused() {
        assert!(nonce_from_query(Some("nonce=0011")).is_err());
        assert!(nonce_from_query(Some(&format!("nonce={}", "aa".repeat(65)))).is_err());
    }

    #[test]
    fn a_non_hex_nonce_is_refused() {
        assert!(nonce_from_query(Some("nonce=zzzzzzzzzzzzzzzz")).is_err());
    }

    #[tokio::test]
    async fn only_the_enclave_prefix_is_claimed() {
        let endpoints = fake_endpoints();
        assert!(endpoints.handle("/", None).await.is_none());
        assert!(endpoints.handle("/counter", None).await.is_none());
        // A guest route that merely starts with the same letters is not ours.
        assert!(endpoints.handle("/enclaves/list", None).await.is_none());
        assert!(endpoints.handle("/enclave/config", None).await.is_some());
    }

    #[tokio::test]
    async fn an_attestation_request_carries_the_binding_and_the_nonce() {
        let nsm = Arc::new(nitro_nsm::fake::FakeNsm::new());
        let endpoints = EnclaveEndpoints::new(
            nsm.clone(),
            CertificateSlot::fixed(b"a certificate".to_vec()),
            b"a guest",
        )
        .expect("endpoints");

        let response = endpoints
            .handle("/enclave/attestation", Some("nonce=00112233445566778899"))
            .await
            .expect("ours");
        assert_eq!(response.status(), 200);

        let request = nsm
            .last_attestation_request
            .lock()
            .unwrap()
            .clone()
            .expect("the device was asked");
        assert_eq!(
            request.nonce.as_deref(),
            Some(&hex::decode("00112233445566778899").unwrap()[..])
        );
        assert_eq!(
            request.user_data.as_deref(),
            Some(&AttestationHashes::new(b"a certificate", b"a guest").serialize()[..]),
            "user_data must bind the certificate and the guest"
        );
    }

    #[tokio::test]
    async fn a_document_is_never_cached() {
        let endpoints = fake_endpoints();
        let response = endpoints
            .handle("/enclave/attestation", Some("nonce=00112233445566778899"))
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "no-store",
            "a cached document would answer a different nonce"
        );
    }

    #[tokio::test]
    async fn config_reports_the_binding_without_secrets() {
        let endpoints = fake_endpoints();
        let response = endpoints.handle("/enclave/config", None).await.unwrap();
        assert_eq!(response.status(), 200);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        let hashes = AttestationHashes::new(b"a certificate", b"a guest");
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
        assert!(
            EnclaveEndpoints::new(nsm, CertificateSlot::fixed(b"cert".to_vec()), b"guest").is_err()
        );
    }

    fn fake_endpoints() -> EnclaveEndpoints {
        EnclaveEndpoints::new(
            Arc::new(nitro_nsm::fake::FakeNsm::new()),
            CertificateSlot::fixed(b"a certificate".to_vec()),
            b"a guest",
        )
        .expect("endpoints")
    }
}
