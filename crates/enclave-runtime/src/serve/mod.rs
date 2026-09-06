//! Serving a `wasi:http/proxy` guest over plaintext HTTP.
//!
//! The runtime owns the connection, the TLS session and the HTTP parser; the
//! guest receives a parsed request and returns a response. It never sees a
//! socket, a certificate, or a TLS record — [`crate::linker`] does not give it
//! `wasi:sockets` permission to open one and [`EgressPolicy`] refuses the one
//! outbound path `wasi:http` would otherwise offer.
//!
//! That division is the point of terminating TLS here rather than in front of
//! the enclave. A reverse proxy on the parent instance would see every request
//! in the clear, and the parent is precisely the party an enclave exists to
//! exclude.
//!
//! ```text
//!   :443 ──TLS──▶ hyper ──▶ /enclave/* ──▶ runtime (attestation, config)
//!                       └──▶ everything else ──▶ guest
//! ```

pub mod acme;
pub mod attest;
pub mod client;
pub mod endpoints;
mod http;
pub mod pool;
pub mod progress;
pub mod tls;

pub use acme::{AcmeConfig, CertificateSlot, SealedAcmeCache};
pub use client::{apply_tenant, X_ENCLAVE_TENANT};
pub use endpoints::{EnclaveEndpoints, ENCLAVE_PREFIX};
pub use http::{serve_component, GuestInstance, ServeConfig, ServeHandle, Server, Tenancy};
pub use pool::{Checkout, LiveTenant, PoolLimits, Slot, TenantPool};
pub use tls::{TlsIdentity, TlsMode};

use wasmtime_wasi_http::p2::{
    bindings::http::types::ErrorCode, body::HyperOutgoingBody, types::HostFutureIncomingResponse,
    types::OutgoingRequestConfig, HttpResult, WasiHttpHooks,
};

/// What the guest is allowed to do with `wasi:http/outgoing-handler`.
///
/// `wasmtime-wasi-http`'s `default-send-request` feature is off in this
/// crate's manifest, which turns `send_request` from a defaulted method into a
/// required one. That is deliberate: with the feature on, a guest importing
/// `outgoing-handler` silently gains real network egress through a rustls
/// instance and root store that nothing in this codebase configures or
/// audits. Making the method mandatory means the answer has to be written
/// down, and this is where it is written down.
///
/// A guest inside an enclave should not originate connections. Its filesystem
/// is remote already and reached by the *host*, whose S3 traffic is
/// authenticated and encrypted under keys the guest never holds. Egress from
/// the guest itself would be a channel out of the attested boundary carrying
/// whatever the guest chose to put in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicy {
    /// Every outgoing request fails with `HTTP-request-denied`.
    Denied,
}

impl WasiHttpHooks for EgressPolicy {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        _config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        match self {
            EgressPolicy::Denied => {
                // Logged rather than silently refused: a guest attempting
                // egress is either misconfigured or doing something it should
                // not, and both are worth seeing in the enclave's console.
                tracing::warn!(
                    uri = %request.uri(),
                    "guest attempted an outgoing HTTP request; denied by policy"
                );
                Err(ErrorCode::HttpRequestDenied.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Empty};

    fn empty_request() -> hyper::Request<HyperOutgoingBody> {
        hyper::Request::builder()
            .uri("https://example.invalid/")
            .body(
                Empty::<bytes::Bytes>::new()
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap()
    }

    /// The guest has no outbound network. If this test ever needs changing,
    /// the change is a security decision, not a refactor.
    #[test]
    fn the_guest_cannot_originate_requests() {
        let mut policy = EgressPolicy::Denied;
        // `let ... else` rather than `expect_err`: the success type is a
        // pending response future and does not implement `Debug`.
        let Err(err) = policy.send_request(empty_request(), test_config()) else {
            panic!("egress must be refused");
        };
        assert!(
            format!("{err:?}").contains("HttpRequestDenied"),
            "denial must be reported as HTTP-request-denied, got {err:?}"
        );
    }

    fn test_config() -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls: true,
            connect_timeout: std::time::Duration::from_secs(1),
            first_byte_timeout: std::time::Duration::from_secs(1),
            between_bytes_timeout: std::time::Duration::from_secs(1),
        }
    }
}
