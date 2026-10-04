//! Serving a `wasi:http/proxy` guest over plaintext HTTP.
//!
//! The runtime owns the connection, the TLS session and the HTTP parser; the
//! guest receives a parsed request and returns a response. It never sees a
//! socket, a certificate, or a TLS record — [`crate::linker`] does not give it
//! `wasi:sockets` permission to open one, and the one outbound path `wasi:http`
//! offers is [`GuestEgress`], where the runtime makes the connection itself.
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
pub mod egress;
mod http;
pub mod pool;
pub mod progress;
pub mod tls;

pub use acme::{AcmeConfig, CertificateSlot, SealedAcmeCache};
pub use client::{apply_tenant, X_ENCLAVE_TENANT};
pub use egress::Origin;
pub use http::{serve_component, GuestInstance, ServeConfig, ServeHandle, Server, Tenancy};
pub use pool::{Checkout, LiveTenant, PoolLimits, Slot, TenantPool};
pub use tls::{TlsIdentity, TlsMode};

use wasmtime_wasi_http::p2::{
    bindings::http::types::ErrorCode, body::HyperOutgoingBody, types::HostFutureIncomingResponse,
    types::OutgoingRequestConfig, HttpResult, WasiHttpHooks,
};

/// What the guest is allowed to do with `wasi:http/outgoing-handler`: reach the public
/// internet, through a connection the runtime makes — see [`egress`].
///
/// `wasmtime-wasi-http`'s `default-send-request` feature is off in this
/// crate's manifest, which turns `send_request` from a defaulted method into a
/// required one. That is deliberate: with the feature on, a guest importing
/// `outgoing-handler` silently gains real network egress through a rustls
/// instance and root store that nothing in this codebase configures or
/// audits. Making the method mandatory means the answer has to be written
/// down, and this is where it is written down.
///
/// Whatever the guest puts in a request leaves the attested boundary, so what
/// it sends is the guest's code to decide, and that code is measured into
/// PCR16. Where it can send is decided by address, not by any setting: the
/// metadata service, the proxy, this machine and the operator's network are
/// out of reach of every guest.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestEgress;

impl WasiHttpHooks for GuestEgress {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        // The scheme the URI names and the TLS flag the guest set must agree: a
        // guest cannot name `https://` and have it sent in the clear, or the reverse.
        let Some(origin) = egress::Origin::of(&request, config.use_tls)
            .filter(|origin| origin.tls == config.use_tls)
        else {
            tracing::warn!(
                uri = %request.uri(),
                "guest attempted an outgoing HTTP request with no origin, or one whose scheme \
                 and TLS setting disagree; denied"
            );
            return Err(ErrorCode::HttpRequestDenied.into());
        };
        tracing::debug!(%origin, path = %request.uri().path(), "guest egress");
        Ok(egress::spawn_send(origin, request, config))
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

    /// A request whose scheme and TLS setting disagree is refused before anything is sent:
    /// `https://` must not leave in the clear.
    #[test]
    fn a_scheme_that_disagrees_with_the_tls_setting_is_refused() {
        // `let ... else` rather than `expect_err`: the success type is a
        // pending response future and does not implement `Debug`.
        let Err(err) = GuestEgress.send_request(empty_request(), test_config(false)) else {
            panic!("https:// sent in the clear must be refused");
        };
        assert!(
            format!("{err:?}").contains("HttpRequestDenied"),
            "denial must be reported as HTTP-request-denied, got {err:?}"
        );
    }

    fn test_config(use_tls: bool) -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls,
            connect_timeout: std::time::Duration::from_secs(1),
            first_byte_timeout: std::time::Duration::from_secs(1),
            between_bytes_timeout: std::time::Duration::from_secs(1),
        }
    }
}
