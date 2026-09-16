//! The one place this runtime opens an outbound connection of its own.
//!
//! Everything else that leaves the enclave goes through an AWS SDK. This does
//! not, because Firebase is not AWS — so the trust decision is made here, in
//! code, rather than inherited from a feature name.
//!
//! # Why the roots are compiled in
//!
//! [`crate::net`] notes that the **parent instance answers DNS**. Certificate
//! validation is therefore the only thing standing between
//! `fcm.googleapis.com` and whatever the parent would prefer to point it at.
//! The anchor set is `webpki-roots`, compiled into the image and covered by
//! PCR0, rather than a file the image happens to ship — so what this enclave
//! trusts outbound is part of what a client attests to.
//!
//! There is deliberately **no custom certificate verifier** on this path.
//! `src/bin/passkey-client.rs` has one; that binary exists to drive a
//! self-signed harness and is behind the `testing` feature. Nothing here may
//! acquire one, whatever a test would find convenient.

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use super::fcm::FcmTransport;

/// Refuse a response larger than this rather than buffering whatever arrives.
/// FCM's answers are small; anything this size is a sign the far end is not
/// FCM.
const MAX_RESPONSE: usize = 64 * 1024;

/// A hyper client pinned to the public roots.
pub struct HttpsTransport {
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<bytes::Bytes>,
    >,
}

impl std::fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsTransport").finish_non_exhaustive()
    }
}

/// The runtime's one client TLS configuration: aws-lc-rs, safe protocol versions, and the
/// `webpki-roots` anchors compiled into the image. Shared with guest egress (`serve::egress`) so
/// there is still one root store to audit, not two.
pub fn web_pki_client_config() -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .context("selecting TLS protocol versions for the FCM client")?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

impl HttpsTransport {
    /// `allow_plaintext` exists for the emulator harness, which points the
    /// runtime at a local stub. It is the same downgrade `--guest-log-endpoint`
    /// already is, and PCR0 records which image was built.
    pub fn new(allow_plaintext: bool) -> Result<Self> {
        let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(web_pki_client_config()?);
        let connector = if allow_plaintext {
            builder
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build()
        } else {
            builder.https_only().enable_http1().enable_http2().build()
        };
        Ok(HttpsTransport {
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }
}

#[async_trait::async_trait]
impl FcmTransport for HttpsTransport {
    async fn send(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Vec<u8>>, String> {
        let (parts, body) = request.into_parts();
        let request = http::Request::from_parts(parts, Full::new(bytes::Bytes::from(body)));

        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| format!("{e}"))?;
        let (parts, body) = response.into_parts();

        // Bounded: a body is read to answer a question, not to be stored, and
        // an unbounded read is an allocation somebody else decides the size of.
        let collected = http_body_util::Limited::new(body, MAX_RESPONSE)
            .collect()
            .await
            .map_err(|e| format!("reading the response body: {e}"))?;
        Ok(http::Response::from_parts(
            parts,
            collected.to_bytes().to_vec(),
        ))
    }
}
