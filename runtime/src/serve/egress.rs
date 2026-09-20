//! The origins a guest may reach, when a deployment names any.
//!
//! A guest reaches nothing by default — see [`super::EgressPolicy`]. Some guests
//! cannot do their job from inside that: a wallet cosigner that holds a pre-signed
//! renewal has to talk to the service it renews with, and the only alternative is
//! routing the conversation through a phone that may be off. So a deployment may
//! name **origins** — scheme, host and port, nothing else — and a guest may send
//! `wasi:http` requests to exactly those.
//!
//! What that does and does not open:
//!
//! - **Origins, compared exactly.** `https://asp.example.com` admits that host on
//!   443 and nothing else: not a subdomain, not another port, not plaintext to
//!   the same name. No wildcards, no paths, no user info.
//! - **HTTPS is verified against the public web PKI** (webpki roots, the same
//!   store the runtime's own FCM client uses). A plaintext `http://` origin is
//!   admitted only when named as one — which is for a local development stack
//!   and is measured like every other choice.
//! - **It is part of the image.** The list reaches the runtime as image
//!   environment, so PCR0 covers it: a client verifying an enclave learns where
//!   its guest can send traffic, and changing it is a new image.
//! - **It is a channel out of the enclave.** Whatever the guest puts in a request
//!   leaves the attested boundary. Name only services the guest has to reach, and
//!   treat the guest code as the thing deciding what they are sent.
//!
//! Requests travel over HTTP/1.1, from a fresh connection per request.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http_body_util::BodyExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::{
    bindings::http::types::ErrorCode,
    body::{HyperIncomingBody, HyperOutgoingBody},
    hyper_request_error,
    types::{HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig},
};

/// One origin a guest may reach.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Origin {
    pub tls: bool,
    /// Lowercase.
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Parse `https://host[:port]` or `http://host[:port]`. Anything more — a
    /// path, a query, user info, a wildcard — is refused rather than ignored,
    /// because an entry that reads as narrower than it is would be the worst kind
    /// of mistake in this list.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (tls, rest) = if let Some(rest) = s.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = s.strip_prefix("http://") {
            (false, rest)
        } else {
            bail!("guest egress origin {s:?} must start with https:// or http://");
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() || rest.contains(['/', '?', '#', '@', '*']) {
            bail!("guest egress origin {s:?} must be scheme://host[:port] and nothing else");
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(']') || host.ends_with(']') => (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .with_context(|| format!("guest egress origin {s:?} has an invalid port"))?,
            ),
            _ => (rest, if tls { 443 } else { 80 }),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':'))
        {
            bail!("guest egress origin {s:?} has an invalid host");
        }
        Ok(Origin {
            tls,
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// The origin a request is addressed to, or `None` if it names none.
    fn of(request: &hyper::Request<HyperOutgoingBody>, use_tls: bool) -> Option<Self> {
        let uri = request.uri();
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            None => use_tls,
            Some(_) => return None,
        };
        let authority = uri.authority()?;
        Some(Origin {
            tls,
            host: authority.host().to_ascii_lowercase(),
            port: authority.port_u16().unwrap_or(if tls { 443 } else { 80 }),
        })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}:{}", self.host, self.port)
    }
}

/// The origins a deployment admits.
#[derive(Debug, Default)]
pub struct EgressAllowlist {
    origins: BTreeSet<Origin>,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl EgressAllowlist {
    /// Parse every entry, failing on the first that does not parse. Empty
    /// entries are dropped: an image built with no origins still sets the
    /// variable, to nothing.
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self> {
        let origins = entries
            .iter()
            .map(|e| e.as_ref().trim())
            .filter(|e| !e.is_empty())
            .map(Origin::parse)
            .collect::<Result<BTreeSet<_>>>()?;
        let tls = if origins.iter().any(|o| o.tls) {
            Some(Arc::new(crate::notify::web_pki_client_config()?))
        } else {
            None
        };
        Ok(EgressAllowlist { origins, tls })
    }

    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    pub fn origins(&self) -> impl Iterator<Item = &Origin> {
        self.origins.iter()
    }

    /// Whether `request` is addressed to an admitted origin.
    ///
    /// The scheme the URI names and the TLS flag the guest set must agree: a
    /// guest cannot name `https://` and have it sent in the clear, or the reverse.
    pub fn admits(
        &self,
        request: &hyper::Request<HyperOutgoingBody>,
        config: &OutgoingRequestConfig,
    ) -> Option<Origin> {
        let origin = Origin::of(request, config.use_tls)?;
        (origin.tls == config.use_tls && self.origins.contains(&origin)).then_some(origin)
    }

    /// Send from the RUNTIME's own code rather than on a guest's behalf.
    ///
    /// Same connection, same TLS, same allowlist — the caller has already had
    /// `origin` admitted. What differs is only the shape of the answer: a guest
    /// gets a `wasi:http` future it will poll, and the runtime gets a response
    /// it can await. Used by [`crate::stream`], which holds connections that no
    /// guest could hold for itself.
    pub async fn send_direct(
        &self,
        origin: Origin,
        request: hyper::Request<HyperOutgoingBody>,
        first_byte_timeout: std::time::Duration,
    ) -> std::result::Result<HeldResponse, ErrorCode> {
        let config = OutgoingRequestConfig {
            use_tls: origin.tls,
            connect_timeout: std::time::Duration::from_secs(10),
            first_byte_timeout,
            // A held stream is quiet between events; a service that has said
            // nothing for this long is one worth reconnecting to.
            between_bytes_timeout: std::time::Duration::from_secs(300),
        };
        let incoming = send(origin, self.tls.clone(), request, config).await?;
        Ok(HeldResponse {
            response: incoming.resp,
            _worker: incoming.worker,
        })
    }

    /// Send `request` to `origin`, which [`Self::admits`] has already approved.
    pub fn send(
        &self,
        origin: Origin,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HostFutureIncomingResponse {
        let tls = self.tls.clone();
        let handle = wasmtime_wasi::runtime::spawn(async move {
            Ok(send(origin, tls, request, config).await)
        });
        HostFutureIncomingResponse::pending(handle)
    }
}

/// A response, with the connection that is still feeding it.
///
/// The body of a `hyper` response is fed by a task driving the connection, and that task is
/// abort-on-drop. Handing back the response alone therefore ends the body the moment the call
/// returns — for a request/response exchange nobody notices, because the whole body is already
/// buffered, but for a stream held open it means the stream ends immediately and cleanly. That is
/// not a hypothetical: it is what `send_direct` did, and the symptom was a service being dialled
/// once a second for ever with no failures recorded and nothing ever delivered.
///
/// So the worker rides along, and the caller keeps this alive for as long as it reads.
pub struct HeldResponse {
    pub response: hyper::Response<HyperIncomingBody>,
    _worker: Option<wasmtime_wasi::runtime::AbortOnDropJoinHandle<()>>,
}

async fn send(
    origin: Origin,
    tls: Option<Arc<rustls::ClientConfig>>,
    mut request: hyper::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
) -> std::result::Result<IncomingResponse, ErrorCode> {
    let OutgoingRequestConfig {
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
        ..
    } = config;

    // To the origin as admitted, not to whatever the URI's authority spells: the
    // two agree by construction, and connecting to the parsed value leaves no
    // second interpretation to disagree with.
    let host = origin.host.trim_start_matches('[').trim_end_matches(']');
    let tcp = timeout(connect_timeout, TcpStream::connect((host, origin.port)))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|e| {
            tracing::warn!(%origin, error = %e, "guest egress: could not connect");
            ErrorCode::ConnectionRefused
        })?;

    let (mut sender, worker) = if origin.tls {
        let config = tls.ok_or(ErrorCode::InternalError(Some(
            "no TLS configuration for an https origin".into(),
        )))?;
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(|e| {
                tracing::warn!(%origin, error = %e, "guest egress: TLS failed");
                ErrorCode::TlsProtocolError
            })?;
        let (sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(TokioIo::new(stream)),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "guest egress connection ended");
            }
        });
        (sender, worker)
    } else {
        let (sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(TokioIo::new(tcp)),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "guest egress connection ended");
            }
        });
        (sender, worker)
    };

    // Origin-form on the wire: the scheme and authority are only sent to a proxy.
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    *request.uri_mut() = hyper::Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;
    // HTTP/1.1 requires Host; a guest that did not set one gets the origin's.
    if !request.headers().contains_key(hyper::header::HOST) {
        let value = if (origin.tls && origin.port == 443) || (!origin.tls && origin.port == 80) {
            origin.host.clone()
        } else {
            format!("{}:{}", origin.host, origin.port)
        };
        request.headers_mut().insert(
            hyper::header::HOST,
            value.parse().map_err(|_| ErrorCode::HttpRequestUriInvalid)?,
        );
    }

    let resp = timeout(first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(hyper_request_error)?
        .map(|body| body.map_err(hyper_request_error).boxed_unsync());

    Ok(IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;
    use std::time::Duration;

    fn request(uri: &str) -> hyper::Request<HyperOutgoingBody> {
        hyper::Request::builder()
            .uri(uri)
            .body(
                Empty::<bytes::Bytes>::new()
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap()
    }

    fn config(use_tls: bool) -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls,
            connect_timeout: Duration::from_secs(2),
            first_byte_timeout: Duration::from_secs(2),
            between_bytes_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn an_origin_is_scheme_host_and_port_and_nothing_else() {
        assert_eq!(
            Origin::parse("https://ASP.example.com").unwrap(),
            Origin { tls: true, host: "asp.example.com".into(), port: 443 }
        );
        assert_eq!(
            Origin::parse("http://192.168.127.254:7070/").unwrap(),
            Origin { tls: false, host: "192.168.127.254".into(), port: 7070 }
        );
        for bad in [
            "asp.example.com",
            "ftp://asp.example.com",
            "https://asp.example.com/v1",
            "https://asp.example.com?x=1",
            "https://user@asp.example.com",
            "https://*.example.com",
            "https://asp.example.com:0",
            "https://asp.example.com:99999",
            "https://",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn only_the_exact_origin_is_admitted() {
        let list = EgressAllowlist::parse(&["https://asp.example.com", "http://127.0.0.1:7070"])
            .unwrap();
        let admits = |uri: &str, tls: bool| list.admits(&request(uri), &config(tls)).is_some();

        assert!(admits("https://asp.example.com/v1/info", true));
        assert!(admits("https://asp.example.com:443/v1/info", true));
        assert!(admits("http://127.0.0.1:7070/v1/batch/events", false));

        assert!(!admits("https://evil.example.com/", true), "another host");
        assert!(!admits("https://sub.asp.example.com/", true), "a subdomain");
        assert!(!admits("https://asp.example.com:8443/", true), "another port");
        assert!(!admits("http://asp.example.com/", false), "plaintext to a TLS origin");
        assert!(!admits("http://127.0.0.1:7071/", false), "the admin port beside it");
        assert!(
            !admits("https://asp.example.com/", false),
            "the scheme and the guest's TLS flag must agree"
        );
    }

    #[test]
    fn an_empty_list_admits_nothing() {
        let list = EgressAllowlist::parse(&["", "  "]).unwrap();
        assert!(list.is_empty());
        assert!(list.admits(&request("https://example.com/"), &config(true)).is_none());
    }

    /// An admitted request really goes out, and the answer really comes back.
    #[tokio::test]
    async fn an_admitted_request_reaches_the_origin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
                .await
                .unwrap();
            head
        });

        let list = EgressAllowlist::parse(&[format!("http://127.0.0.1:{port}")]).unwrap();
        let req = request(&format!("http://127.0.0.1:{port}/v1/info?x=1"));
        let origin = list.admits(&req, &config(false)).expect("admitted");
        let response = send(origin, None, req, config(false)).await.expect("sent");
        assert_eq!(response.resp.status(), 200);
        let body = response.resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello");

        let head = server.await.unwrap();
        assert!(head.starts_with("GET /v1/info?x=1 HTTP/1.1"), "origin-form: {head}");
        assert!(
            head.to_ascii_lowercase().contains(&format!("host: 127.0.0.1:{port}")),
            "{head}"
        );
    }
}
