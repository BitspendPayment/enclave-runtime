//! Where a guest may send: the public internet, and nothing else.
//!
//! A guest reaches outward through `wasi:http`, and the runtime makes the connection for it.
//! What it may reach is decided here, on the address a name resolves to and never on the name:
//! the parent answers this enclave's DNS, so a name can be pointed anywhere, and `2852039166` is
//! as good a spelling of 169.254.169.254 as the dotted one.
//!
//! What a public-only rule keeps out of reach, and why each one matters:
//!
//! - **The instance metadata service** (link-local): the parent's role credentials, and with them
//!   every tenant's storage.
//! - **The proxy's own network** (192.168.127.0/24): gvproxy's control API on `.1`, which asks
//!   for no credential and can unpublish this enclave; this enclave on `.2`; the runtime's own way
//!   to the metadata service on `.253`; the parent's loopback on `.254`.
//! - **This machine** (loopback, `0.0.0.0`): the runtime's own listener.
//! - **The operator's network** (private and shared ranges): whatever the parent can reach that
//!   the internet cannot.
//!
//! Nothing here is configured, so nothing here can be configured wrong: a guest that has to reach
//! a service reaches it on the public internet. The image no longer says where a guest may send —
//! the guest's code, measured into PCR16, does. In the emulator (the `testing` build) the host's
//! services sit on `.254`, and that one address is open on every port but the runtime's own
//! there; see [`admit_dev_host`].
//!
//! HTTPS is verified against the public web PKI, the same roots the runtime's own clients use. A
//! redirect is never followed here: a 3xx goes back to the guest, and a request it then makes is
//! checked like any other. Requests travel over HTTP/1.1, from a fresh connection per request.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http_body_util::BodyExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::{
    bindings::http::types::{DnsErrorPayload, ErrorCode},
    body::{HyperIncomingBody, HyperOutgoingBody},
    hyper_request_error,
    types::{HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig},
};

/// The emulator's host, as gvproxy presents it to the enclave.
const DEV_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 254);

/// Whether a guest may connect to `addr`: a public IPv4 address, or — in the emulator only —
/// [`DEV_HOST`] on a port that is not in `dev_host`, the runtime's own there.
pub(crate) fn admits(addr: SocketAddr, dev_host: Option<&[u16]>) -> bool {
    // gvproxy carries IPv4 only, so an IPv6 destination is unreachable or an IPv4 one in
    // disguise, which `to_canonical` turns back into what it is.
    let IpAddr::V4(ip) = addr.ip().to_canonical() else {
        return false;
    };
    if let Some(own) = dev_host.filter(|_| ip == DEV_HOST) {
        return !own.contains(&addr.port());
    }
    let [a, b, c, _] = ip.octets();
    !(a == 0 // 0.0.0.0 is this machine, on Linux
        || a >= 224 // multicast, 240/4 and broadcast
        || ip.is_private() // 10/8, 172.16/12, 192.168/16, the proxy's /24 among them
        || ip.is_loopback()
        || ip.is_link_local() // 169.254/16: the metadata service, time sync, the VPC resolver
        || ip.is_documentation()
        || (a == 100 && b & 0xc0 == 64) // 100.64/10, shared address space
        || (a == 198 && b & 0xfe == 18) // 198.18/15, benchmarking
        || (a == 192 && b == 0 && c == 0)) // 192.0.0/24, protocol assignments
}

/// The emulator's exemption: the ports on [`DEV_HOST`] the runtime uses itself. Set once at boot.
#[cfg(any(test, feature = "testing"))]
static DEV_HOST_OWN_PORTS: std::sync::OnceLock<Vec<u16>> = std::sync::OnceLock::new();

/// Open the emulator's host to guests, except `own` — the ports of the runtime's own services
/// there, its store and its certificate authority among them.
///
/// The emulator's services (an ASP, a payout platform) live on the host, which the enclave reaches
/// only as `.254`, so a guest under test needs it. Only in a `testing` build, and only once: the
/// image's own boot sets it, and nothing after can widen it.
#[cfg(any(test, feature = "testing"))]
pub fn admit_dev_host(own: Vec<u16>) {
    let _ = DEV_HOST_OWN_PORTS.set(own);
}

#[cfg(any(test, feature = "testing"))]
fn dev_host() -> Option<&'static [u16]> {
    DEV_HOST_OWN_PORTS.get().map(Vec::as_slice)
}

#[cfg(not(any(test, feature = "testing")))]
fn dev_host() -> Option<&'static [u16]> {
    None
}

/// Names a unit test points at a local listener, which the rule would otherwise refuse.
#[cfg(test)]
static TEST_HOSTS: std::sync::Mutex<Vec<(String, IpAddr)>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn test_host(name: &str, ip: IpAddr) {
    TEST_HOSTS
        .lock()
        .unwrap()
        .push((name.to_ascii_lowercase(), ip));
}

/// Every address `host` resolves to that a guest may connect to.
///
/// Resolved once, and the connection goes to exactly these: a name cannot answer one address to
/// this check and another to the connect.
async fn public_addrs(host: &str, port: u16) -> std::result::Result<Vec<SocketAddr>, ErrorCode> {
    #[cfg(test)]
    if let Some((_, ip)) = TEST_HOSTS.lock().unwrap().iter().find(|(n, _)| n == host) {
        return Ok(vec![SocketAddr::new(*ip, port)]);
    }
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| {
            tracing::warn!(host, error = %e, "guest egress: could not resolve");
            ErrorCode::DnsError(DnsErrorPayload {
                rcode: None,
                info_code: None,
            })
        })?
        .map(|a| SocketAddr::new(a.ip().to_canonical(), a.port()))
        .collect();
    let admitted: Vec<SocketAddr> = resolved
        .iter()
        .copied()
        .filter(|a| admits(*a, dev_host()))
        .collect();
    if admitted.is_empty() {
        tracing::warn!(
            host,
            ?resolved,
            "guest egress: not the public internet; refused"
        );
        return Err(ErrorCode::DestinationIpProhibited);
    }
    Ok(admitted)
}

/// Where a request is addressed: scheme, host and port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Origin {
    pub tls: bool,
    /// Lowercase.
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Parse `https://host[:port]` or `http://host[:port]`. Anything more — a
    /// path, a query, user info, a wildcard — is refused rather than ignored:
    /// a held stream's origin is an instruction, and one that reads as narrower
    /// than it is would be the worst kind of mistake in it.
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
    pub(crate) fn of(request: &hyper::Request<HyperOutgoingBody>, use_tls: bool) -> Option<Self> {
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

/// Send a guest's `request` to `origin`, as the `wasi:http` future the guest will poll.
pub(crate) fn spawn_send(
    origin: Origin,
    request: hyper::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
) -> HostFutureIncomingResponse {
    let handle =
        wasmtime_wasi::runtime::spawn(async move { Ok(send(origin, request, config).await) });
    HostFutureIncomingResponse::pending(handle)
}

/// Send from the RUNTIME's own code rather than as a guest's future.
///
/// Same connection, same TLS, same rule. What differs is only the shape of the answer: a guest
/// gets a `wasi:http` future it will poll, and the runtime gets a response it can await. Used by
/// [`crate::stream`], which holds connections that no guest could hold for itself.
pub async fn send_direct(
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
    let incoming = send(origin, request, config).await?;
    Ok(HeldResponse {
        response: incoming.resp,
        _worker: incoming.worker,
    })
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
    mut request: hyper::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
) -> std::result::Result<IncomingResponse, ErrorCode> {
    let OutgoingRequestConfig {
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
        ..
    } = config;

    // To the origin as parsed, not to whatever the URI's authority spells: the
    // two agree by construction, and connecting to the parsed value leaves no
    // second interpretation to disagree with. To the addresses checked, and to
    // no other: there is no second lookup for a name to answer differently.
    let host = origin.host.trim_start_matches('[').trim_end_matches(']');
    let tcp = timeout(connect_timeout, async {
        let addrs = public_addrs(host, origin.port).await?;
        TcpStream::connect(&addrs[..]).await.map_err(|e| {
            tracing::warn!(%origin, error = %e, "guest egress: could not connect");
            ErrorCode::ConnectionRefused
        })
    })
    .await
    .map_err(|_| ErrorCode::ConnectionTimeout)??;

    let (mut sender, worker) = if origin.tls {
        let config = crate::notify::web_pki_client_config()
            .map(Arc::new)
            .map_err(|e| ErrorCode::InternalError(Some(format!("{e:#}"))))?;
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
            value
                .parse()
                .map_err(|_| ErrorCode::HttpRequestUriInvalid)?,
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
            Origin {
                tls: true,
                host: "asp.example.com".into(),
                port: 443
            }
        );
        assert_eq!(
            Origin::parse("http://192.168.127.254:7070/").unwrap(),
            Origin {
                tls: false,
                host: "192.168.127.254".into(),
                port: 7070
            }
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

    fn at(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    #[test]
    fn only_the_public_internet_is_admitted() {
        for public in [
            "1.1.1.1:443",
            "8.8.8.8:53",
            "100.63.255.255:80",
            "100.128.0.1:80",
            "172.15.255.255:80",
            "172.32.0.1:80",
            "198.17.255.255:80",
            "198.20.0.1:80",
            "223.255.255.255:80",
            "[::ffff:1.1.1.1]:443",
        ] {
            assert!(
                admits(at(public), None),
                "{public} is on the public internet"
            );
        }
        for private in [
            "0.0.0.0:80",
            "0.1.2.3:80",
            "10.0.0.1:80",
            "100.64.0.1:80",
            "100.127.255.255:80",
            "127.0.0.1:443",
            "169.254.169.254:80",
            "169.254.170.2:80",
            "172.16.0.1:80",
            "172.31.255.255:80",
            "192.0.0.1:80",
            "192.0.2.1:80",
            "192.168.127.1:80",
            "192.168.127.2:443",
            "192.168.127.253:80",
            "192.168.127.254:7070",
            "198.18.0.1:80",
            "198.19.255.255:80",
            "198.51.100.1:80",
            "203.0.113.1:80",
            "224.0.0.1:80",
            "240.0.0.1:80",
            "255.255.255.255:80",
            "[::ffff:169.254.169.254]:80",
            "[::1]:443",
            "[fd00:ec2::254]:80",
            "[2606:4700:4700::1111]:443",
        ] {
            assert!(!admits(at(private), None), "{private} must be refused");
        }
    }

    #[test]
    fn the_emulators_host_is_open_except_the_runtimes_own_services() {
        let own: &[u16] = &[9000, 9180, 14000];
        assert!(admits(at("192.168.127.254:7070"), Some(own)));
        assert!(admits(at("[::ffff:192.168.127.254]:7200"), Some(own)));
        assert!(!admits(at("192.168.127.254:9000"), Some(own)), "its store");
        assert!(!admits(at("192.168.127.254:14000"), Some(own)), "its CA");
        assert!(
            !admits(at("192.168.127.253:80"), Some(own)),
            "its way to the metadata service"
        );
        assert!(
            !admits(at("192.168.127.1:80"), Some(own)),
            "the proxy's control API"
        );
        assert!(
            !admits(at("192.168.127.254:7070"), None),
            "only in the emulator"
        );
    }

    /// The metadata service, however it is spelled — the check runs on what the name resolves
    /// to, and glibc reads every one of these numerically, with no network.
    #[tokio::test]
    async fn every_spelling_of_the_metadata_service_is_refused() {
        for host in [
            "169.254.169.254",
            "2852039166",
            "0xa9fea9fe",
            "0251.0376.0251.0376",
            "169.254.43518",
            "0xa9.0xfe.0xa9.0xfe",
            "::ffff:169.254.169.254",
            "::ffff:a9fe:a9fe",
            "fd00:ec2::254",
            "192.168.127.253",
            "192.168.127.1",
            "0",
            "0.0.0.0",
            "127.1",
        ] {
            assert!(
                matches!(
                    public_addrs(host, 80).await,
                    Err(ErrorCode::DestinationIpProhibited)
                ),
                "{host} must be refused"
            );
        }
        assert!(public_addrs("1.1.1.1", 443).await.is_ok());
    }

    /// A guest's request to this machine never connects, however it names it. A real listener
    /// waits on loopback; without the check, the first of these lands.
    #[tokio::test]
    async fn a_request_to_this_machine_never_connects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        for host in [
            "127.0.0.1",
            "2130706433",
            "0x7f000001",
            "127.1",
            "[::ffff:127.0.0.1]",
            "0.0.0.0",
            "localhost",
        ] {
            let origin = Origin {
                tls: false,
                host: host.into(),
                port,
            };
            let req = request(&format!("http://{host}:{port}/"));
            assert!(
                matches!(
                    send(origin, req, config(false)).await,
                    Err(ErrorCode::DestinationIpProhibited)
                ),
                "{host} must be refused"
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "nothing reached the listener"
        );
    }

    /// An admitted request really goes out, and the answer really comes back: in origin-form,
    /// with the name it was addressed to as its `Host`.
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

        test_host("origin.test", IpAddr::V4(Ipv4Addr::LOCALHOST));
        let req = request(&format!("http://origin.test:{port}/v1/info?x=1"));
        let origin = Origin::of(&req, false).expect("an origin");
        let response = send(origin, req, config(false)).await.expect("sent");
        assert_eq!(response.resp.status(), 200);
        let body = response
            .resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"hello");

        let head = server.await.unwrap();
        assert!(
            head.starts_with("GET /v1/info?x=1 HTTP/1.1"),
            "origin-form: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("host: origin.test:{port}")),
            "{head}"
        );
    }
}
