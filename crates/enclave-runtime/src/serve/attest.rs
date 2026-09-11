//! A proof, on every response, that this connection is terminated by this
//! enclave.
//!
//! ```text
//!   client nonce ──┐
//!                  ├──▶ NSM ──▶ COSE_Sign1 ──▶ x-enclave-attestation
//!   this connection's leaf ──┘
//! ```
//!
//! # What it proves
//!
//! That the enclave holding the private key for **the certificate this
//! connection was served** is alive now, and saw a nonce the client chose. A
//! client checks it by hashing the certificate from its *own* handshake and
//! comparing. Putting that on every response, rather than behind a separate
//! attestation route, is what makes it need no second round trip and stops it
//! drifting from the connection it describes.
//!
//! # What it does not prove
//!
//! **Nothing about the response body.** The document is generated before the
//! guest runs and binds only the nonce and the certificate. It is not a receipt
//! for what the guest said, and adding one would mean a new `user_data` layout
//! and a verifier that understands it.
//!
//! **Nothing before the request was sent.** By the time a client sees the
//! proof, its request is already inside the enclave. A client that must know
//! first sends a nonced request, verifies, and reuses **the same
//! connection** — which proves more than a separate round trip could, since the
//! binding is per-connection.
//!
//! The client also has to do its part, and the runtime cannot make it: generate
//! the nonce from a CSPRNG per request, compare the document's nonce to the one
//! sent, and treat a *missing* header as a failure. Without the last of those,
//! an attacker who strips the header downgrades every client that does not
//! check.

use std::sync::Arc;

use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;
use nitro_attestation::AttestationHashes;
use nitro_nsm::{AttestationRequest, Nsm};
use tokio::sync::Semaphore;

/// The client's nonce, base64url without padding — the encoding the auth
/// headers already use.
pub const NONCE_HEADER: HeaderName = HeaderName::from_static("x-enclave-nonce");

/// The document, base64 standard — one line, one value, decodable by anything
/// that can read a header.
pub const ATTESTATION_HEADER: HeaderName = HeaderName::from_static("x-enclave-attestation");

/// A nonce shorter than this is not worth calling a nonce.
pub const MIN_NONCE_BYTES: usize = 8;
/// The NSM's own request field limit is far higher; this is a sanity bound.
pub const MAX_NONCE_BYTES: usize = 64;

/// Ceiling on the encoded header.
///
/// A real Nitro document is roughly 4–6 KiB of CBOR — most of it the CA bundle,
/// which is inside the signed payload and cannot be trimmed — so base64 lands
/// near 6–8 KiB. Checked once at startup rather than per request, because a
/// document too large for a header is a deployment fact, not a request-time
/// surprise.
pub const MAX_DOCUMENT_HEADER_BYTES: usize = 16 * 1024;

/// Documents in flight at once.
///
/// Each document is an ECDSA P-384 signature on the device, and the device is
/// one device. This is what stops attestation exhausting the NSM or the
/// blocking pool — and, because it is now on the path of *every* request, it is
/// also the runtime's throughput ceiling.
const CONCURRENT_DOCUMENTS: usize = 4;

/// Why a nonce was not acceptable.
///
/// Every variant is a client mistake and says so plainly — unlike the auth
/// gate, there is nothing here an attacker learns from the distinction.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceError {
    Missing,
    NotAscii,
    NotBase64Url,
    TooShort(usize),
    TooLong(usize),
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceError::Missing => write!(
                f,
                "every request must carry {NONCE_HEADER}: \
                 {MIN_NONCE_BYTES}..={MAX_NONCE_BYTES} random bytes, base64url, unpadded"
            ),
            NonceError::NotAscii => write!(f, "{NONCE_HEADER} is not printable ASCII"),
            NonceError::NotBase64Url => {
                write!(f, "{NONCE_HEADER} is not unpadded base64url")
            }
            NonceError::TooShort(n) => write!(
                f,
                "{NONCE_HEADER} decoded to {n} bytes; the minimum is {MIN_NONCE_BYTES}"
            ),
            NonceError::TooLong(n) => write!(
                f,
                "{NONCE_HEADER} decoded to {n} bytes; the maximum is {MAX_NONCE_BYTES}"
            ),
        }
    }
}

/// A nonce the client chose, already checked.
///
/// A newtype so a validated nonce cannot be confused with arbitrary bytes on
/// the way to the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNonce(Vec<u8>);

impl ClientNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Read and check the nonce.
///
/// Uses the first value: `HeaderMap` keeps every copy a client sent, and
/// `get` returns the first, deterministically. A client that sends two knows
/// which one was bound — it is the one it sent first — rather than having to
/// guess at the runtime's choice.
pub fn nonce_from_headers(headers: &HeaderMap) -> Result<ClientNonce, NonceError> {
    use base64::Engine as _;

    let value = headers.get(&NONCE_HEADER).ok_or(NonceError::Missing)?;
    let text = value.to_str().map_err(|_| NonceError::NotAscii)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .map_err(|_| NonceError::NotBase64Url)?;

    if bytes.len() < MIN_NONCE_BYTES {
        return Err(NonceError::TooShort(bytes.len()));
    }
    if bytes.len() > MAX_NONCE_BYTES {
        return Err(NonceError::TooLong(bytes.len()));
    }
    Ok(ClientNonce(bytes))
}

/// Why a document could not be produced.
#[derive(Debug)]
pub enum AttestError {
    /// No certificate on this connection — plaintext, or nothing issued yet.
    NoCertificate,
    /// The device refused, or the runtime is shutting down.
    Device(String),
    /// The document does not fit in a header.
    TooLarge(usize),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::NoCertificate => {
                write!(f, "this connection has no certificate to bind")
            }
            AttestError::Device(e) => write!(f, "the security module did not answer: {e}"),
            AttestError::TooLarge(n) => write!(
                f,
                "the document is {n} bytes encoded, over the {MAX_DOCUMENT_HEADER_BYTES}-byte \
                 header ceiling"
            ),
        }
    }
}

/// Produces one document per response.
pub struct ResponseAttestor {
    nsm: Arc<dyn Nsm>,
    guest: [u8; 32],
    limit: Arc<Semaphore>,
}

impl std::fmt::Debug for ResponseAttestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseAttestor")
            .field("guest_sha256", &hex::encode(self.guest))
            .field("available", &self.limit.available_permits())
            .finish_non_exhaustive()
    }
}

impl ResponseAttestor {
    pub fn new(nsm: Arc<dyn Nsm>, guest_component: &[u8]) -> Self {
        ResponseAttestor {
            nsm,
            guest: nitro_attestation::sha256(guest_component),
            limit: Arc::new(Semaphore::new(CONCURRENT_DOCUMENTS)),
        }
    }

    /// A document binding `nonce` and the leaf this connection was served.
    ///
    /// The permit is taken **before** the blocking call, not inside it: tokio's
    /// blocking pool queues without bound, so acquiring inside would convert a
    /// burst into thread growth rather than backpressure.
    ///
    /// It is then *moved into* the closure, and this is load-bearing. A
    /// `spawn_blocking` task cannot be cancelled — dropping its `JoinHandle`
    /// only detaches it, and the ioctl runs to completion regardless. A permit
    /// merely borrowed by this future would therefore be released the moment a
    /// caller went away while the device was still working, letting the next
    /// request start a call the limit was supposed to hold back. Since this
    /// runs before the request is routed, and so before any auth gate, a peer
    /// that connects and disconnects in a loop could drive the device past
    /// `CONCURRENT_DOCUMENTS` without ever authenticating. Owning the permit
    /// ties its lifetime to the work rather than to the waiter.
    pub async fn document(
        &self,
        certificate: Option<&[u8]>,
        nonce: &ClientNonce,
    ) -> Result<HeaderValue, AttestError> {
        let leaf = certificate.ok_or(AttestError::NoCertificate)?;
        // Constructed field-wise, not via `AttestationHashes::new`: `self.guest`
        // is already the digest of the component, and `new` hashes what it is
        // given. Passing it there would bind sha256(sha256(guest)) — which
        // verifies against nothing a client can compute.
        let user_data = AttestationHashes {
            tls_certificate: nitro_attestation::sha256(leaf),
            guest: self.guest,
        }
        .serialize();
        let request = AttestationRequest::with_user_data(user_data).nonce(nonce.0.clone());

        let permit = self
            .limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AttestError::Device("attestation is shutting down".into()))?;

        // `Nsm::attest` is a synchronous ioctl. Left inline it would hold a
        // tokio worker thread for the whole signature, which on a per-response
        // path is every worker.
        let nsm = self.nsm.clone();
        let document = tokio::task::spawn_blocking(move || {
            // Held until the ioctl returns, not until this caller does.
            let _permit = permit;
            nsm.attest(&request)
        })
        .await
        .map_err(|e| AttestError::Device(format!("attestation task: {e}")))?
        .map_err(|e| AttestError::Device(format!("{e:#}")))?;

        encode(&document)
    }

    /// Check at startup that a document from this device fits in a header.
    ///
    /// Boot is the only place this can be a hard failure rather than a
    /// per-request surprise, and a runtime that cannot attest its responses
    /// should not accept requests it will have to refuse. It is also the first
    /// call to the device, so an NSM that will not answer at all is found here
    /// rather than on a client's first request.
    ///
    /// Deliberately does **not** take the serving certificate. On the ACME path
    /// there is none yet — issuance needs a round trip to the CA and an inbound
    /// challenge, both of which happen after this — and refusing to start then
    /// would mean no ACME deployment could ever boot. A placeholder is sound
    /// because only the leaf's 32-byte SHA-256 reaches `user_data`, so the
    /// document is the same size whatever certificate is eventually served.
    pub async fn verify_fits(&self) -> Result<usize, AttestError> {
        let probe = ClientNonce(vec![0u8; MAX_NONCE_BYTES]);
        let header = self.document(Some(b"boot-time size probe"), &probe).await?;
        Ok(header.len())
    }
}

/// Base64 the document into a header value.
fn encode(document: &[u8]) -> Result<HeaderValue, AttestError> {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(document);
    if encoded.len() > MAX_DOCUMENT_HEADER_BYTES {
        return Err(AttestError::TooLarge(encoded.len()));
    }
    // Base64 is header-safe by construction, so this cannot fail — but a
    // device returning something unexpected should not panic a request path.
    HeaderValue::from_str(&encoded)
        .map_err(|_| AttestError::Device("document is not a header value".into()))
}

/// Put the document on a response, and take ownership of the name.
///
/// `insert`, never `append`: a guest can set any response header it likes, and
/// `HeaderMap::insert` replaces *every* existing value for the name, so a guest
/// that sets three copies ends up with none of its own. This is the response
/// side of the discipline `apply_tenant` follows for requests.
///
/// `cache-control: no-store` goes with it. A cached attested response is a
/// replayed document, bound to a nonce the next reader never chose.
pub fn attach<B>(response: &mut hyper::Response<B>, document: HeaderValue) {
    let headers = response.headers_mut();
    headers.insert(ATTESTATION_HEADER, document);
    headers.insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
}

/// Take the header away from a response the runtime did not attest.
///
/// The header is runtime-owned, and it was only ever guest-proof because
/// [`attach`] overwrote it on every response. Once some responses are not
/// attested — an operation whose caller already identified the enclave on the
/// `/auth/` exchange and pinned its certificate — "overwritten" stops being
/// true for them, and a guest that sets it would be handing the client a
/// document of its own choosing under the runtime's name.
///
/// So the header is removed rather than left alone. A guest cannot speak here
/// whether or not the runtime is speaking here, which is the property; that it
/// used to hold as a side effect of always attesting was luck, not design.
pub fn strip<B>(response: &mut hyper::Response<B>) {
    response.headers_mut().remove(ATTESTATION_HEADER);
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(NONCE_HEADER, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn encoded(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A cancelled caller must not hand its permit to the next request while
    /// the device is still working on its behalf.
    ///
    /// `spawn_blocking` cannot be cancelled, so the ioctl outlives the future
    /// that asked for it. If the permit were merely borrowed by that future it
    /// would be released on cancellation, and `CONCURRENT_DOCUMENTS` would cap
    /// nothing: with a limit of four this drove eight concurrent calls. The
    /// permit is owned by the closure precisely so this cannot happen — and
    /// since attestation runs ahead of the auth gate, an unauthenticated peer
    /// is the one who would otherwise drive it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cancelled_caller_does_not_release_the_device() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Reports how many `attest` calls are inside the device at once.
        #[derive(Debug)]
        struct SlowNsm {
            inflight: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
        }

        impl nitro_nsm::Nsm for SlowNsm {
            fn get_random(&self, _buf: &mut [u8]) -> anyhow::Result<()> {
                unreachable!("attestation does not draw entropy")
            }

            fn attest(&self, _request: &AttestationRequest) -> anyhow::Result<Vec<u8>> {
                let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                // Long enough that a cancelled caller is gone well before the
                // "device" returns, which is the whole point of the test.
                std::thread::sleep(std::time::Duration::from_millis(300));
                self.inflight.fetch_sub(1, Ordering::SeqCst);
                Ok(vec![0u8; 16])
            }

            fn describe_pcr(&self, _index: u16) -> anyhow::Result<nitro_nsm::Pcr> {
                unreachable!("attestation does not read PCRs")
            }

            fn extend_pcr(&self, _index: u16, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
                unreachable!("attestation does not extend PCRs")
            }

            fn lock_pcr(&self, _index: u16) -> anyhow::Result<()> {
                unreachable!("attestation does not lock PCRs")
            }

            fn describe(&self) -> String {
                "a deliberately slow test device".into()
            }
        }

        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let attestor = Arc::new(ResponseAttestor::new(
            Arc::new(SlowNsm {
                inflight: inflight.clone(),
                peak: peak.clone(),
            }),
            b"guest",
        ));

        let call = |a: Arc<ResponseAttestor>| async move {
            let nonce = ClientNonce(vec![0u8; MIN_NONCE_BYTES]);
            a.document(Some(b"leaf"), &nonce).await
        };

        // Take every permit, then abandon each caller mid-ioctl.
        let abandoned: Vec<_> = (0..CONCURRENT_DOCUMENTS)
            .map(|_| tokio::spawn(call(attestor.clone())))
            .collect();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        for handle in &abandoned {
            handle.abort();
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;

        assert_eq!(
            attestor.limit.available_permits(),
            0,
            "cancelling the callers released permits the device is still using"
        );

        // Fresh callers must queue behind the work that is still running.
        let queued: Vec<_> = (0..CONCURRENT_DOCUMENTS)
            .map(|_| tokio::spawn(call(attestor.clone())))
            .collect();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let observed = peak.load(Ordering::SeqCst);
        for handle in queued {
            let _ = handle.await;
        }

        assert!(
            observed <= CONCURRENT_DOCUMENTS,
            "{observed} concurrent attestations against a limit of {CONCURRENT_DOCUMENTS}"
        );
    }

    #[test]
    fn a_well_formed_nonce_is_accepted() {
        let nonce = [7u8; 20];
        let parsed = nonce_from_headers(&headers_with(&encoded(&nonce))).expect("valid");
        assert_eq!(parsed.as_bytes(), &nonce);
    }

    /// A request with no nonce reaches nothing: there is no value to bind, and
    /// one the runtime chose would prove nothing to the client.
    #[test]
    fn a_missing_nonce_is_refused() {
        assert_eq!(
            nonce_from_headers(&HeaderMap::new()),
            Err(NonceError::Missing)
        );
    }

    #[test]
    fn the_boundaries_are_where_they_are_documented() {
        let ok = |n: usize| nonce_from_headers(&headers_with(&encoded(&vec![0u8; n])));
        assert!(ok(MIN_NONCE_BYTES).is_ok(), "the minimum must be allowed");
        assert!(ok(MAX_NONCE_BYTES).is_ok(), "the maximum must be allowed");
        assert_eq!(
            ok(MIN_NONCE_BYTES - 1),
            Err(NonceError::TooShort(MIN_NONCE_BYTES - 1))
        );
        assert_eq!(
            ok(MAX_NONCE_BYTES + 1),
            Err(NonceError::TooLong(MAX_NONCE_BYTES + 1))
        );
    }

    /// Standard base64 is refused rather than quietly accepted: one encoding,
    /// so a client cannot be right by accident and wrong later.
    #[test]
    fn only_unpadded_base64url_is_accepted() {
        let nonce = [0xffu8; 16];
        let standard = base64::engine::general_purpose::STANDARD.encode(nonce);
        assert!(standard.contains('/') || standard.contains('+') || standard.ends_with('='));
        assert_eq!(
            nonce_from_headers(&headers_with(&standard)),
            Err(NonceError::NotBase64Url)
        );
        assert_eq!(
            nonce_from_headers(&headers_with("not base64 at all!")),
            Err(NonceError::NotBase64Url)
        );
    }

    /// Whatever the guest set, the runtime's value is the only one that
    /// survives — including when the guest sent several. The response-side
    /// mirror of `a_client_cannot_smuggle_a_tenant_header`.
    #[test]
    fn a_guest_cannot_own_the_attestation_header() {
        let mut response = hyper::Response::new(());
        for forged in ["forged-one", "forged-two", "forged-three"] {
            response
                .headers_mut()
                .append(ATTESTATION_HEADER, HeaderValue::from_static(forged));
        }
        response.headers_mut().insert(
            hyper::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=3600"),
        );

        attach(&mut response, HeaderValue::from_static("the-real-document"));

        let values: Vec<_> = response
            .headers()
            .get_all(ATTESTATION_HEADER)
            .iter()
            .collect();
        assert_eq!(values.len(), 1, "the guest's copies survived: {values:?}");
        assert_eq!(values[0], "the-real-document");

        // A cached attested response is a replayed document.
        assert_eq!(
            response
                .headers()
                .get(hyper::header::CACHE_CONTROL)
                .unwrap(),
            "no-store",
            "the guest's caching directive survived"
        );
    }

    #[tokio::test]
    async fn a_document_binds_the_nonce_and_this_connection_certificate() {
        let nsm = Arc::new(nitro_nsm::fake::FakeNsm::new());
        let attestor = ResponseAttestor::new(nsm.clone(), b"a guest");
        let nonce = nonce_from_headers(&headers_with(&encoded(&[3u8; 24]))).unwrap();

        let header = attestor
            .document(Some(b"this connection's leaf"), &nonce)
            .await
            .expect("a document");
        assert!(!header.is_empty());

        let request = nsm
            .last_attestation_request
            .lock()
            .unwrap()
            .clone()
            .expect("the device was asked");
        assert_eq!(request.nonce.as_deref(), Some(nonce.as_bytes()));
        assert_eq!(
            request.user_data.as_deref(),
            // Computed the way a *client* computes it — from the certificate it
            // was served and the component bytes it knows — not from the
            // runtime's own intermediate values. The earlier version of this
            // assertion mirrored a double-hash bug in the code above and so
            // agreed with it; an integration test against a real verifier
            // caught what this one could not.
            Some(&AttestationHashes::new(b"this connection's leaf", b"a guest").serialize()[..]),
            "the document must bind the certificate this connection was served"
        );
    }

    /// Plaintext, or a certificate that has not been issued yet. Refusing is
    /// the only honest answer: there is nothing to bind.
    #[tokio::test]
    async fn a_connection_without_a_certificate_cannot_be_attested() {
        let attestor = ResponseAttestor::new(Arc::new(nitro_nsm::fake::FakeNsm::new()), b"g");
        let nonce = nonce_from_headers(&headers_with(&encoded(&[1u8; 16]))).unwrap();
        assert!(matches!(
            attestor.document(None, &nonce).await,
            Err(AttestError::NoCertificate)
        ));
    }

    /// A device that will not answer fails the request rather than releasing
    /// an unattested response as though it were attested.
    #[tokio::test]
    async fn a_refusing_device_is_an_error_not_a_missing_header() {
        let nsm = Arc::new(nitro_nsm::fake::FakeNsm::new());
        nsm.empty.store(true, std::sync::atomic::Ordering::SeqCst);
        let attestor = ResponseAttestor::new(nsm, b"g");
        let nonce = nonce_from_headers(&headers_with(&encoded(&[1u8; 16]))).unwrap();
        assert!(matches!(
            attestor.document(Some(b"leaf"), &nonce).await,
            Err(AttestError::Device(_))
        ));
    }

    /// The boot check exists so an oversized document stops the runtime rather
    /// than every request.
    #[tokio::test]
    async fn an_oversized_document_is_refused() {
        let nsm = Arc::new(nitro_nsm::fake::FakeNsm::new());
        *nsm.attestation.lock().unwrap() = vec![0u8; MAX_DOCUMENT_HEADER_BYTES];
        let attestor = ResponseAttestor::new(nsm, b"g");
        assert!(matches!(
            attestor.verify_fits().await,
            Err(AttestError::TooLarge(_))
        ));
    }

    /// The check must not need the serving certificate. An ACME deployment has
    /// none at boot — issuance happens later — so a check that asked for one
    /// would refuse to start exactly the deployments this runtime is for.
    #[tokio::test]
    async fn the_boot_check_does_not_need_a_certificate_yet() {
        let nsm = Arc::new(nitro_nsm::fake::FakeNsm::new());
        let attestor = ResponseAttestor::new(nsm, b"g");
        assert!(attestor.verify_fits().await.is_ok());
    }
}
