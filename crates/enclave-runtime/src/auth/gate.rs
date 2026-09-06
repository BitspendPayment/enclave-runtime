//! The gate: no verified assertion, no guest.
//!
//! Everything a request must survive before a tenant exists, let alone a warm
//! instance. [`Gate::verify`] is the only way past it and it either returns a
//! [`Verified`] tenant or a [`Denied`]; there is no third outcome and no
//! caller-supplied way to skip it.
//!
//! ## What is checked where
//!
//! `webauthn-rs` owns the assertion itself — `clientDataJSON` names
//! `webauthn.get` and the challenge that was issued, the origin matches
//! exactly, `rpIdHash` is this relying party, user *verification* happened
//! rather than mere presence, and the signature verifies under the stored key.
//!
//! This module owns everything the protocol has no field for:
//!
//! - the challenge exists, has not expired, and has not been used before;
//! - the credential is one this runtime knows and has not revoked;
//! - and the request that arrived is the request the challenge was issued for.
//!
//! That last one is the reason any of this is worth doing. Without it an
//! approval the user gave for one transaction would authorize a different one,
//! and a cosigner that can be made to sign a substituted payload is not a
//! cosigner.
//!
//! ## Why the body is buffered here
//!
//! The binding commits to `sha256(body)`, so the runtime has to have the whole
//! body before it can check it. It is read to a bounded buffer and the hash is
//! computed from **the bytes that will actually be forwarded** — never from a
//! length or digest the client supplied, which would let the client decide what
//! it was approving.

use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use webauthn_rs::prelude::*;

use super::challenge::{ChallengeError, ChallengeStore, RequestBinding};

/// Names the challenge a request is answering.
pub const CHALLENGE_HEADER: &str = "x-webauthn-challenge-id";
/// Carries the assertion: base64url of the `PublicKeyCredential` JSON that
/// `navigator.credentials.get()` produced.
///
/// One header holding the credential verbatim, rather than five holding its
/// parts. The client already has this JSON; splitting it up would mean
/// reassembling a structure by hand on the verifying side, which is exactly
/// where a subtle mismatch would hide.
pub const ASSERTION_HEADER: &str = "x-webauthn-assertion";

/// Every header the gate consumes. Stripped before the guest sees a request,
/// so a guest can neither read a client's assertion nor forge one.
/// Asks for a bidirectional stream rather than an ordinary request.
///
/// Runtime vocabulary, alongside `x-enclave-nonce` and `x-enclave-tenant`, and
/// deliberately not `content-type: application/grpc` or a path prefix. The
/// content type is application data the guest also reads, and two parties
/// interpreting one field is where they come to disagree; a path prefix would
/// bake a service name into a runtime that knows nothing about the guest's
/// routes. This header is impossible to send by accident and trivial to set as
/// gRPC call metadata.
///
/// It is not believed on its own. It must agree with the binding the challenge
/// was issued under — see [`Gate::verify`].
pub const STREAM_HEADER: &str = "x-enclave-stream";

pub const AUTH_HEADERS: [&str; 3] = [CHALLENGE_HEADER, ASSERTION_HEADER, STREAM_HEADER];

/// Ceiling on the assertion header. An assertion is a few hundred bytes; this
/// is loose enough not to matter and tight enough that the header cannot be
/// used to make the runtime allocate.
const MAX_ASSERTION_BYTES: usize = 8 * 1024;

/// What a client is known as, once it has proved it.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Sixteen bytes, matching [`crate::tenant::TenantRoot`] — the plan said
    /// thirty-two, but the directory layout already used sixteen and one
    /// number for one thing is worth more than the extra bits. A minted,
    /// collision-checked 128-bit identifier is ample; it is not a secret and
    /// nothing derives a key from it.
    pub tenant_id: [u8; 16],
    pub credential_id: Vec<u8>,
    /// The buffered body, to be forwarded. Returned rather than re-read
    /// because it has already been consumed to compute the hash, and reading
    /// it twice is not possible.
    ///
    /// `None` for a stream open, where there is no hash and so nothing was
    /// read: the caller forwards the live body instead.
    pub body: Option<Bytes>,
}

/// Why a request did not get past the gate.
///
/// The variants exist for the runtime's log. **Clients are told one thing.** An
/// attacker distinguishing "unknown credential" from "bad signature" learns
/// which guesses to keep making; a legitimate client learns nothing it can act
/// on, because the remedy for all of them is to fetch a new challenge.
#[derive(Debug)]
pub enum Denied {
    /// No assertion at all.
    Missing,
    /// Present but not parseable, or over the size limit.
    Malformed(String),
    Challenge(ChallengeError),
    /// The request is not the one the challenge was issued for.
    NotTheRequest,
    /// No such credential, or it has been revoked.
    UnknownCredential,
    /// The assertion did not verify.
    Assertion(String),
    /// The body was larger than the runtime will buffer.
    BodyTooLarge,
    /// Reading the body failed.
    Body(String),
}

impl Denied {
    /// What the client is told. Deliberately the same for every variant.
    pub fn public_message(&self) -> &'static str {
        match self {
            Denied::BodyTooLarge => "request body too large",
            _ => "a fresh WebAuthn assertion bound to this request is required",
        }
    }

    pub fn status(&self) -> hyper::StatusCode {
        match self {
            Denied::BodyTooLarge => hyper::StatusCode::PAYLOAD_TOO_LARGE,
            _ => hyper::StatusCode::UNAUTHORIZED,
        }
    }
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Denied::Missing => write!(f, "no assertion presented"),
            Denied::Malformed(e) => write!(f, "malformed assertion: {e}"),
            Denied::Challenge(e) => write!(f, "{e}"),
            Denied::NotTheRequest => {
                write!(f, "the assertion was issued for a different request")
            }
            Denied::UnknownCredential => write!(f, "unknown or revoked credential"),
            Denied::Assertion(e) => write!(f, "assertion did not verify: {e}"),
            Denied::BodyTooLarge => write!(f, "request body over the limit"),
            Denied::Body(e) => write!(f, "reading the request body: {e}"),
        }
    }
}

/// One registered passkey, and the tenant it speaks for.
#[derive(Debug, Clone)]
pub struct CredentialRecord {
    pub tenant_id: [u8; 16],
    pub passkey: Passkey,
    /// A revoked credential stays on record rather than being deleted, so a
    /// lost phone's key can be refused by name rather than merely forgotten.
    pub active: bool,
    pub counter: u32,
}

/// Where registered credentials live.
///
/// A trait so the gate can be tested without a filesystem, and so the
/// filesystem-backed implementation can arrive separately without the gate
/// changing.
#[async_trait::async_trait]
pub trait CredentialStore: Send + Sync {
    async fn lookup(&self, credential_id: &[u8]) -> anyhow::Result<Option<CredentialRecord>>;
    /// Record that this credential was used, and at what counter.
    async fn record_use(&self, credential_id: &[u8], counter: u32) -> anyhow::Result<()>;
}

impl std::fmt::Debug for Gate {
    /// Names what it is configured for, never what it holds. A `Debug` that
    /// printed challenges would put single-use secrets in any log line that
    /// formatted a struct containing one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("outstanding_challenges", &self.challenges.outstanding())
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

pub struct Gate {
    webauthn: Webauthn,
    challenges: ChallengeStore,
    credentials: Arc<dyn CredentialStore>,
    max_body_bytes: usize,
}

impl Gate {
    pub fn new(
        webauthn: Webauthn,
        challenges: ChallengeStore,
        credentials: Arc<dyn CredentialStore>,
        max_body_bytes: usize,
    ) -> Self {
        Gate {
            webauthn,
            challenges,
            credentials,
            max_body_bytes,
        }
    }

    pub fn webauthn(&self) -> &Webauthn {
        &self.webauthn
    }

    pub fn challenges(&self) -> &ChallengeStore {
        &self.challenges
    }

    pub fn credentials(&self) -> &Arc<dyn CredentialStore> {
        &self.credentials
    }

    /// Issue a challenge for one intended request.
    ///
    /// The binding is recorded now and compared later; the client cannot
    /// influence it after the fact because it never sees the record.
    pub fn issue(
        &self,
        id: [u8; 16],
        binding: RequestBinding,
        allowed: &[Passkey],
    ) -> Result<RequestChallengeResponse, Denied> {
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(allowed)
            .map_err(|e| Denied::Assertion(e.to_string()))?;
        self.challenges
            .issue(id, binding, state)
            .map_err(Denied::Challenge)?;
        Ok(options)
    }

    /// The whole gate, in the order the checks have to happen.
    ///
    /// Returns the buffered body alongside the identity, because the caller
    /// must forward exactly the bytes that were hashed — anything else would
    /// mean the guest saw a body the user never approved.
    pub async fn verify<B>(&self, req: &mut hyper::Request<B>) -> Result<Verified, Denied>
    where
        B: hyper::body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display,
    {
        let challenge_id = header_bytes(req, CHALLENGE_HEADER)?
            .ok_or(Denied::Missing)
            .and_then(|raw| {
                <[u8; 16]>::try_from(raw.as_slice())
                    .map_err(|_| Denied::Malformed("challenge id is not 16 bytes".into()))
            })?;
        let assertion_json = header_bytes(req, ASSERTION_HEADER)?.ok_or(Denied::Missing)?;
        let assertion: PublicKeyCredential =
            serde_json::from_slice(&assertion_json).map_err(|e| {
                Denied::Malformed(format!("assertion is not a PublicKeyCredential: {e}"))
            })?;

        // Consumed before the body is touched, because the binding is what
        // decides whether there is a body to read at all. Consumed whatever
        // happens next, for the reason it always was: an assertion that was
        // offered and refused has still been seen by whoever sent it, and a
        // second attempt at the same challenge buys them only attempts.
        //
        // One consequence of consuming first: an oversized body now burns its
        // challenge before it is refused, where before the refusal came first.
        // That is the safer direction — the alternative lets a caller probe the
        // size limit without ever spending an approval.
        let (issued_for, state) = self
            .challenges
            .consume(&challenge_id)
            .map_err(Denied::Challenge)?;

        // Two keys, and both must turn. The client's header alone cannot talk
        // the runtime out of hashing a body, and an unbound approval alone
        // cannot be spent on a request that arrived as an ordinary one.
        let asked_for_stream = req.headers().contains_key(STREAM_HEADER);
        let body = match (issued_for.is_stream_open(), asked_for_stream) {
            // The ordinary path, unchanged: buffer, then compare the hash of
            // the bytes that will actually be forwarded.
            (false, false) => {
                let bytes = self.buffer_body(req).await?;
                let arrived_as = RequestBinding::new(
                    req.method().as_str(),
                    req.uri().path(),
                    req.uri().query(),
                    &bytes,
                );
                if arrived_as != issued_for {
                    return Err(Denied::NotTheRequest);
                }
                Some(bytes)
            }
            // A stream open: the route is pinned, the body is not read, not
            // hashed and not held.
            (true, true) => {
                let arrived_as = RequestBinding::stream_open(
                    req.method().as_str(),
                    req.uri().path(),
                    req.uri().query(),
                );
                if arrived_as != issued_for {
                    return Err(Denied::NotTheRequest);
                }
                None
            }
            // An approval offered for the other kind of request. Refused with
            // the same message as everything else, so the mismatch teaches a
            // caller nothing it could not have worked out itself.
            _ => return Err(Denied::NotTheRequest),
        };

        let record = self
            .credentials
            .lookup(assertion.raw_id.as_ref())
            .await
            .map_err(|e| Denied::Assertion(e.to_string()))?
            .filter(|r| r.active)
            .ok_or(Denied::UnknownCredential)?;

        let result = self
            .webauthn
            .finish_passkey_authentication(&assertion, &state)
            .map_err(|e| Denied::Assertion(e.to_string()))?;

        // Belt and braces: `start_passkey_authentication` sets
        // `UserVerificationPolicy::Required`, so the crate has already refused
        // an unverified assertion. Checked again because "a person did this"
        // is the entire claim a cosigner rests on, and a policy that moved
        // upstream should not silently weaken this.
        if !result.user_verified() {
            return Err(Denied::Assertion("user was not verified".into()));
        }

        self.credentials
            .record_use(assertion.raw_id.as_ref(), result.counter())
            .await
            .map_err(|e| Denied::Assertion(e.to_string()))?;

        Ok(Verified {
            tenant_id: record.tenant_id,
            credential_id: assertion.raw_id.as_ref().to_vec(),
            body,
        })
    }

    async fn buffer_body<B>(&self, req: &mut hyper::Request<B>) -> Result<Bytes, Denied>
    where
        B: hyper::body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display,
    {
        // Refused on the declared length where there is one, so an oversized
        // body is rejected before it is read rather than after.
        if let Some(len) = req.body().size_hint().upper() {
            if len as usize > self.max_body_bytes {
                return Err(Denied::BodyTooLarge);
            }
        }

        let mut collected = Vec::new();
        let body = req.body_mut();
        loop {
            let frame = match std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut *body).poll_frame(cx)
            })
            .await
            {
                Some(Ok(frame)) => frame,
                Some(Err(e)) => return Err(Denied::Body(e.to_string())),
                None => break,
            };
            if let Ok(data) = frame.into_data() {
                // Checked as it arrives, not after: a body with no declared
                // length must not be able to exhaust memory by streaming.
                if collected.len() + data.len() > self.max_body_bytes {
                    return Err(Denied::BodyTooLarge);
                }
                collected.extend_from_slice(&data);
            }
        }
        Ok(Bytes::from(collected))
    }
}

fn header_bytes<B>(req: &hyper::Request<B>, name: &str) -> Result<Option<Vec<u8>>, Denied> {
    let Some(value) = req.headers().get(name) else {
        return Ok(None);
    };
    if value.len() > MAX_ASSERTION_BYTES {
        return Err(Denied::Malformed(format!("{name} is too large")));
    }
    let text = value
        .to_str()
        .map_err(|_| Denied::Malformed(format!("{name} is not ASCII")))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .map(Some)
        .map_err(|_| Denied::Malformed(format!("{name} is not base64url")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authenticator::flags;
    use crate::auth::testing::{Harness, Relying, ORIGIN};

    fn plain(method: &str, path: &str, body: &[u8]) -> hyper::Request<http_body_util::Full<Bytes>> {
        hyper::Request::builder()
            .method(method)
            .uri(format!("https://enclave.test{path}"))
            .body(http_body_util::Full::new(Bytes::copy_from_slice(body)))
            .expect("well-formed request")
    }

    /// The happy path, so every refusal below means something.
    #[tokio::test]
    async fn a_bound_assertion_identifies_the_tenant() {
        let h = Harness::new();
        let mut req = h.signed_request("POST", "/sign", b"pay alice");
        let verified = h.gate.verify(&mut req).await.expect("verifies");
        assert_eq!(verified.tenant_id, h.tenant_id);
        assert_eq!(verified.credential_id, h.authenticator.credential_id());
        assert_eq!(verified.body.as_deref(), Some(&b"pay alice"[..]));
    }

    /// A stream open is authorized, and its body is never read.
    #[tokio::test]
    async fn a_stream_open_assertion_opens_a_stream() {
        let h = Harness::new();
        let mut req = h.stream_request("POST", "/enclave.cosign.v1.SigningSession/Sign", b"");
        let verified = h.gate.verify(&mut req).await.expect("verifies");
        assert_eq!(verified.tenant_id, h.tenant_id);
        assert!(
            verified.body.is_none(),
            "a stream open buffered a body it made no promise about"
        );
    }

    /// **The substitution, in the direction this change could have opened.**
    ///
    /// A stream-open approval commits to no body, so if it could be spent on
    /// an ordinary request it would authorize any payload at that route — the
    /// exact attack the body hash exists to stop, reintroduced through a
    /// weaker sibling. Refused because the bindings are different values, not
    /// because anything remembered to check.
    #[tokio::test]
    async fn a_stream_open_assertion_cannot_authorize_an_ordinary_request() {
        let h = Harness::new();
        let mut req = h.stream_request("POST", "/sign", b"pay mallory 1 btc");
        // The client drops the header and sends it as a normal request.
        req.headers_mut().remove(STREAM_HEADER);
        assert!(
            matches!(h.gate.verify(&mut req).await, Err(Denied::NotTheRequest)),
            "an approval that named no body authorized a body"
        );
    }

    /// And the reverse: an ordinary approval cannot be escalated into a
    /// channel by claiming one, which would turn a one-operation approval into
    /// an open-ended session.
    #[tokio::test]
    async fn an_ordinary_assertion_cannot_open_a_stream() {
        let h = Harness::new();
        let mut req = h.signed_request("POST", "/sign", b"pay alice");
        req.headers_mut().insert(
            STREAM_HEADER,
            hyper::header::HeaderValue::from_static("open"),
        );
        assert!(
            matches!(h.gate.verify(&mut req).await, Err(Denied::NotTheRequest)),
            "an approval for one operation was spent on an open channel"
        );
    }

    /// A stream's body is never buffered, so the body limit cannot apply to it.
    ///
    /// This is the point of the whole split: an open-ended stream has no body
    /// to hold, and holding one would be both wrong and unbounded. A body well
    /// past the limit must pass here — where an ordinary request of the same
    /// size is refused, which the test below it still asserts.
    #[tokio::test]
    async fn a_stream_open_body_is_never_buffered_and_so_never_too_large() {
        let h = Harness::with_body_limit(1024);
        let oversized = vec![0x41u8; 8 * 1024];
        let mut req = h.stream_request("POST", "/stream", &oversized);
        let verified = h
            .gate
            .verify(&mut req)
            .await
            .expect("a stream open must not be measured against the body limit");
        assert!(verified.body.is_none());
    }

    /// The whole rule: nothing gets through without one.
    #[tokio::test]
    async fn a_request_without_an_assertion_is_refused() {
        let h = Harness::new();
        let mut req = plain("POST", "/sign", b"pay alice");
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::Missing)
        ));
    }

    /// **The replay.** One approval authorizes one operation, once.
    #[tokio::test]
    async fn an_assertion_cannot_be_used_twice() {
        let h = Harness::new();
        let mut first = h.signed_request("POST", "/sign", b"pay alice");
        let headers = first.headers().clone();
        h.gate.verify(&mut first).await.expect("first use verifies");

        let mut replay = plain("POST", "/sign", b"pay alice");
        *replay.headers_mut() = headers;
        assert!(matches!(
            h.gate.verify(&mut replay).await,
            Err(Denied::Challenge(ChallengeError::Unknown))
        ));
    }

    /// **The substitution.** An approval for one payload must not authorize a
    /// different one — the reason the binding exists at all.
    #[tokio::test]
    async fn an_assertion_for_one_body_cannot_authorize_another() {
        let h = Harness::new();
        let mut req = h.assertion_for(
            ("POST", "/sign", b"pay alice 1 btc"),
            ("POST", "/sign", b"pay mallory 1 btc"),
        );
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::NotTheRequest)
        ));
    }

    #[tokio::test]
    async fn an_assertion_for_one_route_cannot_authorize_another() {
        let h = Harness::new();
        let mut req = h.assertion_for(("POST", "/sign", b"{}"), ("POST", "/policy/limit", b"{}"));
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::NotTheRequest)
        ));
    }

    #[tokio::test]
    async fn an_assertion_for_one_method_cannot_authorize_another() {
        let h = Harness::new();
        let mut req = h.assertion_for(("GET", "/keys", b""), ("DELETE", "/keys", b""));
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::NotTheRequest)
        ));
    }

    /// A query is part of the operation: `?limit=1` is not `?limit=100`.
    #[tokio::test]
    async fn an_assertion_for_one_query_cannot_authorize_another() {
        let h = Harness::new();
        let mut req = h.assertion_for(
            ("POST", "/policy?limit=1", b""),
            ("POST", "/policy?limit=100", b""),
        );
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::NotTheRequest)
        ));
    }

    /// A lost phone's passkey is refused by name, which is why revoked records
    /// are kept rather than deleted.
    #[tokio::test]
    async fn a_revoked_credential_is_refused() {
        let h = Harness::new();
        h.credentials.revoke(h.authenticator.credential_id());
        let mut req = h.signed_request("POST", "/sign", b"pay alice");
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::UnknownCredential)
        ));
    }

    /// A well-formed assertion from a passkey this runtime never registered.
    #[tokio::test]
    async fn an_unregistered_credential_is_refused() {
        let h = Harness::new();
        let stranger = crate::auth::SoftwareAuthenticator::new("enclave.test");
        let id = [3u8; 16];
        let options = h
            .gate
            .issue(
                id,
                RequestBinding::new("POST", "/sign", None, b"x"),
                std::slice::from_ref(&h.passkey),
            )
            .unwrap();
        let assertion = stranger.assert(&Relying::challenge_for(&options), ORIGIN);
        let mut req = Harness::request_with("POST", "/sign", b"x", &id, &assertion);
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::UnknownCredential)
        ));
    }

    /// A phone in a pocket is not a person approving a transaction.
    #[tokio::test]
    async fn an_assertion_without_user_verification_is_refused() {
        let h = Harness::new();
        let id = [4u8; 16];
        let options = h
            .gate
            .issue(
                id,
                RequestBinding::new("POST", "/sign", None, b"x"),
                std::slice::from_ref(&h.passkey),
            )
            .unwrap();
        let assertion = h.authenticator.assert_with(
            &Relying::challenge_for(&options),
            ORIGIN,
            flags::UP, // present, not verified
        );
        let mut req = Harness::request_with("POST", "/sign", b"x", &id, &assertion);
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::Assertion(_))
        ));
    }

    #[tokio::test]
    async fn an_assertion_from_another_origin_is_refused() {
        let h = Harness::new();
        let id = [5u8; 16];
        let options = h
            .gate
            .issue(
                id,
                RequestBinding::new("POST", "/sign", None, b"x"),
                std::slice::from_ref(&h.passkey),
            )
            .unwrap();
        let assertion = h.authenticator.assert(
            &Relying::challenge_for(&options),
            "https://attacker.example",
        );
        let mut req = Harness::request_with("POST", "/sign", b"x", &id, &assertion);
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::Assertion(_))
        ));
    }

    #[tokio::test]
    async fn a_challenge_that_was_never_issued_is_refused() {
        let h = Harness::new();
        let mut req = h.signed_request("POST", "/sign", b"x");
        req.headers_mut().insert(
            CHALLENGE_HEADER,
            hyper::header::HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA"),
        );
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::Challenge(ChallengeError::Unknown))
        ));
    }

    #[tokio::test]
    async fn a_malformed_assertion_is_refused_rather_than_panicking() {
        let h = Harness::new();
        for value in ["", "not-base64url!!", "aGVsbG8"] {
            let mut req = h.signed_request("POST", "/sign", b"x");
            req.headers_mut().insert(
                ASSERTION_HEADER,
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
            assert!(
                h.gate.verify(&mut req).await.is_err(),
                "{value:?} was accepted"
            );
        }
    }

    /// The body must be bounded: it is buffered to be hashed, and an unbounded
    /// buffer is an unauthenticated way to exhaust an enclave's memory.
    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let h = Harness::with_body_limit(16);
        let mut req = h.signed_request("POST", "/sign", &[b'x'; 64]);
        assert!(matches!(
            h.gate.verify(&mut req).await,
            Err(Denied::BodyTooLarge)
        ));
    }

    /// **The race.** Two copies of one assertion, arriving together. Exactly
    /// one may win — a lock that merely looked the challenge up and removed it
    /// separately would let both through, and both would be a signature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_simultaneous_uses_of_one_assertion_race_to_exactly_one_winner() {
        for _ in 0..25 {
            let h = std::sync::Arc::new(Harness::new());
            let mut first = h.signed_request("POST", "/sign", b"pay alice");
            let headers = first.headers().clone();
            let mut second = plain("POST", "/sign", b"pay alice");
            *second.headers_mut() = headers;

            let a = {
                let h = h.clone();
                tokio::spawn(async move { h.gate.verify(&mut first).await.is_ok() })
            };
            let b = {
                let h = h.clone();
                tokio::spawn(async move { h.gate.verify(&mut second).await.is_ok() })
            };
            let winners = [a.await.unwrap(), b.await.unwrap()]
                .into_iter()
                .filter(|ok| *ok)
                .count();
            assert_eq!(winners, 1, "an assertion authorized {winners} requests");
        }
    }

    /// Every refusal tells the client the same thing. Distinguishing them
    /// would tell an attacker which guess to refine.
    #[test]
    fn refusals_are_indistinguishable_to_the_client() {
        let messages = [
            Denied::Missing.public_message(),
            Denied::NotTheRequest.public_message(),
            Denied::UnknownCredential.public_message(),
            Denied::Assertion("signature".into()).public_message(),
            Denied::Challenge(ChallengeError::Expired).public_message(),
        ];
        assert!(
            messages.iter().all(|m| *m == messages[0]),
            "refusals leak which check failed: {messages:?}"
        );
        assert!(messages
            .iter()
            .all(|m| !m.contains("credential") && !m.contains("signature")));
    }
}
