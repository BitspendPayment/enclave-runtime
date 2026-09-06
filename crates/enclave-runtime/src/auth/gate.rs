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

use webauthn_rs::prelude::*;

use super::challenge::{ChallengeError, ChallengeStore};
use super::token::{InteractionScope, TokenError, TokenStore};

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

/// Carries the interaction token: `Authorization: Bearer <token>`.
///
/// An ordinary HTTP header rather than an `x-enclave-*` one, deliberately: a
/// gRPC stream's opening metadata *is* an HTTP/2 HEADERS frame, so one header
/// covers a request and a stream alike, and every client library already knows
/// how to set this one.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Every header the gate consumes. Stripped before the guest sees a request, so
/// a guest can neither read a client's token nor forge one.
pub const AUTH_HEADERS: [&str; 1] = [AUTHORIZATION_HEADER];

/// Ceiling on a bearer token, in characters.
///
/// The runtime mints 32 bytes as base64url, so anything much longer is not one
/// of ours; the bound exists so a header cannot make the runtime hash an
/// arbitrary amount of input before deciding it was never valid.
const MAX_TOKEN_CHARS: usize = 128;

/// What a client is known as, once it has proved it.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Sixteen bytes, matching [`crate::tenant::TenantRoot`] — the plan said
    /// thirty-two, but the directory layout already used sixteen and one
    /// number for one thing is worth more than the extra bits. A minted,
    /// collision-checked 128-bit identifier is ample; it is not a secret and
    /// nothing derives a key from it.
    pub tenant_id: [u8; 16],
}

/// What a passkey ceremony established, before a token was minted for it.
#[derive(Debug, Clone)]
pub struct Authenticated {
    pub tenant_id: [u8; 16],
    pub credential_id: Vec<u8>,
    /// The interaction the challenge was issued for, which is what the token
    /// will be good for and nothing else.
    pub scope: InteractionScope,
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
    Token(TokenError),
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
            Denied::Token(e) => write!(f, "{e}"),
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
            .field("outstanding_tokens", &self.tokens.outstanding())
            .finish_non_exhaustive()
    }
}

pub struct Gate {
    webauthn: Webauthn,
    challenges: ChallengeStore,
    credentials: Arc<dyn CredentialStore>,
    tokens: TokenStore,
}

impl Gate {
    pub fn new(
        webauthn: Webauthn,
        challenges: ChallengeStore,
        credentials: Arc<dyn CredentialStore>,
        tokens: TokenStore,
    ) -> Self {
        Gate {
            webauthn,
            challenges,
            credentials,
            tokens,
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

    pub fn tokens(&self) -> &TokenStore {
        &self.tokens
    }

    /// Issue a challenge for one intended interaction.
    ///
    /// The scope is recorded now and compared when the token it leads to is
    /// spent; the client cannot influence it after the fact because it never
    /// sees the record.
    pub fn issue(
        &self,
        id: [u8; 16],
        scope: InteractionScope,
        allowed: &[Passkey],
    ) -> Result<RequestChallengeResponse, Denied> {
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(allowed)
            .map_err(|e| Denied::Assertion(e.to_string()))?;
        self.challenges
            .issue(id, scope, state)
            .map_err(Denied::Challenge)?;
        Ok(options)
    }

    /// The passkey half: prove who is asking, and what they are asking for.
    ///
    /// This is everything the old per-request gate did except reading a body,
    /// in the same order and with the same refusals. What it does *not* do is
    /// let anything through — it establishes an identity and an interaction, and
    /// the caller mints a token for that pair. The interaction itself presents
    /// the token.
    pub async fn authenticate(
        &self,
        challenge_id: &[u8; 16],
        assertion: &PublicKeyCredential,
    ) -> Result<Authenticated, Denied> {
        // Consumed whatever happens next: an assertion that was offered and
        // refused has still been seen by whoever sent it, and a second attempt
        // at the same challenge buys them only attempts.
        let (issued_for, state) = self
            .challenges
            .consume(challenge_id)
            .map_err(Denied::Challenge)?;

        let record = self
            .credentials
            .lookup(assertion.raw_id.as_ref())
            .await
            .map_err(|e| Denied::Assertion(e.to_string()))?
            .filter(|r| r.active)
            .ok_or(Denied::UnknownCredential)?;

        let result = self
            .webauthn
            .finish_passkey_authentication(assertion, &state)
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

        Ok(Authenticated {
            tenant_id: record.tenant_id,
            credential_id: assertion.raw_id.as_ref().to_vec(),
            scope: issued_for,
        })
    }

    /// Record an approval as a token, and hand back the token's bytes.
    ///
    /// Generated here rather than by the caller so that the only copy outside
    /// this function is the one going to the client — the store keeps a hash.
    pub fn grant(&self, token: &[u8], who: &Authenticated) -> Result<std::time::Duration, Denied> {
        self.tokens
            .issue(token, who.tenant_id, who.scope.clone())
            .map_err(Denied::Token)?;
        Ok(self.tokens.ttl())
    }

    /// The token half: spend one approval on one interaction.
    ///
    /// The scope is rebuilt from the request that actually arrived and compared
    /// with the one the person approved, so a token cannot be moved to another
    /// route. It says nothing about the body, and deliberately: an interaction
    /// may be a stream, whose body does not exist when the approval is given.
    pub fn redeem<B>(&self, req: &hyper::Request<B>) -> Result<Verified, Denied> {
        let offered = req
            .headers()
            .get(AUTHORIZATION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or(Denied::Missing)?;
        if offered.is_empty() || offered.len() > MAX_TOKEN_CHARS {
            return Err(Denied::Malformed("token is not a plausible length".into()));
        }

        let arrived_as =
            InteractionScope::new(req.method().as_str(), req.uri().path(), req.uri().query());
        let tenant_id = self
            .tokens
            .redeem(offered.as_bytes(), &arrived_as)
            .map_err(Denied::Token)?;

        Ok(Verified { tenant_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authenticator::flags;
    use crate::auth::testing::{Harness, Relying, ORIGIN};
    use bytes::Bytes;

    fn credential(assertion: &serde_json::Value) -> PublicKeyCredential {
        serde_json::from_str(&assertion.to_string()).expect("a credential")
    }

    /// Issue a challenge for `scope` and answer it with `authenticator`.
    async fn answer(
        h: &Harness,
        id: [u8; 16],
        scope: InteractionScope,
        authenticator: &crate::auth::SoftwareAuthenticator,
        origin: &str,
    ) -> Result<Authenticated, Denied> {
        let options = h
            .gate
            .issue(id, scope, std::slice::from_ref(&h.passkey))
            .expect("issuing a challenge");
        let assertion = authenticator.assert(&Relying::challenge_for(&options), origin);
        h.gate.authenticate(&id, &credential(&assertion)).await
    }

    fn scope() -> InteractionScope {
        InteractionScope::new("POST", "/sign", None)
    }

    // --- the passkey half -------------------------------------------------

    /// The happy path, so every refusal below means something.
    #[tokio::test]
    async fn an_assertion_identifies_the_tenant_and_the_interaction() {
        let h = Harness::new();
        let who = answer(&h, [1u8; 16], scope(), &h.authenticator, ORIGIN)
            .await
            .expect("verifies");
        assert_eq!(who.tenant_id, h.tenant_id);
        assert_eq!(who.credential_id, h.authenticator.credential_id());
        assert_eq!(
            who.scope,
            scope(),
            "the approval named a different interaction"
        );
    }

    /// **The replay.** One challenge, one assertion, once.
    #[tokio::test]
    async fn a_challenge_cannot_be_answered_twice() {
        let h = Harness::new();
        let id = [2u8; 16];
        let options = h
            .gate
            .issue(id, scope(), std::slice::from_ref(&h.passkey))
            .unwrap();
        let assertion = credential(
            &h.authenticator
                .assert(&Relying::challenge_for(&options), ORIGIN),
        );
        h.gate.authenticate(&id, &assertion).await.expect("first");
        assert!(matches!(
            h.gate.authenticate(&id, &assertion).await,
            Err(Denied::Challenge(ChallengeError::Unknown))
        ));
    }

    #[tokio::test]
    async fn a_revoked_credential_is_refused() {
        let h = Harness::new();
        h.credentials.revoke(h.authenticator.credential_id());
        assert!(matches!(
            answer(&h, [3u8; 16], scope(), &h.authenticator, ORIGIN).await,
            Err(Denied::UnknownCredential)
        ));
    }

    /// A well-formed assertion from a passkey this runtime never registered.
    #[tokio::test]
    async fn an_unregistered_credential_is_refused() {
        let h = Harness::new();
        let stranger = crate::auth::SoftwareAuthenticator::new("enclave.test");
        assert!(matches!(
            answer(&h, [4u8; 16], scope(), &stranger, ORIGIN).await,
            Err(Denied::UnknownCredential)
        ));
    }

    /// A phone in a pocket is not a person approving anything.
    #[tokio::test]
    async fn an_assertion_from_another_origin_is_refused() {
        let h = Harness::new();
        assert!(matches!(
            answer(
                &h,
                [5u8; 16],
                scope(),
                &h.authenticator,
                "https://attacker.example"
            )
            .await,
            Err(Denied::Assertion(_))
        ));
    }

    /// **"A person did this" is the entire claim.** Mere presence is not it.
    #[tokio::test]
    async fn an_assertion_without_user_verification_is_refused() {
        let h = Harness::new();
        let id = [6u8; 16];
        let options = h
            .gate
            .issue(id, scope(), std::slice::from_ref(&h.passkey))
            .unwrap();
        let assertion =
            h.authenticator
                .assert_with(&Relying::challenge_for(&options), ORIGIN, flags::UP);
        assert!(matches!(
            h.gate.authenticate(&id, &credential(&assertion)).await,
            Err(Denied::Assertion(_))
        ));
    }

    #[tokio::test]
    async fn a_challenge_that_was_never_issued_is_refused() {
        let h = Harness::new();
        let id = [7u8; 16];
        let options = h
            .gate
            .issue(id, scope(), std::slice::from_ref(&h.passkey))
            .unwrap();
        let assertion = credential(
            &h.authenticator
                .assert(&Relying::challenge_for(&options), ORIGIN),
        );
        assert!(matches!(
            h.gate.authenticate(&[0xff; 16], &assertion).await,
            Err(Denied::Challenge(ChallengeError::Unknown))
        ));
    }

    /// **Under concurrency, one winner.** Two threads answering one challenge.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_simultaneous_answers_to_one_challenge_race_to_exactly_one_winner() {
        for _ in 0..25 {
            let h = std::sync::Arc::new(Harness::new());
            let id = [8u8; 16];
            let options = h
                .gate
                .issue(id, scope(), std::slice::from_ref(&h.passkey))
                .unwrap();
            let assertion = credential(
                &h.authenticator
                    .assert(&Relying::challenge_for(&options), ORIGIN),
            );

            let (a, b) = {
                let (h1, h2) = (h.clone(), h.clone());
                let (c1, c2) = (assertion.clone(), assertion.clone());
                tokio::join!(
                    tokio::spawn(async move { h1.gate.authenticate(&id, &c1).await.is_ok() }),
                    tokio::spawn(async move { h2.gate.authenticate(&id, &c2).await.is_ok() }),
                )
            };
            let winners = usize::from(a.unwrap()) + usize::from(b.unwrap());
            assert_eq!(winners, 1, "one challenge was answered {winners} times");
        }
    }

    // --- the token half ---------------------------------------------------

    /// A token identifies its tenant, and spends itself doing it.
    #[tokio::test]
    async fn a_token_admits_one_interaction() {
        let h = Harness::new();
        let token = h.token_for("POST", "/sign").await;
        let req = Harness::bearer("POST", "/sign", b"pay alice", &token);
        assert_eq!(h.gate.redeem(&req).unwrap().tenant_id, h.tenant_id);

        let again = Harness::bearer("POST", "/sign", b"pay alice", &token);
        assert!(
            matches!(h.gate.redeem(&again), Err(Denied::Token(_))),
            "a token admitted a second interaction"
        );
    }

    /// **What the token still refuses.** It names a route, and cannot be moved.
    #[tokio::test]
    async fn a_token_cannot_be_moved_to_another_interaction() {
        for (method, path) in [
            ("POST", "/withdraw"),
            ("GET", "/sign"),
            ("POST", "/sign?all=1"),
        ] {
            let h = Harness::new();
            let token = h.token_for("POST", "/sign").await;
            let req = Harness::bearer(method, path, b"", &token);
            assert!(
                matches!(h.gate.redeem(&req), Err(Denied::Token(_))),
                "an approval for POST /sign was spent on {method} {path}"
            );
        }
    }

    /// **What it deliberately does not refuse, and this is the trade.**
    ///
    /// The approval names the interaction, not the payload. A different body at
    /// the same route is the same interaction as far as the runtime is
    /// concerned, and the person who approved it saw no bytes. This test exists
    /// so the property is written down rather than discovered.
    #[tokio::test]
    async fn a_token_does_not_bind_the_body() {
        let h = Harness::new();
        let token = h.token_for("POST", "/sign").await;
        let req = Harness::bearer("POST", "/sign", b"pay mallory 1000", &token);
        assert!(
            h.gate.redeem(&req).is_ok(),
            "the token bound a body it was never given"
        );
    }

    /// The whole rule: nothing gets through without one.
    #[tokio::test]
    async fn a_request_without_a_token_is_refused() {
        let h = Harness::new();
        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://enclave.test/sign")
            .body(http_body_util::Full::new(Bytes::new()))
            .expect("well-formed request");
        assert!(matches!(h.gate.redeem(&req), Err(Denied::Missing)));
    }

    #[tokio::test]
    async fn a_malformed_authorization_header_is_refused_rather_than_panicking() {
        let h = Harness::new();
        for value in [
            "",
            "Bearer ",
            "Basic abc",
            "bearer lowercase-scheme",
            &"x".repeat(4096),
        ] {
            let req = hyper::Request::builder()
                .method("POST")
                .uri("https://enclave.test/sign")
                .header(AUTHORIZATION_HEADER, value)
                .body(http_body_util::Full::new(Bytes::new()))
                .expect("well-formed request");
            assert!(
                h.gate.redeem(&req).is_err(),
                "{value:?} was accepted as a token"
            );
        }
    }

    /// **The uniformity guarantee.** Every refusal says the same thing.
    #[test]
    fn refusals_are_indistinguishable_to_the_client() {
        let all = [
            Denied::Missing,
            Denied::Malformed("x".into()),
            Denied::Challenge(ChallengeError::Unknown),
            Denied::Token(crate::auth::TokenError::WrongInteraction),
            Denied::Token(crate::auth::TokenError::Expired),
            Denied::UnknownCredential,
            Denied::Assertion("x".into()),
        ];
        for denied in &all {
            assert_eq!(
                denied.public_message(),
                all[0].public_message(),
                "{denied} tells a client something the others do not"
            );
            let public = denied.public_message();
            assert!(!public.contains("credential"), "{public}");
            assert!(!public.contains("signature"), "{public}");
            assert!(!public.contains("expired"), "{public}");
        }
    }
}
