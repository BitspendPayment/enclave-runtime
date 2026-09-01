//! `/auth/*` — the only routes that answer without an assertion.
//!
//! They are runtime-owned in the same sense `/enclave/*` is: refused before
//! dispatch, never forwarded, and unreachable by any guest. That is not a
//! convenience. A guest able to answer under `/auth/` could hand out its own
//! challenges and verify its own assertions, which is the same as having none.
//!
//! Nothing here performs a cosigner action or touches a tenant's directory.
//! The most any of it does is create a tenant — and only against a single-use
//! token an operator provisioned.
//!
//! ## Why registration is two calls
//!
//! WebAuthn registration is a challenge and a response, and the runtime has to
//! remember which challenge it issued while the user holds their thumb to a
//! phone. The state is kept here, keyed by an id the client quotes back, for
//! the same reasons the assertion challenges are: single use, short lived, and
//! bounded, because issuing one is necessarily unauthenticated.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use super::challenge::RequestBinding;
use super::credential::{FilesystemCredentials, StoredCredential};
use super::enrollment::EnrollmentTokens;
use super::gate::Gate;
use super::ratelimit::RateLimiter;

/// The prefix the guest can never see.
pub const AUTH_PREFIX: &str = "/auth/";

/// How long a half-finished registration is held.
const REGISTRATION_TTL: Duration = Duration::from_secs(300);
/// Half-finished registrations allowed at once.
const MAX_REGISTRATIONS: usize = 64;
/// Ceiling on an `/auth/*` request body.
const MAX_BODY: usize = 16 * 1024;

#[derive(Deserialize)]
struct RegisterOptionsRequest {
    enrollment_token: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Serialize)]
struct RegisterOptionsResponse {
    registration_id: String,
    options: CreationChallengeResponse,
}

#[derive(Deserialize)]
struct RegisterVerifyRequest {
    registration_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct RegisterVerifyResponse {
    tenant_id: String,
    credential_id: String,
}

#[derive(Deserialize)]
struct RequestOptionsRequest {
    /// Which passkey the client intends to use. The runtime allows exactly
    /// that one, so an assertion from any other credential fails even before
    /// the credential lookup.
    credential_id: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    /// Base64url SHA-256 of the body the client intends to send.
    ///
    /// Advisory only. The runtime rehashes what actually arrives and compares
    /// against the binding, so a client that lies here has bound its assertion
    /// to a request it cannot then send.
    body_sha256: String,
}

#[derive(Serialize)]
struct RequestOptionsResponse {
    challenge_id: String,
    options: RequestChallengeResponse,
}

struct PendingRegistration {
    state: PasskeyRegistration,
    /// Set when an existing tenant is adding a passkey rather than a new
    /// tenant being created.
    join: Option<[u8; 16]>,
    expires: Instant,
}

impl std::fmt::Debug for AuthEndpoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthEndpoints")
            .field(
                "pending_registrations",
                &self.registrations.lock().map(|r| r.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

pub struct AuthEndpoints {
    gate: Arc<Gate>,
    credentials: Arc<FilesystemCredentials>,
    enrollment: EnrollmentTokens,
    entropy: Arc<dyn nitro_nsm::Nsm>,
    fs: Arc<s3fs_core::Fs>,
    registrations: Mutex<HashMap<[u8; 16], PendingRegistration>>,
    /// Bounds how often one credential can make a phone buzz — see
    /// [`RateLimiter`] for why the key is a credential and not an address.
    challenges: RateLimiter,
}

impl AuthEndpoints {
    pub fn new(
        gate: Arc<Gate>,
        credentials: Arc<FilesystemCredentials>,
        fs: Arc<s3fs_core::Fs>,
        entropy: Arc<dyn nitro_nsm::Nsm>,
    ) -> Self {
        AuthEndpoints {
            enrollment: EnrollmentTokens::new(fs.clone()),
            gate,
            credentials,
            entropy,
            fs,
            registrations: Mutex::new(HashMap::new()),
            challenges: RateLimiter::default(),
        }
    }

    pub fn enrollment(&self) -> &EnrollmentTokens {
        &self.enrollment
    }

    fn random_id(&self) -> anyhow::Result<[u8; 16]> {
        let mut id = [0u8; 16];
        self.entropy.get_random(&mut id)?;
        Ok(id)
    }

    /// Answer an `/auth/*` request, or `None` if this is not one.
    pub async fn handle(
        &self,
        method: &hyper::Method,
        path: &str,
        body: &[u8],
    ) -> Option<hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody>> {
        if !path.starts_with(AUTH_PREFIX) {
            return None;
        }
        if method != hyper::Method::POST {
            return Some(problem(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                "auth routes are POST",
            ));
        }
        if body.len() > MAX_BODY {
            return Some(problem(
                hyper::StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }

        Some(match &path[AUTH_PREFIX.len()..] {
            "register/options" => self.register_options(body).await,
            "register/verify" => self.register_verify(body).await,
            "request/options" => self.request_options(body).await,
            other => problem(
                hyper::StatusCode::NOT_FOUND,
                &format!("no auth endpoint {other:?}"),
            ),
        })
    }

    async fn register_options(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(request) = serde_json::from_slice::<RegisterOptionsRequest>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };

        // Spent before anything else, so a failure later does not hand the
        // token back. A wasted token is an operator inconvenience; a reusable
        // one is an open door.
        match self.enrollment.spend(&request.enrollment_token).await {
            Ok(true) => {}
            Ok(false) => return problem(hyper::StatusCode::FORBIDDEN, "enrollment is not open"),
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "reading enrollment tokens");
                return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        }

        let name = request.display_name.as_deref().unwrap_or("cosigner");
        let (options, state) =
            match self
                .gate
                .webauthn()
                .start_passkey_registration(Uuid::new_v4(), name, name, None)
            {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!(error = %e, "starting registration");
                    return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
                }
            };

        let Ok(id) = self.random_id() else {
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        {
            let now = Instant::now();
            let mut pending = self.registrations.lock().expect("registrations poisoned");
            pending.retain(|_, p| p.expires > now);
            if pending.len() >= MAX_REGISTRATIONS {
                return problem(hyper::StatusCode::SERVICE_UNAVAILABLE, "try again");
            }
            pending.insert(
                id,
                PendingRegistration {
                    state,
                    join: None,
                    expires: now + REGISTRATION_TTL,
                },
            );
        }

        json(
            hyper::StatusCode::OK,
            &RegisterOptionsResponse {
                registration_id: b64(&id),
                options,
            },
        )
    }

    async fn register_verify(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(request) = serde_json::from_slice::<RegisterVerifyRequest>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(id) = decode_id(&request.registration_id) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed registration id");
        };

        // Taken, not borrowed: an attempt that fails must not leave the
        // registration open for another try at the same challenge.
        let pending = {
            let mut registrations = self.registrations.lock().expect("registrations poisoned");
            registrations.remove(&id)
        };
        let Some(pending) = pending.filter(|p| p.expires > Instant::now()) else {
            return problem(hyper::StatusCode::FORBIDDEN, "registration expired");
        };

        let passkey = match self
            .gate
            .webauthn()
            .finish_passkey_registration(&request.credential, &pending.state)
        {
            Ok(passkey) => passkey,
            Err(e) => {
                tracing::warn!(error = %e, "registration did not verify");
                return problem(hyper::StatusCode::FORBIDDEN, "registration did not verify");
            }
        };

        // Joining an existing tenant, or minting one. Minted from the NSM so a
        // host cannot predict a tenant id and create its directory first.
        let tenant_id = match pending.join {
            Some(existing) => existing,
            None => match super::credential::mint_tenant_id(&self.entropy) {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!(error = format!("{e:#}"), "minting a tenant id");
                    return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
                }
            },
        };

        let credential_id = request.credential.raw_id.as_ref().to_vec();
        let record = StoredCredential {
            version: 1,
            tenant_id,
            passkey,
            active: true,
            created_ms: 0,
            counter: 0,
        };
        if let Err(e) = self.credentials.register(&credential_id, record).await {
            tracing::error!(error = format!("{e:#}"), "storing a credential");
            return problem(hyper::StatusCode::CONFLICT, "could not register");
        }

        // The directory, so the tenant's first request finds one rather than
        // paying for it while a user waits.
        if let Err(e) = crate::tenant::tenant_root_by_id(&self.fs, tenant_id).await {
            tracing::error!(error = format!("{e:#}"), "creating a tenant directory");
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        }

        tracing::info!(
            tenant = %hex::encode(tenant_id),
            credential = %hex::encode(&credential_id[..8.min(credential_id.len())]),
            joined = pending.join.is_some(),
            "registered a passkey"
        );
        json(
            hyper::StatusCode::OK,
            &RegisterVerifyResponse {
                tenant_id: hex::encode(tenant_id),
                credential_id: b64(&credential_id),
            },
        )
    }

    async fn request_options(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(request) = serde_json::from_slice::<RequestOptionsRequest>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(credential_id) = decode(&request.credential_id) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed credential id");
        };
        let Some(body_hash) =
            decode(&request.body_sha256).and_then(|h| <[u8; 32]>::try_from(h.as_slice()).ok())
        else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed body hash");
        };

        // Before the credential is even looked up, so a refusal costs nothing
        // and reveals nothing. This is the request that puts a biometric
        // prompt in front of a person, and it is the one an attacker would
        // repeat until they tapped approve out of habit.
        if !self.challenges.allow(&credential_id) {
            tracing::warn!(
                credential = %hex::encode(&credential_id[..8.min(credential_id.len())]),
                "rate-limited challenge requests"
            );
            return problem(
                hyper::StatusCode::TOO_MANY_REQUESTS,
                "too many challenge requests",
            );
        }

        let record = match self.credentials_lookup(&credential_id).await {
            Ok(Some(record)) if record.active => record,
            Ok(_) => {
                // Deliberately the same answer as a credential that exists but
                // is revoked, and the same as one that never did.
                return problem(
                    hyper::StatusCode::FORBIDDEN,
                    "no challenge for that credential",
                );
            }
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "looking up a credential");
                return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        };

        let Ok(id) = self.random_id() else {
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        let binding = RequestBinding {
            method: request.method.to_ascii_uppercase(),
            path: request.path.clone(),
            query: request.query.clone(),
            body_sha256: body_hash,
        };
        match self
            .gate
            .issue(id, binding, std::slice::from_ref(&record.passkey))
        {
            Ok(options) => json(
                hyper::StatusCode::OK,
                &RequestOptionsResponse {
                    challenge_id: b64(&id),
                    options,
                },
            ),
            Err(e) => {
                tracing::warn!(error = %e, "issuing a challenge");
                problem(hyper::StatusCode::SERVICE_UNAVAILABLE, "try again")
            }
        }
    }

    async fn credentials_lookup(
        &self,
        credential_id: &[u8],
    ) -> anyhow::Result<Option<super::gate::CredentialRecord>> {
        use super::gate::CredentialStore;
        self.credentials.lookup(credential_id).await
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()
}

fn decode_id(text: &str) -> Option<[u8; 16]> {
    decode(text).and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
}

fn body_of(bytes: Vec<u8>) -> wasmtime_wasi_http::p2::body::HyperOutgoingBody {
    use http_body_util::BodyExt;
    http_body_util::Full::new(Bytes::from(bytes))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

fn json<T: Serialize>(
    status: hyper::StatusCode,
    value: &T,
) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        // Challenges and options are single-use and short-lived; a cache that
        // replayed one would be handing out a used challenge.
        .header("cache-control", "no-store")
        .body(body_of(bytes))
        .expect("response is well formed")
}

fn problem(
    status: hyper::StatusCode,
    detail: &str,
) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
    json(status, &serde_json::json!({ "error": detail }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::challenge::{ChallengeStore, DEFAULT_CAPACITY, DEFAULT_TTL};
    use crate::auth::testing::{Relying, ORIGIN, RP_ID};
    use crate::auth::SoftwareAuthenticator;
    use http_body_util::BodyExt;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, Fs, MasterSecret};

    const TOKEN: &str = "an-invite-code-long-enough";

    struct Fixture {
        endpoints: AuthEndpoints,
        fs: Arc<Fs>,
        credentials: Arc<FilesystemCredentials>,
    }

    async fn fixture() -> Fixture {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([7u8; 32]),
            [0u8; 16],
            Arc::new(Config::default()),
        )
        .await
        .expect("filesystem");

        let credentials = Arc::new(FilesystemCredentials::new(fs.clone()));
        let gate = Arc::new(Gate::new(
            Relying::new().webauthn,
            ChallengeStore::new(DEFAULT_TTL, DEFAULT_CAPACITY),
            credentials.clone(),
            64 * 1024,
        ));
        let entropy: Arc<dyn nitro_nsm::Nsm> = Arc::new(nitro_nsm::fake::FakeNsm::new());
        let endpoints = AuthEndpoints::new(gate, credentials.clone(), fs.clone(), entropy);
        endpoints.enrollment().seed(TOKEN).await.unwrap();
        Fixture {
            endpoints,
            fs,
            credentials,
        }
    }

    async fn post(f: &Fixture, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
        let response = f
            .endpoints
            .handle(&hyper::Method::POST, path, body.to_string().as_bytes())
            .await
            .expect("an auth route");
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Register a passkey the way a client does, and get its tenant back.
    async fn register(f: &Fixture, auth: &SoftwareAuthenticator) -> (u16, serde_json::Value) {
        let (status, options) = post(
            f,
            "/auth/register/options",
            serde_json::json!({ "enrollment_token": TOKEN }),
        )
        .await;
        if status != 200 {
            return (status, options);
        }
        let challenge = options["options"]["publicKey"]["challenge"]
            .as_str()
            .expect("a challenge")
            .to_string();
        post(
            f,
            "/auth/register/verify",
            serde_json::json!({
                "registration_id": options["registration_id"],
                "credential": auth.register(&challenge, ORIGIN),
            }),
        )
        .await
    }

    /// The whole enrollment path: token, options, response, tenant.
    #[tokio::test]
    async fn registration_creates_a_tenant() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        let (status, body) = register(&f, &auth).await;
        assert_eq!(status, 200, "{body}");

        let tenant_hex = body["tenant_id"].as_str().expect("a tenant id");
        assert_eq!(tenant_hex.len(), 32, "a 16-byte tenant id in hex");

        // The credential is stored and points at that tenant.
        use crate::auth::gate::CredentialStore;
        let record = f
            .credentials
            .lookup(auth.credential_id())
            .await
            .unwrap()
            .expect("the credential was stored");
        assert_eq!(hex::encode(record.tenant_id), tenant_hex);

        // And the tenant's directory exists, so their first request is cheap.
        assert!(crate::tenant::tenants(&f.fs)
            .await
            .unwrap()
            .contains(&tenant_hex.to_string()));
    }

    /// One token, one tenant. Otherwise a leaked invite mints them without end.
    #[tokio::test]
    async fn an_enrollment_token_works_once() {
        let f = fixture().await;
        assert_eq!(
            register(&f, &SoftwareAuthenticator::new(RP_ID)).await.0,
            200
        );
        let (status, _) = register(&f, &SoftwareAuthenticator::new(RP_ID)).await;
        assert_eq!(status, 403, "a spent token registered a second tenant");
    }

    #[tokio::test]
    async fn registration_without_a_token_is_refused() {
        let f = fixture().await;
        let (status, _) = post(
            &f,
            "/auth/register/options",
            serde_json::json!({ "enrollment_token": "not-a-real-token-but-long" }),
        )
        .await;
        assert_eq!(status, 403);
    }

    /// A registration response for a challenge that was never issued.
    #[tokio::test]
    async fn an_unknown_registration_id_is_refused() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        let (status, _) = post(
            &f,
            "/auth/register/verify",
            serde_json::json!({
                "registration_id": "AAAAAAAAAAAAAAAAAAAAAA",
                "credential": auth.register("Y2hhbGxlbmdl", ORIGIN),
            }),
        )
        .await;
        assert_eq!(status, 403);
    }

    /// A failed attempt must not leave the registration open for another try.
    #[tokio::test]
    async fn a_registration_id_cannot_be_retried() {
        let f = fixture().await;
        let (_, options) = post(
            &f,
            "/auth/register/options",
            serde_json::json!({ "enrollment_token": TOKEN }),
        )
        .await;
        let auth = SoftwareAuthenticator::new(RP_ID);

        // Wrong challenge: fails.
        let (first, _) = post(
            &f,
            "/auth/register/verify",
            serde_json::json!({
                "registration_id": options["registration_id"],
                "credential": auth.register("d3JvbmctY2hhbGxlbmdl", ORIGIN),
            }),
        )
        .await;
        assert_eq!(first, 403);

        // The right one now also fails: the id was consumed by the attempt.
        let challenge = options["options"]["publicKey"]["challenge"]
            .as_str()
            .unwrap();
        let (second, _) = post(
            &f,
            "/auth/register/verify",
            serde_json::json!({
                "registration_id": options["registration_id"],
                "credential": auth.register(challenge, ORIGIN),
            }),
        )
        .await;
        assert_eq!(second, 403, "a failed registration could be retried");
    }

    /// A challenge is issued only for a credential this runtime knows.
    #[tokio::test]
    async fn a_challenge_is_issued_for_a_registered_credential() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (status, body) = post(
            &f,
            "/auth/request/options",
            serde_json::json!({
                "credential_id": b64.encode(auth.credential_id()),
                "method": "POST",
                "path": "/sign",
                "body_sha256": b64.encode(nitro_attestation::sha256(b"tx")),
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body["challenge_id"].is_string());
        assert!(body["options"]["publicKey"]["challenge"].is_string());
    }

    /// Unknown and revoked credentials are refused identically, so the route
    /// cannot be used to learn which passkeys exist.
    #[tokio::test]
    async fn unknown_and_revoked_credentials_are_indistinguishable() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);
        f.credentials.revoke(auth.credential_id()).await.unwrap();

        async fn ask(f: &Fixture, id: &[u8]) -> (u16, serde_json::Value) {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            post(
                f,
                "/auth/request/options",
                serde_json::json!({
                    "credential_id": b64.encode(id),
                    "method": "POST",
                    "path": "/sign",
                    "body_sha256": b64.encode([0u8; 32]),
                }),
            )
            .await
        }
        let revoked = ask(&f, auth.credential_id()).await;
        let unknown = ask(&f, &[0xff; 32]).await;
        assert_eq!(revoked.0, 403);
        assert_eq!(revoked, unknown, "the refusals differ and leak existence");
    }

    /// Asking for challenges is what makes a phone buzz, so it is limited —
    /// otherwise an attacker prompts a user until they approve out of habit.
    #[tokio::test]
    async fn challenge_requests_are_rate_limited() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);

        async fn ask(f: &Fixture, credential_id: &[u8]) -> u16 {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            post(
                f,
                "/auth/request/options",
                serde_json::json!({
                    "credential_id": b64.encode(credential_id),
                    "method": "POST",
                    "path": "/sign",
                    "body_sha256": b64.encode([0u8; 32]),
                }),
            )
            .await
            .0
        }

        let mut refused = false;
        for _ in 0..(crate::auth::ratelimit::DEFAULT_PER_CREDENTIAL + 5) {
            if ask(&f, auth.credential_id()).await == 429 {
                refused = true;
                break;
            }
        }
        assert!(refused, "a credential could ask for prompts without limit");
    }

    /// Everything outside `/auth/` is somebody else's business.
    #[tokio::test]
    async fn other_paths_are_not_claimed() {
        let f = fixture().await;
        assert!(f
            .endpoints
            .handle(&hyper::Method::POST, "/sign", b"{}")
            .await
            .is_none());
        assert!(f
            .endpoints
            .handle(&hyper::Method::GET, "/enclave/config", b"")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn an_unknown_auth_route_is_a_404() {
        let f = fixture().await;
        let (status, _) = post(&f, "/auth/nonsense", serde_json::json!({})).await;
        assert_eq!(status, 404);
    }
}
