//! `/auth/*` — the only routes that answer without an assertion.
//!
//! They are runtime-owned in the same sense `/enclave/*` is: refused before
//! dispatch, never forwarded, and unreachable by any guest. That is not a
//! convenience. A guest able to answer under `/auth/` could hand out its own
//! challenges and verify its own assertions, which is the same as having none.
//!
//! Nothing here performs a cosigner action or touches an *existing* tenant's
//! directory. The most any of it does is create a new tenant, which anyone may
//! do: registration is open, and what it grants is an empty tenant and nothing
//! else.
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

use super::credential::{FilesystemCredentials, StoredCredential};
use super::gate::Gate;
use super::token::InteractionScope;

/// The prefix the guest can never see.
pub const AUTH_PREFIX: &str = "/auth/";

/// How long a half-finished registration is held.
const REGISTRATION_TTL: Duration = Duration::from_secs(300);
/// Half-finished registrations allowed at once.
const MAX_REGISTRATIONS: usize = 64;
/// Ceiling on an `/auth/*` request body.
const MAX_BODY: usize = 16 * 1024;

/// Registration is open, so nothing here is required. The only thing a caller
/// may supply is what to call the credential.
///
/// `deny_unknown_fields` for the same reason `RequestOptionsRequest` has it: an
/// older client still sending `enrollment_token` is told that it means nothing
/// now, rather than having it quietly ignored and believing it was admitted on
/// the strength of one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterOptionsRequest {
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

/// What an interaction challenge is issued for.
///
/// `deny_unknown_fields` is load-bearing: this route used to take a
/// `body_sha256`, and a client still sending one must be told that it means
/// nothing now rather than have it quietly ignored. An approval that names a
/// body it does not bind would be worse than one that never claimed to.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestOptionsRequest {
    /// Which passkey the client intends to use. The runtime allows exactly
    /// that one, so an assertion from any other credential fails even before
    /// the credential lookup.
    credential_id: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
}

/// The assertion, coming back to be turned into a token.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestVerifyRequest {
    challenge_id: String,
    /// Base64url of the `PublicKeyCredential` JSON `navigator.credentials.get()`
    /// produced.
    assertion: String,
}

/// The token, and how long it has to be spent.
#[derive(Serialize)]
struct TokenResponse {
    token: String,
    /// Seconds. This bounds the time to *start* an interaction, and is not how
    /// long one may run once started.
    expires_in_secs: u64,
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
    entropy: Arc<dyn nitro_nsm::Nsm>,
    fs: Arc<s3fs_core::Fs>,
    registrations: Mutex<HashMap<[u8; 16], PendingRegistration>>,
}

impl AuthEndpoints {
    pub fn new(
        gate: Arc<Gate>,
        credentials: Arc<FilesystemCredentials>,
        fs: Arc<s3fs_core::Fs>,
        entropy: Arc<dyn nitro_nsm::Nsm>,
    ) -> Self {
        AuthEndpoints {
            gate,
            credentials,
            entropy,
            fs,
            registrations: Mutex::new(HashMap::new()),
        }
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
            "request/verify" => self.request_verify(body).await,
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

        // Registration is open: anyone who can reach this route may create a
        // tenant. What that grants is deliberately narrow — a *new*, empty
        // tenant and nothing else. It cannot reach an existing tenant's data,
        // approve anything, or add a passkey to somebody else's account, all of
        // which still need an assertion from a credential already registered
        // there. Admission control over resource creation is what was given up
        // here; access control was not.
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

    /// Turn a verified assertion into a token for one interaction.
    ///
    /// The second of the three trips a signed interaction takes, and it has to
    /// be its own exchange: a passkey is a challenge-response, so the assertion
    /// cannot exist until `request/options` has already answered. Named to
    /// match `register/options` → `register/verify`, which is the same shape.
    ///
    /// **What the token authorizes: one interaction at the method, path and
    /// query the challenge was issued for.** It commits to no bytes. A person
    /// approved *doing this thing*, not *sending these bytes*, and nothing here
    /// should be described as approval of a payload.
    async fn request_verify(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(request) = serde_json::from_slice::<RequestVerifyRequest>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(challenge_id) = decode_id(&request.challenge_id) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed challenge id");
        };
        let Some(assertion_json) = decode(&request.assertion) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed assertion");
        };
        let Ok(assertion) = serde_json::from_slice::<PublicKeyCredential>(&assertion_json) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed assertion");
        };

        let who = match self.gate.authenticate(&challenge_id, &assertion).await {
            Ok(who) => who,
            Err(denied) => {
                // Logged in full, answered in one sentence — the same rule the
                // gate has always followed.
                tracing::info!(reason = %denied, "refused an assertion");
                return problem(denied.status(), denied.public_message());
            }
        };

        // Minted here, from the enclave's entropy, and held in exactly two
        // places: this response, and a hash in the store.
        let mut token = [0u8; 32];
        if self.entropy.get_random(&mut token).is_err() {
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        }
        let token = b64(&token);

        let ttl = match self.gate.grant(token.as_bytes(), &who) {
            Ok(ttl) => ttl,
            Err(denied) => {
                tracing::warn!(reason = %denied, "could not record an approval");
                return problem(denied.status(), denied.public_message());
            }
        };

        // The token itself is never logged. What identifies this event is the
        // tenant it belongs to and the interaction it is good for.
        tracing::info!(
            tenant = %hex::encode(who.tenant_id),
            method = %who.scope.method,
            path = %who.scope.path,
            "issued an interaction token"
        );

        json(
            hyper::StatusCode::OK,
            &TokenResponse {
                token,
                expires_in_secs: ttl.as_secs(),
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
        let scope = InteractionScope::new(&request.method, &request.path, request.query.as_deref());
        match self
            .gate
            .issue(id, scope, std::slice::from_ref(&record.passkey))
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
            super::super::TokenStore::new(
                std::time::Duration::from_secs(60),
                super::super::token::DEFAULT_CAPACITY,
            ),
        ));
        let entropy: Arc<dyn nitro_nsm::Nsm> = Arc::new(nitro_nsm::fake::FakeNsm::new());
        let endpoints = AuthEndpoints::new(gate, credentials.clone(), fs.clone(), entropy);
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
        let (status, options) = post(f, "/auth/register/options", serde_json::json!({})).await;
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

    /// The whole registration path: options, response, tenant.
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

    /// Registration is open, and each one stands alone: a second, unrelated
    /// passkey registers too and lands in a tenant of its own rather than
    /// joining the first.
    #[tokio::test]
    async fn registration_is_open_and_each_one_is_a_new_tenant() {
        let f = fixture().await;
        let (first_status, first) = register(&f, &SoftwareAuthenticator::new(RP_ID)).await;
        assert_eq!(first_status, 200, "{first}");
        let (second_status, second) = register(&f, &SoftwareAuthenticator::new(RP_ID)).await;
        assert_eq!(second_status, 200, "{second}");
        assert_ne!(
            first["tenant_id"], second["tenant_id"],
            "a second registration joined the first one's tenant"
        );
    }

    /// An older client still sending an enrollment token is told the field
    /// means nothing now, rather than being quietly admitted as though one had
    /// been checked.
    #[tokio::test]
    async fn a_registration_still_carrying_an_enrollment_token_is_refused() {
        let f = fixture().await;
        let (status, _) = post(
            &f,
            "/auth/register/options",
            serde_json::json!({ "enrollment_token": "not-a-real-token-but-long" }),
        )
        .await;
        assert_eq!(status, 400);
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
        let (_, options) = post(&f, "/auth/register/options", serde_json::json!({})).await;
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
                }),
            )
            .await
        }
        let revoked = ask(&f, auth.credential_id()).await;
        let unknown = ask(&f, &[0xff; 32]).await;
        assert_eq!(revoked.0, 403);
        assert_eq!(revoked, unknown, "the refusals differ and leak existence");
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
            .handle(&hyper::Method::GET, "/counter", b"")
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
