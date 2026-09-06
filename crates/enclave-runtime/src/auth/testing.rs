//! A relying party in a test, paired with [`super::SoftwareAuthenticator`].
//!
//! The point of this file is one assertion: **bytes the software
//! authenticator produces are bytes `webauthn-rs` accepts.** If that ever
//! stopped being true, every test built on the authenticator would be checking
//! the runtime against a fiction. So the round trip is exercised directly, and
//! the rest of the suite builds on it.
//!
//! The challenge is pulled out of the options the way a browser gets it —
//! serialise to JSON, read `publicKey.challenge` — rather than by reaching
//! into the crate's types. That is the path a real client takes, so it is the
//! path worth depending on.

use webauthn_rs::prelude::*;

use super::SoftwareAuthenticator;

pub const RP_ID: &str = "enclave.test";
pub const ORIGIN: &str = "https://enclave.test";

pub struct Relying {
    pub webauthn: Webauthn,
}

impl Default for Relying {
    fn default() -> Self {
        Self::new()
    }
}

impl Relying {
    pub fn new() -> Self {
        Relying {
            webauthn: WebauthnBuilder::new(RP_ID, &Url::parse(ORIGIN).expect("origin"))
                .expect("relying party")
                .build()
                .expect("relying party"),
        }
    }

    /// The challenge a browser would read out of the options it was handed.
    fn challenge_of<T: serde::Serialize>(options: &T) -> String {
        serde_json::to_value(options)
            .expect("options serialise")
            .get("publicKey")
            .and_then(|k| k.get("challenge"))
            .and_then(|c| c.as_str())
            .expect("options carry a challenge")
            .to_string()
    }

    /// Register a fresh software passkey and return it, ready to authenticate.
    pub fn register(&self, auth: &SoftwareAuthenticator) -> Passkey {
        let (options, state) = self
            .webauthn
            .start_passkey_registration(Uuid::new_v4(), "tester", "Tester", None)
            .expect("registration options");
        let response: RegisterPublicKeyCredential =
            serde_json::from_value(auth.register(&Self::challenge_of(&options), ORIGIN))
                .expect("the authenticator produces a well-formed registration");
        self.webauthn
            .finish_passkey_registration(&response, &state)
            .expect("the authenticator's registration verifies")
    }

    /// Begin an authentication against a throwaway credential.
    ///
    /// For tests that only need a `PasskeyAuthentication` to put in the
    /// challenge store and do not care which credential it names.
    pub fn begin_authentication(&self) -> (RequestChallengeResponse, PasskeyAuthentication) {
        let auth = SoftwareAuthenticator::new(RP_ID);
        let passkey = self.register(&auth);
        self.webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .expect("authentication options")
    }

    /// Challenge, then assert against it, then verify — the whole ceremony.
    pub fn round_trip(
        &self,
        auth: &SoftwareAuthenticator,
        passkey: &Passkey,
    ) -> WebauthnResult<AuthenticationResult> {
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(passkey))
            .expect("authentication options");
        let response: PublicKeyCredential =
            serde_json::from_value(auth.assert(&Self::challenge_of(&options), ORIGIN))
                .expect("the authenticator produces a well-formed assertion");
        self.webauthn
            .finish_passkey_authentication(&response, &state)
    }

    pub fn challenge_for(options: &RequestChallengeResponse) -> String {
        Self::challenge_of(options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authenticator::flags;

    /// The foundation. Everything else in the suite trusts that this holds.
    #[test]
    fn a_software_passkey_registers_and_authenticates() {
        let rp = Relying::new();
        let auth = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&auth);

        let result = rp.round_trip(&auth, &passkey).expect("assertion verifies");
        assert_eq!(result.cred_id().as_ref(), auth.credential_id());
        assert!(result.user_verified(), "the fixture must assert UV");
    }

    /// A passkey that merely sat in an unlocked pocket is not approval. The
    /// crate is configured `UserVerificationPolicy::Required`; this proves it.
    #[test]
    fn an_assertion_without_user_verification_is_refused() {
        let rp = Relying::new();
        let auth = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&auth);

        let (options, state) = rp
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let response: PublicKeyCredential = serde_json::from_value(auth.assert_with(
            &Relying::challenge_for(&options),
            ORIGIN,
            flags::UP, // present, but not verified
        ))
        .unwrap();
        assert!(
            rp.webauthn
                .finish_passkey_authentication(&response, &state)
                .is_err(),
            "a merely-present authenticator must not authorize anything"
        );
    }

    /// A page on another origin cannot borrow the user's passkey for this one.
    #[test]
    fn an_assertion_from_another_origin_is_refused() {
        let rp = Relying::new();
        let auth = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&auth);

        let (options, state) = rp
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let response: PublicKeyCredential = serde_json::from_value(auth.assert(
            &Relying::challenge_for(&options),
            "https://attacker.example",
        ))
        .unwrap();
        assert!(rp
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .is_err());
    }

    /// Signing something other than the challenge it was given.
    #[test]
    fn an_assertion_over_the_wrong_challenge_is_refused() {
        let rp = Relying::new();
        let auth = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&auth);

        let (_, state) = rp
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let response: PublicKeyCredential =
            serde_json::from_value(auth.assert("bm90LXRoZS1jaGFsbGVuZ2U", ORIGIN)).unwrap();
        assert!(rp
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .is_err());
    }

    /// A different passkey, however well-formed, is not this one.
    #[test]
    fn another_credential_cannot_answer_this_challenge() {
        let rp = Relying::new();
        let mine = SoftwareAuthenticator::new(RP_ID);
        let theirs = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&mine);
        rp.register(&theirs);

        let (options, state) = rp
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let response: PublicKeyCredential =
            serde_json::from_value(theirs.assert(&Relying::challenge_for(&options), ORIGIN))
                .unwrap();
        assert!(rp
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .is_err());
    }
}

/// Credentials in memory, for tests and as the smallest thing that satisfies
/// [`CredentialStore`].
#[derive(Default)]
pub struct MemoryCredentials {
    records: std::sync::Mutex<std::collections::HashMap<Vec<u8>, super::CredentialRecord>>,
}

impl MemoryCredentials {
    pub fn insert(&self, credential_id: &[u8], record: super::CredentialRecord) {
        self.records
            .lock()
            .expect("credentials poisoned")
            .insert(credential_id.to_vec(), record);
    }

    pub fn revoke(&self, credential_id: &[u8]) {
        if let Some(r) = self
            .records
            .lock()
            .expect("credentials poisoned")
            .get_mut(credential_id)
        {
            r.active = false;
        }
    }

    pub fn counter(&self, credential_id: &[u8]) -> Option<u32> {
        self.records
            .lock()
            .expect("credentials poisoned")
            .get(credential_id)
            .map(|r| r.counter)
    }
}

#[async_trait::async_trait]
impl super::CredentialStore for MemoryCredentials {
    async fn lookup(
        &self,
        credential_id: &[u8],
    ) -> anyhow::Result<Option<super::CredentialRecord>> {
        Ok(self
            .records
            .lock()
            .expect("credentials poisoned")
            .get(credential_id)
            .cloned())
    }

    async fn record_use(&self, credential_id: &[u8], counter: u32) -> anyhow::Result<()> {
        if let Some(r) = self
            .records
            .lock()
            .expect("credentials poisoned")
            .get_mut(credential_id)
        {
            r.counter = counter;
        }
        Ok(())
    }
}

/// A gate with one registered passkey, ready to be asked awkward questions.
pub struct Harness {
    pub gate: super::Gate,
    pub authenticator: SoftwareAuthenticator,
    pub passkey: Passkey,
    pub credentials: std::sync::Arc<MemoryCredentials>,
    pub tenant_id: [u8; 16],
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::with_body_limit(64 * 1024)
    }

    pub fn with_body_limit(max_body_bytes: usize) -> Self {
        let rp = Relying::new();
        let authenticator = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&authenticator);
        let tenant_id = [0xab; 16];

        let credentials = std::sync::Arc::new(MemoryCredentials::default());
        credentials.insert(
            authenticator.credential_id(),
            super::CredentialRecord {
                tenant_id,
                passkey: passkey.clone(),
                active: true,
                counter: 0,
            },
        );

        Harness {
            gate: super::Gate::new(
                rp.webauthn,
                super::ChallengeStore::new(super::DEFAULT_TTL, super::DEFAULT_CAPACITY),
                credentials.clone(),
                max_body_bytes,
            ),
            authenticator,
            passkey,
            credentials,
            tenant_id,
        }
    }

    /// A request carrying a valid assertion for exactly itself.
    pub fn signed_request(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> hyper::Request<http_body_util::Full<bytes::Bytes>> {
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let id = [7u8; 16];
        let options = self
            .gate
            .issue(
                id,
                super::RequestBinding::new(method, path, query, body),
                std::slice::from_ref(&self.passkey),
            )
            .expect("issuing a challenge");
        let assertion = self
            .authenticator
            .assert(&Relying::challenge_for(&options), ORIGIN);
        Self::request_with(method, path_and_query, body, &id, &assertion)
    }

    /// A request carrying a *stream-open* assertion, with the header that says
    /// so.
    ///
    /// `body` is whatever the client happens to send after the head; a stream
    /// open commits to none of it, so passing something here is the point
    /// rather than an oversight.
    pub fn stream_request(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> hyper::Request<http_body_util::Full<bytes::Bytes>> {
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let id = [9u8; 16];
        let options = self
            .gate
            .issue(
                id,
                super::RequestBinding::stream_open(method, path, query),
                std::slice::from_ref(&self.passkey),
            )
            .expect("issuing a stream-open challenge");
        let assertion = self
            .authenticator
            .assert(&Relying::challenge_for(&options), ORIGIN);
        let mut req = Self::request_with(method, path_and_query, body, &id, &assertion);
        req.headers_mut().insert(
            super::STREAM_HEADER,
            hyper::header::HeaderValue::from_static("open"),
        );
        req
    }

    /// A request carrying an assertion that was issued for something else.
    pub fn assertion_for(
        &self,
        issued: (&str, &str, &[u8]),
        sent: (&str, &str, &[u8]),
    ) -> hyper::Request<http_body_util::Full<bytes::Bytes>> {
        let (path, query) = match issued.1.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (issued.1, None),
        };
        let id = [8u8; 16];
        let options = self
            .gate
            .issue(
                id,
                super::RequestBinding::new(issued.0, path, query, issued.2),
                std::slice::from_ref(&self.passkey),
            )
            .expect("issuing a challenge");
        let assertion = self
            .authenticator
            .assert(&Relying::challenge_for(&options), ORIGIN);
        Self::request_with(sent.0, sent.1, sent.2, &id, &assertion)
    }

    pub fn request_with(
        method: &str,
        path_and_query: &str,
        body: &[u8],
        challenge_id: &[u8; 16],
        assertion: &serde_json::Value,
    ) -> hyper::Request<http_body_util::Full<bytes::Bytes>> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        hyper::Request::builder()
            .method(method)
            .uri(format!("https://{RP_ID}{path_and_query}"))
            .header(super::gate::CHALLENGE_HEADER, b64.encode(challenge_id))
            .header(
                super::gate::ASSERTION_HEADER,
                b64.encode(assertion.to_string()),
            )
            .body(http_body_util::Full::new(bytes::Bytes::copy_from_slice(
                body,
            )))
            .expect("well-formed request")
    }
}
