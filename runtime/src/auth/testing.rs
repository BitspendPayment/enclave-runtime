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

    /// An Android app claims `android:apk-key-hash:…`, never `https://<rp id>`.
    /// Allowed, it registers and authenticates; any other app is still refused.
    #[test]
    fn an_allowed_android_app_registers_and_authenticates_and_no_other_app_does() {
        const APP: &str = "android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
        const OTHER_APP: &str = "android:apk-key-hash:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0";
        let rp = Relying {
            webauthn: crate::build_relying_party(RP_ID, ORIGIN, &[APP.into()])
                .expect("relying party"),
        };
        let auth = SoftwareAuthenticator::new(RP_ID);

        let (options, state) = rp
            .webauthn
            .start_passkey_registration(Uuid::new_v4(), "tester", "Tester", None)
            .unwrap();
        let response: RegisterPublicKeyCredential =
            serde_json::from_value(auth.register(&Relying::challenge_of(&options), APP)).unwrap();
        let passkey = rp
            .webauthn
            .finish_passkey_registration(&response, &state)
            .expect("the app's registration verifies");

        let assert_from = |origin: &str| {
            let (options, state) = rp
                .webauthn
                .start_passkey_authentication(std::slice::from_ref(&passkey))
                .unwrap();
            let response: PublicKeyCredential =
                serde_json::from_value(auth.assert(&Relying::challenge_for(&options), origin))
                    .unwrap();
            rp.webauthn.finish_passkey_authentication(&response, &state)
        };
        assert_from(APP).expect("the app's assertion verifies");
        assert_from(ORIGIN).expect("the web origin still verifies");
        assert!(
            assert_from(OTHER_APP).is_err(),
            "an app signed with another key must not borrow the passkey"
        );
    }

    /// Without the setting, what the app sends is refused — the blocker this
    /// setting exists to lift.
    #[test]
    fn an_android_app_is_refused_unless_allowed() {
        let rp = Relying::new();
        let auth = SoftwareAuthenticator::new(RP_ID);
        let passkey = rp.register(&auth);

        let (options, state) = rp
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let response: PublicKeyCredential = serde_json::from_value(auth.assert(
            &Relying::challenge_for(&options),
            "android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
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
        Self::with_token_ttl(super::token::DEFAULT_TTL)
    }

    pub fn with_token_ttl(ttl: std::time::Duration) -> Self {
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
                super::TokenStore::new(ttl, super::token::DEFAULT_CAPACITY),
            ),
            authenticator,
            passkey,
            credentials,
            tenant_id,
        }
    }

    /// Walk the real two-trip flow and return the token it produces.
    ///
    /// Challenge, assertion, verification — the same path a client takes, so a
    /// test that uses this is exercising what a client actually does rather
    /// than a shortcut around it.
    pub async fn token_for(&self, method: &str, path_and_query: &str) -> String {
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let id = [7u8; 16];
        let options = self
            .gate
            .issue(
                id,
                super::InteractionScope::new(method, path, query),
                std::slice::from_ref(&self.passkey),
            )
            .expect("issuing a challenge");
        let assertion = self
            .authenticator
            .assert(&Relying::challenge_for(&options), ORIGIN);
        let assertion: webauthn_rs::prelude::PublicKeyCredential =
            serde_json::from_str(&assertion.to_string()).expect("a credential");
        let who = self
            .gate
            .authenticate(&id, &assertion)
            .await
            .expect("the assertion verifies");

        let token = "a-test-token-of-plausible-length".to_string();
        self.gate
            .grant(token.as_bytes(), &who)
            .expect("recording the approval");
        token
    }

    /// A request carrying a bearer token.
    pub fn bearer(
        method: &str,
        path_and_query: &str,
        body: &[u8],
        token: &str,
    ) -> hyper::Request<http_body_util::Full<bytes::Bytes>> {
        hyper::Request::builder()
            .method(method)
            .uri(format!("https://enclave.test{path_and_query}"))
            .header(super::AUTHORIZATION_HEADER, format!("Bearer {token}"))
            .body(http_body_util::Full::new(bytes::Bytes::copy_from_slice(
                body,
            )))
            .expect("well-formed request")
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
