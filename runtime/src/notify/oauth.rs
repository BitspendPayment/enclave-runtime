//! Proving to Google that this enclave may send for its Firebase project.
//!
//! FCM's HTTP v1 API takes an OAuth2 access token, and obtaining one means
//! signing a JWT with a service account's private key and exchanging it at
//! Google's token endpoint. There is no long-lived API key to present instead:
//! the legacy server-key API was decommissioned in 2024.
//!
//! # What is here and what is not
//!
//! This module signs and parses. It opens no sockets — the exchange itself is
//! [`super::fcm`]'s, so everything below can be tested without a network, and
//! the signature can be checked against the key that produced it rather than
//! against a recorded blob.
//!
//! # The clock
//!
//! `iat` and `exp` come from the runtime's trusted clock, which in an enclave
//! is PTP. This is the one place an outside party checks that clock: a skew
//! beyond Google's tolerance comes back as `invalid_grant`, which is
//! indistinguishable from a credential that was never valid. If tokens stop
//! minting after an image change, suspect the clock before the key.

use anyhow::{ensure, Context, Result};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use base64::Engine as _;
use serde::Deserialize;
use zeroize::Zeroizing;

/// The only scope this runtime asks for. Sending is all it does.
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Where a service account exchanges an assertion, unless its JSON says
/// otherwise. Whatever this ends up being is also the assertion's `aud`, and
/// Google refuses the pair if they disagree.
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// Google refuses an assertion that claims longer than an hour.
const ASSERTION_LIFETIME_SECS: u64 = 3600;
/// Replace a token this long before it expires, so a send never races one out.
pub const REFRESH_SKEW_MS: u64 = 60_000;
/// An access token is never treated as living longer than this, whatever the
/// response said. Trusting a number from the network to decide when to next
/// talk to the network is how a stale token becomes a permanent one.
const MAX_LIFETIME_MS: u64 = 3600 * 1000;

/// Percent-encoded so the form body needs no encoder: the value is a constant,
/// and the only other field is a JWT, which is base64url and already safe.
const GRANT_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The fields of a Google service-account JSON this runtime uses.
#[derive(Deserialize)]
struct ServiceAccountJson {
    #[serde(rename = "type")]
    kind: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    #[serde(default)]
    token_uri: Option<String>,
}

/// A parsed, usable service account.
///
/// It cannot exist in an invalid state: the key is decoded and accepted by
/// `aws-lc-rs` before this is constructed, so a malformed credential fails at
/// boot rather than on the first wake somebody was waiting for.
pub struct ServiceAccount {
    pub project_id: String,
    pub client_email: String,
    pub token_uri: String,
    private_key_id: String,
    key: RsaKeyPair,
}

impl std::fmt::Debug for ServiceAccount {
    /// Names the account, never the key. `ServeConfig` derives `Debug` and is
    /// logged at startup, so this is on a path that reaches the console.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .finish_non_exhaustive()
    }
}

impl ServiceAccount {
    pub fn parse(json: &str) -> Result<Self> {
        let parsed: ServiceAccountJson =
            serde_json::from_str(json).context("the FCM service account is not valid JSON")?;
        ensure!(
            parsed.kind == "service_account",
            "expected a service-account key, got {:?}",
            parsed.kind
        );
        ensure!(
            !parsed.project_id.trim().is_empty()
                && !parsed.client_email.trim().is_empty()
                && !parsed.private_key_id.trim().is_empty(),
            "the FCM service account is missing project_id, client_email or private_key_id"
        );

        let block = pem::parse(parsed.private_key.as_bytes())
            .context("the service account's private_key is not valid PEM")?;
        ensure!(
            block.tag() == "PRIVATE KEY",
            "expected a PKCS#8 \"PRIVATE KEY\" block, found {:?}. A key exported as \
             \"RSA PRIVATE KEY\" is PKCS#1 and has to be converted.",
            block.tag()
        );
        let key = RsaKeyPair::from_pkcs8(block.contents())
            .map_err(|e| anyhow::anyhow!("the service account's private key was rejected: {e}"))?;

        Ok(ServiceAccount {
            project_id: parsed.project_id,
            client_email: parsed.client_email,
            token_uri: parsed
                .token_uri
                .filter(|u| !u.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_TOKEN_URI.to_string()),
            private_key_id: parsed.private_key_id,
            key,
        })
    }

    /// The signed assertion Google exchanges for an access token.
    pub fn assertion(&self, now_ms: u64) -> Result<String> {
        let now = now_ms / 1000;
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            // Which of the account's keys signed this, so rotation does not
            // need both sides to change at the same instant.
            "kid": self.private_key_id,
        });
        let claims = serde_json::json!({
            "iss": self.client_email,
            "scope": SCOPE,
            "aud": self.token_uri,
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECS,
        });

        let signing_input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&header)?),
            b64(&serde_json::to_vec(&claims)?)
        );
        let mut signature = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|e| anyhow::anyhow!("signing the FCM assertion: {e}"))?;

        Ok(format!("{signing_input}.{}", b64(&signature)))
    }

    /// The `application/x-www-form-urlencoded` body of the token request.
    pub fn token_form(&self, assertion: &str) -> String {
        format!("grant_type={GRANT_TYPE}&assertion={assertion}")
    }
}

/// What Google sends back.
#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
}

/// An access token, and when to stop using it.
pub struct AccessToken {
    pub token: Zeroizing<String>,
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl AccessToken {
    pub fn new(response: TokenResponse, now_ms: u64) -> Self {
        let lifetime = response
            .expires_in
            .saturating_mul(1000)
            .min(MAX_LIFETIME_MS);
        AccessToken {
            token: Zeroizing::new(response.access_token),
            expires_at_ms: now_ms.saturating_add(lifetime),
        }
    }

    /// Whether this token is still worth sending with.
    pub fn is_fresh(&self, now_ms: u64) -> bool {
        now_ms.saturating_add(REFRESH_SKEW_MS) < self.expires_at_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = include_str!("testdata/service-account-key.pem");

    fn account_json() -> String {
        serde_json::json!({
            "type": "service_account",
            "project_id": "enclave-test",
            "private_key_id": "kid-1",
            "private_key": KEY,
            "client_email": "wake@enclave-test.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string()
    }

    fn account() -> ServiceAccount {
        ServiceAccount::parse(&account_json()).expect("the fixture parses")
    }

    fn part(jwt: &str, index: usize) -> serde_json::Value {
        let raw = jwt.split('.').nth(index).expect("a JWT part");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .expect("base64url");
        serde_json::from_slice(&bytes).expect("JSON")
    }

    #[test]
    fn the_assertion_carries_the_issuer_scope_and_audience_google_requires() {
        let a = account();
        let jwt = a.assertion(1_000_000).unwrap();

        let header = part(&jwt, 0);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "kid-1");

        let claims = part(&jwt, 1);
        assert_eq!(claims["iss"], "wake@enclave-test.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(
            claims["aud"], "https://oauth2.googleapis.com/token",
            "aud must equal the endpoint the assertion is posted to, or Google refuses it"
        );
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["exp"], 1000 + ASSERTION_LIFETIME_SECS);
    }

    /// Verified against the key that signed it, rather than compared to a
    /// recorded blob: that proves the signing is real, where a fixed string
    /// would only prove it is unchanged.
    #[test]
    fn the_assertion_verifies_against_the_service_accounts_own_public_key() {
        use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

        let a = account();
        let jwt = a.assertion(1_000_000).unwrap();
        let (signing_input, signature) = jwt.rsplit_once('.').expect("three parts");
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .unwrap();

        let public = UnparsedPublicKey::new(
            &RSA_PKCS1_2048_8192_SHA256,
            a.key.public_key().as_ref().to_vec(),
        );
        public
            .verify(signing_input.as_bytes(), &signature)
            .expect("the assertion does not verify under its own key");

        // And a tampered claim set does not.
        let forged = format!("{signing_input}x");
        assert!(public.verify(forged.as_bytes(), &signature).is_err());
    }

    #[test]
    fn a_service_account_missing_a_required_field_is_refused_before_any_network_call() {
        for missing in ["project_id", "client_email", "private_key_id"] {
            let mut value: serde_json::Value = serde_json::from_str(&account_json()).unwrap();
            value[missing] = serde_json::json!("");
            assert!(
                ServiceAccount::parse(&value.to_string()).is_err(),
                "an empty {missing} was accepted"
            );
        }
        let mut value: serde_json::Value = serde_json::from_str(&account_json()).unwrap();
        value["type"] = serde_json::json!("authorized_user");
        assert!(
            ServiceAccount::parse(&value.to_string()).is_err(),
            "a user credential was accepted as a service account"
        );
    }

    #[test]
    fn a_private_key_that_is_not_pkcs8_is_refused_at_startup() {
        let mut value: serde_json::Value = serde_json::from_str(&account_json()).unwrap();
        value["private_key"] = serde_json::json!(
            "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"
        );
        assert!(ServiceAccount::parse(&value.to_string()).is_err());

        // PKCS#1, the other thing an export commonly produces. Refused by tag,
        // with a message that says what to do about it.
        let mut value: serde_json::Value = serde_json::from_str(&account_json()).unwrap();
        value["private_key"] = serde_json::json!(KEY.replace("PRIVATE KEY", "RSA PRIVATE KEY"));
        let err = ServiceAccount::parse(&value.to_string())
            .unwrap_err()
            .to_string();
        assert!(err.contains("PKCS#1"), "unhelpful error: {err}");
    }

    #[test]
    fn the_service_account_never_appears_in_a_debug_line() {
        let a = account();
        let rendered = format!("{a:?}");
        assert!(rendered.contains("enclave-test"));
        assert!(
            !rendered.contains("PRIVATE KEY") && !rendered.contains("kid-1"),
            "a debug line carried key material: {rendered}"
        );

        let token = AccessToken::new(
            TokenResponse {
                access_token: "ya29.secret-value".into(),
                expires_in: 3600,
            },
            0,
        );
        assert!(
            !format!("{token:?}").contains("secret-value"),
            "a debug line carried an access token"
        );
    }

    #[test]
    fn a_cached_access_token_is_reused_until_it_is_about_to_expire() {
        let token = AccessToken::new(
            TokenResponse {
                access_token: "ya29.x".into(),
                expires_in: 3600,
            },
            1_000_000,
        );
        assert_eq!(token.expires_at_ms, 1_000_000 + 3_600_000);
        assert!(token.is_fresh(1_000_000));
        assert!(token.is_fresh(1_000_000 + 3_600_000 - REFRESH_SKEW_MS - 1));
        assert!(
            !token.is_fresh(1_000_000 + 3_600_000 - REFRESH_SKEW_MS),
            "a token inside the refresh skew was still considered fresh"
        );
        assert!(!token.is_fresh(9_999_999_999));
    }

    /// A lifetime from the network decides when we next talk to the network,
    /// so it is clamped rather than believed.
    #[test]
    fn an_implausible_token_lifetime_is_clamped_rather_than_trusted() {
        let token = AccessToken::new(
            TokenResponse {
                access_token: "ya29.x".into(),
                expires_in: u64::MAX,
            },
            0,
        );
        assert_eq!(token.expires_at_ms, MAX_LIFETIME_MS);
    }

    #[test]
    fn the_token_request_is_a_jwt_bearer_grant() {
        let a = account();
        let jwt = a.assertion(0).unwrap();
        let body = a.token_form(&jwt);
        assert!(body.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ));
        assert!(
            !body[body.find("assertion=").unwrap()..].contains('+'),
            "the assertion needed escaping the body does not do"
        );
    }
}
