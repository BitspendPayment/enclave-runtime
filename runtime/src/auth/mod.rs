//! Who is allowed to reach the guest, and for which request.
//!
//! **No valid, fresh, single-use WebAuthn assertion bound to this exact
//! request means the guest is never called.** No session, no cookie, no bearer
//! token and no certificate authorizes a guest request by itself.
//!
//! ## The division of labour
//!
//! `webauthn-rs` verifies the assertion: that `clientDataJSON` names
//! `webauthn.get` and the challenge it was issued, that the origin matches
//! exactly, that `rpIdHash` is this relying party, that user *verification*
//! happened rather than mere presence, and that the signature checks out under
//! the credential's stored key.
//!
//! What it cannot know is which HTTP request any of that was for — WebAuthn has
//! no field for it. So [`challenge`] records, when a challenge is issued, the
//! method, path, query and body hash it was issued for, and the gate compares
//! that record against the request that actually arrived. Without it an
//! approval for one transaction would authorize another.
//!
//! ## What a signature does and does not prove
//!
//! An authenticator displays nothing. The user approves *a prompt at a moment*,
//! not a payload they read. So "the user approved this exact operation" is
//! precise only because the runtime chose the challenge, remembered what it was
//! for, and will accept it for nothing else — the strength is in the binding,
//! not in the ceremony.

/// A passkey in software, for tests and for the QEMU harness.
///
/// Behind a feature because it *forges assertions*. Nothing that can mint an
/// approval should be reachable in a production image, however carefully it is
/// otherwise unused.
#[cfg(any(test, feature = "testing"))]
pub mod authenticator;
pub mod challenge;
pub mod credential;
pub mod gate;
pub mod routes;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
mod token;

#[cfg(any(test, feature = "testing"))]
pub use authenticator::SoftwareAuthenticator;
pub use challenge::{ChallengeError, ChallengeStore, DEFAULT_CAPACITY, DEFAULT_TTL};
pub use credential::{mint_tenant_id, FilesystemCredentials, StoredCredential};
pub use gate::{
    Authenticated, CredentialRecord, CredentialStore, Denied, Gate, Verified, AUTHORIZATION_HEADER,
    AUTH_HEADERS,
};
pub use routes::{AuthEndpoints, AUTH_PREFIX};
pub use token::{
    InteractionScope, TokenError, TokenStore, DEFAULT_CAPACITY as DEFAULT_TOKEN_CAPACITY,
    DEFAULT_TTL as DEFAULT_TOKEN_TTL,
};

/// Build the relying party from a domain, an origin, and any further origins
/// assertions may claim.
///
/// All are checked here rather than deep inside a request: an enclave that
/// booted with a malformed origin would otherwise refuse every assertion at
/// runtime, with the reason buried.
///
/// `allowed_origins` exists for native apps, which do not claim
/// `https://<rp id>`. An Android app using Credential Manager claims
/// `android:apk-key-hash:<hash>`, and Android only lets it claim that after
/// checking the app against `https://<rp id>/.well-known/assetlinks.json` — so
/// the origin names an app the domain vouched for, not a page anyone can serve.
/// Every origin is still compared exactly.
pub fn build_relying_party(
    rp_id: &str,
    origin: &str,
    allowed_origins: &[String],
) -> anyhow::Result<webauthn_rs::Webauthn> {
    use anyhow::Context as _;
    let url = webauthn_rs::prelude::Url::parse(origin)
        .with_context(|| format!("--webauthn-origin {origin:?} is not a URL"))?;
    let mut builder = webauthn_rs::WebauthnBuilder::new(rp_id, &url)
        .with_context(|| format!("relying party {rp_id:?} at {origin:?}"))?;
    for allowed in allowed_origins {
        builder = builder.append_allowed_origin(&parse_allowed_origin(allowed)?);
    }
    builder.build().context("building the relying party")
}

/// Parse one `--webauthn-allowed-origin`, refusing the mistakes that would
/// otherwise surface only as every assertion from the app being refused.
///
/// An Android origin is checked for shape: the hash is the unpadded base64url
/// SHA-256 of the signing certificate. The likeliest wrong value is the
/// colon-separated hex fingerprint `keytool` and the Play Console print, which
/// names the same certificate but can never equal what Android sends.
fn parse_allowed_origin(origin: &str) -> anyhow::Result<webauthn_rs::prelude::Url> {
    use anyhow::Context as _;
    use base64::Engine as _;

    let url = webauthn_rs::prelude::Url::parse(origin)
        .with_context(|| format!("--webauthn-allowed-origin {origin:?} is not a URL"))?;
    if url.scheme() == "android" {
        let hash = url.path().strip_prefix("apk-key-hash:").with_context(|| {
            format!(
                "--webauthn-allowed-origin {origin:?}: an Android origin has the form \
                 android:apk-key-hash:<hash>"
            )
        })?;
        let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(hash)
            .ok()
            .filter(|d| d.len() == 32);
        anyhow::ensure!(
            digest.is_some(),
            "--webauthn-allowed-origin {origin:?}: the hash must be the SHA-256 of the \
             app's signing certificate as unpadded base64url (43 characters). A \
             colon-separated hex fingerprint from keytool or the Play Console names the \
             same certificate but must be converted: Android never sends it in that form."
        );
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of the empty string, in the form Android sends.
    const APK_KEY_HASH: &str = "android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    #[test]
    fn an_android_origin_is_accepted() {
        assert_eq!(
            parse_allowed_origin(APK_KEY_HASH).unwrap().as_str(),
            APK_KEY_HASH
        );
        build_relying_party(
            "enclave.test",
            "https://enclave.test",
            &[APK_KEY_HASH.into()],
        )
        .expect("relying party");
    }

    #[test]
    fn a_hex_fingerprint_is_refused_with_the_reason() {
        let err = parse_allowed_origin(
            "android:apk-key-hash:E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("hex fingerprint"), "{err:#}");
    }

    #[test]
    fn a_truncated_or_padded_hash_is_refused() {
        assert!(parse_allowed_origin(&APK_KEY_HASH[..APK_KEY_HASH.len() - 1]).is_err());
        assert!(parse_allowed_origin(&format!("{APK_KEY_HASH}=")).is_err());
    }

    #[test]
    fn an_android_origin_without_the_key_hash_prefix_is_refused() {
        assert!(
            parse_allowed_origin("android:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU").is_err()
        );
    }

    #[test]
    fn something_that_is_not_a_url_is_refused() {
        assert!(build_relying_party(
            "enclave.test",
            "https://enclave.test",
            &["not a url".into()]
        )
        .is_err());
    }
}
