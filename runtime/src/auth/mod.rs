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

/// Build the relying party from a domain and an origin.
///
/// Both are checked here rather than deep inside a request: an enclave that
/// booted with a malformed origin would otherwise refuse every assertion at
/// runtime, with the reason buried.
pub fn build_relying_party(rp_id: &str, origin: &str) -> anyhow::Result<webauthn_rs::Webauthn> {
    use anyhow::Context as _;
    let url = webauthn_rs::prelude::Url::parse(origin)
        .with_context(|| format!("--webauthn-origin {origin:?} is not a URL"))?;
    webauthn_rs::WebauthnBuilder::new(rp_id, &url)
        .with_context(|| format!("relying party {rp_id:?} at {origin:?}"))?
        .build()
        .context("building the relying party")
}
