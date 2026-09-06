//! Challenges, and what each one is *for*.
//!
//! A WebAuthn assertion proves that a passkey signed a challenge with user
//! verification. It says nothing at all about which HTTP request that was
//! meant to authorize — the protocol has no field for it, and an authenticator
//! displays nothing the user could check.
//!
//! So the binding is the server's job, and this is where it is kept. Issuing a
//! challenge records the exact request it was issued for; consuming one hands
//! that record back, and the caller compares it against the request that
//! actually arrived. An assertion moved to a different body, a different path
//! or a different method names a challenge whose record does not match, and is
//! refused.
//!
//! Three properties make that hold, and all three are enforced here rather than
//! left to a caller to remember:
//!
//! - **Single use.** [`ChallengeStore::consume`] removes the entry as it
//!   returns it, under one lock, so two copies of one assertion cannot both
//!   find it. That is not a nicety: replaying a signing approval is the whole
//!   attack.
//! - **Short lived.** An unconsumed challenge expires, so an assertion captured
//!   and held is worthless within the minute.
//! - **Bounded.** The table is capped and swept, because anyone who can reach
//!   the runtime can ask for challenges, and memory in an enclave is finite.
//!
//! Nothing here survives a restart, and nothing should: the browser asks for a
//! new challenge, and every assertion in flight becomes worthless. That is the
//! safe direction to fail in.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use webauthn_rs::prelude::PasskeyAuthentication;

/// How long a challenge is good for.
///
/// Long enough for a human to look at a prompt and present a finger; short
/// enough that a captured assertion is stale before it can be used. WebAuthn
/// gives the authenticator its own timeout, but that one is advisory and the
/// client controls it — this one is not.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Outstanding challenges allowed at once.
///
/// Issuing one is unauthenticated by necessity — a client cannot prove who it
/// is until it has a challenge to sign — so this is the bound on what an
/// anonymous caller can make the runtime hold.
pub const DEFAULT_CAPACITY: usize = 1024;

/// What a challenge was issued for.
///
/// Every field is something an attacker would otherwise be free to vary while
/// reusing an approval the user gave for something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBinding {
    pub method: String,
    pub path: String,
    /// `None` and `Some("")` are different: a challenge issued for `?a=1` must
    /// not be usable for a request with no query at all.
    pub query: Option<String>,
    pub body: BodyBinding,
}

/// What an approval says about the body.
///
/// The distinction is the whole of what separates authorizing an operation
/// from authorizing a channel, and it is an enum rather than an
/// `Option<[u8; 32]>` so that neither can be mistaken for the other by
/// anything that merely forgot to look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyBinding {
    /// SHA-256 of the exact bytes, recomputed by the runtime from what it will
    /// forward — never taken from the client. **The only binding that
    /// authorizes an operation**, because it is the only one that says which
    /// operation.
    Exact([u8; 32]),
    /// Nothing at all about the body.
    ///
    /// Issued only for opening a bidirectional stream, where there is no body
    /// yet to commit to: the messages are the body, and they do not exist when
    /// the channel opens. It authorizes **opening one channel on this
    /// method, path and query, and nothing else** — the same shape as an
    /// enrollment token, which authorizes creating a tenant and nothing else.
    ///
    /// It approves no message that travels on the channel. Anything asking the
    /// enclave to sign carries its own fresh, single-use assertion, inside the
    /// stream. Treating an open channel as standing permission to sign is the
    /// failure this split exists to prevent.
    Unbound,
}

impl RequestBinding {
    pub fn new(method: &str, path: &str, query: Option<&str>, body: &[u8]) -> Self {
        RequestBinding {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            query: query.map(str::to_string),
            body: BodyBinding::Exact(nitro_attestation::sha256(body)),
        }
    }

    /// The only way to make an approval that commits to no body.
    ///
    /// Separate from [`RequestBinding::new`] deliberately: an unbound approval
    /// is weaker than every other kind, so it should be impossible to produce
    /// one by passing a different argument to the usual constructor.
    pub fn stream_open(method: &str, path: &str, query: Option<&str>) -> Self {
        RequestBinding {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            query: query.map(str::to_string),
            body: BodyBinding::Unbound,
        }
    }

    /// Whether this approval commits to a body, and so to an operation.
    pub fn is_stream_open(&self) -> bool {
        matches!(self.body, BodyBinding::Unbound)
    }
}

/// A challenge that has been issued and not yet used.
struct Pending {
    binding: RequestBinding,
    /// The crate's own state for this challenge. Holding it here is what makes
    /// the challenge single-use: it exists in exactly one place, and consuming
    /// takes it.
    state: PasskeyAuthentication,
    expires: Instant,
}

/// Why a challenge could not be used.
///
/// Distinguished for the log, never for the client: an attacker learns
/// something from "expired" versus "already used" and a legitimate caller
/// learns nothing it can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    Unknown,
    Expired,
    Full,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ChallengeError::Unknown => "no such challenge, or it has already been used",
            ChallengeError::Expired => "the challenge expired",
            ChallengeError::Full => "too many outstanding challenges",
        })
    }
}

pub struct ChallengeStore {
    pending: Mutex<HashMap<[u8; 16], Pending>>,
    ttl: Duration,
    capacity: usize,
}

impl ChallengeStore {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        ChallengeStore {
            pending: Mutex::new(HashMap::new()),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Record a challenge and what it is for.
    ///
    /// `id` is generated by the caller from the enclave's entropy source, so
    /// the identifier a client quotes back is unguessable — otherwise an
    /// attacker could name somebody else's outstanding challenge and race them
    /// for it.
    pub fn issue(
        &self,
        id: [u8; 16],
        binding: RequestBinding,
        state: PasskeyAuthentication,
    ) -> Result<(), ChallengeError> {
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("challenge store poisoned");
        pending.retain(|_, p| p.expires > now);
        if pending.len() >= self.capacity {
            return Err(ChallengeError::Full);
        }
        pending.insert(
            id,
            Pending {
                binding,
                state,
                expires: now + self.ttl,
            },
        );
        Ok(())
    }

    /// Take a challenge, if it is there and still good.
    ///
    /// Removes it whether or not it turns out to verify. A challenge that was
    /// offered to a bad assertion has been seen by whoever sent it, and giving
    /// them a second attempt at the same one buys nothing but attempts.
    pub fn consume(
        &self,
        id: &[u8; 16],
    ) -> Result<(RequestBinding, PasskeyAuthentication), ChallengeError> {
        let mut pending = self.pending.lock().expect("challenge store poisoned");
        let entry = pending.remove(id).ok_or(ChallengeError::Unknown)?;
        if entry.expires <= Instant::now() {
            return Err(ChallengeError::Expired);
        }
        Ok((entry.binding, entry.state))
    }

    pub fn outstanding(&self) -> usize {
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("challenge store poisoned");
        pending.retain(|_, p| p.expires > now);
        pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::Relying;

    #[test]
    fn a_binding_normalises_the_method_and_hashes_the_body() {
        let b = RequestBinding::new("post", "/sign", None, b"x");
        assert_eq!(b.method, "POST", "method case must not decide a match");
        assert_eq!(b.body, BodyBinding::Exact(nitro_attestation::sha256(b"x")));
    }

    /// A query that is absent is not a query that is empty. Otherwise a
    /// challenge issued for `?limit=1` would be usable with no query at all.
    #[test]
    fn an_absent_query_differs_from_an_empty_one() {
        assert_ne!(
            RequestBinding::new("GET", "/p", None, b""),
            RequestBinding::new("GET", "/p", Some(""), b"")
        );
    }

    #[test]
    fn a_different_body_is_a_different_binding() {
        assert_ne!(
            RequestBinding::new("POST", "/sign", None, b"pay alice"),
            RequestBinding::new("POST", "/sign", None, b"pay mallory")
        );
    }

    /// Issued, then used once — and the second attempt finds nothing. This is
    /// what stops a captured signing approval being replayed.
    #[test]
    fn a_challenge_can_be_consumed_exactly_once() {
        let rp = Relying::new();
        let store = ChallengeStore::new(DEFAULT_TTL, DEFAULT_CAPACITY);
        let id = [1u8; 16];
        let binding = RequestBinding::new("POST", "/sign", None, b"tx");

        store
            .issue(id, binding.clone(), rp.begin_authentication().1)
            .unwrap();
        assert_eq!(store.consume(&id).unwrap().0, binding);
        assert_eq!(store.consume(&id).unwrap_err(), ChallengeError::Unknown);
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let rp = Relying::new();
        let store = ChallengeStore::new(Duration::from_millis(1), DEFAULT_CAPACITY);
        let id = [2u8; 16];
        store
            .issue(
                id,
                RequestBinding::new("POST", "/sign", None, b""),
                rp.begin_authentication().1,
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.consume(&id).unwrap_err(), ChallengeError::Expired);
    }

    #[test]
    fn an_unknown_challenge_is_refused() {
        let store = ChallengeStore::new(DEFAULT_TTL, DEFAULT_CAPACITY);
        assert_eq!(
            store.consume(&[9u8; 16]).unwrap_err(),
            ChallengeError::Unknown
        );
    }

    /// Issuing is unauthenticated by necessity, so the table has to be bounded
    /// against whoever can reach the port.
    #[test]
    fn the_store_refuses_to_grow_without_bound() {
        let rp = Relying::new();
        let store = ChallengeStore::new(DEFAULT_TTL, 4);
        for i in 0..4u8 {
            let mut id = [0u8; 16];
            id[0] = i;
            store
                .issue(
                    id,
                    RequestBinding::new("GET", "/", None, b""),
                    rp.begin_authentication().1,
                )
                .unwrap();
        }
        assert_eq!(
            store
                .issue(
                    [99u8; 16],
                    RequestBinding::new("GET", "/", None, b""),
                    rp.begin_authentication().1
                )
                .unwrap_err(),
            ChallengeError::Full
        );
        assert_eq!(store.outstanding(), 4);
    }

    /// Expired entries are swept, so a burst does not wedge the store for the
    /// lifetime of the process.
    #[test]
    fn expiry_makes_room() {
        let rp = Relying::new();
        let store = ChallengeStore::new(Duration::from_millis(1), 2);
        for i in 0..2u8 {
            let mut id = [0u8; 16];
            id[0] = i;
            store
                .issue(
                    id,
                    RequestBinding::new("GET", "/", None, b""),
                    rp.begin_authentication().1,
                )
                .unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.outstanding(), 0);
        store
            .issue(
                [7u8; 16],
                RequestBinding::new("GET", "/", None, b""),
                rp.begin_authentication().1,
            )
            .unwrap();
    }

    /// The refusal that costs nothing to maintain.
    ///
    /// A stream-open binding and an ordinary one are different values, so
    /// neither can satisfy the other's comparison. No `if` enforces this and
    /// none can be forgotten — which matters more than the check itself,
    /// because the check is in `Gate::verify` and this is what makes it
    /// impossible to weaken by accident there.
    #[test]
    fn a_stream_open_binding_never_equals_a_bound_one() {
        let bound = RequestBinding::new("POST", "/sign", None, b"");
        let open = RequestBinding::stream_open("POST", "/sign", None);
        assert_ne!(bound, open);
        assert!(open.is_stream_open());
        assert!(!bound.is_stream_open());
        // Including against the hash of the empty body, which is the one an
        // unbound binding might plausibly be mistaken for.
        assert_ne!(
            open.body,
            BodyBinding::Exact(nitro_attestation::sha256(b""))
        );
    }

    /// It still pins the route, so an approval to open one channel is not an
    /// approval to open a different one.
    #[test]
    fn a_stream_open_binding_still_pins_the_route() {
        let sign = RequestBinding::stream_open("POST", "/Sign", None);
        assert_ne!(sign, RequestBinding::stream_open("POST", "/Withdraw", None));
        assert_ne!(sign, RequestBinding::stream_open("GET", "/Sign", None));
        assert_ne!(
            sign,
            RequestBinding::stream_open("POST", "/Sign", Some("a=1"))
        );
    }
}
