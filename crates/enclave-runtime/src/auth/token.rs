//! Interaction tokens: what a passkey approval buys, once.
//!
//! A person approves an **interaction** — one HTTP request and its response, or
//! one bidirectional stream until it closes or reaches its lifetime limit. The
//! runtime records that approval as a short-lived, single-use bearer token, and
//! the interaction presents it.
//!
//! # What a token is and is not
//!
//! It authorizes **one interaction at one route**: a method, a path and a
//! query. It says nothing whatever about the bytes that travel on it.
//!
//! That is a deliberate policy, and the honest way to describe it is that the
//! approval names *what the person is about to do*, not *what they are about to
//! send*. A token issued for `POST /sign` authorizes whatever body follows, so
//! a client compromised between the approval and the request can substitute the
//! payload. Nothing here should be described as proof that a person approved
//! particular bytes, because it is not.
//!
//! What it does still carry: a person authenticated with their passkey to get
//! it, it belongs to exactly one tenant, it is good once, and it expires.
//!
//! # Why the store never holds a token
//!
//! Entries are keyed by `sha256(token)`. Possession of the store is not
//! possession of a token — the same reason [`crate::auth::EnrollmentTokens`]
//! names its files by their hash rather than their contents.
//!
//! Nothing here survives a restart, and nothing should: an approval that
//! outlived the enclave that issued it would be an approval nobody could
//! account for.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a token may sit unused before it is worthless.
///
/// This bounds the time to *start* an interaction, and is deliberately not the
/// same thing as how long one may run once started — see the runtime's
/// interaction deadline for that. A person who approves something and then puts
/// their phone down should not find the approval still live an hour later.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Outstanding tokens allowed at once.
///
/// The bound on what authenticated callers can make the runtime hold. Reaching
/// it refuses new tokens rather than evicting live ones — evicting to admit
/// would let one caller cancel another's approval.
pub const DEFAULT_CAPACITY: usize = 1024;

/// The one interaction a token is good for.
///
/// Every field is something an attacker would otherwise be free to vary while
/// spending an approval given for something else. There is deliberately no
/// body hash: an interaction may be a stream, whose body does not exist when
/// the approval is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionScope {
    pub method: String,
    pub path: String,
    /// `None` and `Some("")` are different: an approval for `?a=1` must not be
    /// usable for a request with no query at all.
    pub query: Option<String>,
}

impl InteractionScope {
    pub fn new(method: &str, path: &str, query: Option<&str>) -> Self {
        InteractionScope {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            query: query.map(str::to_string),
        }
    }
}

/// What an approval was recorded as.
struct Granted {
    tenant_id: [u8; 16],
    scope: InteractionScope,
    expires: Instant,
}

/// Why a token could not be spent.
///
/// Distinguished for the log, never for the client. "Wrong route" and "no such
/// token" tell an attacker which half of a guess was right; a legitimate caller
/// learns nothing it can act on from either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Unknown,
    Expired,
    WrongInteraction,
    Full,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenError::Unknown => "no such token, or it has already been spent",
            TokenError::Expired => "the token expired before it was used",
            TokenError::WrongInteraction => "the token was issued for a different interaction",
            TokenError::Full => "too many outstanding tokens",
        })
    }
}

/// Live approvals, keyed by the hash of the token that names them.
///
/// No `Debug`: a store that printed itself would put the only thing standing
/// between a caller and a tenant's guest into any log line that formatted a
/// struct containing one.
pub struct TokenStore {
    granted: Mutex<HashMap<[u8; 32], Granted>>,
    ttl: Duration,
    capacity: usize,
}

impl TokenStore {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        TokenStore {
            granted: Mutex::new(HashMap::new()),
            ttl,
            capacity: capacity.max(1),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Record an approval against a token the caller has already generated.
    ///
    /// The token itself is never stored — only its hash — so this takes the
    /// bytes, hashes them, and forgets them.
    pub fn issue(
        &self,
        token: &[u8],
        tenant_id: [u8; 16],
        scope: InteractionScope,
    ) -> Result<(), TokenError> {
        let now = Instant::now();
        let mut granted = self.granted.lock().expect("token store poisoned");
        granted.retain(|_, g| g.expires > now);
        if granted.len() >= self.capacity {
            return Err(TokenError::Full);
        }
        granted.insert(
            nitro_attestation::sha256(token),
            Granted {
                tenant_id,
                scope,
                expires: now + self.ttl,
            },
        );
        Ok(())
    }

    /// Spend a token on one interaction.
    ///
    /// Removed before anything about it is checked, so a token offered for the
    /// wrong route is gone as surely as one that worked. Two callers racing the
    /// same token reach the `remove` in some order and exactly one finds it —
    /// which is what makes "one interaction" true under concurrency rather than
    /// only in a diagram.
    pub fn redeem(&self, token: &[u8], scope: &InteractionScope) -> Result<[u8; 16], TokenError> {
        let mut granted = self.granted.lock().expect("token store poisoned");
        let entry = granted
            .remove(&nitro_attestation::sha256(token))
            .ok_or(TokenError::Unknown)?;
        if entry.expires <= Instant::now() {
            return Err(TokenError::Expired);
        }
        if &entry.scope != scope {
            return Err(TokenError::WrongInteraction);
        }
        Ok(entry.tenant_id)
    }

    pub fn outstanding(&self) -> usize {
        let now = Instant::now();
        let mut granted = self.granted.lock().expect("token store poisoned");
        granted.retain(|_, g| g.expires > now);
        granted.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> InteractionScope {
        InteractionScope::new("POST", "/sign", None)
    }

    fn store() -> TokenStore {
        TokenStore::new(DEFAULT_TTL, DEFAULT_CAPACITY)
    }

    #[test]
    fn a_token_is_good_for_the_interaction_it_was_issued_for() {
        let s = store();
        s.issue(b"a-token", [7u8; 16], scope()).unwrap();
        assert_eq!(s.redeem(b"a-token", &scope()).unwrap(), [7u8; 16]);
    }

    /// **One interaction.** The second attempt has nothing to find.
    #[test]
    fn a_token_cannot_be_spent_twice() {
        let s = store();
        s.issue(b"a-token", [7u8; 16], scope()).unwrap();
        s.redeem(b"a-token", &scope()).unwrap();
        assert_eq!(s.redeem(b"a-token", &scope()), Err(TokenError::Unknown));
    }

    /// **The substitution this model still refuses.** An approval names a
    /// route, and cannot be moved to another one.
    #[test]
    fn a_token_cannot_be_moved_to_another_route() {
        for wrong in [
            InteractionScope::new("POST", "/withdraw", None),
            InteractionScope::new("GET", "/sign", None),
            InteractionScope::new("POST", "/sign", Some("all=true")),
        ] {
            let s = store();
            s.issue(b"a-token", [7u8; 16], scope()).unwrap();
            assert_eq!(
                s.redeem(b"a-token", &wrong),
                Err(TokenError::WrongInteraction),
                "an approval for {:?} was spent on {wrong:?}",
                scope()
            );
        }
    }

    /// And a refused attempt still spends it — a caller that guessed the route
    /// wrong does not get to keep guessing with the same token.
    #[test]
    fn a_token_offered_for_the_wrong_route_is_still_gone() {
        let s = store();
        s.issue(b"a-token", [7u8; 16], scope()).unwrap();
        let wrong = InteractionScope::new("POST", "/withdraw", None);
        assert_eq!(
            s.redeem(b"a-token", &wrong),
            Err(TokenError::WrongInteraction)
        );
        assert_eq!(
            s.redeem(b"a-token", &scope()),
            Err(TokenError::Unknown),
            "the token survived being offered for the wrong interaction"
        );
    }

    #[test]
    fn an_expired_token_is_refused_and_destroyed_by_the_attempt() {
        let s = TokenStore::new(Duration::from_millis(1), DEFAULT_CAPACITY);
        s.issue(b"a-token", [7u8; 16], scope()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(s.redeem(b"a-token", &scope()), Err(TokenError::Expired));
        assert_eq!(s.redeem(b"a-token", &scope()), Err(TokenError::Unknown));
    }

    /// A full store refuses new approvals rather than cancelling live ones.
    #[test]
    fn a_full_store_refuses_rather_than_evicting() {
        let s = TokenStore::new(DEFAULT_TTL, 2);
        s.issue(b"one", [1u8; 16], scope()).unwrap();
        s.issue(b"two", [2u8; 16], scope()).unwrap();
        assert_eq!(s.issue(b"three", [3u8; 16], scope()), Err(TokenError::Full));
        // And the two that were there are untouched.
        assert_eq!(s.redeem(b"one", &scope()).unwrap(), [1u8; 16]);
        assert_eq!(s.redeem(b"two", &scope()).unwrap(), [2u8; 16]);
    }

    /// Two tenants' approvals never resolve to each other.
    #[test]
    fn a_token_resolves_only_to_its_own_tenant() {
        let s = store();
        s.issue(b"alices", [0xaa; 16], scope()).unwrap();
        s.issue(b"bobs", [0xbb; 16], scope()).unwrap();
        assert_eq!(s.redeem(b"alices", &scope()).unwrap(), [0xaa; 16]);
        assert_eq!(s.redeem(b"bobs", &scope()).unwrap(), [0xbb; 16]);
    }

    /// Nothing outlives the enclave that issued it.
    #[test]
    fn an_unused_token_does_not_survive_a_restart() {
        let before = store();
        before.issue(b"a-token", [7u8; 16], scope()).unwrap();
        let after = store();
        assert_eq!(
            after.redeem(b"a-token", &scope()),
            Err(TokenError::Unknown),
            "an approval survived the runtime that issued it"
        );
    }

    /// **Under concurrency, exactly one winner.**
    #[test]
    fn racing_redemptions_have_exactly_one_winner() {
        use std::sync::Arc;
        for _ in 0..25 {
            let s = Arc::new(store());
            s.issue(b"a-token", [7u8; 16], scope()).unwrap();
            let winners: usize = std::thread::scope(|scope_| {
                let handles: Vec<_> = (0..8)
                    .map(|_| {
                        let s = s.clone();
                        scope_.spawn(move || {
                            usize::from(s.redeem(b"a-token", &super::tests::scope()).is_ok())
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).sum()
            });
            assert_eq!(winners, 1, "a token was spent {winners} times");
        }
    }
}
