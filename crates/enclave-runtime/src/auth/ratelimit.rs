//! How often one credential may make a phone buzz.
//!
//! Issuing a challenge is cheap for the runtime and expensive for a person: it
//! is what puts a biometric prompt in front of them. An attacker who can ask
//! for challenges without limit can ask a hundred times in a row, and the
//! attack is not on the enclave at all — it is on the human, waiting for the
//! one tap that approves something.
//!
//! ## Per credential, not per address
//!
//! The plan for this said "per credential and per peer". Per peer turns out to
//! be nearly useless in the deployment this runs in: the enclave sits behind
//! gvproxy, which forwards `:443` from one address, so **every client arrives
//! from the same peer**. An address limit would throttle everybody together
//! and single nobody out.
//!
//! So the key is the credential. That is also the right unit for what is being
//! protected — one person's attention — and it is unforgeable in the only
//! sense that matters here: an attacker can name someone else's credential id,
//! but naming it is exactly what triggers the prompt, so limiting by it limits
//! the attack.
//!
//! A coarse global ceiling sits behind that, because a credential id is 32
//! bytes an attacker can vary freely to get a fresh bucket each time.
//!
//! ## Fixed windows, deliberately
//!
//! A fixed window allows a burst across a boundary — up to twice the rate over
//! two adjacent windows. That is fine for this: the number being defended is a
//! human's patience, not a precise budget, and a token bucket's extra state
//! buys nothing at this granularity. Said out loud so the burst is a known
//! property rather than a surprise.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Challenges one credential may ask for per window.
pub const DEFAULT_PER_CREDENTIAL: u32 = 10;
/// Challenges anyone may ask for per window, across all credentials.
pub const DEFAULT_GLOBAL: u32 = 120;
/// How long a window lasts.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
/// Distinct keys tracked at once. Bounds what an attacker varying credential
/// ids can make the runtime hold.
const MAX_KEYS: usize = 4096;

struct Window {
    started: Instant,
    count: u32,
}

/// A fixed-window counter, keyed by whatever the caller is limiting.
pub struct RateLimiter {
    windows: Mutex<HashMap<Vec<u8>, Window>>,
    global: Mutex<Window>,
    per_key: u32,
    per_global: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(per_key: u32, per_global: u32, window: Duration) -> Self {
        RateLimiter {
            windows: Mutex::new(HashMap::new()),
            global: Mutex::new(Window {
                started: Instant::now(),
                count: 0,
            }),
            per_key: per_key.max(1),
            per_global: per_global.max(1),
            window,
        }
    }

    /// Count one attempt. `false` means it is over the limit.
    ///
    /// The global ceiling is checked first and counted only if the per-key
    /// check also passes, so a single noisy credential cannot exhaust
    /// everybody else's budget by being refused repeatedly.
    pub fn allow(&self, key: &[u8]) -> bool {
        let now = Instant::now();

        {
            let mut windows = self.windows.lock().expect("rate limiter poisoned");
            windows.retain(|_, w| now.duration_since(w.started) < self.window);
            // Full means refuse, not evict: evicting to make room would let an
            // attacker varying keys reset somebody else's counter.
            if windows.len() >= MAX_KEYS && !windows.contains_key(key) {
                return false;
            }
            let entry = windows.entry(key.to_vec()).or_insert(Window {
                started: now,
                count: 0,
            });
            if now.duration_since(entry.started) >= self.window {
                entry.started = now;
                entry.count = 0;
            }
            if entry.count >= self.per_key {
                return false;
            }
            entry.count += 1;
        }

        let mut global = self.global.lock().expect("rate limiter poisoned");
        if now.duration_since(global.started) >= self.window {
            global.started = now;
            global.count = 0;
        }
        if global.count >= self.per_global {
            return false;
        }
        global.count += 1;
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter::new(DEFAULT_PER_CREDENTIAL, DEFAULT_GLOBAL, DEFAULT_WINDOW)
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("per_key", &self.per_key)
            .field("per_global", &self.per_global)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_is_limited() {
        let limiter = RateLimiter::new(3, 100, Duration::from_secs(60));
        for i in 0..3 {
            assert!(limiter.allow(b"alice"), "attempt {i} was refused early");
        }
        assert!(!limiter.allow(b"alice"), "a fourth prompt was allowed");
    }

    /// One noisy credential must not silence another. This is the difference
    /// between limiting an attacker and limiting the victim.
    #[test]
    fn one_credential_does_not_limit_another() {
        let limiter = RateLimiter::new(2, 100, Duration::from_secs(60));
        assert!(limiter.allow(b"attacker"));
        assert!(limiter.allow(b"attacker"));
        assert!(!limiter.allow(b"attacker"));
        assert!(
            limiter.allow(b"victim"),
            "a victim was limited by an attacker"
        );
    }

    /// A credential id is 32 bytes an attacker can vary freely, so there has to
    /// be a ceiling behind the per-key limit.
    #[test]
    fn varying_the_key_still_hits_a_global_ceiling() {
        let limiter = RateLimiter::new(10, 5, Duration::from_secs(60));
        let allowed = (0u16..50)
            .filter(|i| limiter.allow(&i.to_be_bytes()))
            .count();
        assert_eq!(allowed, 5, "the global ceiling did not hold");
    }

    #[test]
    fn a_window_expires() {
        let limiter = RateLimiter::new(1, 100, Duration::from_millis(20));
        assert!(limiter.allow(b"alice"));
        assert!(!limiter.allow(b"alice"));
        std::thread::sleep(Duration::from_millis(40));
        assert!(limiter.allow(b"alice"), "the window never reopened");
    }

    /// A refusal must not consume global budget, or a credential being refused
    /// in a loop would starve everyone else.
    #[test]
    fn a_refused_attempt_does_not_spend_the_global_budget() {
        let limiter = RateLimiter::new(1, 10, Duration::from_secs(60));
        assert!(limiter.allow(b"noisy"));
        for _ in 0..50 {
            assert!(!limiter.allow(b"noisy"));
        }
        // Nine of the global ten remain for everybody else.
        let others = (0u16..9)
            .filter(|i| limiter.allow(&i.to_be_bytes()))
            .count();
        assert_eq!(others, 9, "refusals ate the global budget");
    }

    /// The table is bounded, and filling it must not reset an existing
    /// credential's counter.
    #[test]
    fn a_full_table_refuses_new_keys_rather_than_evicting() {
        let limiter = RateLimiter::new(1, u32::MAX, Duration::from_secs(60));
        for i in 0..MAX_KEYS {
            assert!(limiter.allow(&(i as u64).to_be_bytes()));
        }
        assert!(
            !limiter.allow(b"one-too-many"),
            "a full table admitted a new key"
        );
        // The keys already there keep their counts.
        assert!(!limiter.allow(&0u64.to_be_bytes()));
    }
}
