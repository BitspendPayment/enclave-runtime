//! What the guest's environment contains, and what it must never contain.
//!
//! This process holds the filesystem master key, and under the attestation
//! milestone it will hold KMS-released credentials. The guest is the code the
//! enclave exists to contain. So the environment it sees is the host's, minus
//! two categories:
//!
//! - **Credentials**, obviously.
//! - **The runtime's own configuration**, which tells the guest where its data
//!   lives and is of no use to it — an enclave guest has no network of its own.
//!
//! Both fall under one rule that is easy to state and hard to get wrong:
//! nothing whose name begins with `AWS_` or `S3FS_` is inherited. That covers
//! `S3FS_MASTER_KEY` and the whole AWS credential set without anyone having to
//! enumerate them, and it keeps working when a new one is added.
//!
//! An operator who genuinely needs one of those names can still set it
//! explicitly. Explicit is a decision; inheritance is an accident waiting to
//! happen.

use std::collections::BTreeMap;

/// Name prefixes that are never inherited from the host.
pub const DENIED_PREFIXES: &[&str] = &["AWS_", "S3FS_"];

/// Names that are credentials wherever they appear. Setting one explicitly is
/// permitted — the operator asked for it — but it is worth saying out loud.
const CREDENTIAL_NAMES: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "S3FS_MASTER_KEY",
];

fn is_denied(name: &str) -> bool {
    DENIED_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn is_credential(name: &str) -> bool {
    CREDENTIAL_NAMES.contains(&name)
}

/// How the guest's environment is assembled.
#[derive(Debug, Clone)]
pub struct GuestEnvPolicy {
    /// Inherit the host environment (minus [`DENIED_PREFIXES`]).
    pub inherit: bool,
    /// Explicit entries, as `NAME` (inherit that one by name) or `NAME=VALUE`.
    /// Applied after inheritance, so they override it.
    pub explicit: Vec<String>,
}

impl Default for GuestEnvPolicy {
    fn default() -> Self {
        GuestEnvPolicy {
            inherit: true,
            explicit: Vec::new(),
        }
    }
}

impl GuestEnvPolicy {
    /// Inherit nothing; the guest sees only what is named explicitly.
    pub fn explicit_only(explicit: Vec<String>) -> Self {
        GuestEnvPolicy {
            inherit: false,
            explicit,
        }
    }

    /// Build the environment, reading the host's via `std::env::vars`.
    pub fn build(&self) -> anyhow::Result<Vec<(String, String)>> {
        self.build_from(std::env::vars().collect::<Vec<_>>().as_slice())
    }

    /// Build against an explicit host environment. Separated so the policy is
    /// testable without mutating the process, which no test should have to do.
    pub fn build_from(&self, host: &[(String, String)]) -> anyhow::Result<Vec<(String, String)>> {
        // Sorted so the guest's environment is deterministic regardless of the
        // host's iteration order.
        let mut out: BTreeMap<String, String> = BTreeMap::new();
        let lookup = |name: &str| -> Option<&str> {
            host.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };

        if self.inherit {
            let mut denied: Vec<&str> = Vec::new();
            for (name, value) in host {
                if is_denied(name) {
                    denied.push(name);
                    continue;
                }
                out.insert(name.clone(), value.clone());
            }
            if !denied.is_empty() {
                // Say what was withheld. A guest missing a variable should be
                // diagnosable from the log rather than mysterious.
                denied.sort_unstable();
                tracing::info!(
                    withheld = denied.join(", "),
                    "guest environment: withheld runtime configuration and credentials"
                );
            }
        }

        for spec in &self.explicit {
            let (name, value) = match spec.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (spec.as_str(), None),
            };
            if name.is_empty() {
                anyhow::bail!("guest-env: empty variable name in {spec:?}");
            }
            let value = match value {
                Some(v) => v,
                None => match lookup(name) {
                    Some(v) => v.to_string(),
                    // A bare name that is unset on the host is skipped rather
                    // than passed as empty, so the guest can tell "unset" from
                    // "set to nothing".
                    None => {
                        tracing::debug!(name, "guest-env: not set on host, skipping");
                        continue;
                    }
                },
            };
            if is_credential(name) {
                tracing::warn!(
                    name,
                    "guest-env: exposing a credential to guest code, because it was named explicitly"
                );
            }
            out.insert(name.to_string(), value);
        }

        Ok(out.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Vec<(String, String)> {
        [
            ("LANG", "en_GB.UTF-8"),
            ("RUST_LOG", "info"),
            ("MY_APP_ENDPOINT", "https://example.invalid"),
            ("AWS_SECRET_ACCESS_KEY", "super-secret"),
            ("AWS_ACCESS_KEY_ID", "AKIA..."),
            ("AWS_SESSION_TOKEN", "token"),
            ("AWS_REGION", "eu-west-2"),
            ("S3FS_MASTER_KEY", "0011..."),
            ("S3FS_BUCKET", "prod-data"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn names(env: &[(String, String)]) -> Vec<&str> {
        env.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn inheritance_passes_ordinary_variables() {
        let env = GuestEnvPolicy::default().build_from(&host()).unwrap();
        assert_eq!(names(&env), vec!["LANG", "MY_APP_ENDPOINT", "RUST_LOG"]);
    }

    /// The property the whole module exists for.
    #[test]
    fn no_credential_or_runtime_variable_is_ever_inherited() {
        let env = GuestEnvPolicy::default().build_from(&host()).unwrap();
        for (name, _) in &env {
            assert!(
                !name.starts_with("AWS_") && !name.starts_with("S3FS_"),
                "{name} reached the guest by inheritance"
            );
        }
        assert!(!env.iter().any(|(_, v)| v == "super-secret"));
    }

    /// Withholding is by prefix, not by an enumerated list, so a variable
    /// nobody thought of is still withheld.
    #[test]
    fn an_unanticipated_denied_variable_is_still_withheld() {
        let mut h = host();
        h.push(("AWS_SOMETHING_INVENTED_LATER".into(), "x".into()));
        h.push(("S3FS_FUTURE_OPTION".into(), "y".into()));
        let env = GuestEnvPolicy::default().build_from(&h).unwrap();
        assert!(!names(&env).iter().any(|n| n.contains("INVENTED")));
        assert!(!names(&env).iter().any(|n| n.contains("FUTURE")));
    }

    #[test]
    fn an_explicit_value_overrides_inheritance() {
        let policy = GuestEnvPolicy {
            inherit: true,
            explicit: vec!["RUST_LOG=trace".into()],
        };
        let env = policy.build_from(&host()).unwrap();
        assert_eq!(
            env.iter().find(|(k, _)| k == "RUST_LOG").unwrap().1,
            "trace"
        );
    }

    /// A deployment that genuinely needs a denied name can still have it, but
    /// only by saying so.
    #[test]
    fn an_explicitly_named_denied_variable_is_allowed_through() {
        let policy = GuestEnvPolicy {
            inherit: true,
            explicit: vec!["AWS_REGION".into()],
        };
        let env = policy.build_from(&host()).unwrap();
        assert_eq!(
            env.iter().find(|(k, _)| k == "AWS_REGION").unwrap().1,
            "eu-west-2"
        );
        // ...and nothing else under the prefix came with it.
        assert!(!names(&env).contains(&"AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn explicit_only_inherits_nothing() {
        let policy = GuestEnvPolicy::explicit_only(vec!["LANG".into(), "EXTRA=1".into()]);
        let env = policy.build_from(&host()).unwrap();
        assert_eq!(names(&env), vec!["EXTRA", "LANG"]);
    }

    #[test]
    fn explicit_only_with_nothing_named_yields_an_empty_environment() {
        assert!(GuestEnvPolicy::explicit_only(vec![])
            .build_from(&host())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_bare_name_unset_on_the_host_is_skipped_not_blanked() {
        let policy = GuestEnvPolicy::explicit_only(vec!["NOT_SET_ANYWHERE".into()]);
        assert!(policy.build_from(&host()).unwrap().is_empty());
    }

    #[test]
    fn an_explicit_empty_value_is_kept() {
        let policy = GuestEnvPolicy::explicit_only(vec!["EMPTY=".into()]);
        let env = policy.build_from(&host()).unwrap();
        assert_eq!(env, vec![("EMPTY".to_string(), String::new())]);
    }

    #[test]
    fn a_value_may_contain_equals_signs() {
        let policy = GuestEnvPolicy::explicit_only(vec!["OPTS=a=1,b=2".into()]);
        let env = policy.build_from(&host()).unwrap();
        assert_eq!(env[0].1, "a=1,b=2");
    }

    #[test]
    fn an_empty_variable_name_is_rejected() {
        assert!(GuestEnvPolicy::explicit_only(vec!["=value".into()])
            .build_from(&host())
            .is_err());
        assert!(GuestEnvPolicy::explicit_only(vec![String::new()])
            .build_from(&host())
            .is_err());
    }

    /// Two runs with the same inputs must produce the same environment, even
    /// though the host's iteration order is not defined.
    #[test]
    fn output_is_sorted_and_deterministic() {
        let mut shuffled = host();
        shuffled.reverse();
        let a = GuestEnvPolicy::default().build_from(&host()).unwrap();
        let b = GuestEnvPolicy::default().build_from(&shuffled).unwrap();
        assert_eq!(a, b);
        assert!(a.windows(2).all(|w| w[0].0 < w[1].0));
    }
}
