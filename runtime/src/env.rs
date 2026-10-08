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
//! nothing whose name begins with `AWS_` or `ENCLAVE_` is inherited. That covers
//! `ENCLAVE_MASTER_KEY` and the whole AWS credential set without anyone having to
//! enumerate them, and it keeps working when a new one is added.
//!
//! An operator who genuinely needs one of those names can still set it
//! explicitly. Explicit is a decision; inheritance is an accident waiting to
//! happen.

use std::collections::BTreeMap;

/// Name prefixes that are never inherited from the host.
pub const DENIED_PREFIXES: &[&str] = &["AWS_", "ENCLAVE_"];

/// Names that are credentials wherever they appear. Setting one explicitly is
/// permitted — the operator asked for it — but it is worth saying out loud.
const CREDENTIAL_NAMES: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "ENCLAVE_MASTER_KEY",
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

/// The custom section a guest file carries its settings in.
pub const GUEST_SETTINGS_SECTION: &str = "enclave-guest-env";

/// The settings a guest was deployed with: `NAME=VALUE` lines in the guest file's
/// [`GUEST_SETTINGS_SECTION`], or none.
///
/// In the guest file rather than the image, so one image serves any deployment of any guest, and
/// so what configures a guest is measured with it: the runtime hashes the whole file into PCR16
/// before it asks KMS for a key, so a changed setting is a changed PCR16, exactly as changed code
/// is. A setting that decides where a guest sends data — which service it may pair with, where a
/// credential may go — must not be one the host can change at boot unseen.
///
/// Only the component's own sections are read, not those of modules nested inside it, and one
/// section at most: two would be two answers to the same question.
pub fn from_guest(component: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    use anyhow::{bail, ensure, Context};

    fn leb128(bytes: &[u8], at: &mut usize) -> anyhow::Result<usize> {
        let mut value = 0usize;
        for shift in (0..35).step_by(7) {
            let byte = *bytes.get(*at).context("a truncated guest file")?;
            *at += 1;
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("a malformed guest file: an over-long length")
    }

    ensure!(
        component.len() >= 8 && component.starts_with(b"\0asm"),
        "the guest is not a wasm file"
    );
    let mut found: Option<&[u8]> = None;
    let mut at = 8;
    while at < component.len() {
        let id = component[at];
        at += 1;
        let size = leb128(component, &mut at)?;
        let end = at.checked_add(size).filter(|&e| e <= component.len());
        let end = end.context("a malformed guest file: a section runs past its end")?;
        if id == 0 {
            let mut name_at = at;
            let name_len = leb128(component, &mut name_at)?;
            let name_end = name_at
                .checked_add(name_len)
                .filter(|&e| e <= end)
                .context("a malformed guest file: a section name runs past its section")?;
            if &component[name_at..name_end] == GUEST_SETTINGS_SECTION.as_bytes() {
                ensure!(found.is_none(), "the guest file carries its settings twice");
                found = Some(&component[name_end..end]);
            }
        }
        at = end;
    }

    let Some(section) = found else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(section).context("the guest's settings are not UTF-8")?;
    let mut settings: Vec<(String, String)> = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (name, value) = line
            .split_once('=')
            .with_context(|| format!("a guest setting is NAME=VALUE, not {line:?}"))?;
        ensure!(
            name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "{name:?} is not a variable name"
        );
        ensure!(
            settings.iter().all(|(n, _)| n != name),
            "the guest file sets {name} twice"
        );
        settings.push((name.to_string(), value.to_string()));
    }
    Ok(settings)
}

/// `env`, with the settings `component` carries laid over it: the guest file is what was
/// measured, so it has the last word.
pub fn with_guest_settings(
    env: Vec<(String, String)>,
    component: &[u8],
) -> anyhow::Result<Vec<(String, String)>> {
    let settings = from_guest(component)?;
    if settings.is_empty() {
        return Ok(env);
    }
    // Names only: a value can be a credential.
    tracing::info!(
        names = %settings.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", "),
        "guest environment: the settings the guest file carries"
    );
    let mut out: BTreeMap<String, String> = env.into_iter().collect();
    out.extend(settings);
    Ok(out.into_iter().collect())
}

/// `component` with `settings` appended as its [`GUEST_SETTINGS_SECTION`] — what
/// `deploy/qemu-nitro/guest-env.py` writes, for tests that need a configured guest.
#[cfg(any(test, feature = "testing"))]
pub fn with_settings_section(component: &[u8], settings: &[(&str, &str)]) -> Vec<u8> {
    fn leb128(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }
    let data: String = settings.iter().map(|(n, v)| format!("{n}={v}\n")).collect();
    let mut body = Vec::new();
    leb128(GUEST_SETTINGS_SECTION.len(), &mut body);
    body.extend_from_slice(GUEST_SETTINGS_SECTION.as_bytes());
    body.extend_from_slice(data.as_bytes());
    let mut out = component.to_vec();
    out.push(0);
    leb128(body.len(), &mut out);
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest component there is: the preamble, and nothing else.
    const EMPTY_COMPONENT: &[u8] = b"\0asm\x0d\x00\x01\x00";

    #[test]
    fn a_guest_file_carries_its_settings_and_they_override_the_image() {
        let guest = with_settings_section(
            EMPTY_COMPONENT,
            &[("ASP_URL", "https://asp.example"), ("LANG", "C")],
        );
        assert_eq!(
            from_guest(&guest).unwrap(),
            vec![
                ("ASP_URL".to_string(), "https://asp.example".to_string()),
                ("LANG".to_string(), "C".to_string())
            ]
        );
        let env = with_guest_settings(vec![("LANG".into(), "en_GB.UTF-8".into())], &guest).unwrap();
        assert_eq!(
            env,
            vec![
                ("ASP_URL".to_string(), "https://asp.example".to_string()),
                ("LANG".to_string(), "C".to_string())
            ],
            "the measured guest file has the last word"
        );
    }

    #[test]
    fn a_guest_with_no_settings_changes_nothing() {
        assert!(from_guest(EMPTY_COMPONENT).unwrap().is_empty());
        // Another custom section is not settings: leg 8's substitute is one of these.
        let mut other = EMPTY_COMPONENT.to_vec();
        other.extend_from_slice(b"\x00\x0b\x0asubstitute");
        assert!(from_guest(&other).unwrap().is_empty());
    }

    #[test]
    fn settings_that_do_not_read_one_way_are_refused() {
        let twice = with_settings_section(
            &with_settings_section(EMPTY_COMPONENT, &[("A", "1")]),
            &[("A", "2")],
        );
        assert!(from_guest(&twice).is_err(), "two sections");
        assert!(
            from_guest(&with_settings_section(
                EMPTY_COMPONENT,
                &[("A", "1"), ("A", "2")]
            ))
            .is_err(),
            "one name twice"
        );
        assert!(from_guest(&with_settings_section(EMPTY_COMPONENT, &[("NO-DASH", "1")])).is_err());
        let mut truncated = with_settings_section(EMPTY_COMPONENT, &[("A", "1")]);
        truncated.pop();
        assert!(
            from_guest(&truncated).is_err(),
            "a section past the end of the file"
        );
        assert!(from_guest(b"not wasm").is_err());
    }

    fn host() -> Vec<(String, String)> {
        [
            ("LANG", "en_GB.UTF-8"),
            ("RUST_LOG", "info"),
            ("MY_APP_ENDPOINT", "https://example.invalid"),
            ("AWS_SECRET_ACCESS_KEY", "super-secret"),
            ("AWS_ACCESS_KEY_ID", "AKIA..."),
            ("AWS_SESSION_TOKEN", "token"),
            ("AWS_REGION", "eu-west-2"),
            ("ENCLAVE_MASTER_KEY", "0011..."),
            ("ENCLAVE_BUCKET", "prod-data"),
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
                !name.starts_with("AWS_") && !name.starts_with("ENCLAVE_"),
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
        h.push(("ENCLAVE_FUTURE_OPTION".into(), "y".into()));
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
