//! Boolean settings that come from an environment variable.
//!
//! clap's default `bool` handling insists on exactly `true` or `false` when a
//! value arrives through `env`. That is fine on a command line, where the flag
//! is usually written bare, and wrong for a deployment configured by
//! environment: `ENV S3FS_FORCE_PATH_STYLE=1` is the obvious thing to put in a
//! Dockerfile, and it fails at startup with a message about possible values.
//!
//! Inside an enclave that failure is expensive to diagnose — there is no shell
//! to go and check, and the only symptom is an enclave that will not start.

/// Parse a boolean the way a person writing a Dockerfile would expect.
///
/// Accepts `1`/`0`, `true`/`false`, `yes`/`no`, `on`/`off`, in any case. An
/// empty value is `false`, matching the shell convention that an unset-looking
/// variable is off.
pub fn parse_bool_flag(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!(
            "expected a boolean (1/0, true/false, yes/no, on/off), got {other:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_what_a_dockerfile_would_say() {
        for s in ["1", "true", "TRUE", "True", "yes", "on", " 1 "] {
            assert_eq!(parse_bool_flag(s), Ok(true), "{s:?}");
        }
        for s in ["0", "false", "FALSE", "no", "off", "", "  "] {
            assert_eq!(parse_bool_flag(s), Ok(false), "{s:?}");
        }
    }

    #[test]
    fn rejects_anything_ambiguous_with_a_useful_message() {
        let err = parse_bool_flag("maybe").unwrap_err();
        assert!(err.contains("maybe"));
        assert!(err.contains("1/0"));
        assert!(parse_bool_flag("2").is_err());
    }
}
