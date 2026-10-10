//! What the guest's environment contains: the settings its own file carries, and nothing else.
//!
//! The runtime's environment holds its configuration and, in the emulator, its object store's
//! credentials. None of that is the guest's business, and none of it reaches the guest: a
//! guest's environment is exactly the `NAME=VALUE` lines in its file's [`GUEST_SETTINGS_SECTION`],
//! which the runtime measures into PCR16 with the guest's code. There is no inheritance to get
//! wrong, and so no denylist to keep up to date.

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
    fn a_guest_file_carries_its_settings() {
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
}
