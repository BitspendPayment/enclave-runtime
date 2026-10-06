//! KMS's `CiphertextForRecipient`, from the BER it is sent in to the DER the
//! `cms` crate reads.
//!
//! KMS encodes the CMS with indefinite-length constructed values and chunks
//! OCTET STRINGs into constructed form — BER, which `der` refuses with
//! "indefinite length disallowed". Found on the first boot on Nitro hardware:
//! KMS released the key and the enclave could not read the answer. (The QEMU
//! harness never meets real KMS, and the tests here encoded their own DER.)
//!
//! This rewrites every TLV with a definite length and collapses chunked OCTET
//! STRINGs into primitive ones. Already-DER input comes back unchanged. It runs
//! before anything is authenticated — the parent proxies these bytes — so it
//! fails closed on anything it does not expect and bounds its own recursion.
//! Taken from enclavia-protocol's `kms_recipient`, which met the same KMS.

use anyhow::{bail, Context, Result};

/// Far above a real EnvelopedData's handful of levels; low enough that `30 80`
/// repeated by a hostile parent cannot exhaust the enclave's stack.
const MAX_DEPTH: usize = 64;

/// Transcode a possibly-BER ASN.1 value to strict DER.
pub fn to_der(input: &[u8]) -> Result<Vec<u8>> {
    let (out, rest) = transcode(input, 0)?;
    if !rest.is_empty() {
        bail!("{} bytes after the end of the value", rest.len());
    }
    Ok(out)
}

/// One TLV: its definite-length DER, and the input after it.
fn transcode(input: &[u8], depth: usize) -> Result<(Vec<u8>, &[u8])> {
    if depth > MAX_DEPTH {
        bail!("nested deeper than {MAX_DEPTH} levels");
    }
    let id = *input.first().context("unexpected end of input")?;
    if id & 0x1f == 0x1f {
        bail!("high tag numbers are not supported");
    }
    let constructed = id & 0x20 != 0;
    let (len, after_len) = read_len(&input[1..])?;

    if !constructed {
        let len = len.context("an indefinite length on a primitive value")?;
        let content = after_len
            .get(..len)
            .context("a primitive value runs past the end")?;
        return Ok((emit(id, content), &after_len[len..]));
    }

    let mut children = Vec::new();
    let after = match len {
        Some(len) => {
            let mut region = after_len
                .get(..len)
                .context("a constructed value runs past the end")?;
            while !region.is_empty() {
                let (child, rest) = transcode(region, depth + 1)?;
                children.push(child);
                region = rest;
            }
            &after_len[len..]
        }
        // Children until end-of-contents, 00 00.
        None => {
            let mut region = after_len;
            loop {
                if let [0, 0, rest @ ..] = region {
                    break rest;
                }
                let (child, rest) = transcode(region, depth + 1)?;
                children.push(child);
                region = rest;
            }
        }
    };

    // A chunked OCTET STRING becomes one primitive: the universal constructed
    // form (0x24), and an IMPLICIT one under a context tag whose children are
    // all OCTET STRINGs — how KMS sends EncryptedContentInfo's
    // `encryptedContent [0]` (0xA0 → 0x80). Any other constructed value, an
    // EXPLICIT [0] wrapper included, keeps its children as they are.
    let universal_octets = id == 0x24;
    let context_octets = id & 0xc0 == 0x80
        && !children.is_empty()
        && children.iter().all(|c| c.first() == Some(&0x04));
    let mut body = Vec::new();
    if universal_octets || context_octets {
        for child in &children {
            body.extend_from_slice(octet_value(child)?);
        }
        let id = if universal_octets { 0x04 } else { id & !0x20 };
        return Ok((emit(id, &body), after));
    }
    for child in &children {
        body.extend_from_slice(child);
    }
    Ok((emit(id, &body), after))
}

/// An ASN.1 length, `None` for indefinite, and the input after it.
fn read_len(input: &[u8]) -> Result<(Option<usize>, &[u8])> {
    let (&first, rest) = input.split_first().context("a truncated length")?;
    match first {
        0x80 => Ok((None, rest)),
        short if short & 0x80 == 0 => Ok((Some(short as usize), rest)),
        long => {
            let n = (long & 0x7f) as usize;
            let bytes = rest
                .get(..n)
                .filter(|_| n <= 4)
                .context("a bad long-form length")?;
            let len = bytes.iter().fold(0usize, |len, &b| (len << 8) | b as usize);
            Ok((Some(len), &rest[n..]))
        }
    }
}

fn emit(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let significant = &be[be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1)..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// The value of a transcoded primitive OCTET STRING.
fn octet_value(der: &[u8]) -> Result<&[u8]> {
    if der.first() != Some(&0x04) {
        bail!("a chunk of an OCTET STRING is not an OCTET STRING");
    }
    let (len, content) = read_len(&der[1..])?;
    content
        .get(..len.context("an indefinite OCTET STRING chunk")?)
        .context("a truncated OCTET STRING chunk")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indefinite_lengths_and_chunked_strings_become_der() {
        // DER passes through unchanged: SEQUENCE { INTEGER 1 }.
        let der = [0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(to_der(&der).unwrap(), der);
        assert_eq!(
            to_der(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]).unwrap(),
            der
        );

        // A chunked OCTET STRING, indefinite and definite: "ab" + "cd".
        let octets = [0x04, 0x04, 0x61, 0x62, 0x63, 0x64];
        let chunks = [0x04, 0x02, 0x61, 0x62, 0x04, 0x02, 0x63, 0x64];
        assert_eq!(
            to_der(&[&[0x24, 0x80][..], &chunks, &[0, 0]].concat()).unwrap(),
            octets
        );
        assert_eq!(
            to_der(&[&[0x24, 0x08][..], &chunks].concat()).unwrap(),
            octets
        );

        // encryptedContent [0] IMPLICIT, chunked as KMS sends it.
        let context = [0x80, 0x04, 0x61, 0x62, 0x63, 0x64];
        assert_eq!(
            to_der(&[&[0xA0, 0x80][..], &chunks, &[0, 0]].concat()).unwrap(),
            context
        );

        // An EXPLICIT [0] wrapper stays constructed: ContentInfo.content.
        assert_eq!(
            to_der(&[0xA0, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0, 0, 0, 0]).unwrap(),
            [0xA0, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]
        );
    }

    /// The parent supplies these bytes, before anything is authenticated.
    #[test]
    fn hostile_input_is_refused_rather_than_followed() {
        let deep = [[0x30, 0x80].repeat(5000), [0, 0].repeat(5000)].concat();
        assert!(to_der(&deep).is_err(), "unbounded nesting must be refused");
        assert!(to_der(&[0x30, 0x80, 0x02, 0x01]).is_err(), "truncated");
        assert!(
            to_der(&[0x04, 0x80, 0x00, 0x00]).is_err(),
            "indefinite primitive"
        );
        assert!(
            to_der(&[0x30, 0x03, 0x02, 0x01, 0x01, 0xff]).is_err(),
            "trailing bytes"
        );
        assert!(
            to_der(&[0x04, 0x85, 1, 1, 1, 1, 1]).is_err(),
            "five-byte length"
        );
        assert!(to_der(&[]).is_err());
    }
}
