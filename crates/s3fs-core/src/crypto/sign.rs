//! Ed25519 signatures over root records.
//!
//! The signature is what turns a pile of immutable objects into a filesystem
//! we are willing to trust. It covers the sequence number and the previous
//! root's hash as well as the Merkle root, so the *chain* is authenticated,
//! not merely each link: an attacker who can write to the bucket cannot mint a
//! root, cannot re-point an existing root at different data, and cannot splice
//! two legitimate histories together.

use aws_lc_rs::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};

use crate::errors::{FsError, FsResult};

use super::keys::{ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};

/// Sign `message`, returning a detached 64-byte signature.
pub fn sign(key: &Ed25519KeyPair, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
    let sig = key.sign(message);
    let mut out = [0u8; ED25519_SIGNATURE_LEN];
    out.copy_from_slice(sig.as_ref());
    out
}

/// Verify a detached signature.
///
/// Returns [`FsError::Integrity`] on any failure. The caller must treat that
/// as fatal for the mount: a bad root signature means the store is serving
/// something we did not write.
pub fn verify(
    public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; ED25519_SIGNATURE_LEN],
) -> FsResult<()> {
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| FsError::Integrity("root signature verification failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyMaterial, MasterSecret};

    fn material(master: u8) -> KeyMaterial {
        KeyMaterial::derive(&MasterSecret::from_bytes([master; 32]), [0u8; 16]).unwrap()
    }

    #[test]
    fn sign_then_verify() {
        let km = material(1);
        let msg = b"root record bytes";
        let sig = sign(km.signing_key(), msg);
        assert!(verify(km.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_modified_message() {
        let km = material(1);
        let sig = sign(km.signing_key(), b"root record bytes");
        assert!(matches!(
            verify(km.public_key(), b"root record bytez", &sig),
            Err(FsError::Integrity(_))
        ));
    }

    #[test]
    fn verify_rejects_modified_signature() {
        let km = material(1);
        let mut sig = sign(km.signing_key(), b"msg");
        sig[0] ^= 0x01;
        assert!(verify(km.public_key(), b"msg", &sig).is_err());
    }

    /// The forgery case that matters: an attacker who controls the bucket can
    /// write any bytes they like, but cannot produce a signature that our
    /// public key accepts.
    #[test]
    fn verify_rejects_signature_from_another_key() {
        let ours = material(1);
        let theirs = material(2);
        let sig = sign(theirs.signing_key(), b"forged root");
        assert!(verify(ours.public_key(), b"forged root", &sig).is_err());
    }

    #[test]
    fn verify_rejects_all_zero_signature() {
        let km = material(1);
        assert!(verify(km.public_key(), b"msg", &[0u8; ED25519_SIGNATURE_LEN]).is_err());
    }

    #[test]
    fn signatures_are_deterministic() {
        // Ed25519 is deterministic; two signings of the same message with the
        // same key must agree. Relied on by the commit path, which signs a
        // canonical encoding and expects a stable root object.
        let km = material(1);
        assert_eq!(
            sign(km.signing_key(), b"same message"),
            sign(km.signing_key(), b"same message")
        );
    }

    #[test]
    fn empty_message_signs_and_verifies() {
        let km = material(1);
        let sig = sign(km.signing_key(), b"");
        assert!(verify(km.public_key(), b"", &sig).is_ok());
        assert!(verify(km.public_key(), b"x", &sig).is_err());
    }
}
