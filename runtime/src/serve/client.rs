//! Which tenant a request speaks for, as the guest is told.
//!
//! The runtime resolves a tenant from a verified WebAuthn assertion — see
//! [`crate::auth`] — and injects it here. A guest can read this header and can
//! never write one: it is overwritten on every request before the guest sees
//! anything, so what arrives is the runtime's word rather than the client's.
//!
//! There used to be a second answer to "who is calling": a TLS client
//! certificate, hashed to its SPKI. It was removed when passkeys arrived, and
//! not because it was broken. A certificate proves possession of a key for the
//! life of a connection; it cannot say that a person approved *this*
//! transaction, and two independent ways to become a tenant is where an
//! authorization bug grows.

use hyper::header::{HeaderName, HeaderValue};

/// The tenant the runtime resolved. Written by the runtime, never read from a
/// client.
pub const X_ENCLAVE_TENANT: HeaderName = HeaderName::from_static("x-enclave-tenant");

/// Set or remove the tenant header, whatever the client sent.
///
/// `insert`, not `append`: a client that sent the header three times would
/// otherwise leave two of its own behind for a guest reading `[0]`. And the
/// `None` arm removes rather than skips, so an unauthenticated request cannot
/// carry a tenant into the guest by claiming one.
///
/// This cannot live in `EgressPolicy::is_forbidden_header`, which runs *inside*
/// `new_incoming_request` after injection — it could only delete the header,
/// silently, with no error anywhere.
pub fn apply_tenant<B>(tenant: Option<&[u8; 16]>, req: &mut hyper::Request<B>) {
    match tenant {
        Some(id) => {
            let value = HeaderValue::from_str(&hex::encode(id))
                .expect("hex is always a valid header value");
            req.headers_mut().insert(X_ENCLAVE_TENANT, value);
        }
        None => {
            req.headers_mut().remove(X_ENCLAVE_TENANT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(values: &[&str]) -> hyper::Request<()> {
        let mut builder = hyper::Request::builder();
        for v in values {
            builder = builder.header(X_ENCLAVE_TENANT, *v);
        }
        builder.body(()).expect("well-formed request")
    }

    /// The forgery. A client sending the header itself must not be believed —
    /// and sending it three times must not leave one behind, because a guest
    /// reading the first value would get the attacker's.
    #[test]
    fn a_client_cannot_smuggle_a_tenant_header() {
        let mut req = request_with(&["deadbeef", "deadbeef", "deadbeef"]);
        apply_tenant(Some(&[0xab; 16]), &mut req);
        let seen: Vec<_> = req.headers().get_all(X_ENCLAVE_TENANT).iter().collect();
        assert_eq!(seen.len(), 1, "a client-supplied header survived");
        assert_eq!(seen[0], &hex::encode([0xab; 16]));
    }

    /// The shorter route to the same forgery: no tenant at all, so the
    /// client's own header must be removed rather than passed through.
    #[test]
    fn an_unauthenticated_request_carries_no_tenant() {
        let mut req = request_with(&["deadbeef"]);
        apply_tenant(None, &mut req);
        assert!(req.headers().get(X_ENCLAVE_TENANT).is_none());
    }

    #[test]
    fn a_tenant_reaches_the_guest_as_hex() {
        let mut req = request_with(&[]);
        apply_tenant(Some(&[0x01; 16]), &mut req);
        assert_eq!(
            req.headers().get(X_ENCLAVE_TENANT).unwrap(),
            &"01".repeat(16)
        );
    }
}
