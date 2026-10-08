//! One pool, one dataset per client, and a `/` that means different things to
//! different guests.
//!
//! Every client's data lives in its own ZFS dataset, `/tenants/<id>`, on the
//! runtime's single pool — see [`crate::zfs`]. A client costs a dataset, not a
//! pool: one disk, one anchor chain, one cache.
//!
//! ## Where the separation actually is
//!
//! Not in the guest. A tenant's instance is handed its own directory as its
//! only preopen, and `wasmtime-wasi` resolves every path through `cap-std`,
//! which refuses each way a path can name something above it: `..` stops at
//! the preopen, an absolute path has nothing to start from but it, and a
//! symlink cannot point out of it. A guest that tries `/tenants/other/secret`
//! gets its own `tenants/other/secret`, which does not exist.
//!
//! That is a capability, not a convention, and it is why this is safe to do
//! on a shared pool at all.
//!
//! ## Why the identifier is minted
//!
//! Sixteen bytes from the NSM at first registration, stored with the
//! credential — see [`crate::auth::credential`] — so a host cannot predict a
//! tenant's directory and create it first.
//!
//! ## Why there is no separate register
//!
//! `/tenants/<id>` either exists in the pool or it does not, and the pool is
//! pinned by an anchor the boot checks. Hiding one client's dataset means
//! serving a pool state no anchor names, which the boot refuses before any
//! request is served. **The pool is the register.**

/// A client's arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// Their directory was already there.
    Returning,
    /// First contact: it was created.
    New,
}
