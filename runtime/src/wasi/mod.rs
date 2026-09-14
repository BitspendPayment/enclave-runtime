//! `wasi:filesystem@0.2.x` implemented over `s3fs-core`'s `Fs`.
//!
//! Only `wasi:filesystem/{types,preopens}` lives here. Everything else a guest
//! needs — `wasi:io`, `wasi:cli`, clocks, random, sockets — comes from
//! `wasmtime-wasi` unchanged, and [`crate::linker`] assembles the two.
//!
//! This module depends on nothing AWS-specific: it is written against
//! `s3fs_core::Fs`, so it works over any [`s3fs_core::backend::Backend`],
//! including the in-memory one. That is why `mount` — the only part that needs
//! the AWS SDK — sits behind a feature flag rather than here.

pub mod bindings;
pub mod descriptors;
pub mod error_map;
pub mod host_filesystem;
pub mod host_preopens;
pub mod streams;
pub mod view;

pub use descriptors::{Descriptor, DirectoryEntryStream};
pub use view::{S3FsCtxView, S3WasiView};

use wasmtime::component::{HasData, Linker};
use wasmtime::Result;

/// `HasData` marker so bindgen knows the trait impls live on
/// [`S3FsCtxView<'_>`].
pub struct HasS3Fs;
impl HasData for HasS3Fs {
    type Data<'a> = S3FsCtxView<'a>;
}

/// Add `wasi:filesystem/{types,preopens}` to `linker`, backed by the `Fs` the
/// store yields through [`S3WasiView`].
///
/// Public and generic over `T` so a host with its own state type can take just
/// the filesystem and build the rest of its linker however it likes.
/// [`crate::build_linker`] is the batteries-included version.
pub fn add_filesystem_to_linker<T: S3WasiView + 'static>(linker: &mut Linker<T>) -> Result<()> {
    fn getter<T: S3WasiView>(t: &mut T) -> S3FsCtxView<'_> {
        t.s3fs_view()
    }
    bindings::wasi::filesystem::types::add_to_linker::<T, HasS3Fs>(linker, getter::<T>)?;
    bindings::wasi::filesystem::preopens::add_to_linker::<T, HasS3Fs>(linker, getter::<T>)?;
    Ok(())
}
