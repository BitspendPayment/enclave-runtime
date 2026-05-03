//! `s3fs-wasmtime` — Wasmtime host bindings exposing `s3fs-core`'s `Fs` as
//! the `wasi:filesystem@0.2.x` interface.
//!
//! Designed to plug into a `wasmtime::component::Linker` alongside the rest
//! of `wasmtime-wasi` (which provides `wasi:io`, `wasi:cli`, clocks, random,
//! …). Only `wasi:filesystem/{types,preopens}` is overridden by this crate —
//! everything else stays on `wasmtime-wasi`'s implementations.
//!
//! Streams (`read-via-stream` / `write-via-stream`) are **not** yet wired up;
//! they currently return `error-code::unsupported`. The synchronous
//! `descriptor.read` / `descriptor.write` paths work end-to-end.

pub mod bindings;
pub mod descriptors;
pub mod error_map;
pub mod host_filesystem;
pub mod host_preopens;
pub mod streams;
pub mod view;

pub use descriptors::{Descriptor, DirectoryEntryStream};
pub use view::{S3FsCtxView, S3WasiView};

use wasmtime::Result;
use wasmtime::component::{HasData, Linker};

/// `HasData` marker so bindgen knows the trait impls live on
/// [`S3FsCtxView<'_>`].
pub struct HasS3Fs;
impl HasData for HasS3Fs {
    type Data<'a> = S3FsCtxView<'a>;
}

/// Add the `wasi:filesystem/{types,preopens}` interfaces to `linker`, backed
/// by an `s3fs-core::Fs` retrieved from the store via the [`S3WasiView`] trait.
///
/// The caller is responsible for adding the rest of WASI (i/o, clocks, cli,
/// …) before or after this call. See `s3fs-runner` for a worked example.
pub fn add_to_linker<T: S3WasiView + 'static>(linker: &mut Linker<T>) -> Result<()> {
    fn getter<T: S3WasiView>(t: &mut T) -> S3FsCtxView<'_> {
        t.s3fs_view()
    }
    bindings::wasi::filesystem::types::add_to_linker::<T, HasS3Fs>(linker, getter::<T>)?;
    bindings::wasi::filesystem::preopens::add_to_linker::<T, HasS3Fs>(linker, getter::<T>)?;
    Ok(())
}
