//! Host state and the trait that connects user `T` (the wasmtime store data)
//! to the bits this crate needs.

use std::sync::Arc;

use s3fs_core::Fs;
use wasmtime::component::ResourceTable;

/// "View" struct holding mutable references the host trait impls need.
/// Built fresh by the [`S3WasiView::s3fs_view`] closure for each linker
/// call — this is the same shape `wasmtime-wasi` uses (e.g.
/// `WasiCtxView`, `WasiFilesystemCtxView`).
///
/// Crucially, `table` is the SAME `ResourceTable` instance used by
/// `wasmtime-wasi`'s host impls. Sharing the table is required so that
/// stream resources we push (`DynInputStream`, `DynOutputStream`) can be
/// looked up by `wasmtime-wasi`'s stream methods when the guest reads /
/// writes them.
pub struct S3FsCtxView<'a> {
    pub fs: &'a Arc<Fs>,
    pub table: &'a mut ResourceTable,
    /// The same clock the guest sees through `wasi:clocks/wall-clock`, so
    /// `set-times` with "now" cannot disagree with what the guest just read.
    pub clock: &'a Arc<crate::clock::WallClockAdapter>,
}

/// Implement this on your store-data type `T` to plug the filesystem into
/// a `Linker<T>`. The closure passed to [`crate::add_to_linker`] uses this
/// trait to fetch a fresh view per call.
pub trait S3WasiView: Send {
    fn s3fs_view(&mut self) -> S3FsCtxView<'_>;
}
