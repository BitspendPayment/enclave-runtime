//! Host state and the trait that connects user `T` (the wasmtime store data)
//! to the bits this crate needs.

use std::sync::Arc;

use s3fs_core::Fs;
use wasmtime::component::ResourceTable;

/// State this crate keeps in the wasmtime store. The user holds one of these
/// inside their bigger store-data type and exposes it via [`S3WasiView`].
#[derive(Debug)]
pub struct S3FsHostState {
    pub fs: Arc<Fs>,
    pub table: ResourceTable,
}

impl S3FsHostState {
    pub fn new(fs: Arc<Fs>) -> Self {
        Self {
            fs,
            table: ResourceTable::new(),
        }
    }
}

/// Implement this on your store-data type `T` to plug `s3fs-wasmtime` into
/// a `Linker<T>`. The closure passed to [`crate::add_to_linker`] uses this
/// trait to fetch our host state.
pub trait S3WasiView: Send {
    fn s3fs_state(&mut self) -> &mut S3FsHostState;
}
