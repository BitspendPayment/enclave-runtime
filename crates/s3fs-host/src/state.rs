//! The store-data type both binaries hand to wasmtime.

use std::sync::Arc;

use crate::wasi::{S3FsCtxView, S3WasiView};
use s3fs_core::Fs;
use wasmtime::component::ResourceTable;
use wasmtime::{Result, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

/// Implements both `WasiView` (so `wasmtime-wasi` can serve `wasi:io`,
/// `wasi:cli`, clocks, random, sockets) and `S3WasiView` (so [`crate::wasi`]
/// can serve `wasi:filesystem`).
pub struct State {
    wasi: WasiCtx,
    table: ResourceTable,
    fs: Arc<Fs>,
}

impl State {
    pub fn new(wasi: WasiCtx, fs: Arc<Fs>) -> Self {
        State {
            wasi,
            table: ResourceTable::new(),
            fs,
        }
    }

    pub fn fs(&self) -> &Arc<Fs> {
        &self.fs
    }
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl S3WasiView for State {
    fn s3fs_view(&mut self) -> S3FsCtxView<'_> {
        // The SAME `ResourceTable` instance `wasmtime-wasi` uses. Stream
        // resources this crate pushes are resolved by wasmtime-wasi's stream
        // methods, so two tables would produce handles that look valid and
        // resolve to nothing.
        S3FsCtxView {
            fs: &self.fs,
            table: &mut self.table,
        }
    }
}

/// Convenience for callers that need a `Store` without naming `State`'s
/// internals.
pub fn new_store(engine: &wasmtime::Engine, state: State) -> Result<Store<State>> {
    Ok(Store::new(engine, state))
}
