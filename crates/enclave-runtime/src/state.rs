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
    /// The same clock the guest sees through `wasi:clocks`, so `set-times`
    /// with "now" agrees with it.
    clock: Arc<crate::clock::WallClockAdapter>,
    http: wasmtime_wasi_http::WasiHttpCtx,
    egress: crate::serve::EgressPolicy,
}

impl State {
    pub fn new(wasi: WasiCtx, fs: Arc<Fs>, clock: Arc<crate::clock::WallClockAdapter>) -> Self {
        State {
            wasi,
            table: ResourceTable::new(),
            fs,
            clock,
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
            egress: crate::serve::EgressPolicy::Denied,
        }
    }

    pub fn fs(&self) -> &Arc<Fs> {
        &self.fs
    }

    /// Whether the guest left anything behind in the resource table.
    ///
    /// Meaningless for a `State` that lives one request — the whole table goes
    /// with it. It matters when a `State` is reused across requests: the host
    /// pushes an `incoming-request` and a `response-outparam` per call and
    /// never removes them, so everything here is reclaimed by the guest
    /// dropping its handles. A guest that does not is not leaking unboundedly
    /// (the table is a slab with a free list) but it *is* leaving entries a
    /// later request could still address, so the caller discards the session
    /// rather than carrying it.
    pub fn resources_settled(&self) -> bool {
        self.table.is_empty()
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
            clock: &self.clock,
        }
    }
}

/// `wasi:http` needs its own context and its own hooks, projected out of the
/// same `ResourceTable` as everything else — a second table would hand the
/// guest stream handles that look valid and resolve to nothing, the same trap
/// documented on [`S3WasiView`].
impl wasmtime_wasi_http::p2::WasiHttpView for State {
    fn http(&mut self) -> wasmtime_wasi_http::p2::WasiHttpCtxView<'_> {
        wasmtime_wasi_http::p2::WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.egress,
        }
    }
}

/// Convenience for callers that need a `Store` without naming `State`'s
/// internals.
pub fn new_store(engine: &wasmtime::Engine, state: State) -> Result<Store<State>> {
    Ok(Store::new(engine, state))
}
