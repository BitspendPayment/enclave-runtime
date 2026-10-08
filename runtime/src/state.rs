//! The store-data type both binaries hand to wasmtime.

use wasmtime::component::ResourceTable;
use wasmtime::{Result, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

/// Implements `WasiView`, so `wasmtime-wasi` serves every WASI interface —
/// the filesystem included, over the directory the guest was preopened.
pub struct State {
    pub(crate) tasks: Option<crate::tasks::TaskContext>,
    /// The connections the runtime holds for this tenant — see [`crate::stream`].
    pub(crate) streams: Option<crate::stream::StreamContext>,
    pub(crate) notify: Option<crate::notify::NotifyContext>,
    wasi: WasiCtx,
    table: ResourceTable,
    http: wasmtime_wasi_http::WasiHttpCtx,
    /// What `wasi:http/outgoing-handler` reaches: the public internet, and the
    /// same for every guest — see [`crate::serve::GuestEgress`].
    egress: crate::serve::GuestEgress,
}

impl State {
    pub fn new(wasi: WasiCtx) -> Self {
        State {
            tasks: None,
            streams: None,
            notify: None,
            wasi,
            table: ResourceTable::new(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
            egress: crate::serve::GuestEgress,
        }
    }

    /// Whether the guest left anything behind in the resource table.
    ///
    /// It matters for a *pooled* instance: the host pushes an
    /// `incoming-request` and a `response-outparam` per call and never removes
    /// them, so everything here is reclaimed by the guest dropping its
    /// handles. A guest that does not is not leaking unboundedly — the table
    /// is a slab with a free list — but it is leaving entries a later request
    /// from the same client could still address.
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

/// `wasi:http` needs its own context and its own hooks, projected out of the
/// same `ResourceTable` as everything else — a second table would hand the
/// guest stream handles that look valid and resolve to nothing.
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
