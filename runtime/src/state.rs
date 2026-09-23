//! The store-data type both binaries hand to wasmtime.

use std::sync::Arc;

use crate::wasi::descriptors::Descriptor;
use crate::wasi::{S3FsCtxView, S3WasiView};
use s3fs_core::{Fs, Inode};
use wasmtime::component::ResourceTable;
use wasmtime::{Result, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

/// Implements both `WasiView` (so `wasmtime-wasi` can serve `wasi:io`,
/// `wasi:cli`, clocks, random, sockets) and `S3WasiView` (so [`crate::wasi`]
/// can serve `wasi:filesystem`).
pub struct State {
    pub(crate) tasks: Option<crate::tasks::TaskContext>,
    /// The connections the runtime holds for this tenant — see [`crate::stream`].
    pub(crate) streams: Option<crate::stream::StreamContext>,
    pub(crate) notify: Option<crate::notify::NotifyContext>,
    wasi: WasiCtx,
    table: ResourceTable,
    fs: Arc<Fs>,
    /// What this guest sees as `/` — see [`S3FsCtxView::scope`].
    scope: Arc<Inode>,
    /// The same clock the guest sees through `wasi:clocks`, so `set-times`
    /// with "now" agrees with it.
    clock: Arc<crate::clock::WallClockAdapter>,
    http: wasmtime_wasi_http::WasiHttpCtx,
    /// What `wasi:http/outgoing-handler` may reach. `Denied` until the
    /// serving code says otherwise — see [`State::set_egress`].
    egress: crate::serve::EgressPolicy,
}

impl State {
    pub fn new(wasi: WasiCtx, fs: Arc<Fs>, clock: Arc<crate::clock::WallClockAdapter>) -> Self {
        let scope = fs.root();
        Self::scoped(wasi, fs, scope, clock)
    }

    /// A `State` whose guest sees `scope` as `/` and can name nothing above it.
    pub fn scoped(
        wasi: WasiCtx,
        fs: Arc<Fs>,
        scope: Arc<Inode>,
        clock: Arc<crate::clock::WallClockAdapter>,
    ) -> Self {
        State {
            tasks: None,
            streams: None,
            notify: None,
            wasi,
            scope,
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

    /// Give the guest the deployment's egress policy.
    pub fn set_egress(&mut self, egress: crate::serve::EgressPolicy) {
        self.egress = egress;
    }

    /// Whether the guest left anything behind in the resource table.
    ///
    /// For a `State` that lives one request the table goes with it, and the
    /// `Drop` below closes whatever files it still held. It matters for a
    /// *pooled* instance: the host pushes an `incoming-request` and a
    /// `response-outparam` per call and never removes them, so everything
    /// here is reclaimed by the guest dropping its handles. A guest that does
    /// not is not leaking unboundedly — the table is a slab with a free list
    /// — but it is leaving entries a later request from the same client could
    /// still address.
    pub fn resources_settled(&self) -> bool {
        self.table.is_empty()
    }
}

/// A file the guest opened and never dropped is held open by the filesystem's
/// own handle table, not only by this one: dropping the resource table on a
/// trap, an abort or an eviction releases the guest's reference and nothing
/// else. Every discard path ends here, so this is the one place to close them.
/// Closing is async — a writable handle flushes — and `Drop` is not, hence
/// the spawn; without a runtime there is nothing to spawn on, and the handles
/// stay open until the process does, which is what would have happened anyway.
impl Drop for State {
    fn drop(&mut self) {
        let handles: Vec<_> = self
            .table
            .iter_mut()
            .filter_map(|entry| match entry.downcast_ref::<Descriptor>() {
                Some(Descriptor::File { handle, .. }) => Some(handle.clone()),
                _ => None,
            })
            .collect();
        if handles.is_empty() {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                open = handles.len(),
                "guest files left open with no runtime to close them"
            );
            return;
        };
        let fs = self.fs.clone();
        rt.spawn(async move {
            for h in handles {
                if let Err(e) = fs.close(&h).await {
                    tracing::warn!(error = %e, "closing a file a discarded guest left open");
                }
            }
        });
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
            scope: &self.scope,
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

#[cfg(test)]
mod tests {
    use super::*;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, MasterSecret, OpenFlags};

    /// A trapped guest's files are closed by the runtime, not kept open
    /// forever by the filesystem's handle table — dirty buffer and all.
    #[tokio::test]
    async fn dropping_a_state_closes_the_files_its_guest_left_open() {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([3; 32]),
            [4; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        let clock = Arc::new(
            crate::clock::WallClockAdapter::new(Box::new(crate::clock::HostClock)).unwrap(),
        );
        let mut state = State::new(
            wasmtime_wasi::WasiCtxBuilder::new().build(),
            fs.clone(),
            clock,
        );

        let handle = fs
            .open("/left-open", OpenFlags::create_new())
            .await
            .unwrap();
        fs.pwrite(&handle, 0, b"unsynced").await.unwrap();
        let id = handle.id;
        state
            .table
            .push(Descriptor::File {
                parent: fs.root(),
                handle,
            })
            .unwrap();
        drop(state);

        for _ in 0..100 {
            if fs.get_handle(id).is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(fs.get_handle(id).is_none(), "the handle is still open");
        // Closed with a flush, as a guest dropping the descriptor would get.
        let h = fs.open("/left-open", OpenFlags::read_only()).await.unwrap();
        assert_eq!(fs.pread(&h, 0, 16).await.unwrap().as_ref(), b"unsynced");
    }
}
