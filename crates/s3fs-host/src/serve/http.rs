//! Dispatching an incoming HTTP request into a `wasi:http/proxy` guest.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use hyper::server::conn::http1;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use wasmtime::component::{Component, InstancePre};
use wasmtime::{Engine, Store};
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::WasiHttpView;

use crate::linker::build_linker;
use crate::run::GuestEnvironment;
use crate::state::State;

/// How the guest is served.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Address to accept plaintext HTTP on.
    pub addr: SocketAddr,
    /// Requests allowed inside the guest at once. See [`ServeConfig::default`].
    pub concurrency: usize,
}

impl Default for ServeConfig {
    /// One request at a time.
    ///
    /// The store layer is safe to share — `Fs` keeps its handles under a
    /// `parking_lot::Mutex` and its transaction state under a `tokio::Mutex`,
    /// so nothing corrupts. The *guest* is the problem. `docs/COMPATIBILITY.md`
    /// records that SQLite on WASI has to run `locking_mode=EXCLUSIVE`, because
    /// WASI has no `fcntl` and therefore no file locking; two guest instances
    /// holding the same database would each believe they had it alone.
    ///
    /// A guest that keeps no cross-request state in the filesystem can raise
    /// this safely. One that opens a database cannot, and would fail in a way
    /// that looks like corruption rather than contention — so the default is
    /// the one that cannot surprise anybody.
    fn default() -> Self {
        ServeConfig {
            addr: ([0, 0, 0, 0], 8080).into(),
            concurrency: 1,
        }
    }
}

/// A compiled guest plus the environment its instances are built from.
///
/// Compilation and `instantiate_pre` happen once, at startup: per-request
/// instantiation is then cheap, and — more usefully inside an enclave — a
/// component that will not compile fails at boot rather than on the first
/// request to arrive.
pub struct ServeHandle {
    pre: ProxyPre<State>,
    guest: Arc<GuestEnvironment>,
    limit: Arc<Semaphore>,
}

impl ServeHandle {
    pub fn new(
        engine: &Engine,
        component_bytes: &[u8],
        guest: GuestEnvironment,
        concurrency: usize,
    ) -> Result<Self> {
        let component = Component::new(engine, component_bytes)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("compiling guest component")?;

        let mut linker = build_linker(engine).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("adding wasi:http to the linker")?;

        let instance_pre: InstancePre<State> = linker
            .instantiate_pre(&component)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("pre-instantiating guest component")?;
        let pre = ProxyPre::new(instance_pre)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("guest does not export wasi:http/incoming-handler")?;

        Ok(ServeHandle {
            pre,
            guest: Arc::new(guest),
            limit: Arc::new(Semaphore::new(concurrency.max(1))),
        })
    }

    /// Run one request through a fresh guest instance.
    ///
    /// `scheme` is what the *client* used, which is not what this function was
    /// reached over: with TLS terminated upstream of here the connection is
    /// plaintext, but the guest must be told `https` or it will build wrong
    /// absolute URLs and set wrong cookie flags.
    /// Generic over the request body rather than taking
    /// `hyper::body::Incoming`, which cannot be constructed outside a real
    /// connection — the whole dispatch path would be untestable without a
    /// listening socket.
    pub async fn handle<B>(
        &self,
        scheme: Scheme,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        let _permit = self
            .limit
            .clone()
            .acquire_owned()
            .await
            .context("request limiter closed")?;

        let mut store = Store::new(self.pre.engine(), self.guest.new_state()?);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let req = store.data_mut().http().new_incoming_request(scheme, req)?;
        let out = store.data_mut().http().new_response_outparam(sender)?;
        let pre = self.pre.clone();

        // The guest runs in its own task so it can keep streaming a body after
        // the status line and headers have gone out.
        let task = tokio::task::spawn(async move {
            let proxy = pre.instantiate_async(&mut store).await?;
            proxy
                .wasi_http_incoming_handler()
                .call_handle(store, req, out)
                .await
        });

        match receiver.await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e.into()),
            // The sender dropped with the `Store`, so the guest returned or
            // trapped without setting a response. Whatever the task says is
            // the real error; "never set a response" alone would send someone
            // looking in the wrong place.
            Err(_) => match task.await {
                Ok(Ok(())) => {
                    anyhow::bail!("guest returned without calling response-outparam::set")
                }
                Ok(Err(e)) => Err(anyhow::anyhow!(e.to_string())
                    .context("guest failed before setting a response")),
                Err(e) => Err(anyhow::Error::from(e).context("guest task panicked")),
            },
        }
    }
}

/// Serve a guest over plaintext HTTP until the process is stopped.
///
/// This is the development and inside-the-image path. In an enclave the same
/// [`ServeHandle`] sits behind TLS; nothing about the guest changes, which is
/// the reason the dispatch lives here rather than inside the TLS listener.
pub async fn serve_component(
    component_bytes: &[u8],
    guest: GuestEnvironment,
    config: ServeConfig,
) -> Result<()> {
    // wasmtime 44 enables async at the engine level when the `async` feature
    // is on; `Config::async_support` is a no-op. Same as `run_component`.
    let engine = Engine::new(&wasmtime::Config::new())?;
    let handle = Arc::new(ServeHandle::new(
        &engine,
        component_bytes,
        guest,
        config.concurrency,
    )?);

    let listener = TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("binding {}", config.addr))?;
    tracing::info!(
        addr = %listener.local_addr()?,
        concurrency = config.concurrency,
        "serving guest over plaintext HTTP"
    );

    loop {
        let (client, peer) = listener.accept().await.context("accepting connection")?;
        let handle = handle.clone();
        tokio::task::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let handle = handle.clone();
                async move { handle.handle(Scheme::Http, req).await }
            });
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(client), service)
                .await
            {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}
