//! Dispatching an incoming HTTP request into a `wasi:http/proxy` guest.
//!
//! **One instance per request. No two requests ever share one.**
//!
//! That is the invariant this module exists to hold, and it is where the
//! boundary between two clients actually lives. A `Store` is what separates two
//! wasm instances; give two clients one instance and the separation becomes
//! guest code instead, so a single bug that confuses two clients stops being a
//! leak of one and becomes a total compromise. A trap has nothing to poison and
//! leaked resource handles die with the store, both for the same reason.
//!
//! What a guest keeps therefore has to reach the filesystem, because there is
//! nothing else: no memory outlives the call that created it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper::server::conn::http1;
use tokio::net::TcpListener;
use wasmtime::component::{Component, InstancePre};
use wasmtime::{Engine, Store};
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::WasiHttpView;

use crate::auth::{AuthEndpoints, Gate};
use crate::linker::build_linker;
use crate::run::GuestEnvironment;
use crate::serve::acme::CertificateSlot;
use crate::serve::attest::{nonce_from_headers, ResponseAttestor};
use crate::serve::client::apply_tenant;
use crate::serve::endpoints::EnclaveEndpoints;
use crate::serve::pool::{LiveTenant, PoolLimits, TenantPool};
use crate::state::State;
use crate::tenant::tenant_root_by_id;
use nitro_nsm::Nsm;

/// How the guest is served.
#[derive(Debug)]
pub struct ServeConfig {
    /// Address to accept on.
    pub addr: SocketAddr,
    /// Where TLS connections take their serving identity. `None` serves
    /// plaintext.
    ///
    /// A renewal is a `set()` on it. Connections already established keep the
    /// identity they loaded, which is the property per-response attestation
    /// depends on and the only way to exercise it without driving a real ACME
    /// order.
    pub certificate: Option<CertificateSlot>,
    /// A running ACME client, instead of a fixed certificate.
    pub acme: Option<crate::serve::acme::Acme>,
    /// NSM to sign each response's attestation document.
    ///
    /// Only useful alongside `tls`: the document binds the serving
    /// certificate, and without one there is nothing to bind. Supplying it
    /// without TLS is refused rather than silently serving documents that
    /// promise a binding they do not have.
    pub attestation: Option<Arc<dyn Nsm>>,
    /// How long a guest may take to produce a response head.
    ///
    /// A guest that neither returns nor sets a response otherwise hangs that
    /// tenant forever — and only that tenant, since nothing else queues behind
    /// it. See [`EPOCH_TICK`].
    pub request_timeout: Duration,
    /// Give each authenticated client their own filesystem. `None` keeps the
    /// original model: one filesystem, a fresh instance per request.
    pub tenancy: Option<Arc<Tenancy>>,
    /// `/auth/*` and the gate every other request must pass.
    ///
    /// `None` serves the guest to anyone who can open a connection. That is a
    /// development and QEMU arrangement, and [`serve_component`] says so
    /// loudly at startup rather than leaving it to be noticed.
    pub authentication: Option<(Arc<AuthEndpoints>, Arc<Gate>)>,
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
            certificate: None,
            acme: None,
            attestation: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            // Off. Turning it on changes what two clients may do at the same
            // time, which a guest may have been relying on — so it is asked
            // for, never inherited.
            tenancy: None,
            authentication: None,
        }
    }
}

/// How often the epoch advances, and therefore the resolution of the deadline
/// a spinning guest is trapped by.
///
/// Coarse on purpose: the ticker wakes on every interval for the life of the
/// process, and the deadline only needs to be accurate to a fraction of the
/// request timeout.
const EPOCH_TICK: Duration = Duration::from_millis(250);

/// Default ceiling on producing a response head.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A guest instance and the store it is bound to.
///
/// The two travel together because `instantiate_async` binds a `Proxy` to one
/// store: separating them would produce a handle that looks usable and
/// resolves against the wrong memory.
pub struct GuestInstance {
    store: Store<State>,
    proxy: wasmtime_wasi_http::p2::bindings::Proxy,
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
    /// One request at a time for callers with no resolved tenant.
    ///
    /// There is no identity to separate them by, so they are treated as one:
    /// anonymous requests serialise against each other and against nothing
    /// else. Unbounded would let anyone with a socket multiply wasm linear
    /// memories, which is the same exhaustion a per-tenant lock prevents for
    /// everybody who *is* identified.
    anonymous: Arc<tokio::sync::Mutex<()>>,
    /// Ceiling on producing a response head. See [`ServeHandle::watchdog`].
    timeout: Duration,
    /// Per-client filesystems, when the deployment asked for them.
    ///
    /// `None` is the original model and stays the default: one filesystem, a
    /// fresh instance per request, every request serialised against every
    /// other. Turning this on changes what two clients can do at the same time,
    /// which is a property a guest may have been relying on — so it is opted
    /// into, and PCR0 records the choice.
    tenancy: Option<Arc<Tenancy>>,
}

/// Everything needed to give a client their own corner of the filesystem.
///
/// No backends and no mounting: there is one filesystem, and a client costs a
/// directory in it. What is per-client is the *view* — which directory the
/// guest calls `/` — plus a warm instance and a lock.
pub struct Tenancy {
    pool: TenantPool<GuestInstance>,
}

impl std::fmt::Debug for Tenancy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tenancy")
            .field("tenants", &self.pool.len())
            .finish_non_exhaustive()
    }
}

impl Tenancy {
    pub fn new(limits: PoolLimits) -> Self {
        Tenancy {
            pool: TenantPool::new(limits),
        }
    }

    pub fn pool(&self) -> &TenantPool<GuestInstance> {
        &self.pool
    }
}

impl ServeHandle {
    /// An `Engine` configured for the watchdog, plus the ticker that drives it.
    ///
    /// Epoch interruption is what makes a spinning guest interruptible at all:
    /// without it, wasm that never yields cannot be stopped, and
    /// `tokio::task::abort` has no await point to act on. The returned task
    /// advances the epoch forever and is detached — it must outlive every
    /// request, and there is nothing to join it back to.
    pub fn engine_with_watchdog() -> Result<Engine> {
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;

        let ticker = engine.weak();
        tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(EPOCH_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                // A weak handle, so this task cannot keep a dropped engine
                // alive — it simply stops when the engine goes.
                match ticker.upgrade() {
                    Some(engine) => engine.increment_epoch(),
                    None => break,
                }
            }
        });
        Ok(engine)
    }

    pub fn new(engine: &Engine, component_bytes: &[u8], guest: GuestEnvironment) -> Result<Self> {
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
            anonymous: Arc::new(tokio::sync::Mutex::new(())),
            timeout: DEFAULT_REQUEST_TIMEOUT,
            tenancy: None,
        })
    }

    /// The environment instances are built from — the runtime's own
    /// filesystem, the clock, and the entropy source.
    pub fn environment(&self) -> &Arc<GuestEnvironment> {
        &self.guest
    }

    /// Give each authenticated client their own filesystem and warm instance.
    pub fn with_tenancy(mut self, tenancy: Arc<Tenancy>) -> Self {
        self.tenancy = Some(tenancy);
        self
    }

    /// Override the response-head deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Ticks of [`EPOCH_TICK`] a guest gets before the epoch traps it.
    ///
    /// Deliberately **shorter** than the timeout, and that ordering is the
    /// whole mechanism. The epoch is the only thing that can stop wasm which
    /// never yields; `tokio::task::abort` needs an await point and a spinning
    /// guest never reaches one. Give the deadline slack *past* the timeout —
    /// as a first attempt here did, to get a tidier error message — and the
    /// abort fires first against a guest nothing can interrupt, which leaves
    /// the task spinning for the life of the process and hangs runtime
    /// shutdown. The nicer message cost the entire guarantee.
    ///
    /// So the epoch fires first and the guest traps with a real reason. The
    /// timeout stays as the backstop for what the epoch cannot see: a guest
    /// parked in a *host* call, where there is no wasm executing to interrupt
    /// but there is an await point for `abort` to land on.
    fn watchdog(&self) -> u64 {
        let ticks = self.timeout.as_millis() / EPOCH_TICK.as_millis();
        (ticks.saturating_sub(2)).max(1) as u64
    }

    /// Run one request, in an instance built for it and discarded after it.
    ///
    /// `scheme` is what the *client* used, which is not what this function was
    /// reached over: with TLS terminated upstream of here the connection is
    /// plaintext, but the guest must be told `https` or it will build wrong
    /// absolute URLs and set wrong cookie flags.
    ///
    /// Generic over the request body rather than taking
    /// `hyper::body::Incoming`, which cannot be constructed outside a real
    /// connection — the whole dispatch path would be untestable without a
    /// listening socket.
    ///
    /// `tenant` is required rather than defaulted, so every caller has to
    /// answer the question. It is **not** a way around the gate: with one
    /// configured, [`serve_connection`] verifies an assertion before it gets
    /// here and there is no path that reaches a guest without one.
    pub async fn handle<B>(
        &self,
        scheme: Scheme,
        mut req: hyper::Request<B>,
        tenant: Option<&[u8; 16]>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        // Before anything else touches the request, and before it is handed to
        // `new_incoming_request`, which copies the header map into the guest
        // verbatim. This is the only ingress, so this is the only place the
        // header can be made trustworthy.
        apply_tenant(tenant, &mut req);

        // Concurrency is per tenant, and the lock that enforces it is taken
        // inside each arm — the per-tenant mutex for an identified caller, one
        // shared lock for the rest. There is no global ceiling: two tenants
        // have nothing to queue on, which is the whole point of giving them
        // separate directories and separate instances.
        //
        // Either lock is held until the guest task finishes, body included, so
        // a tenant's second request waits for its first to be genuinely done
        // rather than merely to have produced headers.
        match (&self.tenancy, tenant) {
            (Some(tenancy), Some(tenant)) => {
                self.in_tenant(tenancy.clone(), *tenant, scheme, req).await
            }
            // No tenant resolved. Either the deployment configured no gate, or
            // the caller reached a path that does not identify itself — and
            // with no identity there is nothing to separate them by, so they
            // share one lock and one filesystem: the runtime's own.
            _ => self.in_fresh_instance(scheme, req).await,
        }
    }

    /// One request, in this client's own filesystem and warm instance.
    ///
    /// The lock is held for the whole call — including the body, because
    /// `call_handle` does not return until the guest has finished writing it —
    /// and it is what serialises this client against **itself and nothing
    /// else**. Two clients holding two different locks over two different
    /// filesystems is the entire point: their commits do not queue, because
    /// there is nothing for them to queue on.
    async fn in_tenant<B>(
        &self,
        tenancy: Arc<Tenancy>,
        tenant_id: [u8; 16],
        scheme: Scheme,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        // Checked out before the lock is taken, so the eviction sweep can see
        // this tenant is busy and leave it alone. The guard releases that mark
        // however the request ends.
        let checkout = tenancy.pool.checkout(&tenant_id);
        // Owned, so it can move into the task below and outlive this function.
        let mut guard = checkout.slot().tenant().clone().lock_owned().await;

        if guard.is_none() {
            // First use of this slot, under the lock — so two simultaneous
            // first requests from one client resolve to one directory, the
            // second waiting here rather than racing the first.
            let opened = tenant_root_by_id(self.guest.fs(), tenant_id).await?;
            tracing::info!(
                tenant = %hex::encode(opened.tenant_id),
                arrival = ?opened.arrival,
                "tenant directory ready"
            );
            *guard = Some(LiveTenant {
                scope: opened.scope,
                tenant_id: opened.tenant_id,
                instance: None,
                requests: 0,
            });
        }

        let tenant = guard.as_mut().expect("just built");
        // Rebuilt when absent, and when this one has served long enough: wasm
        // linear memory never shrinks, so an instance that lived forever would
        // only grow. Cheap — ~24 µs, and no I/O, because there is no
        // filesystem to bring up with it.
        let stale = tenant.requests >= tenancy.pool.limits().max_requests_per_instance;
        if tenant.instance.is_none() || stale {
            tenant.instance = Some(self.instantiate(tenant.scope.clone()).await?);
            tenant.requests = 0;
        }
        tenant.requests += 1;

        let instance = tenant.instance.as_mut().expect("just built");
        // Reset every request: the epoch deadline is absolute, so a reused
        // store would otherwise inherit whatever the last request left.
        instance.store.set_epoch_deadline(self.watchdog());
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let req = instance
            .store
            .data_mut()
            .http()
            .new_incoming_request(scheme, req)?;
        let out = instance
            .store
            .data_mut()
            .http()
            .new_response_outparam(sender)?;

        let task = tokio::task::spawn(async move {
            // Moved in so the lock outlives the response head. A pooled store
            // must not be handed to this tenant's next request until the call
            // has finished writing its body — which is also what makes "one
            // active request per tenant" true rather than "one set of headers
            // at a time". Released when this future completes, fails, or is
            // aborted.
            let mut guard = guard;
            let _checkout = checkout;
            let tenant = guard.as_mut().expect("held across the call");
            let instance = tenant.instance.as_mut().expect("built before the call");
            let result = instance
                .proxy
                .wasi_http_incoming_handler()
                .call_handle(&mut instance.store, req, out)
                .await;

            if result.is_err() {
                // One client's instance, and nothing else. The filesystem is
                // shared and untouched; the next caller for this client gets a
                // fresh instance over the same directory.
                tracing::warn!("guest trapped; this client's instance will be rebuilt");
                tenant.instance = None;
            } else if !instance.store.data().resources_settled() {
                tracing::debug!("guest left resources behind; rebuilding its instance");
                tenant.instance = None;
            }
            result
        });

        await_head(self.timeout, task, receiver).await
    }

    /// Build an instance whose guest sees `scope` as `/`.
    ///
    /// The one place a store and an instance are made, so the per-request path
    /// and the per-tenant path cannot drift in what a guest is handed.
    async fn instantiate(&self, scope: Arc<s3fs_core::Inode>) -> Result<GuestInstance> {
        let mut store = Store::new(self.pre.engine(), self.guest.new_state_scoped(scope)?);
        store.set_epoch_deadline(self.watchdog());
        let proxy = self
            .pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("instantiating the guest")?;
        Ok(GuestInstance { store, proxy })
    }

    /// The only dispatch path. A fresh store, a fresh instance, both dropped
    /// when the request ends — so nothing survives but what was committed.
    async fn in_fresh_instance<B>(
        &self,
        scheme: Scheme,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        // Anonymous callers are one identity, so they queue behind each other.
        // Taken before the store is built: an instance is a wasm linear memory,
        // and building one per waiting request is the exhaustion this prevents.
        let anonymous = self.anonymous.clone().lock_owned().await;

        let mut store = Store::new(self.pre.engine(), self.guest.new_state()?);
        store.set_epoch_deadline(self.watchdog());
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let req = store.data_mut().http().new_incoming_request(scheme, req)?;
        let out = store.data_mut().http().new_response_outparam(sender)?;
        let pre = self.pre.clone();

        // The guest runs in its own task so it can keep streaming a body after
        // the status line and headers have gone out. The lock goes with it, so
        // it is held for the whole call rather than released at the head.
        let task = tokio::task::spawn(async move {
            let _anonymous = anonymous;
            let proxy = pre.instantiate_async(&mut store).await?;
            proxy
                .wasi_http_incoming_handler()
                .call_handle(store, req, out)
                .await
        });

        await_head(self.timeout, task, receiver).await
    }

    /// Prove the guest instantiates, before a single request depends on it.
    ///
    /// Builds one instance and drops it. Narrower than it looks, and worth
    /// saying so: `Component::new` and `instantiate_pre` already fail at
    /// startup for a guest that will not compile or whose imports do not
    /// resolve. What this adds is the *initialiser* — a guest that traps or
    /// hangs in `start` would otherwise answer 500 to every request while the
    /// enclave looked perfectly healthy from the outside.
    ///
    /// The cost is running that initialiser once more than strictly necessary,
    /// which is nothing new: [`ServeHandle::in_fresh_instance`] runs it on
    /// every request already.
    pub async fn verify_instantiates(&self) -> Result<()> {
        let mut store = Store::new(self.pre.engine(), self.guest.new_state()?);
        // A deadline of its own, or a guest that hangs in `start` would hang
        // the boot rather than failing it.
        store.set_epoch_deadline(self.watchdog());
        self.pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("instantiating the guest")?;
        Ok(())
        // The store and the instance drop here. Nothing is kept: an instance
        // that outlived this call would be an instance two requests could
        // share, which is the whole thing this design refuses.
    }
}

/// Wait for the response head, and leave the guest task to finish the body.
///
/// Returns as soon as the guest has set a response. Deliberately: the body may
/// still be streaming out of the task, and hyper cannot read it until this
/// returns — waiting for the task here would deadlock body delivery.
///
/// **The permit is not here.** It lives in the spawned task, so a slot is freed
/// when the guest is genuinely finished — or when its task fails or is aborted
/// — rather than when its headers happened to appear. A free function rather
/// than a method because that lifetime is worth testing on its own, without an
/// engine and a compiled component to build a `ServeHandle` around.
async fn await_head(
    timeout: Duration,
    task: tokio::task::JoinHandle<wasmtime::Result<()>>,
    receiver: tokio::sync::oneshot::Receiver<
        std::result::Result<
            hyper::Response<HyperOutgoingBody>,
            wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
        >,
    >,
) -> Result<hyper::Response<HyperOutgoingBody>> {
    let waited = match tokio::time::timeout(timeout, receiver).await {
        Ok(waited) => waited,
        Err(_) => {
            // Nothing arrived in time. The epoch should already have
            // trapped a spinning guest — see `watchdog` — so reaching here
            // means the guest is parked somewhere the epoch cannot see,
            // which is exactly where `abort` does work.
            // Aborting drops the task's locals, and the permit is one of
            // them — so an abandoned guest frees its slot rather than
            // holding it for the life of the process.
            task.abort();
            anyhow::bail!("guest did not produce a response within {timeout:?}; abandoned");
        }
    };

    match waited {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(e.into()),
        // The sender dropped with the `Store`, so the guest returned or
        // trapped without setting a response. Whatever the task says is
        // the real error; "never set a response" alone would send someone
        // looking in the wrong place.
        Err(_) => {
            match task.await {
                Ok(Ok(())) => {
                    anyhow::bail!("guest returned without calling response-outparam::set")
                }
                Ok(Err(e)) => Err(anyhow::anyhow!(e.to_string())
                    .context("guest failed before setting a response")),
                Err(e) => Err(anyhow::Error::from(e).context("guest task panicked")),
            }
        }
    }
}

/// Refuse a resumed session, and say so.
///
/// Serving configs disable resumption (see `serve::tls`), so this should be
/// unreachable — it is here because the alternative to being unreachable is
/// attesting a certificate the connection was never authenticated under, and
/// that failure would be silent. A loud refusal is the cheaper mistake.
fn resumed<S>(stream: &tokio_rustls::server::TlsStream<S>, peer: SocketAddr) -> bool {
    let (_, connection) = stream.get_ref();
    if connection.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
        tracing::error!(
            %peer,
            "refusing a resumed TLS session: the certificate it was authenticated \
             under cannot be established, so nothing about it can be attested"
        );
        return true;
    }
    false
}

/// A fixed body, in the shape the guest dispatch wants.
fn full(bytes: bytes::Bytes) -> HyperOutgoingBody {
    use http_body_util::BodyExt;
    http_body_util::Full::new(bytes)
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

/// A refusal, in one sentence and no detail.
fn refused(status: hyper::StatusCode, detail: &str) -> hyper::Response<HyperOutgoingBody> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full(bytes::Bytes::from(
            serde_json::json!({ "error": detail }).to_string(),
        )))
        .expect("response is well formed")
}

/// Serve one connection, whatever it is wrapped in.
///
/// Generic over the stream so the three arms above — fixed TLS, ACME TLS and
/// plaintext — share one body instead of three copies of it. All three satisfy
/// the bound, so this monomorphises and costs nothing at runtime.
///
/// The service closure is built here rather than by the caller because it must
/// capture `client`, and `client` does not exist until the handshake has
/// completed.
/// Everything a connection needs that is the same for every connection.
///
/// Grouped because the per-connection values — the certificate this handshake
/// presented — are the interesting ones, and a signature where they are lost
/// among six process-wide `Arc`s hides that.
#[derive(Clone)]
pub struct Routes {
    guest: Arc<ServeHandle>,
    endpoints: Option<Arc<EnclaveEndpoints>>,
    auth: Option<Arc<AuthEndpoints>>,
    gate: Option<Arc<Gate>>,
    attestor: Option<Arc<ResponseAttestor>>,
    scheme: Scheme,
}

async fn serve_connection<S>(
    io: S,
    routes: Routes,
    // The leaf this connection's handshake actually presented, loaded once at
    // accept time. `None` for plaintext.
    certificate: Option<Vec<u8>>,
) -> std::result::Result<(), hyper::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Routes {
        guest,
        endpoints,
        auth,
        gate,
        attestor,
        scheme,
    } = routes;
    let certificate = certificate.map(Arc::new);
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let guest = guest.clone();
        let endpoints = endpoints.clone();
        let auth = auth.clone();
        let gate = gate.clone();
        let attestor = attestor.clone();
        let certificate = certificate.clone();
        // Cloned per request because the closure is `Fn` — it runs again for
        // every request on a kept-alive connection.
        let scheme = scheme.clone();
        async move {
            // One place, before the router, so the rule covers the guest,
            // `/auth/*`, `/enclave/*` and every refusal alike — and so a
            // request without a nonce reaches none of them.
            // Required whether or not this deployment attests. A client then
            // behaves identically either way, and a deployment cannot silently
            // stop attesting without its clients noticing — which is the
            // failure a client can least afford to miss.
            let nonce = match nonce_from_headers(req.headers()) {
                Ok(nonce) => nonce,
                Err(e) => {
                    // No document on this one: there is no nonce to bind, and
                    // one the runtime chose would prove nothing.
                    tracing::debug!(reason = %e, "refused a request with no usable nonce");
                    return Ok::<_, anyhow::Error>(refused(
                        hyper::StatusCode::BAD_REQUEST,
                        &e.to_string(),
                    ));
                }
            };

            // Generated before the request is routed, not after the
            // response exists: it binds the nonce and the connection's
            // certificate, neither of which depends on what the guest says.
            // Doing it here means a failure refuses before the guest runs,
            // rather than stranding a half-produced response.
            let document = match &attestor {
                Some(attestor) => {
                    match attestor
                        .document(certificate.as_ref().map(|c| c.as_slice()), &nonce)
                        .await
                    {
                        Ok(document) => Some(document),
                        Err(e) => {
                            // 503, not a dropped connection. A bare reset
                            // is indistinguishable to a client from a
                            // network fault or an interceptor, and this is
                            // the one signal that says "this enclave will
                            // not vouch for itself".
                            tracing::error!(error = %e, "could not attest a response");
                            let mut response = refused(
                                hyper::StatusCode::SERVICE_UNAVAILABLE,
                                "this response could not be attested",
                            );
                            response.headers_mut().insert(
                                hyper::header::CONNECTION,
                                hyper::header::HeaderValue::from_static("close"),
                            );
                            return Ok(response);
                        }
                    }
                }
                None => None,
            };

            let mut response = route(req, guest, endpoints, auth, gate, scheme).await?;
            if let Some(document) = document {
                crate::serve::attest::attach(&mut response, document);
            }
            Ok(response)
        }
    });

    http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(io), service)
        .await
}

/// Everything that decides what a response *is*, with attestation stripped out.
///
/// A separate function so the closure above has exactly one exit: that is what
/// makes "no response leaves unattested" and "a guest cannot own the header"
/// single facts rather than five places to audit.
async fn route(
    mut req: hyper::Request<hyper::body::Incoming>,
    guest: Arc<ServeHandle>,
    endpoints: Option<Arc<EnclaveEndpoints>>,
    auth: Option<Arc<AuthEndpoints>>,
    gate: Option<Arc<Gate>>,
    scheme: Scheme,
) -> Result<hyper::Response<HyperOutgoingBody>> {
    {
        {
            let method = req.method().clone();
            let path = req.uri().path().to_string();

            // The runtime's own paths are checked first and are not
            // forwardable: a guest able to answer under `/enclave/` could serve
            // any attestation it liked, and one able to answer under `/auth/`
            // could hand out its own challenges and verify its own assertions,
            // which is the same as having none.
            if let Some(endpoints) = &endpoints {
                if let Some(response) = endpoints.handle(&path).await {
                    return Ok::<_, anyhow::Error>(response);
                }
            }
            if let Some(auth) = &auth {
                if path.starts_with(crate::auth::AUTH_PREFIX) {
                    // `/auth/*` bodies are small and bounded by the endpoints
                    // themselves; they are read here because the routes take
                    // bytes rather than a stream.
                    let body = match http_body_util::BodyExt::collect(req.into_body()).await {
                        Ok(collected) => collected.to_bytes(),
                        Err(e) => {
                            tracing::debug!(error = %e, "reading an auth request body");
                            return Ok(refused(
                                hyper::StatusCode::BAD_REQUEST,
                                "malformed request",
                            ));
                        }
                    };
                    if let Some(response) = auth.handle(&method, &path, &body).await {
                        return Ok(response);
                    }
                    return Ok(refused(hyper::StatusCode::NOT_FOUND, "no such endpoint"));
                }
            }

            // Everything else is the guest, and **nothing reaches the guest
            // without a verified assertion bound to exactly this request.**
            // With no gate configured the runtime is unauthenticated by
            // deliberate choice — development, and the QEMU harness.
            let tenant = match &gate {
                Some(gate) => match gate.verify(&mut req).await {
                    Ok(verified) => {
                        // The body was consumed to hash it, so the request is
                        // rebuilt around exactly the bytes that were approved.
                        let mut rebuilt = hyper::Request::builder()
                            .method(req.method().clone())
                            .uri(req.uri().clone());
                        for (name, value) in req.headers() {
                            if !crate::auth::AUTH_HEADERS
                                .iter()
                                .any(|h| name.as_str() == *h)
                            {
                                rebuilt = rebuilt.header(name, value);
                            }
                        }
                        let body = full(verified.body);
                        let rebuilt = rebuilt.body(body).expect("request is well formed");
                        return guest
                            .handle(scheme, rebuilt, Some(&verified.tenant_id))
                            .await;
                    }
                    Err(denied) => {
                        // Logged in full, answered in one sentence: which check
                        // failed is the runtime's business, and telling a
                        // caller would tell them which guess to refine.
                        tracing::info!(%path, reason = %denied, "refused an unauthenticated request");
                        return Ok(refused(denied.status(), denied.public_message()));
                    }
                },
                None => None,
            };
            guest.handle(scheme, req, tenant.as_ref()).await
        }
    }
}

/// The accept loop: TLS if configured, `/enclave/*` to the runtime, the rest
/// to the guest.
///
/// Nothing about the guest changes between the plaintext and TLS paths, which
/// is why dispatch lives in [`ServeHandle`] and this only decides what wraps
/// it.
pub struct Server {
    guest: Arc<ServeHandle>,
    endpoints: Option<Arc<EnclaveEndpoints>>,
    /// Produces the per-response proof. `None` leaves the runtime behaving
    /// exactly as it did before attestation existed, nonce included.
    attestor: Option<Arc<ResponseAttestor>>,
    /// `/auth/*`, and the gate every other request must pass.
    ///
    /// Both or neither: routes that issue challenges nobody checks would be
    /// worse than no routes at all, and a gate with no way to get a challenge
    /// would refuse everything forever.
    auth: Option<Arc<AuthEndpoints>>,
    gate: Option<Arc<Gate>>,
    tls: Option<Tls>,
    /// Fired once the listener is accepting. ACME waits on it before placing
    /// an order, because the challenge is a connection inbound to this socket.
    listening: Option<Arc<tokio::sync::Notify>>,
    addr: SocketAddr,
}

/// How TLS is terminated.
///
/// One shape, not one per certificate source. Every connection loads one
/// identity from `slot` — a configuration and the leaf it presents — and keeps
/// it for its life. That is what makes "the certificate this connection is
/// using" answerable: rustls offers no way to ask a live connection, so the
/// pairing is arranged at accept time instead of discovered later.
///
/// ACME differs only by having a second configuration to offer, so it is a
/// field rather than a variant. As two variants this logic was written twice,
/// which is two places to keep the load-once-and-refuse-resumption discipline
/// and one place to eventually get it wrong.
struct Tls {
    /// Where a connection takes its serving identity. Replaced on an ACME
    /// renewal — and by the renewal test, which is the point: a connection that
    /// already loaded one keeps it.
    slot: CertificateSlot,
    /// ACME only. The ClientHello chooses: a TLS-ALPN-01 validation connection
    /// is answered on this same port, which is the reason that challenge type
    /// was chosen.
    challenge: Option<Arc<rustls::ServerConfig>>,
}

impl Server {
    pub fn new(guest: ServeHandle, addr: SocketAddr) -> Self {
        Server {
            guest: Arc::new(guest),
            endpoints: None,
            attestor: None,
            auth: None,
            gate: None,
            tls: None,
            listening: None,
            addr,
        }
    }

    /// Require a verified assertion for everything the guest could see.
    pub fn with_authentication(mut self, auth: Arc<AuthEndpoints>, gate: Arc<Gate>) -> Self {
        self.auth = Some(auth);
        self.gate = Some(gate);
        self
    }

    pub fn with_endpoints(mut self, endpoints: Arc<EnclaveEndpoints>) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    pub fn with_attestor(mut self, attestor: Arc<ResponseAttestor>) -> Self {
        self.attestor = Some(attestor);
        self
    }

    pub fn with_tls(mut self, certificate: CertificateSlot) -> Self {
        self.tls = Some(Tls {
            slot: certificate,
            challenge: None,
        });
        self
    }

    pub fn with_acme(mut self, acme: &crate::serve::acme::Acme) -> Self {
        self.tls = Some(Tls {
            slot: acme.certificate.clone(),
            challenge: Some(acme.challenge_config.clone()),
        });
        self.listening = Some(acme.listening.clone());
        self
    }

    /// Accept connections until the process is stopped.
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.addr)
            .await
            .with_context(|| format!("binding {}", self.addr))?;
        tracing::info!(
            addr = %listener.local_addr()?,
            tls = self.tls.is_some(),
            attestation = self.endpoints.is_some(),
            "serving"
        );

        // Only now may ACME order. Until this point a validation connection
        // would have found nothing listening, which the CA counts as a failed
        // authorization rather than as "try again in a moment".
        if let Some(listening) = &self.listening {
            listening.notify_one();
        }

        // What the *client* used. With TLS terminated here the guest is still
        // told `https`, or it would build wrong absolute URLs and set wrong
        // cookie flags.
        let scheme = if self.tls.is_some() {
            Scheme::Https
        } else {
            Scheme::Http
        };
        let tls = self.tls.map(Arc::new);

        loop {
            let (client, peer) = listener.accept().await.context("accepting connection")?;
            let routes = Routes {
                guest: self.guest.clone(),
                endpoints: self.endpoints.clone(),
                auth: self.auth.clone(),
                gate: self.gate.clone(),
                attestor: self.attestor.clone(),
                // `Scheme` is not `Copy`, and the service closure is `Fn` — it
                // may run per request on a kept-alive connection.
                scheme: scheme.clone(),
            };
            let tls = tls.clone();

            tokio::task::spawn(async move {
                // The service closure is built *inside* each arm below, after
                // the handshake, because that is the only point at which the
                // peer's certificate exists. Built out here — as it was — the
                // connection's identity could never reach a request.
                let result = match tls.as_deref() {
                    Some(Tls { slot, challenge }) => {
                        // The ClientHello is read before any configuration is
                        // chosen, because under ACME it decides which one: a
                        // validation connection and the real service share this
                        // port, which is the reason TLS-ALPN-01 was chosen.
                        let handshake =
                            match tokio_rustls::LazyConfigAcceptor::new(Default::default(), client)
                                .await
                            {
                                Ok(handshake) => handshake,
                                Err(e) => {
                                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                                    return;
                                }
                            };

                        if let Some(challenge) = challenge {
                            if rustls_acme::is_tls_alpn_challenge(&handshake.client_hello()) {
                                // A validation connection carries no HTTP. The
                                // handshake itself is the proof; completing it
                                // and closing is the whole exchange.
                                tracing::info!(%peer, "answering a TLS-ALPN-01 challenge");
                                match handshake.into_stream(challenge.clone()).await {
                                    Ok(mut tls) => {
                                        use tokio::io::AsyncWriteExt;
                                        let _ = tls.shutdown().await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            %peer, error = %e,
                                            "the ACME challenge handshake failed; \
                                             issuance will not complete"
                                        );
                                    }
                                }
                                return;
                            }
                        }

                        // Loaded once, and after the challenge check so a
                        // validation connection is still answered before any
                        // certificate exists. Everything this connection is
                        // told about its certificate comes from this value.
                        let Some(identity) = slot.get() else {
                            tracing::debug!(%peer, "no certificate to serve with yet");
                            return;
                        };
                        match handshake.into_stream(identity.config.clone()).await {
                            Ok(stream) => {
                                if resumed(&stream, peer) {
                                    return;
                                }
                                serve_connection(
                                    stream,
                                    routes,
                                    Some(identity.certificate_der.clone()),
                                )
                                .await
                            }
                            Err(e) => {
                                // Routine: scanners, health checks, and clients
                                // that reject the certificate. Under ACME every
                                // handshake lands here until the first order
                                // completes, which is the expected state while
                                // one is in flight.
                                tracing::debug!(%peer, error = %e, "TLS handshake failed");
                                return;
                            }
                        }
                    }
                    // No TLS, so no certificate and no identity. Whatever the
                    // client says about itself is discarded, same as any other
                    // unauthenticated connection.
                    None => serve_connection(client, routes, None).await,
                };
                if let Err(e) = result {
                    tracing::debug!(%peer, error = %e, "connection ended");
                }
            });
        }
    }
}

/// Compile the guest, build the server described by `config`, and serve until
/// the process is stopped.
pub async fn serve_component(
    component_bytes: &[u8],
    guest: GuestEnvironment,
    mut config: ServeConfig,
) -> Result<()> {
    // wasmtime 44 enables async at the engine level when the `async` feature
    // is on; `Config::async_support` is a no-op. Same as `run_component`.
    let engine = ServeHandle::engine_with_watchdog()?;
    let mut handle =
        ServeHandle::new(&engine, component_bytes, guest)?.with_timeout(config.request_timeout);
    if let Some(tenancy) = &config.tenancy {
        handle = handle.with_tenancy(tenancy.clone());
    }

    // Before the listener binds. A guest that will not instantiate should stop
    // the enclave, not the first client unlucky enough to arrive.
    handle.verify_instantiates().await?;

    let mut server = Server::new(handle, config.addr);
    match config.authentication {
        Some((auth, gate)) => server = server.with_authentication(auth, gate),
        None => tracing::warn!(
            "serving with NO authentication: every request reaches the guest without a \
             WebAuthn assertion. Set --webauthn-rp-id and --webauthn-origin for anything \
             that is not a development run."
        ),
    }

    // Where a connection loads its serving identity at accept time. Fixed for a
    // self-signed certificate; replaced by the ACME client on issue and on
    // every renewal — but a connection that already loaded one keeps it, which
    // is what makes "the certificate this connection was served" answerable.
    let certificate = match (config.certificate.take(), &config.acme) {
        (Some(slot), _) => Some(slot),
        (None, Some(acme)) => Some(acme.certificate.clone()),
        (None, None) => None,
    };

    match (&certificate, &config.attestation) {
        (Some(slot), attestation) => {
            if let Some(nsm) = attestation {
                let endpoints = EnclaveEndpoints::new(nsm.clone(), slot.clone(), component_bytes)?;
                server = server.with_endpoints(Arc::new(endpoints));

                // Every response carries a proof, so the device is now on the
                // path of every request rather than one endpoint.
                let attestor = Arc::new(ResponseAttestor::new(nsm.clone(), component_bytes));

                // Checked once, here, with the largest nonce a client may send.
                // A document too large for a header is a property of this
                // deployment's certificate chain, and a runtime that cannot
                // attest its responses should refuse to start rather than
                // refuse every request. This is also the first call to the
                // device, so an NSM that will not answer is found now.
                match attestor.verify_fits().await {
                    Ok(bytes) => {
                        tracing::info!(document_header_bytes = bytes, "attesting every response")
                    }
                    Err(e) => anyhow::bail!(
                        "this runtime cannot attest its responses: {e}. Every request would \
                         be refused, so it will not start."
                    ),
                }
                server = server.with_attestor(attestor);
            }

            // ACME owns its own slot and needs the challenge configuration
            // alongside it; a fixed certificate is served straight from the
            // slot built above.
            server = match &config.acme {
                Some(acme) => server.with_acme(acme),
                None => server.with_tls(slot.clone()),
            };
        }
        (None, Some(_)) => {
            anyhow::bail!(
                "attestation was requested without TLS. A document binds the serving \
                 certificate, so without one it would promise a binding it does not have."
            );
        }
        (None, None) => {
            tracing::warn!(
                "serving plaintext HTTP with no attestation; \
                 inside an enclave this exposes every request to the parent instance"
            );
        }
    }

    server.run().await
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use tokio::sync::oneshot;

    type HeadResult = std::result::Result<
        hyper::Response<HyperOutgoingBody>,
        wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
    >;

    fn head() -> HeadResult {
        Ok(hyper::Response::new(full(bytes::Bytes::from_static(
            b"body",
        ))))
    }

    /// A guest task, as the dispatch paths build one: it holds `lock` for the
    /// whole call, sets a response head part way through, and finishes only
    /// when told to.
    fn guest_task<L: Send + 'static>(
        lock: L,
        set_head: oneshot::Sender<HeadResult>,
        finish: oneshot::Receiver<()>,
    ) -> tokio::task::JoinHandle<wasmtime::Result<()>> {
        tokio::task::spawn(async move {
            let _lock = lock;
            let _ = set_head.send(head());
            let _ = finish.await;
            Ok(())
        })
    }

    /// The property the whole design rests on: a tenant's second request waits
    /// for its first to be *finished*, not merely to have produced headers.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_tenant_serialises_against_itself() {
        let tenant = Arc::new(tokio::sync::Mutex::new(()));
        let held = tenant.clone().lock_owned().await;
        let (set_head, receiver) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let task = guest_task(held, set_head, finished);

        // The head is out, and the guest is still writing its body.
        await_head(Duration::from_secs(5), task, receiver)
            .await
            .expect("head");

        let second = tenant.clone().lock_owned();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), second)
                .await
                .is_err(),
            "a second request for this tenant started while the first was still running"
        );

        let _ = finish.send(());
        assert!(
            tokio::time::timeout(Duration::from_secs(5), tenant.clone().lock_owned())
                .await
                .is_ok(),
            "the tenant's lock was not released when its guest finished"
        );
    }

    /// And the other half: two tenants have nothing to queue on. This is what
    /// the removed global semaphore used to prevent.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_tenants_run_at_the_same_time() {
        let alice = Arc::new(tokio::sync::Mutex::new(()));
        let bob = Arc::new(tokio::sync::Mutex::new(()));

        let (alice_head, alice_receiver) = oneshot::channel();
        let (alice_finish, alice_finished) = oneshot::channel();
        let alice_task = guest_task(alice.clone().lock_owned().await, alice_head, alice_finished);
        await_head(Duration::from_secs(5), alice_task, alice_receiver)
            .await
            .expect("alice's head");

        // Alice is mid-body. Bob must not be waiting on her.
        let (bob_head, bob_receiver) = oneshot::channel();
        let (bob_finish, bob_finished) = oneshot::channel();
        let bob_lock = tokio::time::timeout(Duration::from_millis(100), bob.clone().lock_owned())
            .await
            .expect("bob queued behind alice");
        let bob_task = guest_task(bob_lock, bob_head, bob_finished);
        let bob_response = tokio::time::timeout(
            Duration::from_secs(5),
            await_head(Duration::from_secs(5), bob_task, bob_receiver),
        )
        .await
        .expect("bob's head did not arrive while alice was running")
        .expect("bob's head");
        assert_eq!(bob_response.status(), 200);

        let _ = alice_finish.send(());
        let _ = bob_finish.send(());
    }

    /// Callers with no resolved tenant are one identity, so they queue behind
    /// each other rather than multiplying wasm instances.
    #[tokio::test(flavor = "multi_thread")]
    async fn anonymous_callers_share_one_slot() {
        let anonymous = Arc::new(tokio::sync::Mutex::new(()));
        let held = anonymous.clone().lock_owned().await;
        let (set_head, receiver) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let task = guest_task(held, set_head, finished);
        await_head(Duration::from_secs(5), task, receiver)
            .await
            .expect("head");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), anonymous.clone().lock_owned())
                .await
                .is_err(),
            "a second anonymous request ran alongside the first"
        );
        let _ = finish.send(());
    }

    /// A guest that never answers is aborted, and abort drops the task's
    /// locals — so an abandoned request must not hold its tenant's lock
    /// forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_abandoned_guest_releases_its_tenant() {
        let tenant = Arc::new(tokio::sync::Mutex::new(()));
        let held = tenant.clone().lock_owned().await;
        let (_set_head, receiver) = oneshot::channel::<HeadResult>();

        let task = tokio::task::spawn(async move {
            let _lock = held;
            std::future::pending::<()>().await;
            Ok(())
        });

        let error = await_head(Duration::from_millis(50), task, receiver)
            .await
            .expect_err("a guest that never answers should be abandoned");
        assert!(format!("{error:#}").contains("abandoned"), "{error:#}");

        assert!(
            tokio::time::timeout(Duration::from_secs(5), tenant.clone().lock_owned())
                .await
                .is_ok(),
            "an abandoned guest kept its tenant's lock"
        );
    }

    /// A guest that fails without setting a response still releases its lock.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_guest_releases_its_tenant() {
        let tenant = Arc::new(tokio::sync::Mutex::new(()));
        let held = tenant.clone().lock_owned().await;
        let (set_head, receiver) = oneshot::channel::<HeadResult>();

        let task = tokio::task::spawn(async move {
            let _lock = held;
            drop(set_head);
            Err(wasmtime::Error::msg("guest trapped"))
        });

        let error = await_head(Duration::from_secs(5), task, receiver)
            .await
            .expect_err("a trap without a response is an error");
        assert!(format!("{error:#}").contains("guest trapped"), "{error:#}");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), tenant.clone().lock_owned())
                .await
                .is_ok(),
            "a failed guest kept its tenant's lock"
        );
    }
}
