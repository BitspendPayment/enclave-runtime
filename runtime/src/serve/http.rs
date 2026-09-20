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
use tokio::net::TcpListener;
use wasmtime::component::{Component, InstancePre};
use wasmtime::{Engine, Store, UpdateDeadline};
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
use crate::serve::pool::{LiveTenant, PoolLimits, TenantPool};
use crate::serve::progress::{Counting, StreamProgress};
use crate::state::State;
use crate::tenant::tenant_root_by_id;
use nitro_nsm::Nsm;

/// How the guest is served.
#[derive(Debug)]
pub struct ServeConfig {
    /// Opt-in standing authorization for tenant-bound durable tasks.
    pub background_tasks: Option<crate::tasks::TaskLimits>,
    /// Opt-in push notifications. The registry and the forwarder are opened
    /// here rather than by the caller, because both need the mounted
    /// filesystem and the trusted clock, and this is where those exist.
    pub notify: Option<crate::notify::NotifyConfig>,
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
    /// NSM to sign the attestation document on each `/auth/*` response.
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
    /// How long an interaction may run once it has answered.
    ///
    /// Deliberately separate from `request_timeout`: that one bounds getting a
    /// head out, and does not apply afterwards, so without this a stream had no
    /// ceiling at all and held its tenant's slot indefinitely.
    pub max_interaction: Duration,
    /// Give each authenticated client their own filesystem. `None` keeps the
    /// original model: one filesystem, a fresh instance per request.
    pub tenancy: Option<Arc<Tenancy>>,
    /// `/auth/*` and the gate every other request must pass.
    ///
    /// `None` serves the guest to anyone who can open a connection. That is a
    /// development and QEMU arrangement, and [`serve_component`] says so
    /// loudly at startup rather than leaving it to be noticed.
    pub authentication: Option<(Arc<AuthEndpoints>, Arc<Gate>)>,
    /// What guests may reach over `wasi:http`. [`EgressPolicy::Denied`] unless
    /// the deployment names origins.
    pub egress: crate::serve::EgressPolicy,
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
            background_tasks: None,
            notify: None,
            addr: ([0, 0, 0, 0], 8080).into(),
            certificate: None,
            acme: None,
            attestation: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_interaction: DEFAULT_MAX_INTERACTION,
            // Off. Turning it on changes what two clients may do at the same
            // time, which a guest may have been relying on — so it is asked
            // for, never inherited.
            tenancy: None,
            authentication: None,
            egress: crate::serve::EgressPolicy::Denied,
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

/// Consecutive silent epoch expiries before a call is judged a runaway.
///
/// This — not `request_timeout` — is what bounds how long a guest can burn a
/// worker after its budget is spent, and it is deliberately independent of the
/// budget: a deployment that allows generous head timeouts should not thereby
/// allow generous spinning. Eight ticks is two seconds, long enough that a
/// loaded machine delivering frames late is never mistaken for one delivering
/// nothing, short enough that a genuine runaway is gone before it matters.
const SILENT_TICKS_BEFORE_TRAP: u32 = 8;

/// Default ceiling on producing a response head.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an interaction may run once it has produced a head.
///
/// Minutes rather than seconds, because a signing session legitimately takes
/// them and a stream doing its job must not be cut off for being slow. What
/// this bounds is the other case: a peer that opened an interaction and then
/// went quiet still holds its tenant's only slot, and without a ceiling it
/// holds it until the process ends.
const DEFAULT_MAX_INTERACTION: Duration = Duration::from_secs(300);

/// A guest instance and the store it is bound to.
///
/// The two travel together because `instantiate_async` binds a `Proxy` to one
/// store: separating them would produce a handle that looks usable and
/// resolves against the wrong memory.
pub struct GuestInstance {
    store: Store<State>,
    proxy: wasmtime_wasi_http::p2::bindings::Proxy,
    /// Shared with this store's epoch callback, which was installed once and
    /// outlives every request the instance serves. Reset per call rather than
    /// replaced, so the callback never holds a stale one.
    progress: Arc<StreamProgress>,
}

/// A compiled guest plus the environment its instances are built from.
///
/// Compilation and `instantiate_pre` happen once, at startup: per-request
/// instantiation is then cheap, and — more usefully inside an enclave — a
/// component that will not compile fails at boot rather than on the first
/// request to arrive.
pub struct ServeHandle {
    pre: ProxyPre<State>,
    background_pre: InstancePre<State>,
    tasks: Option<Arc<crate::tasks::TaskQueue>>,
    /// Connections this runtime holds for guests — see [`crate::stream`].
    streams: Option<Arc<crate::stream::StreamRegistry>>,
    notify: Option<Arc<crate::notify::Notifier>>,
    egress: crate::serve::EgressPolicy,
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
    /// How long a call may run after its head is out. See `supervise`.
    max_interaction: Duration,
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
    /// `tokio::task::abort` has no await point to act on. A dedicated thread
    /// advances the epoch independently of Tokio workers and exits when the
    /// last engine handle is dropped.
    pub fn engine_with_watchdog() -> Result<Engine> {
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;

        let ticker = engine.weak();
        // The ticker must run even when guest CPU loops occupy every Tokio
        // worker. An async ticker on that same executor cannot guarantee it.
        std::thread::Builder::new()
            .name("guest-epoch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(EPOCH_TICK);
                    // A weak handle, so this thread cannot keep a dropped engine
                    // alive — it simply stops when the engine goes.
                    match ticker.upgrade() {
                        Some(engine) => engine.increment_epoch(),
                        None => break,
                    }
                }
            })?;
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
        let pre = ProxyPre::new(instance_pre.clone())
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("guest does not export wasi:http/incoming-handler")?;

        Ok(ServeHandle {
            background_pre: instance_pre,
            tasks: None,
            streams: None,
            notify: None,
            egress: crate::serve::EgressPolicy::Denied,
            pre,
            guest: Arc::new(guest),
            anonymous: Arc::new(tokio::sync::Mutex::new(())),
            timeout: DEFAULT_REQUEST_TIMEOUT,
            max_interaction: DEFAULT_MAX_INTERACTION,
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

    pub fn with_tasks(mut self, queue: Arc<crate::tasks::TaskQueue>) -> Result<Self> {
        anyhow::ensure!(
            self.tenancy.is_some(),
            "background tasks require tenant isolation"
        );
        self.tasks = Some(queue);
        Ok(self)
    }

    /// Let the runtime hold outbound connections on a guest's behalf.
    ///
    /// Tenant isolation is required for the same reason tasks require it: a
    /// connection belongs to a tenant, and the invocations its messages cause
    /// run in that tenant's filesystem. Without tenancy there is nobody to
    /// attribute either to.
    pub fn with_streams(mut self, registry: Arc<crate::stream::StreamRegistry>) -> Result<Self> {
        anyhow::ensure!(
            self.tenancy.is_some(),
            "held connections require tenant isolation"
        );
        self.streams = Some(registry);
        Ok(self)
    }

    /// The registry, for the interactive path: a guest serving its owner's
    /// request must be able to open and close connections.
    pub(crate) fn streams(&self) -> Option<&Arc<crate::stream::StreamRegistry>> {
        self.streams.as_ref()
    }

    /// Let the guest wake its tenant's devices.
    ///
    /// Tenant isolation is required for the same reason tasks require it: a
    /// device belongs to a tenant, and without tenancy there is no tenant to
    /// bind an enrolment to.
    pub fn with_notify(mut self, notifier: Arc<crate::notify::Notifier>) -> Result<Self> {
        anyhow::ensure!(
            self.tenancy.is_some(),
            "notifications require tenant isolation"
        );
        self.notify = Some(notifier);
        Ok(self)
    }

    /// Let guests reach the origins [`crate::serve::EgressPolicy`] names — for
    /// requests and background tasks alike, since renewing something on a
    /// schedule is exactly the work that happens with nobody connected.
    pub fn with_egress(mut self, egress: crate::serve::EgressPolicy) -> Self {
        self.egress = egress;
        self
    }

    /// An internal component export, never an HTTP route or a fabricated token.
    /// One message from a held connection, as one guest invocation.
    ///
    /// The same shape as [`Self::run_background`] and for the same reasons: a
    /// fresh instance, the tenant's lock, a wall deadline. What differs is only
    /// what woke it — a counterparty rather than a clock — and that it may reply.
    ///
    /// `interactive` is FALSE. A message arriving over a connection is not its
    /// owner asking for something, so it cannot open connections or schedule
    /// work, exactly as a background run cannot.
    pub(crate) async fn run_message(
        &self,
        streams: &Arc<crate::stream::StreamRegistry>,
        tenant: [u8; 16],
        id: &str,
        message_id: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let tenancy = self
            .tenancy
            .as_ref()
            .context("held connections require tenants")?;
        let checkout = tenancy.pool.checkout(&tenant);
        let mut guard = checkout.slot().tenant().clone().lock_owned().await;
        if let Some(t) = guard.as_mut() {
            t.instance = None;
        }
        let work = async {
            let scope = crate::tenant::existing_tenant_root(self.guest.fs(), tenant).await?;
            let state = self.guest.new_state_scoped(scope)?;
            let mut store = Store::new(self.pre.engine(), state);
            store.set_epoch_deadline(1);
            store.epoch_deadline_async_yield_and_update(1);
            let instance = self.background_pre.instantiate_async(&mut store).await?;
            store.data_mut().streams = Some(crate::stream::StreamContext {
                registry: streams.clone(),
                tenant,
                interactive: false,
            });
            store.data_mut().set_egress(self.egress.clone());
            store.data_mut().notify =
                self.notify
                    .as_ref()
                    .map(|notifier| crate::notify::NotifyContext {
                        notifier: notifier.clone(),
                        tenant,
                        interactive: false,
                    });
            let run = instance
                .get_typed_func::<(String, String, Vec<u8>), (std::result::Result<Vec<u8>, String>,)>(
                    &mut store,
                    "on-message",
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))
                .context("held connections require the on-message export")?;
            let (result,) = run
                .call_async(&mut store, (id.to_string(), message_id.to_string(), payload))
                .await?;
            let bytes = result.map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                bytes.len() <= crate::stream::MAX_MESSAGE,
                "reply exceeds the message ceiling"
            );
            Ok(bytes)
        };
        // The same wall clock that bounds an interaction. A guest parked in a
        // host call executes no wasm, so the epoch alone would never reach it.
        tokio::time::timeout(self.timeout, work)
            .await
            .context("the guest took too long to answer a message")?
    }

    /// A fresh instance shares the tenant lock; drop its warm HTTP instance so
    /// no cached database handles survive a background mutation.
    pub(crate) async fn run_background(
        &self,
        queue: &Arc<crate::tasks::TaskQueue>,
        task: &crate::tasks::Task,
    ) -> Result<Option<Vec<u8>>> {
        let tenancy = self
            .tenancy
            .as_ref()
            .context("background tasks require tenants")?;
        let checkout = tenancy.pool.checkout(&task.tenant);
        let Ok(mut guard) = checkout.slot().tenant().clone().try_lock_owned() else {
            return Ok(None);
        };
        if !queue.begin(task).await? {
            return Ok(Some(Vec::new()));
        }
        if let Some(tenant) = guard.as_mut() {
            tenant.instance = None;
        }
        let work = async {
            let scope = crate::tenant::existing_tenant_root(self.guest.fs(), task.tenant).await?;
            let state = self.guest.new_state_scoped(scope)?;
            let mut store = Store::new(self.pre.engine(), state);
            // Yield every tick, even in CPU-only loops, so the wall deadline
            // can cancel both guest code and async host calls.
            store.set_epoch_deadline(1);
            store.epoch_deadline_async_yield_and_update(1);
            let instance = self.background_pre.instantiate_async(&mut store).await?;
            store.data_mut().tasks = Some(crate::tasks::TaskContext {
                queue: queue.clone(),
                tenant: task.tenant,
                interactive: false,
            });
            store.data_mut().set_egress(self.egress.clone());
            store.data_mut().notify =
                self.notify
                    .as_ref()
                    .map(|notifier| crate::notify::NotifyContext {
                        notifier: notifier.clone(),
                        tenant: task.tenant,
                        interactive: false,
                    });
            let run = instance
                .get_typed_func::<(String, Vec<u8>), (std::result::Result<Vec<u8>, String>,)>(
                    &mut store, "run-task",
                )?;
            let (result,) = run
                .call_async(&mut store, (task.run_id(), task.payload.clone()))
                .await?;
            let bytes = result.map_err(anyhow::Error::msg)?;
            anyhow::ensure!(bytes.len() <= 64 * 1024, "task result exceeds 64 KiB");
            Ok(Some(bytes))
        };
        tokio::time::timeout(queue.limits.timeout, work)
            .await
            .context("background task deadline exceeded")?
    }

    /// Override the response-head deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override how long an interaction may run once it has answered.
    ///
    /// Distinct from [`ServeHandle::with_timeout`], and the distinction is the
    /// point: one bounds how long a guest may take to *start* answering, the
    /// other how long it may go on. A stream that is healthy for minutes is
    /// normal; a tenant's slot held for hours is not.
    pub fn with_max_interaction(mut self, max_interaction: Duration) -> Self {
        self.max_interaction = max_interaction;
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
        B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
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
        B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
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
        instance.store.data_mut().streams =
            self.streams
                .as_ref()
                .map(|registry| crate::stream::StreamContext {
                    registry: registry.clone(),
                    tenant: tenant_id,
                    // Its owner is here, so this invocation may open and close
                    // connections — unlike one caused by a message arriving on
                    // one, which may only reply.
                    interactive: true,
                });
        instance.store.data_mut().tasks =
            self.tasks.as_ref().map(|queue| crate::tasks::TaskContext {
                queue: queue.clone(),
                tenant: tenant_id,
                interactive: true,
            });
        instance.store.data_mut().set_egress(self.egress.clone());
        instance.store.data_mut().notify =
            self.notify
                .as_ref()
                .map(|notifier| crate::notify::NotifyContext {
                    notifier: notifier.clone(),
                    tenant: tenant_id,
                    interactive: true,
                });
        // Reset every request: the epoch deadline is absolute, so a reused
        // store would otherwise inherit whatever the last request left. The
        // same is true of the progress this call will be judged on.
        instance.store.set_epoch_deadline(self.watchdog());
        instance.progress.reset();
        let progress = instance.progress.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        // Wrapped before it becomes a guest resource, which is the last point
        // the runtime holds it.
        let req = req.map(|body| Counting::new(body, progress.clone()));
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
            // Taken out of the slot for the duration, and put back only on a
            // clean finish. Held *by reference* instead — as this once did —
            // and an aborted call leaves the instance where it sits: `abort`
            // drops this future at the await below, so nothing after it runs,
            // and the next request for this tenant re-enters a store whose
            // `call_handle` was cancelled part-way through. Ownership is what
            // makes "an interrupted instance is never reused" true for the
            // abort path and not only for the trap path, because a dropped
            // future drops what it owns.
            let mut instance = tenant.instance.take().expect("built before the call");
            let result = instance
                .proxy
                .wasi_http_incoming_handler()
                .call_handle(&mut instance.store, req, out)
                .await;

            // One client's instance, and nothing else. The filesystem is
            // shared and untouched; the next caller for this client gets a
            // fresh instance over the same directory.
            if result.is_err() {
                tracing::warn!("guest trapped; this client's instance will be rebuilt");
            } else if !instance.store.data().resources_settled() {
                tracing::debug!("guest left resources behind; rebuilding its instance");
            } else {
                tenant.instance = Some(instance);
            }
            result
        });

        await_head(self.timeout, self.max_interaction, task, receiver, progress).await
    }

    /// Build an instance whose guest sees `scope` as `/`.
    ///
    /// The one place a store and an instance are made, so the per-request path
    /// and the per-tenant path cannot drift in what a guest is handed.
    async fn instantiate(&self, scope: Arc<s3fs_core::Inode>) -> Result<GuestInstance> {
        let mut store = Store::new(self.pre.engine(), self.guest.new_state_scoped(scope)?);
        let progress = Arc::new(StreamProgress::new());
        store.set_epoch_deadline(self.watchdog());
        self.arm_watchdog(&mut store, progress.clone());
        let proxy = self
            .pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("instantiating the guest")?;
        Ok(GuestInstance {
            store,
            proxy,
            progress,
        })
    }

    /// Let a call that is moving bytes outlive the budget; keep one that is not
    /// on exactly the schedule it had before.
    ///
    /// The deadline set beside this is what a request/response call gets, and
    /// for anything that finishes inside the timeout nothing here ever runs.
    /// When it does expire, the question stops being "how long has this taken"
    /// and becomes "is this still a conversation" — because a signing session
    /// legitimately open for minutes and a guest spinning in a loop are
    /// indistinguishable by elapsed time and obvious by traffic.
    ///
    /// `Yield` rather than `Continue`: extending alone leaves a guest that
    /// makes progress *and* spins between frames with no await point for
    /// `await_head`'s abort to land on. Yielding creates one every tick, which
    /// costs a reschedule per [`EPOCH_TICK`] and keeps the abort path real.
    ///
    /// Note what this deliberately cannot see: a guest parked in a *host* call
    /// executes no wasm, so no epoch check is reached and nothing here fires.
    /// That gap is the idle supervisor's, not this one's.
    fn arm_watchdog(&self, store: &mut Store<State>, progress: Arc<StreamProgress>) {
        let silent = EPOCH_TICK * SILENT_TICKS_BEFORE_TRAP;
        store.epoch_deadline_callback(move |_| {
            // A single tick at a time once the budget is spent, so the
            // question gets asked again promptly rather than handing out
            // another full budget on one frame of evidence.
            if progress.still_working(SILENT_TICKS_BEFORE_TRAP) {
                Ok(UpdateDeadline::Yield(1))
            } else {
                Err(wasmtime::Error::msg(format!(
                    "the guest ran {silent:?} past its budget without moving a byte \
                     in either direction"
                )))
            }
        });
    }

    /// The only dispatch path. A fresh store, a fresh instance, both dropped
    /// when the request ends — so nothing survives but what was committed.
    async fn in_fresh_instance<B>(
        &self,
        scheme: Scheme,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        // Anonymous callers are one identity, so they queue behind each other.
        // Taken before the store is built: an instance is a wasm linear memory,
        // and building one per waiting request is the exhaustion this prevents.
        let anonymous = self.anonymous.clone().lock_owned().await;

        let mut store = Store::new(self.pre.engine(), self.guest.new_state()?);
        let progress = Arc::new(StreamProgress::new());
        store.set_epoch_deadline(self.watchdog());
        self.arm_watchdog(&mut store, progress.clone());
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let req = req.map(|body| Counting::new(body, progress.clone()));
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

        await_head(self.timeout, self.max_interaction, task, receiver, progress).await
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
        if self.tasks.is_some() {
            let instance = self.background_pre.instantiate_async(&mut store).await?;
            instance
                .get_typed_func::<(String, Vec<u8>), (std::result::Result<Vec<u8>, String>,)>(
                    &mut store, "run-task",
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))
                .context("background tasks require the run-task export")?;
        }
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
/// Bound how long an interaction may run, once its head is out.
///
/// Until this existed nothing watched the call after `await_head` returned: the
/// `JoinHandle` was dropped, which detaches, and the only remaining limits were
/// the epoch — which a guest parked in a host call never reaches, because it
/// executes no wasm — and `wasi:http`'s hardcoded ten-minute between-bytes
/// ceiling. A client that opened a stream and then said nothing held its
/// tenant's single slot for as long as it liked.
///
/// A wall clock is the right instrument here precisely where the epoch is the
/// wrong one. A guest blocked in a host call *is* at an await point inside
/// `call_handle`, so `abort` reaches it — and dropping the task drops the
/// tenant's guard, the pool checkout, and the instance, none of which it can
/// hand back.
///
/// Detached deliberately: the caller is returning a response body that hyper is
/// about to stream, so it cannot hold this. The handle races the deadline and
/// goes away when either finishes.
fn supervise(max_interaction: Duration, task: tokio::task::JoinHandle<wasmtime::Result<()>>) {
    tokio::task::spawn(async move {
        let mut task = task;
        if tokio::time::timeout(max_interaction, &mut task)
            .await
            .is_err()
        {
            tracing::info!(
                limit = ?max_interaction,
                "an interaction reached its deadline; abandoning it and freeing its tenant"
            );
            task.abort();
        }
    });
}

async fn await_head(
    timeout: Duration,
    max_interaction: Duration,
    task: tokio::task::JoinHandle<wasmtime::Result<()>>,
    receiver: tokio::sync::oneshot::Receiver<
        std::result::Result<
            hyper::Response<HyperOutgoingBody>,
            wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
        >,
    >,
    progress: Arc<StreamProgress>,
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
        // Wrapped on the way out, which is the first point the runtime holds
        // it again: from here the count follows what hyper actually drains,
        // so a guest writing into a buffer nobody reads earns no extension.
        Ok(Ok(resp)) => {
            // From here `await_head` is out of the picture, so the watchdog may
            // stop racing it and start judging silence on its merits.
            progress.head_sent();
            supervise(max_interaction, task);
            Ok(resp.map(|body| {
                use http_body_util::BodyExt;
                Counting::new(body, progress).boxed_unsync()
            }))
        }
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
    // Boxed rather than `hyper::Error`: the protocol is chosen per connection
    // now, and `auto::Builder` reports failures from whichever of the two it
    // ended up speaking.
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Routes {
        guest,
        auth,
        gate,
        attestor,
        scheme,
    } = routes;
    let certificate = certificate.map(Arc::new);
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let guest = guest.clone();
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

            // Only where a client still has to work out who it is talking to,
            // which is the `/auth/` exchange and nothing after it.
            //
            // A client identifies the enclave on the challenge request — that
            // response's document binds the certificate it was served — and
            // then pins that certificate for the operation. TLS proves the peer
            // holds its private key, which the certificate itself, being
            // public, does not; so "the same certificate" and "the same
            // enclave" are one statement, and the operation needs no second
            // signature to establish what the first already did.
            //
            // Attesting it anyway cost an NSM signature per operation, and the
            // device is the throughput ceiling — `CONCURRENT_DOCUMENTS` is 4.
            // That halves the signatures a signed request costs.
            let attest_this = req.uri().path().starts_with(crate::auth::AUTH_PREFIX);

            // Generated before the request is routed, not after the
            // response exists: it binds the nonce and the connection's
            // certificate, neither of which depends on what the guest says.
            // Doing it here means a failure refuses before the guest runs,
            // rather than stranding a half-produced response.
            let document = match &attestor {
                Some(attestor) if attest_this => {
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
                // Either the deployment does not attest, or this is a request
                // whose caller has already identified the enclave.
                _ => None,
            };

            let mut response = route(req, guest, auth, gate, scheme).await?;
            match document {
                Some(document) => crate::serve::attest::attach(&mut response, document),
                // Not "leave it as it is": a response the runtime did not
                // attest must not carry the header at all, or a guest could
                // put one there itself.
                None => crate::serve::attest::strip(&mut response),
            }
            Ok(response)
        }
    });

    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    builder.http1().keep_alive(true);
    // A stream carrying nothing is indistinguishable from a peer that has gone
    // away, and a peer that has gone away is still holding its tenant's slot.
    // PING is the only thing at this layer that can tell them apart.
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20));
    builder.serve_connection(TokioIo::new(io), service).await
}

/// Everything that decides what a response *is*, with attestation stripped out.
///
/// A separate function so the closure above has exactly one exit: that is what
/// makes "no response leaves unattested" and "a guest cannot own the header"
/// single facts rather than five places to audit.
async fn route(
    req: hyper::Request<hyper::body::Incoming>,
    guest: Arc<ServeHandle>,
    auth: Option<Arc<AuthEndpoints>>,
    gate: Option<Arc<Gate>>,
    scheme: Scheme,
) -> Result<hyper::Response<HyperOutgoingBody>> {
    {
        {
            let method = req.method().clone();
            let path = req.uri().path().to_string();

            // `/auth/` is checked first and is not forwardable: a guest able
            // to answer there could hand out its own challenges and verify its
            // own assertions, which is the same as having none.
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
            // without an unspent interaction token.** With no gate configured
            // the runtime is unauthenticated by deliberate choice —
            // development, and the QEMU harness.
            let tenant = match &gate {
                Some(gate) => match gate.redeem(&req) {
                    Ok(verified) => {
                        // Rebuilt so the token cannot reach the guest. The body
                        // is forwarded as it arrives, never buffered: an
                        // interaction may be a stream, and there is no hash to
                        // hold it still for any more.
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
                        use http_body_util::BodyExt;
                        let body = req
                            .into_body()
                            .map_err(wasmtime_wasi_http::p2::bindings::http::types::ErrorCode::from)
                            .boxed_unsync();
                        let rebuilt = rebuilt.body(body).expect("request is well formed");
                        return guest
                            .handle(scheme, rebuilt, Some(&verified.tenant_id))
                            .await;
                    }
                    Err(denied) => {
                        // Logged in full, answered in one sentence: which check
                        // failed is the runtime's business, and telling a
                        // caller would tell them which guess to refine.
                        tracing::info!(%path, reason = %denied, "refused an unauthorized interaction");
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
        // Dropping the server cancels the scheduler and its owned worker set.
        // A scheduler storage error stops serving instead of losing wakeups.
        let mut scheduler = tokio::task::JoinSet::new();
        if let Some(queue) = &self.guest.tasks {
            anyhow::ensure!(
                self.gate.is_some(),
                "background tasks require authentication"
            );
            scheduler.spawn(queue.clone().run(self.guest.clone()));
        }
        // The supervisors, started from what is already on disk. This is what
        // re-establishes a connection after a restart — no guest is involved and
        // nothing is scheduled; the records are the instruction and this reads
        // them. See [`crate::stream`].
        if let Some(streams) = &self.guest.streams {
            anyhow::ensure!(
                self.gate.is_some(),
                "held connections require authentication"
            );
            streams.set_egress(self.guest.egress.clone()).await;
            scheduler.spawn(streams.clone().run(self.guest.clone()));
        }
        let listener = TcpListener::bind(self.addr)
            .await
            .with_context(|| format!("binding {}", self.addr))?;
        tracing::info!(
            addr = %listener.local_addr()?,
            tls = self.tls.is_some(),
            attestation = self.attestor.is_some(),
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
            let (client, peer) = tokio::select! {
                accepted = listener.accept() => accepted.context("accepting connection")?,
                ended = scheduler.join_next(), if !scheduler.is_empty() => {
                    ended.context("scheduler disappeared")???;
                    anyhow::bail!("scheduler unexpectedly stopped");
                }
            };
            let routes = Routes {
                guest: self.guest.clone(),
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
    let mut handle = ServeHandle::new(&engine, component_bytes, guest)?
        .with_timeout(config.request_timeout)
        .with_max_interaction(config.max_interaction)
        .with_egress(config.egress.clone());
    if let Some(tenancy) = &config.tenancy {
        handle = handle.with_tenancy(tenancy.clone());
    }
    if let Some(limits) = config.background_tasks.take() {
        anyhow::ensure!(
            config.authentication.is_some(),
            "background tasks require authentication"
        );
        let queue = crate::tasks::TaskQueue::open(
            handle.environment().fs().clone(),
            handle.environment().clock().clone(),
            limits,
        )
        .await?;
        handle = handle.with_tasks(queue)?;
    }
    // Held connections, whenever there is a tenant to attribute one to and a gate to authenticate
    // that tenant. No flag of its own: the registry is a directory and a supervisor loop over
    // whatever records exist, and a guest that never asks for a connection has neither. What a
    // guest may REACH is still the egress allowlist's to say, checked on every dial and every
    // send — so enabling this widens nothing.
    if config.tenancy.is_some() && config.authentication.is_some() {
        let registry =
            crate::stream::StreamRegistry::open_registry(handle.environment().fs().clone()).await?;
        handle = handle.with_streams(registry)?;
    }
    let mut notify_forwarder = None;
    if let Some(notify) = config.notify.take() {
        anyhow::ensure!(
            config.authentication.is_some(),
            "notifications require authentication: the tenant a wake belongs to comes \
             from a verified assertion, and without a gate there is none"
        );
        let registry =
            crate::notify::DeviceRegistry::open(handle.environment().fs().clone()).await?;
        // Plaintext only where an endpoint override asked for it, which is the
        // emulator harness pointing at a local stub.
        let plaintext = notify
            .endpoint
            .as_deref()
            .is_some_and(|e| e.starts_with("http://"));
        let transport = Arc::new(crate::notify::HttpsTransport::new(plaintext)?);
        let mut client = crate::notify::FcmClient::new(notify, transport);

        let clock = handle.environment().clock().clone();
        let now = {
            use wasmtime_wasi::HostWallClock;
            clock.now().as_millis().min(u64::MAX as u128) as u64
        };
        // Bounded, and never fatal for a transient failure. A push service
        // must not be what decides whether the enclave binds its listener —
        // but a credential that will never work is a deployment mistake, and
        // finding it now beats finding it the first time somebody needed a
        // wake signal.
        match tokio::time::timeout(
            crate::notify::NOTIFY_STARTUP_PROBE_TIMEOUT,
            client.probe(now),
        )
        .await
        {
            Ok(Ok(())) => tracing::info!("notifications are configured and the credential works"),
            Ok(Err(crate::notify::SendError::Refused(detail))) => {
                anyhow::bail!("the FCM credential was rejected: {detail}")
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "could not reach FCM at startup; wake signals will retry")
            }
            Err(_) => tracing::warn!("FCM did not answer at startup; wake signals will retry"),
        }

        let (notifier, forwarder) = crate::notify::start(registry, clock, client);
        notify_forwarder = Some(forwarder);
        handle = handle.with_notify(notifier)?;
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
                // Every response carries a proof, so the device is on the path
                // of every request.
                let attestor = Arc::new(ResponseAttestor::new(nsm.clone(), component_bytes));

                // Checked once, here, with the largest nonce a client may send.
                // A document too large for a header is a property of this
                // deployment's certificate chain, and a runtime that cannot
                // attest its responses should refuse to start rather than
                // refuse every request. This is also the first call to the
                // device, so an NSM that will not answer is found now.
                match attestor.verify_fits().await {
                    Ok(bytes) => {
                        tracing::info!(document_header_bytes = bytes, "attesting every /auth response")
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

    let served = server.run().await;
    // Drained after serving, so a wake raised by the last request still has its
    // chance to land. Bounded by the forwarder's own flush deadline.
    if let Some(forwarder) = notify_forwarder {
        forwarder.shutdown().await;
    }
    served
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
        await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
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
        await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            alice_task,
            alice_receiver,
            Arc::new(StreamProgress::new()),
        )
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
            await_head(
                Duration::from_secs(5),
                Duration::from_secs(300),
                bob_task,
                bob_receiver,
                Arc::new(StreamProgress::new()),
            ),
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
        await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
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

        let error = await_head(
            Duration::from_millis(50),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
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

        let error = await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
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
