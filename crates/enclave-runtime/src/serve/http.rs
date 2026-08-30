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
use crate::serve::acme::CertificateSlot;
use crate::serve::client::ClientIdentity;
use crate::serve::endpoints::EnclaveEndpoints;
use crate::serve::tls::TlsIdentity;
use crate::state::State;
use nitro_nsm::Nsm;

/// How the guest is served.
#[derive(Debug)]
pub struct ServeConfig {
    /// Address to accept on.
    pub addr: SocketAddr,
    /// Requests allowed inside the guest at once. See [`ServeConfig::default`].
    pub concurrency: usize,
    /// Certificate to terminate TLS with. `None` serves plaintext.
    pub tls: Option<TlsIdentity>,
    /// A running ACME client, instead of a fixed certificate.
    pub acme: Option<crate::serve::acme::Acme>,
    /// NSM to answer `/enclave/attestation` from.
    ///
    /// Only useful alongside `tls`: the document binds the serving
    /// certificate, and without one there is nothing to bind. Supplying it
    /// without TLS is refused rather than silently serving documents that
    /// promise a binding they do not have.
    pub attestation: Option<Arc<dyn Nsm>>,
    /// How long a guest may take to produce a response head.
    ///
    /// A guest that neither returns nor sets a response otherwise hangs the
    /// request forever, and at `concurrency: 1` that is the whole server. See
    /// [`EPOCH_TICK`].
    pub request_timeout: Duration,
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
            tls: None,
            acme: None,
            attestation: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
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
    /// Ceiling on producing a response head. See [`ServeHandle::watchdog`].
    timeout: Duration,
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
            timeout: DEFAULT_REQUEST_TIMEOUT,
        })
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
    /// Generic over the request body rather than taking
    /// `hyper::body::Incoming`, which cannot be constructed outside a real
    /// connection — the whole dispatch path would be untestable without a
    /// listening socket.
    /// `client` is required rather than defaulted, so every caller has to
    /// answer the question. `None` is a real answer — an unauthenticated
    /// connection — but it has to be given, not inherited by omission.
    pub async fn handle<B>(
        &self,
        scheme: Scheme,
        mut req: hyper::Request<B>,
        client: Option<&ClientIdentity>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        // Before anything else touches the request, and before it is handed to
        // `new_incoming_request`, which copies the header map into the guest
        // verbatim. This is the only ingress, so this is the only place the
        // header can be made trustworthy.
        //
        // Note it cannot be done in `EgressPolicy::is_forbidden_header`: that
        // hook runs *inside* `new_incoming_request`, after injection, so it
        // could only delete the header — silently, with no error anywhere.
        ClientIdentity::apply_to(client, &mut req);

        let permit = self
            .limit
            .clone()
            .acquire_owned()
            .await
            .context("request limiter closed")?;

        self.in_fresh_instance(permit, scheme, req).await
    }

    /// The only dispatch path. A fresh store, a fresh instance, both dropped
    /// when the request ends — so nothing survives but what was committed.
    async fn in_fresh_instance<B>(
        &self,
        permit: tokio::sync::OwnedSemaphorePermit,
        scheme: Scheme,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        let mut store = Store::new(self.pre.engine(), self.guest.new_state()?);
        store.set_epoch_deadline(self.watchdog());
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

        self.await_head(task, receiver, permit).await
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

    /// Wait for the guest to produce a response head, or give up on it.
    ///
    /// `permit` is held for the duration and released on return — which is when
    /// the head is ready, not when the body has finished. That is deliberate:
    /// the body streams from the task afterwards, and holding the permit until
    /// it drained would make a slow reader block the next request.
    async fn await_head(
        &self,
        task: tokio::task::JoinHandle<wasmtime::Result<()>>,
        receiver: tokio::sync::oneshot::Receiver<
            std::result::Result<
                hyper::Response<HyperOutgoingBody>,
                wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
            >,
        >,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<hyper::Response<HyperOutgoingBody>> {
        let _permit = permit;

        let waited = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(waited) => waited,
            Err(_) => {
                // Nothing arrived in time. The epoch should already have
                // trapped a spinning guest — see `watchdog` — so reaching here
                // means the guest is parked somewhere the epoch cannot see,
                // which is exactly where `abort` does work.
                task.abort();
                anyhow::bail!(
                    "guest did not produce a response within {:?}; abandoned",
                    self.timeout
                );
            }
        };

        match waited {
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

/// The identity a completed handshake proved, if the client presented one.
///
/// Client authentication is optional, so `None` is an ordinary outcome — a
/// browser, `curl`, or a health check. It is not an error; it is a connection
/// that gets whatever an unauthenticated caller is allowed.
fn peer_identity(conn: &rustls::ServerConnection) -> Option<ClientIdentity> {
    let leaf = conn.peer_certificates()?.first()?;
    ClientIdentity::from_certificate(leaf)
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
async fn serve_connection<S>(
    io: S,
    guest: Arc<ServeHandle>,
    endpoints: Option<Arc<EnclaveEndpoints>>,
    scheme: Scheme,
    client: Option<ClientIdentity>,
) -> std::result::Result<(), hyper::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let guest = guest.clone();
        let endpoints = endpoints.clone();
        let scheme = scheme.clone();
        // Cloned per request because the closure is `Fn` — it runs again for
        // every request on a kept-alive connection.
        let client = client.clone();
        async move {
            // The runtime's own paths are checked first and are not
            // forwardable: a guest able to answer under `/enclave/` could serve
            // any attestation it liked.
            if let Some(endpoints) = &endpoints {
                let path = req.uri().path().to_string();
                let query = req.uri().query().map(str::to_string);
                if let Some(response) = endpoints.handle(&path, query.as_deref()).await {
                    return Ok::<_, anyhow::Error>(response);
                }
            }
            guest.handle(scheme, req, client.as_ref()).await
        }
    });

    http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(io), service)
        .await
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
    tls: Option<Tls>,
    addr: SocketAddr,
}

/// How TLS is terminated.
enum Tls {
    /// A certificate fixed at startup.
    Fixed(Arc<rustls::ServerConfig>),
    /// Two configurations, chosen per connection from the ClientHello: a
    /// TLS-ALPN-01 validation connection is answered on this same port, which
    /// is the reason that challenge type was chosen.
    Acme {
        config: Arc<rustls::ServerConfig>,
        challenge: Arc<rustls::ServerConfig>,
    },
}

impl Server {
    pub fn new(guest: ServeHandle, addr: SocketAddr) -> Self {
        Server {
            guest: Arc::new(guest),
            endpoints: None,
            tls: None,
            addr,
        }
    }

    pub fn with_endpoints(mut self, endpoints: Arc<EnclaveEndpoints>) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    pub fn with_tls(mut self, config: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(Tls::Fixed(config));
        self
    }

    pub fn with_acme(mut self, acme: &crate::serve::acme::Acme) -> Self {
        self.tls = Some(Tls::Acme {
            config: acme.server_config.clone(),
            challenge: acme.challenge_config.clone(),
        });
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
            let guest = self.guest.clone();
            let endpoints = self.endpoints.clone();
            let tls = tls.clone();
            // `Scheme` is not `Copy`, and the service closure is `Fn` — it may
            // run per request on a kept-alive connection, so it needs its own.
            let scheme = scheme.clone();

            tokio::task::spawn(async move {
                // The service closure is built *inside* each arm below, after
                // the handshake, because that is the only point at which the
                // peer's certificate exists. Built out here — as it was — the
                // connection's identity could never reach a request.
                let result = match tls.as_deref() {
                    Some(Tls::Fixed(config)) => {
                        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
                        match acceptor.accept(client).await {
                            Ok(stream) => {
                                let client = peer_identity(stream.get_ref().1);
                                serve_connection(stream, guest, endpoints, scheme, client).await
                            }
                            Err(e) => {
                                // Routine: scanners, health checks and clients
                                // that reject a self-signed certificate all
                                // land here. Not worth a warning each time.
                                tracing::debug!(%peer, error = %e, "TLS handshake failed");
                                return;
                            }
                        }
                    }
                    Some(Tls::Acme { config, challenge }) => {
                        // The ClientHello decides which configuration to use,
                        // so the challenge and the real service share a port.
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

                        if rustls_acme::is_tls_alpn_challenge(&handshake.client_hello()) {
                            // A validation connection carries no HTTP. The
                            // handshake itself is the proof; completing it and
                            // closing is the whole exchange.
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

                        match handshake.into_stream(config.clone()).await {
                            Ok(stream) => {
                                let client = peer_identity(stream.get_ref().1);
                                serve_connection(stream, guest, endpoints, scheme, client).await
                            }
                            Err(e) => {
                                // Every handshake lands here until the first
                                // certificate arrives, which is the expected
                                // state while an order is in flight.
                                tracing::debug!(%peer, error = %e, "TLS handshake failed");
                                return;
                            }
                        }
                    }
                    // No TLS, so no certificate and no identity. Whatever the
                    // client says about itself is discarded, same as any other
                    // unauthenticated connection.
                    None => serve_connection(client, guest, endpoints, scheme, None).await,
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
    config: ServeConfig,
) -> Result<()> {
    // wasmtime 44 enables async at the engine level when the `async` feature
    // is on; `Config::async_support` is a no-op. Same as `run_component`.
    let engine = ServeHandle::engine_with_watchdog()?;
    let handle = ServeHandle::new(&engine, component_bytes, guest, config.concurrency)?
        .with_timeout(config.request_timeout);

    // Before the listener binds. A guest that will not instantiate should stop
    // the enclave, not the first client unlucky enough to arrive.
    handle.verify_instantiates().await?;

    let mut server = Server::new(handle, config.addr);

    // The slot the attestation endpoint reads. Fixed for a self-signed
    // certificate; updated by the ACME client on issue and on every renewal,
    // so a document always binds the certificate actually being presented.
    let certificate = match (&config.tls, &config.acme) {
        (Some(tls), _) => Some(CertificateSlot::fixed(tls.certificate_der.clone())),
        (None, Some(acme)) => Some(acme.certificate.clone()),
        (None, None) => None,
    };

    match (&certificate, &config.attestation) {
        (Some(slot), attestation) => {
            if let Some(nsm) = attestation {
                // Fails here if the device will not attest — before a single
                // request is served.
                let endpoints = EnclaveEndpoints::new(nsm.clone(), slot.clone(), component_bytes)?;
                server = server.with_endpoints(Arc::new(endpoints));
            }
            server = match (&config.tls, &config.acme) {
                (Some(tls), _) => server.with_tls(tls.config.clone()),
                (None, Some(acme)) => server.with_acme(acme),
                (None, None) => unreachable!("a certificate slot exists only with TLS or ACME"),
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
