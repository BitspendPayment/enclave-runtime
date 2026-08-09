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
use crate::serve::acme::CertificateSlot;
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
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let guest = guest.clone();
                        let endpoints = endpoints.clone();
                        let scheme = scheme.clone();
                        async move {
                            // The runtime's own paths are checked first and are
                            // not forwardable: a guest able to answer under
                            // `/enclave/` could serve any attestation it liked.
                            if let Some(endpoints) = &endpoints {
                                let path = req.uri().path().to_string();
                                let query = req.uri().query().map(str::to_string);
                                if let Some(response) =
                                    endpoints.handle(&path, query.as_deref()).await
                                {
                                    return Ok::<_, anyhow::Error>(response);
                                }
                            }
                            guest.handle(scheme, req).await
                        }
                    },
                );

                let result = match tls.as_deref() {
                    Some(Tls::Fixed(config)) => {
                        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
                        match acceptor.accept(client).await {
                            Ok(stream) => {
                                http1::Builder::new()
                                    .keep_alive(true)
                                    .serve_connection(TokioIo::new(stream), service)
                                    .await
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
                                http1::Builder::new()
                                    .keep_alive(true)
                                    .serve_connection(TokioIo::new(stream), service)
                                    .await
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
                    None => {
                        http1::Builder::new()
                            .keep_alive(true)
                            .serve_connection(TokioIo::new(client), service)
                            .await
                    }
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
    let engine = Engine::new(&wasmtime::Config::new())?;
    let handle = ServeHandle::new(&engine, component_bytes, guest, config.concurrency)?;
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
