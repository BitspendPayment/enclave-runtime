//! What a fresh guest instance actually costs, and what a request costs around
//! it.
//!
//! This benchmark exists to answer one question with a number rather than an
//! intuition: **is per-client instance pooling worth its complexity?** Pooling
//! saves exactly one thing — the instantiation in the middle of every request —
//! and buys it at the price of per-client lifecycle, eviction, and a
//! concurrency model where two clients run at once. That trade is only worth
//! making if instantiation is a large fraction of a request.
//!
//! So the interesting output is not any single line, it is the ratio:
//!
//! ```text
//!   instantiate  ÷  dispatch/committing   →  what pooling could remove
//! ```
//!
//! Against [`MemoryBackend`] there is no network, so `dispatch/committing`
//! measures the engine's own cost — encryption, hashing, the copy-on-write
//! rebuild, the commit. Against real S3 the round trips are added to the
//! denominator and never to the numerator, so **the ratio measured here is the
//! most favourable case pooling will ever see.** If it is small here, it is
//! smaller in production.
//!
//! ```bash
//! (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! cargo bench -p enclave-runtime
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

use bytes::Bytes;
use enclave_runtime::{GuestEnvironment, HostClock, ServeHandle};
use http_body_util::{BodyExt, Full};
use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::backend::Backend;
use s3fs_core::{Config, Fs, MasterSecret};
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

fn component_bytes() -> Vec<u8> {
    std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-http && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    })
}

/// A handle over a memory-backed filesystem, compiled once.
///
/// Compilation and `instantiate_pre` are startup costs the runtime pays once
/// for the life of the process, so they belong in setup — measuring them here
/// would drown the per-request number this benchmark exists to find.
async fn handle() -> ServeHandle {
    let backend = Arc::new(MemoryBackend::new());
    let fs = Fs::create(
        backend.clone(),
        backend,
        &MasterSecret::from_bytes([7u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the memory-backed filesystem");

    // Detached deliberately: the collector runs for as long as this
    // environment can send, which is what a test wants. Production drains it
    // explicitly instead.
    let (logs, _collector) =
        enclave_runtime::guest_io::start(std::sync::Arc::new(enclave_runtime::TracingLogSink));
    let guest = GuestEnvironment::new(
        fs,
        Box::new(HostClock),
        Arc::new(nitro_nsm::fake::FakeNsm::new()),
        &[],
        &[],
        logs,
    )
    .expect("guest environment");

    let engine = ServeHandle::engine_with_watchdog().expect("engine");
    ServeHandle::new(&engine, &component_bytes(), guest).expect("preparing the guest")
}

fn body() -> HyperOutgoingBody {
    Full::new(Bytes::new())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

async fn get(handle: &ServeHandle, path: &str) {
    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://enclave.test{path}"))
        .body(body())
        .expect("well-formed request");
    let resp = handle
        .handle(Scheme::Http, req, None)
        .await
        .expect("guest handled the request");
    // Drained, not dropped: the head returns before the guest has finished, so
    // stopping at the head would time half a request.
    resp.into_body().collect().await.expect("collecting body");
}

/// A filesystem that already exists, so it can be mounted rather than created.
async fn existing() -> (Arc<dyn Backend>, Arc<dyn Backend>) {
    let data = Arc::new(MemoryBackend::new()) as Arc<dyn Backend>;
    let roots = Arc::new(MemoryBackend::new()) as Arc<dyn Backend>;
    Fs::create(
        data.clone(),
        roots.clone(),
        &MasterSecret::from_bytes([7u8; 32]),
        [0u8; 16],
        Arc::new(Config::default()),
    )
    .await
    .expect("creating the filesystem");
    (data, roots)
}

fn bench(c: &mut Criterion) {
    let rt = runtime();
    let handle = rt.block_on(handle());

    let mut group = c.benchmark_group("guest");

    // The numerator. Exactly what a warm pool would skip: a fresh `Store` and
    // an `instantiate_async`, with no request dispatched through it.
    group.bench_function("instantiate", |b| {
        b.to_async(&rt)
            .iter(|| async { handle.verify_instantiates().await.expect("instantiates") });
    });

    // A whole request that touches nothing. Instantiation plus dispatch plus
    // the guest's own trivial work — the floor for any request at all.
    group.bench_function("dispatch/trivial", |b| {
        b.to_async(&rt).iter(|| get(&handle, "/memory"));
    });

    // A whole request that reads, modifies, writes and commits — one
    // transaction group, one root record. This is the denominator that matters,
    // because it is the shape of real work, and against real S3 it grows while
    // `instantiate` does not.
    group.bench_function("dispatch/committing", |b| {
        b.to_async(&rt).iter(|| get(&handle, "/counter"));
    });

    // What a *per-client* filesystem would cost to bring up: derive its key
    // material, read its signed root record, verify the signature, open the
    // object set. Against `MemoryBackend` this is the CPU floor and nothing
    // else — in production the root record and the object set are reads against
    // S3, so the real figure is this plus round trips.
    //
    // Worth measuring beside `instantiate`, because if instances are per client
    // then so is this, and it is the larger of the two by orders of magnitude.
    // Whatever a per-client design keeps warm, this is the thing worth keeping.
    let rt2 = runtime();
    let (data, roots) = rt2.block_on(existing());
    group.bench_function("mount", |b| {
        b.to_async(&rt2).iter(|| {
            let data = data.clone();
            let roots = roots.clone();
            async move {
                Fs::mount(
                    data,
                    roots,
                    &MasterSecret::from_bytes([7u8; 32]),
                    [0u8; 16],
                    Arc::new(Config::default()),
                    None,
                )
                .await
                .expect("mounting")
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
