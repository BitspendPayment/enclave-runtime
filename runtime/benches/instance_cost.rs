//! What a fresh guest instance actually costs, and what a request costs around
//! it.
//!
//! Every request gets a fresh instance, and this benchmark keeps that choice
//! honest with a number: **what fraction of a request is instantiation?**
//! Keeping instances between requests would save exactly that, at the price of
//! state that outlives the call that made it. It is only worth reconsidering
//! if the fraction grows large.
//!
//! So the interesting output is not any single line, it is the ratio:
//!
//! ```text
//!   instantiate  ÷  dispatch/committing   →  what keeping instances could remove
//! ```
//!
//! Over a directory standing in for the pool there is no anchor, so
//! `dispatch/committing` measures the guest and its file I/O. In production an
//! anchor — a pool sync and a write to S3 — is added to the denominator and
//! never to the numerator, so **the ratio measured here is the most favourable
//! case keeping instances will ever see.** If it is small here, it is smaller
//! in production.
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
        .join("../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
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

/// A handle over a scratch pool, compiled once.
///
/// Compilation and `instantiate_pre` are startup costs the runtime pays once
/// for the life of the process, so they belong in setup — measuring them here
/// would drown the per-request number this benchmark exists to find.
async fn handle() -> ServeHandle {
    let fs = enclave_runtime::Zfs::scratch().await;

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

fn bench(c: &mut Criterion) {
    let rt = runtime();
    let handle = rt.block_on(handle());

    let mut group = c.benchmark_group("guest");

    // The numerator. What every request pays: a fresh `Store` and an
    // `instantiate_async`, with no request dispatched through it.
    group.bench_function("instantiate", |b| {
        b.to_async(&rt)
            .iter(|| async { handle.verify_instantiates().await.expect("instantiates") });
    });

    // A whole request that touches nothing. Instantiation plus dispatch plus
    // the guest's own trivial work — the floor for any request at all.
    group.bench_function("dispatch/trivial", |b| {
        b.to_async(&rt).iter(|| get(&handle, "/memory"));
    });

    // A whole request that reads, modifies and writes a file. This is the
    // denominator that matters, because it is the shape of real work, and with
    // a real pool's anchor it grows while `instantiate` does not.
    group.bench_function("dispatch/committing", |b| {
        b.to_async(&rt).iter(|| get(&handle, "/counter"));
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
