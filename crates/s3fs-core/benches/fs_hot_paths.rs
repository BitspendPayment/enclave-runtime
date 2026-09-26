//! Hot-path benchmarks against the in-memory backend.
//!
//! Numbers here are relative only — there is no network, so what they measure
//! is the engine's own cost: encryption, hashing, the copy-on-write rebuild,
//! and the commit protocol. That is exactly the part worth watching, because
//! against real S3 the round trips dominate everything else.
//!
//! ```bash
//! cargo bench -p s3fs-core
//! ```

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use tokio::runtime::Runtime;

use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::backend::Backend;
use s3fs_core::{Config, Fs, MasterSecret, OpenFlags};

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

async fn fresh_fs(record_size: usize) -> Arc<Fs> {
    let config = Config::builder()
        .record_size(record_size)
        .root_retention(None)
        .build();
    Fs::create(
        Arc::new(MemoryBackend::new()) as Arc<dyn Backend>,
        Arc::new(MemoryBackend::new()) as Arc<dyn Backend>,
        &MasterSecret::from_bytes([1u8; 32]),
        [0u8; 16],
        Arc::new(config),
    )
    .await
    .expect("creating the filesystem")
}

/// Write and commit a whole file: the full path through encryption, the
/// indirect-tree rebuild, slab packing, and a signed root record.
fn write_and_commit(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("write_and_commit");

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let data = vec![0xabu8; size];
            b.to_async(&rt).iter_batched(
                || data.clone(),
                |data| async move {
                    let fs = fresh_fs(128 * 1024).await;
                    let h = fs.open("/bench", OpenFlags::create_new()).await.unwrap();
                    fs.pwrite(&h, 0, &data).await.unwrap();
                    fs.close(&h).await.unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Commit cost as a function of how many records the transaction group dirties.
///
/// The interesting shape: slab packing means the number of PUTs stays flat, so
/// this should scale with bytes rather than with block count.
fn commit_by_dirty_blocks(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("commit_by_dirty_blocks");
    let record = 4096usize;

    for blocks in [1usize, 16, 256] {
        group.throughput(Throughput::Elements(blocks as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(blocks),
            &blocks,
            |b, &blocks| {
                b.to_async(&rt).iter(|| async move {
                    let fs = fresh_fs(record).await;
                    let h = fs.open("/bench", OpenFlags::create_new()).await.unwrap();
                    // One byte per record, so every record is dirtied but the
                    // volume of data stays small.
                    for i in 0..blocks {
                        fs.pwrite(&h, (i * record) as u64, b"x").await.unwrap();
                    }
                    fs.close(&h).await.unwrap();
                });
            },
        );
    }
    group.finish();
}

/// Random reads over a committed file, warm cache. Measures verification cost:
/// a BLAKE3 pass plus an AEAD open per block, plus the indirect-tree walk.
fn random_reads(c: &mut Criterion) {
    let rt = runtime();
    let file_size = 8 * 1024 * 1024usize;

    let fs = rt.block_on(async {
        let fs = fresh_fs(128 * 1024).await;
        let h = fs.open("/bench", OpenFlags::create_new()).await.unwrap();
        fs.pwrite(&h, 0, &vec![0x5au8; file_size]).await.unwrap();
        fs.close(&h).await.unwrap();
        fs
    });

    let mut group = c.benchmark_group("random_read");
    for len in [4096usize, 64 * 1024] {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, &len| {
            let fs = fs.clone();
            b.to_async(&rt).iter(|| {
                let fs = fs.clone();
                async move {
                    let h = fs.open("/bench", OpenFlags::read_only()).await.unwrap();
                    let offset = fastrand::u64(0..(file_size - len) as u64);
                    fs.pread(&h, offset, len).await.unwrap();
                    fs.close(&h).await.unwrap();
                }
            });
        });
    }
    group.finish();
}

/// Directory lookup as the directory grows. The separator index means this
/// should stay roughly flat rather than degrading with entry count.
fn directory_lookup(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("directory_lookup");

    for entries in [10usize, 1_000, 10_000] {
        let fs = rt.block_on(async {
            let fs = fresh_fs(4096).await;
            let root = fs.root();
            for i in 0..entries {
                let h = fs
                    .open(&format!("/entry-{i:06}"), OpenFlags::create_new())
                    .await
                    .unwrap();
                fs.close(&h).await.unwrap();
            }
            let _ = root;
            fs
        });

        group.bench_with_input(
            BenchmarkId::from_parameter(entries),
            &entries,
            |b, &entries| {
                let fs = fs.clone();
                b.to_async(&rt).iter(|| {
                    let fs = fs.clone();
                    async move {
                        let name = format!("entry-{:06}", fastrand::usize(0..entries));
                        fs.lookup_at(&fs.root(), &name).await.unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    write_and_commit,
    commit_by_dirty_blocks,
    random_reads,
    directory_lookup
);
criterion_main!(benches);
