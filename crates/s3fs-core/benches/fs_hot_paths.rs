//! Benchmarks for the Fs hot paths against `MemoryBackend`. The numbers
//! are useful for relative comparison (regressions, the impact of design
//! changes); they're not representative of real S3 latency since
//! MemoryBackend is in-process.
//!
//! Run with `cargo bench -p s3fs-core`. Add `--bench fs_hot_paths` to
//! filter. To compare two revisions, use `criterion`'s baselines:
//! `cargo bench -p s3fs-core -- --save-baseline before`,
//! then `cargo bench -p s3fs-core -- --baseline before`.

use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use s3fs_core::backend::memory::MemoryBackend;
use s3fs_core::backend::{Backend, PutBlobInput};
use s3fs_core::config::PartSchedule;
use s3fs_core::{Config, Fs, OpenFlags};

fn build_fs(part_size: u64) -> (Arc<MemoryBackend>, Arc<Fs>) {
    let backend = Arc::new(MemoryBackend::new());
    let cfg = Config::builder()
        .part_schedule(PartSchedule {
            tiers: vec![(part_size, 1000)],
        })
        .single_part_threshold(part_size)
        .max_parallel_parts(8)
        .max_parallel_copy(8)
        .max_merge_copy_bytes(128 * 1024 * 1024)
        .memory_limit_bytes(64 * 1024 * 1024)
        .build();
    let fs = Fs::new(backend.clone() as Arc<dyn Backend>, Arc::new(cfg));
    (backend, fs)
}

/// Open a file, write `payload`, sync, close. End-to-end small-file path.
fn bench_small_file_write_sync(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("small_file_write_sync");
    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let payload = vec![0xAB_u8; size];
            b.to_async(&rt).iter(|| {
                let payload = payload.clone();
                async move {
                    let (_backend, fs) = build_fs(5 * 1024 * 1024);
                    let h = fs
                        .open(
                            "k",
                            OpenFlags {
                                read: true,
                                write: true,
                                create: true,
                                ..Default::default()
                            },
                        )
                        .await
                        .unwrap();
                    fs.pwrite(&h, 0, &payload).await.unwrap();
                    fs.sync(&h).await.unwrap();
                    fs.close(&h).await.unwrap();
                    black_box(())
                }
            });
        });
    }
    group.finish();
}

/// Pre-populate a 30 MiB file and `pread` random offsets via the buffer
/// pool. Measures cache-miss + cache-hit read paths.
fn bench_pread_buffered(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("pread_buffered");
    for read_size in [4 * 1024usize, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(read_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(read_size),
            &read_size,
            |b, &read_size| {
                let setup = || {
                    let part_size = 5 * 1024 * 1024u64;
                    let (backend, fs) = build_fs(part_size);
                    let body = Bytes::from(vec![0u8; 30 * 1024 * 1024]);
                    let backend = backend.clone();
                    let fs = fs.clone();
                    rt.block_on(async move {
                        backend
                            .put_blob(PutBlobInput {
                                key: "big".into(),
                                body,
                                metadata: Default::default(),
                                content_type: None,
                            })
                            .await
                            .unwrap();
                        let h = fs.open("big", OpenFlags::read_only()).await.unwrap();
                        (fs, h)
                    })
                };
                let (fs, h) = setup();
                b.to_async(&rt).iter(|| {
                    let fs = fs.clone();
                    let h = h.clone();
                    async move {
                        // Read at a moving offset to vary pool hits/misses.
                        let off = (fastrand::u64(..) % (29 * 1024 * 1024)) as u64;
                        let r = fs.pread(&h, off, read_size).await.unwrap();
                        black_box(r);
                    }
                });
            },
        );
    }
    group.finish();
}

/// In-place edit of a multi-part file: 30 MiB existing object, modify
/// `dirty_kb` at part 1, sync. Exercises the GeeseFS-parity MPU +
/// UploadPartCopy materialisation path and the parallel-upload flusher.
fn bench_inplace_subpart_edit(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("inplace_subpart_edit");
    for dirty_kb in [4_usize, 64, 1024] {
        group.throughput(Throughput::Bytes((dirty_kb * 1024) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(dirty_kb),
            &dirty_kb,
            |b, &dirty_kb| {
                b.to_async(&rt).iter(|| {
                    let dirty = vec![0xAB_u8; dirty_kb * 1024];
                    async move {
                        let part_size = 5 * 1024 * 1024u64;
                        let (backend, fs) = build_fs(part_size);
                        let body = Bytes::from(vec![0u8; 30 * 1024 * 1024]);
                        backend
                            .put_blob(PutBlobInput {
                                key: "k".into(),
                                body,
                                metadata: Default::default(),
                                content_type: None,
                            })
                            .await
                            .unwrap();
                        let h = fs
                            .open(
                                "k",
                                OpenFlags {
                                    read: true,
                                    write: true,
                                    ..Default::default()
                                },
                            )
                            .await
                            .unwrap();
                        fs.pwrite(&h, part_size, &dirty).await.unwrap();
                        fs.sync(&h).await.unwrap();
                        fs.close(&h).await.unwrap();
                        black_box(())
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_small_file_write_sync,
    bench_pread_buffered,
    bench_inplace_subpart_edit,
);
criterion_main!(benches);
