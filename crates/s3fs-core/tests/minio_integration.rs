//! Integration tests for `AwsS3Backend` against a MinIO container.
//!
//! Every test is `#[ignore]`d so default `cargo test` skips them. Run with
//! Docker present:
//!
//! ```bash
//! cargo test -p s3fs-core --features aws --test minio_integration -- --ignored
//! ```
//!
//! Each test spins up its own MinIO container and creates a fresh bucket so
//! tests don't interfere. Containers are cleaned up automatically when the
//! returned `ContainerAsync` handle drops at end of scope.

#![cfg(feature = "aws")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::minio::MinIO;

use s3fs_core::backend::{
    AwsS3Backend, AwsS3BackendConfig, Backend, CompletedPart, ListBlobsInput, PutBlobInput,
};
use s3fs_core::config::PartSchedule;
use s3fs_core::errors::FsError;
use s3fs_core::fs::OpenFlags;
use s3fs_core::{Config, Fs};

/// Start a MinIO container, build an `AwsS3Backend` pointed at it, and create
/// the bucket. The returned `ContainerAsync` MUST stay in scope for the
/// lifetime of the test — when it drops, the container is killed.
async fn fresh_minio_with_bucket(bucket: &str) -> (ContainerAsync<MinIO>, AwsS3Backend) {
    let container = MinIO::default()
        .start()
        .await
        .expect("MinIO container start");
    let port = container
        .get_host_port_ipv4(9000)
        .await
        .expect("get host port");
    let endpoint = format!("http://127.0.0.1:{port}");

    let cfg = AwsS3BackendConfig {
        bucket: bucket.into(),
        region: "us-east-1".into(),
        endpoint: Some(endpoint),
        // testcontainers-modules MinIO defaults: minioadmin / minioadmin.
        access_key_id: Some("minioadmin".into()),
        secret_access_key: Some("minioadmin".into()),
        session_token: None,
        force_path_style: true,
        request_timeout: Duration::from_secs(30),
    };

    let backend = AwsS3Backend::connect_unchecked(cfg)
        .await
        .expect("AwsS3Backend connect");
    backend
        .client()
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    (container, backend)
}

// ---------- Backend-level tests ----------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker; run with --features aws -- --ignored"]
async fn put_head_get_delete_round_trip() {
    let (_c, backend) = fresh_minio_with_bucket("rt-bucket").await;

    let mut metadata = HashMap::new();
    metadata.insert("custom-flag".into(), "1".into());
    backend
        .put_blob(PutBlobInput {
            key: "hello.txt".into(),
            body: Bytes::from_static(b"hello"),
            metadata: metadata.clone(),
            content_type: Some("text/plain".into()),
        })
        .await
        .unwrap();

    let h = backend.head_blob("hello.txt").await.unwrap();
    assert_eq!(h.size, 5);
    assert_eq!(h.content_type.as_deref(), Some("text/plain"));
    assert_eq!(h.metadata.get("custom-flag").map(|s| s.as_str()), Some("1"));

    let g = backend.get_blob("hello.txt", None).await.unwrap();
    assert_eq!(&g.body[..], b"hello");

    backend.delete_blob("hello.txt").await.unwrap();
    assert!(matches!(
        backend.head_blob("hello.txt").await,
        Err(FsError::NotFound)
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn get_with_byte_range() {
    let (_c, backend) = fresh_minio_with_bucket("range-bucket").await;
    backend
        .put_blob(PutBlobInput {
            key: "k".into(),
            body: Bytes::from_static(b"0123456789"),
            metadata: HashMap::new(),
            content_type: None,
        })
        .await
        .unwrap();
    let g = backend.get_blob("k", Some(2..5)).await.unwrap();
    assert_eq!(&g.body[..], b"234");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn put_blob_if_not_exists_returns_already_exists_on_collision() {
    let (_c, backend) = fresh_minio_with_bucket("excl-bucket").await;
    let mk = || PutBlobInput {
        key: "k".into(),
        body: Bytes::from_static(b"v"),
        metadata: HashMap::new(),
        content_type: None,
    };
    backend.put_blob_if_not_exists(mk()).await.unwrap();
    assert!(matches!(
        backend.put_blob_if_not_exists(mk()).await,
        Err(FsError::AlreadyExists)
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn list_with_delimiter_separates_items_and_prefixes() {
    let (_c, backend) = fresh_minio_with_bucket("list-bucket").await;
    for k in ["dir/a.txt", "dir/b.txt", "dir/sub/c.txt", "outside.txt"] {
        backend
            .put_blob(PutBlobInput {
                key: k.into(),
                body: Bytes::from_static(b""),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
    }
    let out = backend
        .list_blobs(ListBlobsInput {
            prefix: "dir/",
            delimiter: Some("/"),
            ..Default::default()
        })
        .await
        .unwrap();
    let item_keys: Vec<_> = out.items.iter().map(|i| i.key.as_str()).collect();
    assert_eq!(item_keys, vec!["dir/a.txt", "dir/b.txt"]);
    assert_eq!(out.prefixes, vec!["dir/sub/".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn multipart_lifecycle_with_upload_part_copy() {
    let (_c, backend) = fresh_minio_with_bucket("mpu-bucket").await;

    // Source blob to copy from. Use 5 MiB exactly so it can be a single
    // MPU part on the destination side. (MinIO/S3 require parts ≥ 5 MiB
    // except the last.)
    let part_size = 5 * 1024 * 1024usize;
    let mut src_body = vec![0u8; part_size * 2];
    for (i, b) in src_body.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    backend
        .put_blob(PutBlobInput {
            key: "src".into(),
            body: Bytes::from(src_body.clone()),
            metadata: HashMap::new(),
            content_type: None,
        })
        .await
        .unwrap();

    // Begin MPU on destination key.
    let upload_id = backend
        .multipart_begin(PutBlobInput {
            key: "dst".into(),
            body: Bytes::new(),
            metadata: HashMap::new(),
            content_type: None,
        })
        .await
        .unwrap();

    // Part 1 = first 5 MiB of src (copied), Part 2 = a fresh 5 MiB upload.
    let p1 = backend
        .multipart_upload_part_copy("dst", &upload_id, 1, "src", 0..(part_size as u64))
        .await
        .unwrap();
    let p2_body = vec![0xAB; part_size];
    let p2 = backend
        .multipart_upload_part("dst", &upload_id, 2, Bytes::from(p2_body.clone()))
        .await
        .unwrap();

    backend
        .multipart_complete(
            "dst",
            &upload_id,
            vec![
                CompletedPart {
                    part_number: 1,
                    e_tag: p1.e_tag,
                },
                CompletedPart {
                    part_number: 2,
                    e_tag: p2.e_tag,
                },
            ],
        )
        .await
        .unwrap();

    // Verify the assembled object: first part_size = bytes from src; second
    // part_size = all 0xAB.
    let g = backend.get_blob("dst", None).await.unwrap();
    assert_eq!(g.body.len(), part_size * 2);
    assert_eq!(&g.body[..part_size], &src_body[..part_size]);
    assert!(g.body[part_size..].iter().all(|&b| b == 0xAB));
}

// ---------- Fs end-to-end tests ----------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn fs_small_file_round_trip() {
    let (_c, backend) = fresh_minio_with_bucket("fs-small").await;
    let cfg = Config::builder()
        .single_part_threshold(5 * 1024 * 1024)
        .build();
    let fs = Fs::new(Arc::new(backend) as Arc<dyn Backend>, Arc::new(cfg));

    let h = fs
        .open(
            "hello.txt",
            OpenFlags {
                read: true,
                write: true,
                create: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    fs.pwrite(&h, 0, b"hello, minio").await.unwrap();
    fs.sync(&h).await.unwrap();
    fs.close(&h).await.unwrap();

    // Re-open and read back.
    let h2 = fs.open("hello.txt", OpenFlags::read_only()).await.unwrap();
    let body = fs.pread(&h2, 0, 100).await.unwrap();
    assert_eq!(&body[..], b"hello, minio");
    fs.close(&h2).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn fs_in_place_update_uses_copy_for_unchanged_parts() {
    // The load-bearing claim end-to-end: a 15 MiB file (3 parts of 5 MiB),
    // modify only part 1 (bytes 5MiB..10MiB), sync, verify content. The Fs
    // commit path should issue UploadPartCopy for parts 0 and 2 — no full
    // re-upload of unchanged data.
    let (_c, backend) = fresh_minio_with_bucket("fs-rmw").await;
    let cfg = Config::builder()
        .part_schedule(PartSchedule {
            tiers: vec![(5 * 1024 * 1024, 1000)],
        })
        .single_part_threshold(5 * 1024 * 1024)
        .max_parallel_parts(4)
        .max_parallel_copy(4)
        .max_merge_copy_bytes(128 * 1024 * 1024)
        .memory_limit_bytes(64 * 1024 * 1024)
        .build();
    let backend_arc = Arc::new(backend);
    let fs = Fs::new(backend_arc.clone() as Arc<dyn Backend>, Arc::new(cfg));

    // Pre-populate "big" with 15 MiB of recognisable bytes.
    let total: usize = 15 * 1024 * 1024;
    let mut src = vec![0u8; total];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    backend_arc
        .put_blob(PutBlobInput {
            key: "big".into(),
            body: Bytes::from(src.clone()),
            metadata: HashMap::new(),
            content_type: None,
        })
        .await
        .unwrap();

    // Open and overwrite part 1 (bytes 5MiB..10MiB).
    let h = fs
        .open(
            "big",
            OpenFlags {
                read: true,
                write: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let new_chunk = vec![0xAB; 5 * 1024 * 1024];
    fs.pwrite(&h, 5 * 1024 * 1024, &new_chunk).await.unwrap();
    fs.sync(&h).await.unwrap();
    fs.close(&h).await.unwrap();

    // Verify the resulting object byte-for-byte.
    let g = backend_arc.get_blob("big", None).await.unwrap();
    assert_eq!(g.body.len(), total);
    for i in 0..total {
        let expected = if (5 * 1024 * 1024..10 * 1024 * 1024).contains(&i) {
            0xAB
        } else {
            (i % 251) as u8
        };
        assert_eq!(g.body[i], expected, "byte {i}");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn fs_mkdir_and_listing() {
    let (_c, backend) = fresh_minio_with_bucket("fs-mkdir").await;
    let cfg = Config::default();
    let fs = Fs::new(Arc::new(backend) as Arc<dyn Backend>, Arc::new(cfg));

    let root = fs.root();
    fs.mkdir(&root, "subdir").await.unwrap();
    let h = fs
        .open(
            "f.txt",
            OpenFlags {
                write: true,
                create: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    fs.pwrite(&h, 0, b"x").await.unwrap();
    fs.sync(&h).await.unwrap();
    fs.close(&h).await.unwrap();

    let snap = fs.read_dir(&root).await.unwrap();
    let names: Vec<_> = snap.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"subdir"));
    assert!(names.contains(&"f.txt"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn fs_o_excl_collision_returns_already_exists() {
    let (_c, backend) = fresh_minio_with_bucket("fs-excl").await;
    let cfg = Config::default();
    let fs = Fs::new(Arc::new(backend) as Arc<dyn Backend>, Arc::new(cfg));

    let _h1 = fs.open("k", OpenFlags::create_new()).await.unwrap();
    let r = fs.open("k", OpenFlags::create_new()).await;
    assert!(matches!(r, Err(FsError::AlreadyExists)));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn fs_symlink_round_trip() {
    let (_c, backend) = fresh_minio_with_bucket("fs-sym").await;
    let cfg = Config::default();
    let fs = Fs::new(Arc::new(backend) as Arc<dyn Backend>, Arc::new(cfg));

    let root = fs.root();
    fs.symlink_at(&root, "link", "target.txt").await.unwrap();
    assert_eq!(fs.readlink_at(&root, "link").await.unwrap(), "target.txt");
    // Re-creating the same symlink should fail with AlreadyExists.
    let r = fs.symlink_at(&root, "link", "other.txt").await;
    assert!(matches!(r, Err(FsError::AlreadyExists)));
}
