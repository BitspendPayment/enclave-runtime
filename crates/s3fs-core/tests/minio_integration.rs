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
use s3fs_core::backend::{ObjectLock, ObjectLockMode};
use s3fs_core::errors::FsError;
use s3fs_core::fs::OpenFlags;
use s3fs_core::{Config, Fs, MasterSecret};

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

/// A second backend against the same container, for the roots bucket.
async fn extra_bucket(backend: &AwsS3Backend, bucket: &str, object_lock: bool) -> AwsS3Backend {
    let mut req = backend.client().create_bucket().bucket(bucket);
    if object_lock {
        req = req.object_lock_enabled_for_bucket(true);
    }
    req.send().await.expect("create bucket");

    let mut cfg = backend.config().clone();
    cfg.bucket = bucket.to_string();
    AwsS3Backend::connect_unchecked(cfg)
        .await
        .expect("connect to second bucket")
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
            object_lock: None,
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
            object_lock: None,
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
        object_lock: None,
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
                object_lock: None,
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
            object_lock: None,
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
            object_lock: None,
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

// ---------- Object Lock ----------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker; run with --features aws -- --ignored"]
async fn object_lock_makes_a_root_record_undeletable() {
    let (_c, data) = fresh_minio_with_bucket("data-lock").await;
    let roots = extra_bucket(&data, "roots-lock", true).await;

    // A minute, not a decade: the container is thrown away, but a real
    // COMPLIANCE retention would make the bucket itself undeletable for the
    // full term, which is not something a test should create.
    let lock = ObjectLock {
        mode: ObjectLockMode::Compliance,
        retain_until: std::time::SystemTime::now() + Duration::from_secs(60),
    };
    let input = PutBlobInput::new("roots/0000000000000000", Bytes::from_static(b"anchor"))
        .with_object_lock(lock);
    roots.put_blob_if_not_exists(input).await.unwrap();

    // The rollback guarantee, checked against a real S3 implementation rather
    // than the in-memory fake: neither delete nor overwrite is permitted.
    let err = roots.delete_blob("roots/0000000000000000").await;
    assert!(err.is_err(), "a retained root must not be deletable");

    assert_eq!(
        roots
            .get_blob("roots/0000000000000000", None)
            .await
            .unwrap()
            .body,
        Bytes::from_static(b"anchor")
    );
}

// ---------- Engine-level tests ----------

const TEST_MASTER: [u8; 32] = [0x42; 32];
const TEST_FS_ID: [u8; 16] = [0x11; 16];

fn engine_config() -> Config {
    Config::builder()
        .record_size(64 * 1024)
        // Retention is exercised separately; leaving it off keeps these tests
        // able to tear their buckets down.
        .root_retention(None)
        .build()
}

/// Create on first use, mount thereafter — several tests here remount a bucket
/// to prove the state survived, and `Fs::mount` no longer formats an empty
/// store, so wanting a filesystem has to be said out loud.
async fn mount(data: &AwsS3Backend, roots: &AwsS3Backend) -> Arc<Fs> {
    let data = Arc::new(data.clone()) as Arc<dyn Backend>;
    let roots = Arc::new(roots.clone()) as Arc<dyn Backend>;
    match Fs::mount(
        data.clone(),
        roots.clone(),
        &MasterSecret::from_bytes(TEST_MASTER),
        TEST_FS_ID,
        Arc::new(engine_config()),
        None,
    )
    .await
    {
        Err(s3fs_core::FsError::NoFilesystem) => Fs::create(
            data,
            roots,
            &MasterSecret::from_bytes(TEST_MASTER),
            TEST_FS_ID,
            Arc::new(engine_config()),
        )
        .await
        .expect("create"),
        other => other.expect("mount"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker; run with --features aws -- --ignored"]
async fn end_to_end_write_read_and_remount() {
    let (_c, data) = fresh_minio_with_bucket("data-e2e").await;
    let roots = extra_bucket(&data, "roots-e2e", false).await;

    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    {
        let fs = mount(&data, &roots).await;
        let root = fs.root();
        fs.mkdir(&root, "dir").await.unwrap();
        let h = fs.open("/dir/file", OpenFlags::create_new()).await.unwrap();
        fs.pwrite(&h, 0, &payload).await.unwrap();
        fs.close(&h).await.unwrap();
    }

    // A separate mount, reading only what the anchored root records commit.
    let fs = mount(&data, &roots).await;
    let h = fs.open("/dir/file", OpenFlags::read_only()).await.unwrap();
    let got = fs.pread(&h, 0, payload.len()).await.unwrap();
    assert_eq!(got.len(), payload.len());
    assert_eq!(got.as_ref(), payload.as_slice());

    let names: Vec<_> = fs
        .read_dir(&fs.root())
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["dir"]);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker; run with --features aws -- --ignored"]
async fn a_commit_costs_a_handful_of_objects() {
    let (_c, data) = fresh_minio_with_bucket("data-cost").await;
    let roots = extra_bucket(&data, "roots-cost", false).await;
    let fs = mount(&data, &roots).await;

    let before = count_keys(&data, "slabs/").await;
    let h = fs.open("/big", OpenFlags::create_new()).await.unwrap();
    // 64 records at the configured record size, committed as one group.
    fs.pwrite(&h, 0, &vec![7u8; 64 * 64 * 1024]).await.unwrap();
    fs.close(&h).await.unwrap();
    let after = count_keys(&data, "slabs/").await;

    // The point of packing blocks into slabs: many dirty blocks, few PUTs.
    // Addressing blocks by content hash would have cost 64 objects here.
    assert!(
        after - before <= 4,
        "expected a handful of slab objects, got {}",
        after - before
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker; run with --features aws -- --ignored"]
async fn tampering_with_a_slab_is_detected() {
    let (_c, data) = fresh_minio_with_bucket("data-tamper").await;
    let roots = extra_bucket(&data, "roots-tamper", false).await;

    {
        let fs = mount(&data, &roots).await;
        let h = fs.open("/f", OpenFlags::create_new()).await.unwrap();
        fs.pwrite(&h, 0, &vec![0x5au8; 100_000]).await.unwrap();
        fs.close(&h).await.unwrap();
    }

    // Rewrite every slab with a flipped byte, as a bucket operator could.
    for key in list_keys(&data, "slabs/").await {
        let body = data.get_blob(&key, None).await.unwrap().body;
        let mut body = body.to_vec();
        body[0] ^= 0xff;
        data.put_blob(PutBlobInput::new(key, Bytes::from(body)))
            .await
            .unwrap();
    }

    let fs = mount(&data, &roots).await;
    let result = async {
        let h = fs.open("/f", OpenFlags::read_only()).await?;
        fs.pread(&h, 0, 100_000).await
    }
    .await;
    assert!(
        matches!(result, Err(FsError::Integrity(_))),
        "expected an integrity failure, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker; run with --features aws -- --ignored"]
async fn a_mount_floor_above_the_tip_is_refused() {
    let (_c, data) = fresh_minio_with_bucket("data-floor").await;
    let roots = extra_bucket(&data, "roots-floor", false).await;
    {
        let fs = mount(&data, &roots).await;
        fs.mkdir(&fs.root(), "a").await.unwrap();
    }

    let result = Fs::mount(
        Arc::new(data.clone()) as Arc<dyn Backend>,
        Arc::new(roots.clone()) as Arc<dyn Backend>,
        &MasterSecret::from_bytes(TEST_MASTER),
        TEST_FS_ID,
        Arc::new(engine_config()),
        Some(9999),
    )
    .await;
    assert!(matches!(result, Err(FsError::Rollback { .. })));
}

async fn list_keys(backend: &AwsS3Backend, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let page = backend
            .list_blobs(ListBlobsInput {
                prefix,
                continuation_token: token.as_deref(),
                ..Default::default()
            })
            .await
            .unwrap();
        out.extend(page.items.into_iter().map(|i| i.key));
        match page.next_continuation_token {
            Some(t) if page.is_truncated => token = Some(t),
            _ => break,
        }
    }
    out
}

async fn count_keys(backend: &AwsS3Backend, prefix: &str) -> usize {
    list_keys(backend, prefix).await.len()
}
