//! Integration tests for `AwsS3Backend` against a MinIO container.
//!
//! Every test is `#[ignore]`d so default `cargo test` skips them. Run with
//! Docker present, after building the image they run on:
//!
//! ```bash
//! scripts/minio-image.sh
//! cargo test -p enclave-runtime --test minio_integration -- --ignored
//! ```
//!
//! Each test spins up its own MinIO container and creates a fresh bucket so
//! tests don't interfere. Containers are cleaned up automatically when the
//! returned `ContainerAsync` handle drops at end of scope.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::minio::MinIO;

use enclave_runtime::store::backend::{
    AwsS3Backend, AwsS3BackendConfig, Backend, CompletedPart, ListBlobsInput, PutBlobInput,
};
use enclave_runtime::store::backend::{ObjectLock, ObjectLockMode};
use enclave_runtime::store::error::StoreError;

/// Start a MinIO container, build an `AwsS3Backend` pointed at it, and create
/// the bucket. The returned `ContainerAsync` MUST stay in scope for the
/// lifetime of the test — when it drops, the container is killed.
///
/// The module's own release, under the name `scripts/minio-image.sh` builds it
/// as: MinIO's published images can no longer be pulled.
async fn fresh_minio_with_bucket(bucket: &str) -> (ContainerAsync<MinIO>, AwsS3Backend) {
    let container = MinIO::default()
        .with_name("enclave-runtime/minio")
        .start()
        .await
        .expect("MinIO container start; is the image built? scripts/minio-image.sh");
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
        credentials_provider: None,
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
        Err(StoreError::NotFound)
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
        Err(StoreError::AlreadyExists)
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

/// What Object Lock COMPLIANCE actually buys, against a real S3 implementation.
///
/// It buys indestructibility, not invisibility. `DeleteObject` without a
/// version id **succeeds** and writes a delete marker; an ordinary `GetObject`
/// then answers `NoSuchKey`. The version underneath cannot be removed — that
/// fails with *"Object is WORM protected"* — and
/// [`Backend::get_retained_blob`] is how the engine reaches it.
///
/// This test used to assert the delete was refused. It was wrong, and it is
/// where the whole delete-marker problem was found.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker; run with --features aws -- --ignored"]
async fn a_retained_root_can_be_hidden_but_not_destroyed() {
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

    // S3 permits this. Asserting otherwise is how the fake came to be stronger
    // than the thing it stands for.
    roots
        .delete_blob("roots/0000000000000000")
        .await
        .expect("a delete marker is a legal write");

    // Hidden from the ordinary read the engine used to use...
    assert!(
        matches!(
            roots.get_blob("roots/0000000000000000", None).await,
            Err(StoreError::NotFound)
        ),
        "a delete marker must hide the current version"
    );

    // ...and still there, which is the guarantee that survives.
    assert_eq!(
        roots
            .get_retained_blob("roots/0000000000000000")
            .await
            .expect("the retained version is reachable past the marker")
            .body,
        Bytes::from_static(b"anchor")
    );

    // Why hiding is dangerous where absence carries meaning: the conditional
    // PUT that serves as "am I the first here?" is satisfied again.
    roots
        .put_blob_if_not_exists(PutBlobInput::new(
            "roots/0000000000000000",
            Bytes::from_static(b"forged"),
        ))
        .await
        .expect("If-None-Match is satisfied by a delete marker");

    // But the pinned version is untouched underneath, so reading the retained
    // version still gets the real one.
    assert_eq!(
        roots
            .get_retained_blob("roots/0000000000000000")
            .await
            .unwrap()
            .body,
        Bytes::from_static(b"anchor"),
        "the retained version must outrank anything written over the marker"
    );
}
