//! `Backend` trait — the storage primitive surface.
//!
//! This trait abstracts over S3, S3-compatible (MinIO, R2), and an in-memory
//! test fake. Methods correspond closely to S3 wire operations; the engine
//! layered on top translates POSIX semantics into sequences of these calls.
//!
//! ## Method coverage
//!
//! | Trait method               | S3 op                       |
//! |----------------------------|-----------------------------|
//! | `head_blob`                | `HeadObject`                |
//! | `get_blob`                 | `GetObject` (+ range)       |
//! | `put_blob`                 | `PutObject`                 |
//! | `put_blob_if_not_exists`   | `PutObject` + `If-None-Match: *` (atomic create; load-bearing for `O_EXCL` and `symlink-at`) |
//! | `delete_blob`              | `DeleteObject`              |
//! | `delete_blobs`             | `DeleteObjects` (batch)     |
//! | `list_blobs`               | `ListObjectsV2`             |
//! | `copy_blob`                | `CopyObject`                |
//! | `multipart_begin`          | `CreateMultipartUpload`     |
//! | `multipart_upload_part`    | `UploadPart`                |
//! | `multipart_upload_part_copy` | `UploadPartCopy` — server-side range copy. Load-bearing for in-place updates. |
//! | `multipart_complete`       | `CompleteMultipartUpload`   |
//! | `multipart_abort`          | `AbortMultipartUpload`      |
//! | `capabilities`             | (sync) feature flags        |

use std::collections::HashMap;
use std::ops::Range;
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;

use crate::errors::FsResult;

pub mod memory;

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "aws")]
pub use aws::{AwsS3Backend, AwsS3BackendConfig};

/// Per-backend feature flags.
///
/// `conditional_put` is the only one currently load-bearing for the engine
/// (we need it for `O_EXCL` and `symlink-at` atomicity). The others let the
/// engine pick faster code paths when available.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Backend supports `If-None-Match: *` on PUT for atomic create.
    pub conditional_put: bool,
    /// Backend supports server-side range copy via `UploadPartCopy`.
    /// (Required for GeeseFS-parity in-place updates.)
    pub upload_part_copy: bool,
    /// Backend supports batch `DeleteObjects`. If false, `delete_blobs`
    /// falls back to N parallel `delete_blob` calls.
    pub batch_delete: bool,
    /// Backend returns user metadata in `ListObjectsV2` results.
    /// Standard S3: `false`. Yandex S3: `true`. When false, symlink detection
    /// via metadata flag costs an extra HEAD on cache miss.
    pub metadata_in_listings: bool,
    /// Backend honours per-object Object Lock retention headers on PUT.
    /// Real S3 and MinIO do (on a bucket created with Object Lock enabled);
    /// the in-memory fake emulates it. When false, [`PutBlobInput::object_lock`]
    /// is rejected rather than silently ignored — an unenforced retention is
    /// worse than no retention, because it looks like a guarantee.
    pub object_lock: bool,
}

/// Object Lock retention mode.
///
/// The distinction matters: `Governance` can be bypassed by a principal
/// holding `s3:BypassGovernanceRetention`, so it protects against accident,
/// not against an adversary. Only `Compliance` is undeletable by every
/// principal including the account root, which is what makes it usable as a
/// rollback anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectLockMode {
    Governance,
    Compliance,
}

impl ObjectLockMode {
    /// Wire value for `x-amz-object-lock-mode`.
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectLockMode::Governance => "GOVERNANCE",
            ObjectLockMode::Compliance => "COMPLIANCE",
        }
    }
}

/// Per-object retention to apply at PUT time.
///
/// Bucket-level default retention achieves the same thing and is simpler to
/// operate; this exists so a caller can lock root records without relying on
/// bucket configuration it may not control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectLock {
    pub mode: ObjectLockMode,
    /// Absolute instant until which the object version cannot be deleted or
    /// overwritten.
    pub retain_until: SystemTime,
}

/// Result of a `HeadObject` (or the equivalent metadata view from a list /
/// get response).
#[derive(Debug, Clone)]
pub struct BlobMeta {
    pub key: String,
    pub e_tag: String,
    pub size: u64,
    pub last_modified: SystemTime,
    pub content_type: Option<String>,
    pub metadata: HashMap<String, String>,
    /// True if this blob represents an explicit directory marker (key ending
    /// in `/`). Useful for distinguishing implicit-from-prefix dirs from
    /// explicit-from-mkdir dirs.
    pub is_dir_marker: bool,
}

/// Single item in a `ListObjectsV2` result.
#[derive(Debug, Clone)]
pub struct BlobItem {
    pub key: String,
    pub e_tag: String,
    pub size: u64,
    pub last_modified: SystemTime,
}

/// Inputs to `list_blobs`.
#[derive(Debug, Clone, Default)]
pub struct ListBlobsInput<'a> {
    pub prefix: &'a str,
    pub delimiter: Option<&'a str>,
    pub max_keys: Option<u32>,
    pub start_after: Option<&'a str>,
    pub continuation_token: Option<&'a str>,
}

/// Output of `list_blobs`.
#[derive(Debug, Clone, Default)]
pub struct ListBlobsOutput {
    pub items: Vec<BlobItem>,
    /// `CommonPrefixes` — implicit-directory keys when `delimiter` is set.
    pub prefixes: Vec<String>,
    pub next_continuation_token: Option<String>,
    pub is_truncated: bool,
}

/// Output of `get_blob`. Body is delivered as a single contiguous buffer for
/// simplicity; for very large bodies callers should issue ranged reads via
/// `range` rather than fetching the whole object.
#[derive(Debug, Clone)]
pub struct GetBlobOutput {
    pub meta: BlobMeta,
    pub body: Bytes,
}

/// Inputs for atomic create (`put_blob_if_not_exists`) and regular `put_blob`.
#[derive(Debug, Clone)]
pub struct PutBlobInput {
    pub key: String,
    pub body: Bytes,
    pub metadata: HashMap<String, String>,
    pub content_type: Option<String>,
    /// Retention to stamp on this object version. `None` leaves it to the
    /// bucket's default retention configuration (if any).
    pub object_lock: Option<ObjectLock>,
}

impl PutBlobInput {
    /// Plain PUT with no metadata, content type, or retention.
    pub fn new(key: impl Into<String>, body: Bytes) -> Self {
        Self {
            key: key.into(),
            body,
            metadata: HashMap::new(),
            content_type: None,
            object_lock: None,
        }
    }

    /// Stamp per-object retention on this PUT.
    pub fn with_object_lock(mut self, lock: ObjectLock) -> Self {
        self.object_lock = Some(lock);
        self
    }
}

/// Inputs to `copy_blob`.
#[derive(Debug, Clone)]
pub struct CopyBlobInput {
    pub source_key: String,
    pub destination_key: String,
    /// `None` → copy source metadata (S3 default).
    /// `Some(_)` → replace metadata (S3 `MetadataDirective=REPLACE`).
    pub replace_metadata: Option<HashMap<String, String>>,
    pub replace_content_type: Option<String>,
}

/// Opaque multipart-upload identifier as returned by the backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MultipartId(pub String);

/// Result of an `UploadPart` or `UploadPartCopy`. Carries the ETag the backend
/// expects in `CompleteMultipartUpload`.
#[derive(Debug, Clone)]
pub struct PartUploadOutput {
    pub e_tag: String,
}

/// One entry in `CompleteMultipartUpload`.
#[derive(Debug, Clone)]
pub struct CompletedPart {
    pub part_number: u32,
    pub e_tag: String,
}

/// Storage backend abstraction. All methods are async and may be called from
/// many tasks concurrently; implementations must be `Send + Sync`.
#[async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug + 'static {
    fn capabilities(&self) -> Capabilities;

    async fn head_blob(&self, key: &str) -> FsResult<BlobMeta>;

    async fn get_blob(&self, key: &str, range: Option<Range<u64>>) -> FsResult<GetBlobOutput>;

    async fn put_blob(&self, input: PutBlobInput) -> FsResult<BlobMeta>;

    /// Atomic create. Returns [`crate::errors::FsError::AlreadyExists`] if the
    /// key already has an object. Backends without conditional-PUT support
    /// must return [`crate::errors::FsError::NotSupported`] from this method
    /// and report `capabilities().conditional_put == false`.
    async fn put_blob_if_not_exists(&self, input: PutBlobInput) -> FsResult<BlobMeta>;

    async fn delete_blob(&self, key: &str) -> FsResult<()>;

    /// Batch delete. Default impl falls back to per-key `delete_blob`.
    async fn delete_blobs(&self, keys: &[String]) -> FsResult<()> {
        for k in keys {
            self.delete_blob(k).await?;
        }
        Ok(())
    }

    async fn list_blobs(&self, input: ListBlobsInput<'_>) -> FsResult<ListBlobsOutput>;

    async fn copy_blob(&self, input: CopyBlobInput) -> FsResult<BlobMeta>;

    async fn multipart_begin(&self, input: PutBlobInput) -> FsResult<MultipartId>;

    async fn multipart_upload_part(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        body: Bytes,
    ) -> FsResult<PartUploadOutput>;

    /// Server-side range copy into a part of an in-flight MPU. The load-bearing
    /// primitive for in-place updates and append.
    async fn multipart_upload_part_copy(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        source_key: &str,
        source_range: Range<u64>,
    ) -> FsResult<PartUploadOutput>;

    async fn multipart_complete(
        &self,
        key: &str,
        upload_id: &MultipartId,
        parts: Vec<CompletedPart>,
    ) -> FsResult<BlobMeta>;

    async fn multipart_abort(&self, key: &str, upload_id: &MultipartId) -> FsResult<()>;
}
