//! `AwsS3Backend` — `Backend` impl over `aws-sdk-s3`.
//!
//! Gated behind the `aws` feature. Pulls in the AWS SDK with the rustls
//! transport and Tokio runtime adapters.
//!
//! Construction is via [`AwsS3BackendConfig`]: bucket + region + optional
//! endpoint override (for MinIO, LocalStack, Yandex, R2, etc.) + optional
//! static credentials. We deliberately do NOT walk the AWS credential chain
//! here — the runner / host is responsible for sourcing creds (in the
//! enclave, that comes from a Nitro KMS attestation flow).

use std::collections::HashMap;
use std::ops::Range;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    CompletedMultipartUpload, CompletedPart as SdkCompletedPart, Delete, MetadataDirective,
    ObjectIdentifier, ObjectLockMode as SdkObjectLockMode,
};
use aws_sdk_s3::Client;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use bytes::Bytes;

use super::{
    Backend, BlobItem, BlobMeta, Capabilities, CompletedPart, CopyBlobInput, GetBlobOutput,
    ListBlobsInput, ListBlobsOutput, MultipartId, ObjectLock, ObjectLockMode, PartUploadOutput,
    PutBlobInput,
};
use crate::errors::{FsError, FsResult};

/// Apply Object Lock retention headers to a `PutObject` request.
///
/// Note the bucket must have been created with Object Lock enabled
/// (`ObjectLockEnabledForBucket`); S3 rejects these headers otherwise. That
/// failure surfaces as `InvalidRequest` from `send()` rather than being
/// swallowed here, which is the behaviour we want — a retention we asked for
/// and didn't get must be loud.
fn apply_object_lock(
    req: aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder,
    lock: &ObjectLock,
) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
    let mode = match lock.mode {
        ObjectLockMode::Governance => SdkObjectLockMode::Governance,
        ObjectLockMode::Compliance => SdkObjectLockMode::Compliance,
    };
    req.object_lock_mode(mode)
        .object_lock_retain_until_date(aws_smithy_types::DateTime::from(lock.retain_until))
}

/// Construction parameters for [`AwsS3Backend`].
#[derive(Debug, Clone)]
pub struct AwsS3BackendConfig {
    pub bucket: String,
    pub region: String,
    /// Endpoint override (e.g. `http://127.0.0.1:9000` for MinIO). Default
    /// is the standard AWS S3 regional endpoint when `None`.
    pub endpoint: Option<String>,
    /// Static credentials. If all three are `None`, the SDK uses the
    /// default credential chain (env vars, profile, IMDS, etc.). Inside an
    /// enclave you should always pass these explicitly.
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    /// MinIO and many other S3-compatible servers require path-style
    /// addressing rather than virtual-host style.
    pub force_path_style: bool,
    /// Per-request timeout. AWS SDK adds its own retries on top.
    pub request_timeout: Duration,
}

impl AwsS3BackendConfig {
    pub fn new(bucket: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            force_path_style: false,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// AWS S3 (and S3-compatible) backend.
#[derive(Debug, Clone)]
pub struct AwsS3Backend {
    bucket: String,
    client: Client,
    config: AwsS3BackendConfig,
}

impl AwsS3Backend {
    /// Build a client from the given config and run a sanity check
    /// (`HeadBucket`) before returning. Use `connect_unchecked` to skip the
    /// startup check.
    pub async fn connect(config: AwsS3BackendConfig) -> FsResult<Self> {
        let backend = Self::connect_unchecked(config).await?;
        // HeadBucket as a startup probe; surfaces creds / bucket-not-found
        // errors at construction time rather than on the first op.
        backend
            .client
            .head_bucket()
            .bucket(&backend.bucket)
            .send()
            .await
            .map_err(|e| map_sdk_error("HeadBucket", e))?;
        Ok(backend)
    }

    /// Build a client without running the `HeadBucket` startup probe.
    pub async fn connect_unchecked(config: AwsS3BackendConfig) -> FsResult<Self> {
        let mut conf_builder = aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .force_path_style(config.force_path_style)
            // `request_timeout` was stored on this config and never applied.
            // The SDK's defaults give a connect timeout and **no operation
            // timeout**, so a read that stalls after the connection is
            // established hangs forever — and inside an enclave that hangs
            // whatever called it: a mount, a commit, or a guest holding its
            // tenant's lock open across a response body. Nothing above can
            // rescue it either, because a task parked in a host future
            // executes no wasm and so is invisible to the epoch watchdog.
            //
            // Per attempt, with the SDK's retries on top, which is what this
            // field's own documentation describes. The overall ceiling is three
            // times that — the standard retry policy's attempt count — so a
            // pathological endpoint cannot stretch one operation without limit.
            .timeout_config(
                aws_smithy_types::timeout::TimeoutConfig::builder()
                    .operation_attempt_timeout(config.request_timeout)
                    .operation_timeout(config.request_timeout * 3)
                    .build(),
            );
        if let Some(ep) = &config.endpoint {
            conf_builder = conf_builder.endpoint_url(ep);
        }
        if let (Some(akid), Some(sak)) = (
            config.access_key_id.as_deref(),
            config.secret_access_key.as_deref(),
        ) {
            let creds = Credentials::new(
                akid,
                sak,
                config.session_token.clone(),
                None, // expiry — None = static (no auto-refresh)
                "s3fs-static",
            );
            conf_builder = conf_builder.credentials_provider(creds);
        }
        let client = Client::from_conf(conf_builder.build());
        Ok(Self {
            bucket: config.bucket.clone(),
            client,
            config,
        })
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The configuration this backend was built from, so a caller can derive
    /// a second backend against another bucket on the same endpoint.
    pub fn config(&self) -> &AwsS3BackendConfig {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[async_trait]
impl Backend for AwsS3Backend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            conditional_put: true, // S3 added If-None-Match: * in 2024
            upload_part_copy: true,
            batch_delete: true,
            metadata_in_listings: false,
            object_lock: true,
        }
    }

    async fn head_blob(&self, key: &str) -> FsResult<BlobMeta> {
        let resp = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| match &e {
                SdkError::ServiceError(svc)
                    if matches!(svc.err(), HeadObjectError::NotFound(_)) =>
                {
                    FsError::NotFound
                }
                _ => map_sdk_error("HeadObject", e),
            })?;

        Ok(BlobMeta {
            key: key.to_string(),
            e_tag: resp.e_tag.unwrap_or_default(),
            size: resp.content_length.unwrap_or(0).max(0) as u64,
            last_modified: resp
                .last_modified
                .as_ref()
                .map(dt_to_systemtime)
                .unwrap_or(std::time::UNIX_EPOCH),
            content_type: resp.content_type,
            metadata: resp.metadata.unwrap_or_default(),
            is_dir_marker: key.ends_with('/'),
        })
    }

    async fn get_blob(&self, key: &str, range: Option<Range<u64>>) -> FsResult<GetBlobOutput> {
        let mut req = self.client.get_object().bucket(&self.bucket).key(key);
        if let Some(r) = &range {
            // S3 Range header is inclusive on both ends.
            if r.end > r.start {
                req = req.range(format!("bytes={}-{}", r.start, r.end - 1));
            }
        }
        let resp = req
            .send()
            .await
            .map_err(|e| map_sdk_error("GetObject", e))?;

        let e_tag = resp.e_tag.clone().unwrap_or_default();
        let last_modified = resp
            .last_modified
            .as_ref()
            .map(dt_to_systemtime)
            .unwrap_or(std::time::UNIX_EPOCH);
        let content_type = resp.content_type.clone();
        let metadata = resp.metadata.clone().unwrap_or_default();
        let body = resp
            .body
            .collect()
            .await
            .map_err(|e| FsError::Io(format!("GetObject body: {e}")))?
            .into_bytes();
        let size = body.len() as u64;

        Ok(GetBlobOutput {
            meta: BlobMeta {
                key: key.to_string(),
                e_tag,
                size,
                last_modified,
                content_type,
                metadata,
                is_dir_marker: key.ends_with('/'),
            },
            body,
        })
    }

    async fn get_retained_blob(&self, key: &str) -> FsResult<GetBlobOutput> {
        // `ListObjectVersions` still reports a version that a delete marker is
        // hiding, so this is what tells "never written" from "hidden". The
        // prefix is not an exact match, hence the `Key == key` filter.
        //
        // Every page, not the first: delete markers count against the page
        // size and anyone with DeleteObject can stack a thousand of them on a
        // key, pushing the retained version onto a later page. Stopping early
        // would report it absent.
        let mut versions = Vec::new();
        let mut key_marker = None;
        let mut version_id_marker = None;
        loop {
            let listed = self
                .client
                .list_object_versions()
                .bucket(&self.bucket)
                .prefix(key)
                .set_key_marker(key_marker.take())
                .set_version_id_marker(version_id_marker.take())
                .send()
                .await
                .map_err(|e| map_sdk_error("ListObjectVersions", e))?;
            versions.extend(
                listed
                    .versions
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|v| v.key.as_deref() == Some(key)),
            );
            if !listed.is_truncated.unwrap_or(false) {
                break;
            }
            key_marker = listed.next_key_marker;
            version_id_marker = listed.next_version_id_marker;
            if key_marker.is_none() {
                return Err(FsError::Io(
                    "ListObjectVersions: truncated without a continuation marker".into(),
                ));
            }
        }

        // Oldest first: `last_modified` ascending, so the version the
        // conditional PUT created wins over anything layered on later.
        versions.sort_by_key(|v| v.last_modified.map(|d| d.as_nanos()).unwrap_or(i128::MIN));

        let version_id = versions
            .into_iter()
            .find_map(|v| v.version_id)
            .ok_or(FsError::NotFound)?;

        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .version_id(&version_id)
            .send()
            .await
            .map_err(|e| map_sdk_error("GetObject(versionId)", e))?;

        let e_tag = resp.e_tag.clone().unwrap_or_default();
        let last_modified = resp
            .last_modified
            .as_ref()
            .map(dt_to_systemtime)
            .unwrap_or(std::time::UNIX_EPOCH);
        let content_type = resp.content_type.clone();
        let metadata = resp.metadata.clone().unwrap_or_default();
        let body = resp
            .body
            .collect()
            .await
            .map_err(|e| FsError::Io(format!("GetObject(versionId) body: {e}")))?
            .into_bytes();
        let size = body.len() as u64;

        Ok(GetBlobOutput {
            meta: BlobMeta {
                key: key.to_string(),
                e_tag,
                size,
                last_modified,
                content_type,
                metadata,
                is_dir_marker: key.ends_with('/'),
            },
            body,
        })
    }

    async fn put_blob(&self, input: PutBlobInput) -> FsResult<BlobMeta> {
        let key = input.key.clone();
        let body = ByteStream::from(input.body.to_vec());
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body);
        if !input.metadata.is_empty() {
            for (k, v) in &input.metadata {
                req = req.metadata(k, v);
            }
        }
        if let Some(ct) = &input.content_type {
            req = req.content_type(ct);
        }
        if let Some(lock) = &input.object_lock {
            req = apply_object_lock(req, lock);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| map_sdk_error("PutObject", e))?;
        Ok(BlobMeta {
            key: key.clone(),
            e_tag: resp.e_tag.unwrap_or_default(),
            size: input.body.len() as u64,
            last_modified: std::time::SystemTime::now(),
            content_type: input.content_type,
            metadata: input.metadata,
            is_dir_marker: key.ends_with('/'),
        })
    }

    async fn put_blob_if_not_exists(&self, input: PutBlobInput) -> FsResult<BlobMeta> {
        let key = input.key.clone();
        let body = ByteStream::from(input.body.to_vec());
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .if_none_match("*");
        if !input.metadata.is_empty() {
            for (k, v) in &input.metadata {
                req = req.metadata(k, v);
            }
        }
        if let Some(ct) = &input.content_type {
            req = req.content_type(ct);
        }
        if let Some(lock) = &input.object_lock {
            req = apply_object_lock(req, lock);
        }
        let resp = req.send().await.map_err(|e| {
            // S3 returns 412 PreconditionFailed when If-None-Match: * fires.
            match service_code(&e) {
                Some("PreconditionFailed") => FsError::AlreadyExists,
                _ => map_sdk_error("PutObject(if-none-match)", e),
            }
        })?;
        Ok(BlobMeta {
            key: key.clone(),
            e_tag: resp.e_tag.unwrap_or_default(),
            size: input.body.len() as u64,
            last_modified: std::time::SystemTime::now(),
            content_type: input.content_type,
            metadata: input.metadata,
            is_dir_marker: key.ends_with('/'),
        })
    }

    async fn delete_blob(&self, key: &str) -> FsResult<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| map_sdk_error("DeleteObject", e))?;
        Ok(())
    }

    async fn delete_blobs(&self, keys: &[String]) -> FsResult<()> {
        if keys.is_empty() {
            return Ok(());
        }
        // S3 DeleteObjects caps at 1000 per request.
        for chunk in keys.chunks(1000) {
            let objects: Vec<_> = chunk
                .iter()
                .map(|k| {
                    ObjectIdentifier::builder()
                        .key(k)
                        .build()
                        .expect("ObjectIdentifier requires only key")
                })
                .collect();
            let delete = Delete::builder()
                .set_objects(Some(objects))
                .quiet(true)
                .build()
                .expect("Delete builder requires only objects");
            self.client
                .delete_objects()
                .bucket(&self.bucket)
                .delete(delete)
                .send()
                .await
                .map_err(|e| map_sdk_error("DeleteObjects", e))?;
        }
        Ok(())
    }

    async fn list_blobs(&self, input: ListBlobsInput<'_>) -> FsResult<ListBlobsOutput> {
        let mut req = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(input.prefix);
        if let Some(d) = input.delimiter {
            req = req.delimiter(d);
        }
        if let Some(m) = input.max_keys {
            req = req.max_keys(m as i32);
        }
        if let Some(s) = input.start_after {
            req = req.start_after(s);
        }
        if let Some(c) = input.continuation_token {
            req = req.continuation_token(c);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| map_sdk_error("ListObjectsV2", e))?;

        let items = resp
            .contents
            .unwrap_or_default()
            .into_iter()
            .map(|o| BlobItem {
                key: o.key.unwrap_or_default(),
                e_tag: o.e_tag.unwrap_or_default(),
                size: o.size.unwrap_or(0).max(0) as u64,
                last_modified: o
                    .last_modified
                    .as_ref()
                    .map(dt_to_systemtime)
                    .unwrap_or(std::time::UNIX_EPOCH),
            })
            .collect();
        let prefixes = resp
            .common_prefixes
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| p.prefix)
            .collect();
        let next_continuation_token = resp.next_continuation_token;
        let is_truncated = resp.is_truncated.unwrap_or(false);

        Ok(ListBlobsOutput {
            items,
            prefixes,
            next_continuation_token,
            is_truncated,
        })
    }

    async fn copy_blob(&self, input: CopyBlobInput) -> FsResult<BlobMeta> {
        let copy_source = format!("{}/{}", self.bucket, input.source_key);
        let mut req = self
            .client
            .copy_object()
            .bucket(&self.bucket)
            .key(&input.destination_key)
            .copy_source(copy_source);
        if let Some(meta) = &input.replace_metadata {
            req = req.metadata_directive(MetadataDirective::Replace);
            for (k, v) in meta {
                req = req.metadata(k, v);
            }
        }
        if let Some(ct) = &input.replace_content_type {
            req = req.content_type(ct);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| map_sdk_error("CopyObject", e))?;
        let e_tag = resp
            .copy_object_result
            .as_ref()
            .and_then(|r| r.e_tag.clone())
            .unwrap_or_default();
        Ok(BlobMeta {
            key: input.destination_key.clone(),
            e_tag,
            size: 0, // CopyObject doesn't return the new size; caller can HEAD if needed
            last_modified: std::time::SystemTime::now(),
            content_type: input.replace_content_type,
            metadata: input.replace_metadata.unwrap_or_default(),
            is_dir_marker: input.destination_key.ends_with('/'),
        })
    }

    async fn multipart_begin(&self, input: PutBlobInput) -> FsResult<MultipartId> {
        let mut req = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&input.key);
        if !input.metadata.is_empty() {
            for (k, v) in &input.metadata {
                req = req.metadata(k, v);
            }
        }
        if let Some(ct) = &input.content_type {
            req = req.content_type(ct);
        }
        if let Some(lock) = &input.object_lock {
            let mode = match lock.mode {
                ObjectLockMode::Governance => SdkObjectLockMode::Governance,
                ObjectLockMode::Compliance => SdkObjectLockMode::Compliance,
            };
            req = req
                .object_lock_mode(mode)
                .object_lock_retain_until_date(aws_smithy_types::DateTime::from(lock.retain_until));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| map_sdk_error("CreateMultipartUpload", e))?;
        let upload_id = resp
            .upload_id
            .ok_or_else(|| FsError::Io("CreateMultipartUpload returned no upload_id".into()))?;
        Ok(MultipartId(upload_id))
    }

    async fn multipart_upload_part(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        body: Bytes,
    ) -> FsResult<PartUploadOutput> {
        let resp = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id.0)
            .part_number(part_number as i32)
            .body(ByteStream::from(body.to_vec()))
            .send()
            .await
            .map_err(|e| map_sdk_error("UploadPart", e))?;
        Ok(PartUploadOutput {
            e_tag: resp.e_tag.unwrap_or_default(),
        })
    }

    async fn multipart_upload_part_copy(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        source_key: &str,
        source_range: Range<u64>,
    ) -> FsResult<PartUploadOutput> {
        let copy_source = format!("{}/{}", self.bucket, source_key);
        // Inclusive end per S3.
        let copy_source_range = format!("bytes={}-{}", source_range.start, source_range.end - 1);
        let resp = self
            .client
            .upload_part_copy()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id.0)
            .part_number(part_number as i32)
            .copy_source(copy_source)
            .copy_source_range(copy_source_range)
            .send()
            .await
            .map_err(|e| map_sdk_error("UploadPartCopy", e))?;
        let e_tag = resp
            .copy_part_result
            .as_ref()
            .and_then(|r| r.e_tag.clone())
            .unwrap_or_default();
        Ok(PartUploadOutput { e_tag })
    }

    async fn multipart_complete(
        &self,
        key: &str,
        upload_id: &MultipartId,
        parts: Vec<CompletedPart>,
    ) -> FsResult<BlobMeta> {
        let sdk_parts: Vec<_> = parts
            .iter()
            .map(|p| {
                SdkCompletedPart::builder()
                    .part_number(p.part_number as i32)
                    .e_tag(&p.e_tag)
                    .build()
            })
            .collect();
        let mpu = CompletedMultipartUpload::builder()
            .set_parts(Some(sdk_parts))
            .build();
        let resp = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id.0)
            .multipart_upload(mpu)
            .send()
            .await
            .map_err(|e| map_sdk_error("CompleteMultipartUpload", e))?;
        Ok(BlobMeta {
            key: key.to_string(),
            e_tag: resp.e_tag.unwrap_or_default(),
            size: 0, // not returned; caller can HEAD if needed
            last_modified: std::time::SystemTime::now(),
            content_type: None,
            metadata: HashMap::new(),
            is_dir_marker: key.ends_with('/'),
        })
    }

    async fn multipart_abort(&self, key: &str, upload_id: &MultipartId) -> FsResult<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id.0)
            .send()
            .await
            .map_err(|e| map_sdk_error("AbortMultipartUpload", e))?;
        Ok(())
    }
}

// --- error mapping helpers ----------------------------------------------

fn dt_to_systemtime(dt: &aws_smithy_types::DateTime) -> std::time::SystemTime {
    let secs = dt.secs();
    let nanos = dt.subsec_nanos();
    if secs >= 0 {
        std::time::UNIX_EPOCH + std::time::Duration::new(secs as u64, nanos)
    } else {
        std::time::UNIX_EPOCH
    }
}

/// Pull the service-error code string out of a `SdkError`, if any.
fn service_code<E, R>(e: &SdkError<E, R>) -> Option<&str>
where
    E: ProvideErrorMetadata,
{
    match e {
        SdkError::ServiceError(svc) => svc.err().code(),
        _ => None,
    }
}

/// Generic mapper: examines the service code and falls back to a category
/// based on the SDK error variant.
fn map_sdk_error<E, R>(_op: &'static str, e: SdkError<E, R>) -> FsError
where
    E: ProvideErrorMetadata + std::fmt::Debug,
    R: std::fmt::Debug,
{
    if let Some(code) = service_code(&e) {
        return match code {
            "NoSuchKey" | "NoSuchUpload" | "NoSuchBucket" | "NotFound" => FsError::NotFound,
            "AccessDenied" | "Forbidden" => FsError::AccessDenied,
            "PreconditionFailed" => FsError::Conflict,
            "BucketAlreadyExists" | "BucketAlreadyOwnedByYou" => FsError::AlreadyExists,
            "EntityTooLarge" | "EntityTooSmall" => FsError::Invalid("entity size"),
            "RequestTimeout" | "SlowDown" | "RequestLimitExceeded" => FsError::IoTimeout,
            _ => FsError::Io(format!("{e:?}")),
        };
    }
    match &e {
        SdkError::TimeoutError(_) => FsError::IoTimeout,
        SdkError::DispatchFailure(_) => FsError::Network(format!("{e:?}")),
        SdkError::ResponseError(_) => FsError::Io(format!("{e:?}")),
        _ => FsError::Io(format!("{e:?}")),
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// The bug this guards: the field existed, was defaulted, was threaded
    /// through two layers of config — and was never handed to the SDK. Asserted
    /// on the built client rather than on our own struct, because our struct
    /// held the right value the whole time it was being ignored.
    #[tokio::test]
    async fn the_request_timeout_reaches_the_client() {
        let mut config = AwsS3BackendConfig::new("bucket", "us-east-1");
        config.request_timeout = Duration::from_secs(7);
        config.endpoint = Some("http://127.0.0.1:1".into());

        let backend = AwsS3Backend::connect_unchecked(config)
            .await
            .expect("building a client does no I/O");
        let timeouts = backend
            .client()
            .config()
            .timeout_config()
            .expect("the SDK was given no timeout configuration at all");

        assert_eq!(
            timeouts.operation_attempt_timeout(),
            Some(Duration::from_secs(7)),
            "one attempt is unbounded"
        );
        assert_eq!(
            timeouts.operation_timeout(),
            Some(Duration::from_secs(21)),
            "the operation as a whole is unbounded"
        );
    }
}
