//! `MemoryBackend` — in-memory backend that faithfully models the bits of S3
//! semantics the engine relies on: flat key space, prefix/delimiter listings,
//! conditional create, multipart uploads with `UploadPartCopy`, last-write-wins.
//!
//! Purely a test fake. Not durable. Not thread-safe across processes.
//!
//! ## What it models of Object Lock, and what it does not
//!
//! It used to describe itself as a non-versioned bucket, which cannot exist:
//! S3 requires versioning for Object Lock. The consequence was worse than
//! inaccuracy — the fake was *stronger* than the real thing, so a test could
//! prove a retained object undeletable when in reality it is only
//! un-destroyable.
//!
//! Now modelled, because it defeats a check that has no signature to fall back
//! on: **a delete marker**. `delete_blob` on a retained object succeeds and
//! hides it from `get_blob`, `head_blob` and `list_blobs`, exactly as S3 does,
//! while the bytes remain reachable through [`Backend::get_retained_blob`].
//!
//! Still *not* modelled, deliberately: a plain `put_blob` over a retained
//! object, which real S3 accepts as a new version. Every such object here is
//! content-verified — a root record by its Ed25519 signature, a receipt by the
//! NSM's — so substituted bytes are refused a layer up. It is the *absence*
//! that has nothing to verify, which is why that half is modelled and this one
//! is named instead.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use siphasher::sip128::{Hasher128, SipHasher24};
use std::hash::Hasher;

use super::{
    Backend, BlobItem, BlobMeta, Capabilities, CompletedPart, CopyBlobInput, GetBlobOutput,
    ListBlobsInput, ListBlobsOutput, MultipartId, ObjectLock, PartUploadOutput, PutBlobInput,
};
use crate::errors::{FsError, FsResult};

#[derive(Debug, Clone)]
struct StoredBlob {
    body: Bytes,
    e_tag: String,
    last_modified: SystemTime,
    content_type: Option<String>,
    metadata: HashMap<String, String>,
    /// Retention stamped at PUT time, if any.
    object_lock: Option<ObjectLock>,
}

impl StoredBlob {
    /// `true` if retention is still in force, i.e. S3 would refuse to delete
    /// or overwrite this object.
    ///
    /// Governance mode is modelled as equally binding: this fake has no notion
    /// of IAM principals, so there is nobody here who could hold
    /// `s3:BypassGovernanceRetention`.
    fn is_retained(&self, now: SystemTime) -> bool {
        self.object_lock.is_some_and(|lock| now < lock.retain_until)
    }
}

#[derive(Debug, Clone)]
struct ActiveMpu {
    key: String,
    metadata: HashMap<String, String>,
    content_type: Option<String>,
    object_lock: Option<ObjectLock>,
    parts: HashMap<u32, MpuPart>,
}

#[derive(Debug, Clone)]
struct MpuPart {
    body: Bytes,
    e_tag: String,
}

#[derive(Debug, Default)]
struct State {
    objects: HashMap<String, StoredBlob>,
    /// Keys with a delete marker on top: the object is still stored, and every
    /// ordinary read must behave as though it is not there.
    delete_markers: std::collections::HashSet<String>,
    /// The version Object Lock pinned, for keys that have since been written
    /// over. A new PUT stacks a version on top and leaves the retained one
    /// where it was — it is the *current* pointer that moves, which is the
    /// distinction the whole delete-marker problem turns on.
    retained: HashMap<String, StoredBlob>,
    mpus: HashMap<MultipartId, ActiveMpu>,
}

impl State {
    /// What an ordinary `GetObject` would see.
    fn current(&self, key: &str) -> Option<&StoredBlob> {
        if self.delete_markers.contains(key) {
            return None;
        }
        self.objects.get(key)
    }

    /// What `ListObjectVersions` plus a versioned `GetObject` would find: the
    /// pinned version if one has been written over, otherwise whatever is
    /// stored — marker or no marker.
    fn retained(&self, key: &str) -> Option<&StoredBlob> {
        self.retained.get(key).or_else(|| self.objects.get(key))
    }

    /// Called before anything replaces `objects[key]`. Retention cannot be
    /// undone by writing, so the pinned version is set aside rather than lost.
    fn pin_before_overwrite(&mut self, key: &str, now: SystemTime) {
        if self.retained.contains_key(key) {
            return;
        }
        if let Some(b) = self.objects.get(key) {
            if b.is_retained(now) {
                self.retained.insert(key.to_string(), b.clone());
            }
        }
    }
}

/// One key's worth of `DeleteObject`.
///
/// Retained: a delete marker goes on top and the object stays, which is what S3
/// does and is not at all the same as refusing. Unretained: the object really
/// goes. Idempotent either way — S3 answers success for a key that was never
/// there.
fn delete_one(state: &mut State, key: &str, now: SystemTime) {
    if state.objects.get(key).is_some_and(|b| b.is_retained(now)) {
        state.delete_markers.insert(key.to_string());
        return;
    }
    state.objects.remove(key);
    state.delete_markers.remove(key);
}

/// In-memory backend.
#[derive(Debug, Clone)]
pub struct MemoryBackend {
    state: Arc<RwLock<State>>,
    next_mpu_id: Arc<AtomicU64>,
    next_etag: Arc<AtomicU64>,
    /// Test-helper: an error the next PUT, conditional or not, returns
    /// instead of storing.
    fail_next_put: Arc<RwLock<Option<FsError>>>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(State::default())),
            next_mpu_id: Arc::new(AtomicU64::new(1)),
            next_etag: Arc::new(AtomicU64::new(1)),
            fail_next_put: Arc::new(RwLock::new(None)),
        }
    }

    /// Test-helper: make the next PUT fail with `e`, storing nothing.
    pub fn fail_next_put(&self, e: FsError) {
        *self.fail_next_put.write() = Some(e);
    }

    /// Test-helper: count of committed objects.
    pub fn object_count(&self) -> usize {
        self.state.read().objects.len()
    }

    /// Test-helper: snapshot of all keys, sorted.
    pub fn keys(&self) -> Vec<String> {
        let mut k: Vec<_> = self.state.read().objects.keys().cloned().collect();
        k.sort();
        k
    }

    /// Test-helper: count of in-flight (uncommitted) multipart uploads.
    pub fn mpu_count(&self) -> usize {
        self.state.read().mpus.len()
    }

    fn make_etag(&self, body: &[u8]) -> String {
        // Use sip-2-4 over the body plus a monotonically increasing counter so
        // identical bodies still get distinct ETags across PUTs (mirrors S3's
        // behaviour for repeated PUT of the same content).
        let counter = self.next_etag.fetch_add(1, Ordering::Relaxed);
        let mut h = SipHasher24::new_with_keys(0, counter);
        h.write(body);
        format!("\"{:032x}\"", h.finish128().as_u128())
    }

    fn meta_from_stored(&self, key: &str, b: &StoredBlob) -> BlobMeta {
        BlobMeta {
            key: key.to_string(),
            e_tag: b.e_tag.clone(),
            size: b.body.len() as u64,
            last_modified: b.last_modified,
            content_type: b.content_type.clone(),
            metadata: b.metadata.clone(),
            is_dir_marker: key.ends_with('/'),
        }
    }
}

#[async_trait]
impl Backend for MemoryBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            conditional_put: true,
            upload_part_copy: true,
            batch_delete: true,
            metadata_in_listings: false, // mirror standard S3
            object_lock: true,
        }
    }

    async fn head_blob(&self, key: &str) -> FsResult<BlobMeta> {
        let g = self.state.read();
        let b = g.current(key).ok_or(FsError::NotFound)?;
        Ok(self.meta_from_stored(key, b))
    }

    async fn get_blob(&self, key: &str, range: Option<Range<u64>>) -> FsResult<GetBlobOutput> {
        let g = self.state.read();
        let b = g.current(key).ok_or(FsError::NotFound)?;
        let meta = self.meta_from_stored(key, b);
        let body = match range {
            None => b.body.clone(),
            Some(r) => {
                let start = r.start.min(b.body.len() as u64) as usize;
                let end = r.end.min(b.body.len() as u64) as usize;
                if start > end {
                    return Err(FsError::Invalid("range start > end"));
                }
                b.body.slice(start..end)
            }
        };
        Ok(GetBlobOutput { meta, body })
    }

    /// Reads straight through a delete marker, which is the whole point.
    async fn get_retained_blob(&self, key: &str) -> FsResult<GetBlobOutput> {
        let g = self.state.read();
        let b = g.retained(key).ok_or(FsError::NotFound)?;
        Ok(GetBlobOutput {
            meta: self.meta_from_stored(key, b),
            body: b.body.clone(),
        })
    }

    async fn put_blob(&self, input: PutBlobInput) -> FsResult<BlobMeta> {
        if let Some(e) = self.fail_next_put.write().take() {
            return Err(e);
        }
        let e_tag = self.make_etag(&input.body);
        let now = SystemTime::now();
        let stored = StoredBlob {
            body: input.body,
            e_tag: e_tag.clone(),
            last_modified: now,
            content_type: input.content_type,
            metadata: input.metadata,
            object_lock: input.object_lock,
        };
        let key = input.key;
        let mut g = self.state.write();
        // This fake models a non-versioned bucket, so an overwrite replaces
        // the retained version rather than adding a new one. Refuse it.
        if g.objects.get(&key).is_some_and(|b| b.is_retained(now)) {
            return Err(FsError::AccessDenied);
        }
        g.objects.insert(key.clone(), stored.clone());
        Ok(self.meta_from_stored(&key, &stored))
    }

    async fn put_blob_if_not_exists(&self, input: PutBlobInput) -> FsResult<BlobMeta> {
        if let Some(e) = self.fail_next_put.write().take() {
            return Err(e);
        }
        let mut g = self.state.write();
        // `If-None-Match: *` tests the *current* version, and a delete marker
        // is a current version that is not an object — so a hidden key accepts
        // a conditional create, and the enclave that makes one believes it is
        // the first ever to write here. That is the attack this fake now
        // permits so it can be tested.
        if g.current(&input.key).is_some() {
            return Err(FsError::AlreadyExists);
        }
        let now = SystemTime::now();
        g.pin_before_overwrite(&input.key, now);
        g.delete_markers.remove(&input.key);
        let e_tag = self.make_etag(&input.body);
        let stored = StoredBlob {
            body: input.body,
            e_tag,
            last_modified: now,
            content_type: input.content_type,
            metadata: input.metadata,
            object_lock: input.object_lock,
        };
        let key = input.key;
        g.objects.insert(key.clone(), stored.clone());
        Ok(self.meta_from_stored(&key, &stored))
    }

    async fn delete_blob(&self, key: &str) -> FsResult<()> {
        let now = SystemTime::now();
        let mut g = self.state.write();
        delete_one(&mut g, key, now);
        Ok(())
    }

    async fn delete_blobs(&self, keys: &[String]) -> FsResult<()> {
        let now = SystemTime::now();
        let mut g = self.state.write();
        for k in keys {
            delete_one(&mut g, k, now);
        }
        Ok(())
    }

    async fn list_blobs(&self, input: ListBlobsInput<'_>) -> FsResult<ListBlobsOutput> {
        let g = self.state.read();
        // `ListObjectsV2` lists current versions, so a marked key is absent
        // from it too. `ListObjectVersions` is the call that still sees them,
        // and `get_retained_blob` is this fake's stand-in for it.
        let mut keys: Vec<String> = g
            .objects
            .keys()
            .filter(|k| k.starts_with(input.prefix) && !g.delete_markers.contains(*k))
            .cloned()
            .collect();
        keys.sort();

        let cursor = input.continuation_token.or(input.start_after);
        if let Some(c) = cursor {
            keys.retain(|k| k.as_str() > c);
        }

        let max_keys = input.max_keys.unwrap_or(1000) as usize;
        let prefix_len = input.prefix.len();

        let mut items = Vec::<BlobItem>::new();
        let mut prefixes = Vec::<String>::new();
        let mut last_consumed_key: Option<String> = None;
        let mut idx = 0usize;
        let mut emitted = 0usize;

        while idx < keys.len() && emitted < max_keys {
            let k = keys[idx].clone();
            if let Some(delim) = input.delimiter {
                let after = &k[prefix_len..];
                if let Some(d) = after.find(delim) {
                    let cp_key = format!("{}{}{}", input.prefix, &after[..d], delim);
                    prefixes.push(cp_key.clone());
                    emitted += 1;
                    // Advance past every key that belongs to this CommonPrefix
                    // so the next pagination cursor properly skips them.
                    while idx < keys.len() && keys[idx].starts_with(&cp_key) {
                        last_consumed_key = Some(keys[idx].clone());
                        idx += 1;
                    }
                    continue;
                }
            }
            let b = &g.objects[&k];
            items.push(BlobItem {
                key: k.clone(),
                e_tag: b.e_tag.clone(),
                size: b.body.len() as u64,
                last_modified: b.last_modified,
            });
            emitted += 1;
            last_consumed_key = Some(k);
            idx += 1;
        }

        let is_truncated = idx < keys.len();
        let next_continuation_token = if is_truncated {
            last_consumed_key
        } else {
            None
        };

        Ok(ListBlobsOutput {
            items,
            prefixes,
            next_continuation_token,
            is_truncated,
        })
    }

    async fn copy_blob(&self, input: CopyBlobInput) -> FsResult<BlobMeta> {
        let mut g = self.state.write();
        let src = g
            .objects
            .get(&input.source_key)
            .ok_or(FsError::NotFound)?
            .clone();

        let now = SystemTime::now();
        if g.objects
            .get(&input.destination_key)
            .is_some_and(|b| b.is_retained(now))
        {
            return Err(FsError::AccessDenied);
        }

        let metadata = input.replace_metadata.unwrap_or(src.metadata);
        let content_type = input.replace_content_type.or(src.content_type);
        let e_tag = self.make_etag(&src.body);
        let stored = StoredBlob {
            body: src.body,
            e_tag,
            last_modified: now,
            content_type,
            metadata,
            // S3 does not carry retention across a copy unless the request
            // asks for it, and `CopyBlobInput` has no way to ask.
            object_lock: None,
        };
        g.objects
            .insert(input.destination_key.clone(), stored.clone());
        Ok(self.meta_from_stored(&input.destination_key, &stored))
    }

    async fn multipart_begin(&self, input: PutBlobInput) -> FsResult<MultipartId> {
        let n = self.next_mpu_id.fetch_add(1, Ordering::Relaxed);
        let id = MultipartId(format!("mpu-{n}"));
        let object_lock = input.object_lock;
        let mpu = ActiveMpu {
            object_lock,
            key: input.key,
            metadata: input.metadata,
            content_type: input.content_type,
            parts: HashMap::new(),
        };
        self.state.write().mpus.insert(id.clone(), mpu);
        Ok(id)
    }

    async fn multipart_upload_part(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        body: Bytes,
    ) -> FsResult<PartUploadOutput> {
        if part_number == 0 || part_number > 10_000 {
            return Err(FsError::Invalid("part_number out of range"));
        }
        let e_tag = self.make_etag(&body);
        let mut g = self.state.write();
        let mpu = g
            .mpus
            .get_mut(upload_id)
            .ok_or_else(|| FsError::Io(format!("unknown upload_id: {upload_id:?}")))?;
        if mpu.key != key {
            return Err(FsError::Invalid("upload_id key mismatch"));
        }
        mpu.parts.insert(
            part_number,
            MpuPart {
                body,
                e_tag: e_tag.clone(),
            },
        );
        Ok(PartUploadOutput { e_tag })
    }

    async fn multipart_upload_part_copy(
        &self,
        key: &str,
        upload_id: &MultipartId,
        part_number: u32,
        source_key: &str,
        source_range: Range<u64>,
    ) -> FsResult<PartUploadOutput> {
        if part_number == 0 || part_number > 10_000 {
            return Err(FsError::Invalid("part_number out of range"));
        }
        let mut g = self.state.write();
        let src = g.objects.get(source_key).ok_or(FsError::NotFound)?.clone();
        let start = source_range.start as usize;
        let end = source_range.end as usize;
        if end > src.body.len() || start > end {
            return Err(FsError::Invalid("source_range out of bounds"));
        }
        let body = src.body.slice(start..end);
        let e_tag = self.make_etag(&body);
        let mpu = g
            .mpus
            .get_mut(upload_id)
            .ok_or_else(|| FsError::Io(format!("unknown upload_id: {upload_id:?}")))?;
        if mpu.key != key {
            return Err(FsError::Invalid("upload_id key mismatch"));
        }
        mpu.parts.insert(
            part_number,
            MpuPart {
                body,
                e_tag: e_tag.clone(),
            },
        );
        Ok(PartUploadOutput { e_tag })
    }

    async fn multipart_complete(
        &self,
        key: &str,
        upload_id: &MultipartId,
        parts: Vec<CompletedPart>,
    ) -> FsResult<BlobMeta> {
        let mut g = self.state.write();
        let mpu = g
            .mpus
            .remove(upload_id)
            .ok_or_else(|| FsError::Io(format!("unknown upload_id: {upload_id:?}")))?;
        if mpu.key != key {
            // Put it back; this is a programmer error, not a state mutation.
            g.mpus.insert(upload_id.clone(), mpu);
            return Err(FsError::Invalid("upload_id key mismatch"));
        }

        // Validate parts in ascending order with matching ETags, assemble body.
        let mut ordered = parts;
        ordered.sort_by_key(|p| p.part_number);
        let mut body_acc: Vec<u8> = Vec::new();
        for cp in &ordered {
            let part = mpu
                .parts
                .get(&cp.part_number)
                .ok_or(FsError::Invalid("missing part on complete"))?;
            if part.e_tag != cp.e_tag {
                return Err(FsError::Invalid("etag mismatch on complete"));
            }
            body_acc.extend_from_slice(&part.body);
        }

        let body = Bytes::from(body_acc);
        let e_tag = self.make_etag(&body);
        let now = SystemTime::now();
        if g.objects.get(key).is_some_and(|b| b.is_retained(now)) {
            return Err(FsError::AccessDenied);
        }
        let stored = StoredBlob {
            body,
            e_tag,
            last_modified: now,
            content_type: mpu.content_type,
            metadata: mpu.metadata,
            object_lock: mpu.object_lock,
        };
        g.objects.insert(key.to_string(), stored.clone());
        Ok(self.meta_from_stored(key, &stored))
    }

    async fn multipart_abort(&self, key: &str, upload_id: &MultipartId) -> FsResult<()> {
        let mut g = self.state.write();
        match g.mpus.get(upload_id) {
            None => Ok(()), // idempotent abort, like S3
            Some(mpu) if mpu.key != key => Err(FsError::Invalid("upload_id key mismatch")),
            Some(_) => {
                g.mpus.remove(upload_id);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_then_head_then_get() {
        let b = MemoryBackend::new();
        let meta = b
            .put_blob(PutBlobInput {
                key: "a/b.txt".into(),
                body: Bytes::from_static(b"hello"),
                metadata: Default::default(),
                content_type: Some("text/plain".into()),
                object_lock: None,
            })
            .await
            .unwrap();
        assert_eq!(meta.size, 5);

        let h = b.head_blob("a/b.txt").await.unwrap();
        assert_eq!(h.size, 5);
        assert_eq!(h.content_type.as_deref(), Some("text/plain"));

        let g = b.get_blob("a/b.txt", None).await.unwrap();
        assert_eq!(&g.body[..], b"hello");
    }

    #[tokio::test]
    async fn head_missing_returns_not_found() {
        let b = MemoryBackend::new();
        assert!(matches!(b.head_blob("nope").await, Err(FsError::NotFound)));
    }

    #[tokio::test]
    async fn get_with_range_slices() {
        let b = MemoryBackend::new();
        b.put_blob(PutBlobInput {
            key: "x".into(),
            body: Bytes::from_static(b"abcdef"),
            metadata: Default::default(),
            content_type: None,
            object_lock: None,
        })
        .await
        .unwrap();
        let g = b.get_blob("x", Some(2..5)).await.unwrap();
        assert_eq!(&g.body[..], b"cde");
    }

    #[tokio::test]
    async fn put_if_not_exists_atomic_create() {
        let b = MemoryBackend::new();
        let body = || PutBlobInput {
            key: "k".into(),
            body: Bytes::from_static(b"v"),
            metadata: Default::default(),
            content_type: None,
            object_lock: None,
        };
        b.put_blob_if_not_exists(body()).await.unwrap();
        assert!(matches!(
            b.put_blob_if_not_exists(body()).await,
            Err(FsError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let b = MemoryBackend::new();
        b.delete_blob("nope").await.unwrap();
    }

    #[tokio::test]
    async fn list_with_delimiter_groups_prefixes() {
        let b = MemoryBackend::new();
        for k in ["dir/a.txt", "dir/b.txt", "dir/sub/c.txt", "other.txt"] {
            b.put_blob(PutBlobInput {
                key: k.into(),
                body: Bytes::from_static(b""),
                metadata: Default::default(),
                content_type: None,
                object_lock: None,
            })
            .await
            .unwrap();
        }
        let out = b
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

    #[tokio::test]
    async fn list_without_delimiter_returns_all_under_prefix() {
        let b = MemoryBackend::new();
        for k in ["dir/a", "dir/b", "dir/sub/c", "other"] {
            b.put_blob(PutBlobInput {
                key: k.into(),
                body: Bytes::from_static(b""),
                metadata: Default::default(),
                content_type: None,
                object_lock: None,
            })
            .await
            .unwrap();
        }
        let out = b
            .list_blobs(ListBlobsInput {
                prefix: "dir/",
                delimiter: None,
                ..Default::default()
            })
            .await
            .unwrap();
        let item_keys: Vec<_> = out.items.iter().map(|i| i.key.as_str()).collect();
        assert_eq!(item_keys, vec!["dir/a", "dir/b", "dir/sub/c"]);
        assert!(out.prefixes.is_empty());
    }

    #[tokio::test]
    async fn list_pagination_with_max_keys() {
        let b = MemoryBackend::new();
        for i in 0..5 {
            b.put_blob(PutBlobInput {
                key: format!("k{i:02}"),
                body: Bytes::from_static(b""),
                metadata: Default::default(),
                content_type: None,
                object_lock: None,
            })
            .await
            .unwrap();
        }
        let p1 = b
            .list_blobs(ListBlobsInput {
                prefix: "",
                max_keys: Some(2),
                ..Default::default()
            })
            .await
            .unwrap();
        let names: Vec<_> = p1.items.iter().map(|i| i.key.as_str()).collect();
        assert_eq!(names, vec!["k00", "k01"]);
        assert!(p1.is_truncated);
        let token = p1.next_continuation_token.clone().unwrap();

        let p2 = b
            .list_blobs(ListBlobsInput {
                prefix: "",
                max_keys: Some(2),
                continuation_token: Some(&token),
                ..Default::default()
            })
            .await
            .unwrap();
        let names: Vec<_> = p2.items.iter().map(|i| i.key.as_str()).collect();
        assert_eq!(names, vec!["k02", "k03"]);
        assert!(p2.is_truncated);

        let p3 = b
            .list_blobs(ListBlobsInput {
                prefix: "",
                max_keys: Some(2),
                continuation_token: p2.next_continuation_token.as_deref(),
                ..Default::default()
            })
            .await
            .unwrap();
        let names: Vec<_> = p3.items.iter().map(|i| i.key.as_str()).collect();
        assert_eq!(names, vec!["k04"]);
        assert!(!p3.is_truncated);
    }

    #[tokio::test]
    async fn copy_blob_basic() {
        let b = MemoryBackend::new();
        b.put_blob(PutBlobInput {
            key: "src".into(),
            body: Bytes::from_static(b"data"),
            metadata: Default::default(),
            content_type: None,
            object_lock: None,
        })
        .await
        .unwrap();
        b.copy_blob(CopyBlobInput {
            source_key: "src".into(),
            destination_key: "dst".into(),
            replace_metadata: None,
            replace_content_type: None,
        })
        .await
        .unwrap();
        let g = b.get_blob("dst", None).await.unwrap();
        assert_eq!(&g.body[..], b"data");
    }

    #[tokio::test]
    async fn multipart_full_lifecycle() {
        let b = MemoryBackend::new();
        let id = b
            .multipart_begin(PutBlobInput {
                key: "big".into(),
                body: Bytes::new(),
                metadata: Default::default(),
                content_type: None,
                object_lock: None,
            })
            .await
            .unwrap();
        let p1 = b
            .multipart_upload_part("big", &id, 1, Bytes::from_static(b"hello "))
            .await
            .unwrap();
        let p2 = b
            .multipart_upload_part("big", &id, 2, Bytes::from_static(b"world"))
            .await
            .unwrap();
        b.multipart_complete(
            "big",
            &id,
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
        let g = b.get_blob("big", None).await.unwrap();
        assert_eq!(&g.body[..], b"hello world");
        assert_eq!(b.mpu_count(), 0);
    }

    #[tokio::test]
    async fn multipart_upload_part_copy_stitches_from_source() {
        let b = MemoryBackend::new();
        // Source object: "0123456789"
        b.put_blob(PutBlobInput {
            key: "src".into(),
            body: Bytes::from_static(b"0123456789"),
            metadata: Default::default(),
            content_type: None,
            object_lock: None,
        })
        .await
        .unwrap();
        // Begin MPU on a new key.
        let id = b
            .multipart_begin(PutBlobInput {
                key: "dst".into(),
                body: Bytes::new(),
                metadata: Default::default(),
                content_type: None,
                object_lock: None,
            })
            .await
            .unwrap();
        // Part 1 = bytes 0..5 of src ("01234"), Part 2 = uploaded "XX".
        let p1 = b
            .multipart_upload_part_copy("dst", &id, 1, "src", 0..5)
            .await
            .unwrap();
        let p2 = b
            .multipart_upload_part("dst", &id, 2, Bytes::from_static(b"XX"))
            .await
            .unwrap();
        b.multipart_complete(
            "dst",
            &id,
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
        let g = b.get_blob("dst", None).await.unwrap();
        assert_eq!(&g.body[..], b"01234XX");
    }

    #[tokio::test]
    async fn multipart_abort_clears_state() {
        let b = MemoryBackend::new();
        let id = b
            .multipart_begin(PutBlobInput {
                key: "k".into(),
                body: Bytes::new(),
                metadata: Default::default(),
                content_type: None,
                object_lock: None,
            })
            .await
            .unwrap();
        b.multipart_upload_part("k", &id, 1, Bytes::from_static(b"x"))
            .await
            .unwrap();
        assert_eq!(b.mpu_count(), 1);
        b.multipart_abort("k", &id).await.unwrap();
        assert_eq!(b.mpu_count(), 0);
        // No object was ever committed.
        assert!(matches!(b.head_blob("k").await, Err(FsError::NotFound)));
    }

    #[tokio::test]
    async fn capabilities_reports_standard_s3ish() {
        let b = MemoryBackend::new();
        let c = b.capabilities();
        assert!(c.conditional_put);
        assert!(c.upload_part_copy);
        assert!(c.batch_delete);
        assert!(!c.metadata_in_listings); // mirror standard S3
        assert!(c.object_lock);
    }

    // ---- Object Lock -------------------------------------------------------
    //
    // These matter because the whole rollback story rests on a committed root
    // record being undeletable. If the fake let a retained object be rewritten,
    // every rollback test built on it would pass vacuously.
    //
    // It is *removal* that needs care in the other direction: retention makes
    // an object indestructible, not unhideable, and the fake used to claim
    // otherwise. See the module documentation.

    fn locked(key: &str, body: &'static [u8], secs: u64) -> PutBlobInput {
        PutBlobInput::new(key, Bytes::from_static(body)).with_object_lock(ObjectLock {
            mode: super::super::ObjectLockMode::Compliance,
            retain_until: SystemTime::now() + std::time::Duration::from_secs(secs),
        })
    }

    /// The correction. A `DeleteObject` on a retained object **succeeds** — it
    /// writes a delete marker — and every ordinary read then answers
    /// "not found" while the bytes sit underneath, undeletable.
    ///
    /// This test used to assert the delete was refused, which is what a
    /// non-versioned bucket would do and what no bucket with Object Lock can
    /// be. Verified against MinIO before changing it.
    #[tokio::test]
    async fn a_retained_object_can_be_hidden_but_not_destroyed() {
        let b = MemoryBackend::new();
        b.put_blob(locked("roots/0001", b"root", 3600))
            .await
            .unwrap();

        b.delete_blob("roots/0001").await.expect("S3 allows this");

        // Hidden from everything that reads the current version.
        assert!(matches!(
            b.get_blob("roots/0001", None).await,
            Err(FsError::NotFound)
        ));
        assert!(matches!(
            b.head_blob("roots/0001").await,
            Err(FsError::NotFound)
        ));
        let listed = b
            .list_blobs(ListBlobsInput {
                prefix: "roots/",
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(listed.items.is_empty(), "{listed:?}");

        // And still there, in the only place that matters.
        assert_eq!(
            b.get_retained_blob("roots/0001").await.unwrap().body,
            Bytes::from_static(b"root")
        );
    }

    /// The consequence, stated on its own because it is the one that bites: a
    /// hidden key accepts a conditional create. `If-None-Match: *` tests the
    /// current version, and a delete marker is a current version that is not an
    /// object — so a writer using the conditional PUT as its "am I the first?"
    /// test is told yes.
    #[tokio::test]
    async fn a_hidden_key_accepts_a_conditional_create() {
        let b = MemoryBackend::new();
        b.put_blob_if_not_exists(locked("origin/receipt", b"first", 3600))
            .await
            .unwrap();
        assert!(matches!(
            b.put_blob_if_not_exists(locked("origin/receipt", b"second", 3600))
                .await,
            Err(FsError::AlreadyExists)
        ));

        b.delete_blob("origin/receipt").await.unwrap();

        b.put_blob_if_not_exists(locked("origin/receipt", b"second", 3600))
            .await
            .expect("a delete marker makes the key look untaken");
    }

    #[tokio::test]
    async fn retained_object_cannot_be_overwritten() {
        let b = MemoryBackend::new();
        b.put_blob(locked("roots/0001", b"root", 3600))
            .await
            .unwrap();

        assert!(matches!(
            b.put_blob(PutBlobInput::new(
                "roots/0001",
                Bytes::from_static(b"forged")
            ))
            .await,
            Err(FsError::AccessDenied)
        ));
        assert!(matches!(
            b.copy_blob(CopyBlobInput {
                source_key: "roots/0001".into(),
                destination_key: "roots/0001".into(),
                replace_metadata: None,
                replace_content_type: None,
            })
            .await,
            Err(FsError::AccessDenied)
        ));
        assert_eq!(
            b.get_blob("roots/0001", None).await.unwrap().body,
            Bytes::from_static(b"root")
        );
    }

    #[tokio::test]
    async fn expired_retention_stops_binding() {
        let b = MemoryBackend::new();
        // Retention already in the past — S3 would allow the delete.
        b.put_blob(
            PutBlobInput::new("roots/0001", Bytes::from_static(b"root")).with_object_lock(
                ObjectLock {
                    mode: super::super::ObjectLockMode::Compliance,
                    retain_until: SystemTime::now() - std::time::Duration::from_secs(1),
                },
            ),
        )
        .await
        .unwrap();

        b.delete_blob("roots/0001").await.unwrap();
        assert!(matches!(
            b.head_blob("roots/0001").await,
            Err(FsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn unlocked_objects_are_unaffected() {
        let b = MemoryBackend::new();
        b.put_blob(PutBlobInput::new("slabs/0001", Bytes::from_static(b"data")))
            .await
            .unwrap();
        b.put_blob(PutBlobInput::new(
            "slabs/0001",
            Bytes::from_static(b"data2"),
        ))
        .await
        .unwrap();
        b.delete_blob("slabs/0001").await.unwrap();
        assert_eq!(b.object_count(), 0);
    }
}
