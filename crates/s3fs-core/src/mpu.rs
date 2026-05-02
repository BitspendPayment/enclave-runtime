//! `MpuState` — per-file multipart-upload state machine.
//!
//! Tracks which parts have been uploaded for an in-flight MPU and which are
//! still missing (and therefore need either a fresh `UploadPart` or a
//! server-side `UploadPartCopy` from the source object during commit).
//!
//! The load-bearing logic is [`MpuState::copy_plan`]: it walks the parts
//! vector in order and produces a list of `UploadPartCopy` entries for the
//! gaps, coalescing adjacent gaps up to `max_merge_copy_bytes`. This is the
//! Rust port of GeeseFS's `copyUnmodifiedParts`.
//!
//! The driver function [`commit`] consumes the plan, issues backend calls,
//! and finishes with `CompleteMultipartUpload`. A small-file fast path
//! (`single_put_commit`) skips MPU entirely when no upload was ever begun.
//!
//! The "MPU started but content is sub-part" fallback (abort + materialize +
//! single PUT) is reserved for the flusher integration in a later session;
//! commits in that state currently return `Invalid` to surface the case
//! during tests.

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{self, StreamExt};

use crate::backend::{Backend, BlobMeta, CompletedPart, MultipartId, PutBlobInput};
use crate::config::PartSchedule;
use crate::errors::{FsError, FsResult};

/// One uploaded part — the etag S3 hands back from `UploadPart` /
/// `UploadPartCopy`, plus a hint about how it got there (useful for tests
/// and metrics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartInfo {
    pub etag: String,
    pub source: PartSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartSource {
    /// `UploadPart` of bytes we held in the buffer pool.
    Uploaded,
    /// `UploadPartCopy` from `source_offset..source_offset+source_len` of the
    /// source object. Records the byte range so commit-time merges can be
    /// reconstructed.
    CopiedFromSelf { source_offset: u64, source_len: u64 },
}

/// One entry in a copy plan. Each becomes one `UploadPartCopy` call.
///
/// `part_index` is the *new* part's slot (0-based; `part_number = part_index + 1`).
/// When a plan entry merges multiple adjacent missing slots, `part_index` is
/// the lowest slot in the merged run; the higher slots remain unfilled in
/// the parts vector and are simply omitted from `CompleteMultipartUpload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPlanEntry {
    pub part_index: u32,
    pub source_offset: u64,
    pub source_len: u64,
}

/// Per-file MPU state. Owned by the file inode (or its handle).
#[derive(Debug)]
pub struct MpuState {
    /// Destination key (where the final object will live).
    pub key: String,
    /// Source object's size in bytes (the value we'd `HeadObject` and read).
    /// `None` means no source (fresh file).
    pub source_size: Option<u64>,
    /// Source object's ETag for optimistic-concurrency `If-Match` (optional;
    /// not yet wired through).
    pub source_etag: Option<String>,
    /// MPU id from `CreateMultipartUpload`. `None` until lazy begin.
    pub upload_id: Option<MultipartId>,
    /// Per-part-index entries. `None` means "not uploaded — needs to be
    /// either uploaded fresh or copied from source on commit." `parts.len()`
    /// is grown as needed by `record_part_*`.
    pub parts: Vec<Option<PartInfo>>,
    /// Highest part index touched. `-1` means no parts yet.
    pub high_water: i32,
    /// Schedule (for `part_range` lookups during `copy_plan`).
    pub schedule: PartSchedule,
}

impl MpuState {
    pub fn new(
        key: String,
        source_size: Option<u64>,
        source_etag: Option<String>,
        schedule: PartSchedule,
    ) -> Self {
        Self {
            key,
            source_size,
            source_etag,
            upload_id: None,
            parts: Vec::new(),
            high_water: -1,
            schedule,
        }
    }

    /// `true` iff `multipart_begin` has been called and no commit/abort yet.
    pub fn has_upload(&self) -> bool {
        self.upload_id.is_some()
    }

    fn ensure_capacity(&mut self, part_index: u32) {
        let needed = part_index as usize + 1;
        if self.parts.len() < needed {
            self.parts.resize(needed, None);
        }
        if (part_index as i32) > self.high_water {
            self.high_water = part_index as i32;
        }
    }

    /// Record a successful `UploadPart` for `part_index`.
    pub fn record_part_uploaded(&mut self, part_index: u32, etag: String) {
        self.ensure_capacity(part_index);
        self.parts[part_index as usize] = Some(PartInfo {
            etag,
            source: PartSource::Uploaded,
        });
    }

    /// Record a successful `UploadPartCopy` for `part_index`.
    pub fn record_part_copied(
        &mut self,
        part_index: u32,
        source_offset: u64,
        source_len: u64,
        etag: String,
    ) {
        self.ensure_capacity(part_index);
        self.parts[part_index as usize] = Some(PartInfo {
            etag,
            source: PartSource::CopiedFromSelf {
                source_offset,
                source_len,
            },
        });
    }

    /// Compute the plan for `copy_unmodified_parts`. Walks part indices
    /// `0..=high_water`; for each gap (`parts[i] == None`) that lies within
    /// the source object, emits a `CopyPlanEntry`. Adjacent gaps are merged
    /// up to `max_merge_copy_bytes`.
    pub fn copy_plan(&self, max_merge_copy_bytes: u64) -> Vec<CopyPlanEntry> {
        let source_size = self.source_size.unwrap_or(0);
        if source_size == 0 || self.high_water < 0 {
            return Vec::new();
        }
        let high = self.high_water as u32;
        let mut plan = Vec::new();
        // Active merge run, if any: (start_part_index, source_start, source_end).
        let mut run: Option<(u32, u64, u64)> = None;

        let flush_run = |run: &mut Option<(u32, u64, u64)>, plan: &mut Vec<CopyPlanEntry>| {
            if let Some((idx, s, e)) = run.take() {
                plan.push(CopyPlanEntry {
                    part_index: idx,
                    source_offset: s,
                    source_len: e - s,
                });
            }
        };

        for i in 0..=high {
            let already_uploaded = matches!(self.parts.get(i as usize), Some(Some(_)));
            let part_range = match self.schedule.part_range(i) {
                Some(r) => r,
                None => break, // exceeded schedule
            };
            let copy_start = part_range.start;
            let copy_end = part_range.end.min(source_size);
            let in_source = copy_end > copy_start;

            if !already_uploaded && in_source {
                let extend = match run.as_ref() {
                    None => false,
                    Some((_, run_s, run_e)) => {
                        let extends_contiguously = *run_e == copy_start;
                        let proposed_len = copy_end - *run_s;
                        extends_contiguously && proposed_len <= max_merge_copy_bytes
                    }
                };
                if extend {
                    if let Some((_, _, run_e)) = run.as_mut() {
                        *run_e = copy_end;
                    }
                } else {
                    flush_run(&mut run, &mut plan);
                    run = Some((i, copy_start, copy_end));
                }
            } else {
                flush_run(&mut run, &mut plan);
            }
        }
        flush_run(&mut run, &mut plan);
        plan
    }

    /// Build the `CompleteMultipartUpload` payload from `parts`. Skips empty
    /// slots (those covered by a merged copy) and emits the rest in
    /// ascending part-number order.
    pub fn build_completed_parts(&self) -> FsResult<Vec<CompletedPart>> {
        let mut out = Vec::new();
        for (i, entry) in self.parts.iter().enumerate() {
            if let Some(p) = entry {
                out.push(CompletedPart {
                    part_number: (i as u32) + 1,
                    e_tag: p.etag.clone(),
                });
            }
        }
        if out.is_empty() {
            return Err(FsError::Invalid("commit with no parts"));
        }
        Ok(out)
    }
}

// --- Driver functions ---------------------------------------------------

/// Small-file fast path: no MPU was ever begun. Issue a single `PutObject`
/// with the assembled body and return.
pub async fn single_put_commit(
    backend: &dyn Backend,
    key: &str,
    body: Bytes,
) -> FsResult<BlobMeta> {
    backend
        .put_blob(PutBlobInput {
            key: key.to_string(),
            body,
            metadata: Default::default(),
            content_type: None,
        })
        .await
}

/// Drive a full MPU commit: issue every `UploadPartCopy` from the plan
/// (concurrently, capped at `max_parallel_copy`), then `CompleteMultipartUpload`.
///
/// Preconditions:
/// - All dirty parts must have already been uploaded (caller's job).
/// - `state.upload_id` must be `Some` — call `single_put_commit` for the
///   no-MPU case.
/// - `source_key` is the key to read unchanged ranges from. For an in-place
///   update of `state.key`, pass `state.key` itself; for a fresh write that
///   never had a source, the copy plan should be empty so this argument
///   doesn't matter.
pub async fn commit(
    state: &mut MpuState,
    backend: Arc<dyn Backend>,
    max_merge_copy_bytes: u64,
    max_parallel_copy: usize,
    source_key: &str,
) -> FsResult<BlobMeta> {
    let upload_id = state
        .upload_id
        .clone()
        .ok_or(FsError::Invalid("commit on MpuState without upload_id"))?;

    let plan = state.copy_plan(max_merge_copy_bytes);
    if !plan.is_empty() {
        let key = Arc::new(state.key.clone());
        let source_key = Arc::new(source_key.to_string());
        let upload_id = Arc::new(upload_id.clone());

        let cap = max_parallel_copy.max(1);
        let copy_results: Vec<FsResult<(CopyPlanEntry, String)>> =
            stream::iter(plan.into_iter().map(|entry| {
                let backend = backend.clone();
                let key = key.clone();
                let source_key = source_key.clone();
                let upload_id = upload_id.clone();
                async move {
                    let out = backend
                        .multipart_upload_part_copy(
                            key.as_str(),
                            &upload_id,
                            entry.part_index + 1,
                            source_key.as_str(),
                            entry.source_offset..entry.source_offset + entry.source_len,
                        )
                        .await?;
                    Ok::<_, FsError>((entry, out.e_tag))
                }
            }))
            .buffer_unordered(cap)
            .collect()
            .await;

        for r in copy_results {
            let (entry, etag) = r?;
            state.record_part_copied(
                entry.part_index,
                entry.source_offset,
                entry.source_len,
                etag,
            );
        }
    }

    let parts = state.build_completed_parts()?;
    let meta = backend
        .multipart_complete(&state.key, &upload_id, parts)
        .await?;

    // Mark complete (drop the upload_id so further operations on this state
    // know the MPU is gone).
    state.upload_id = None;
    Ok(meta)
}

/// Abort an in-flight MPU. Idempotent; safe to call when `upload_id` is None.
pub async fn abort(state: &mut MpuState, backend: &dyn Backend) -> FsResult<()> {
    if let Some(id) = state.upload_id.take() {
        backend.multipart_abort(&state.key, &id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::MemoryBackend;
    use crate::backend::PutBlobInput;
    use crate::config::Config;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn small_schedule() -> PartSchedule {
        // 4-byte parts × 100 → 400 bytes total. Easy to reason about in tests.
        PartSchedule {
            tiers: vec![(4, 100)],
        }
    }

    fn medium_schedule() -> PartSchedule {
        // 5 MiB × 1000 only. Same as the first tier of the default schedule.
        PartSchedule {
            tiers: vec![(5 * 1024 * 1024, 1000)],
        }
    }

    fn fresh_backend() -> Arc<MemoryBackend> {
        Arc::new(MemoryBackend::new())
    }

    async fn put_source(backend: &MemoryBackend, key: &str, body: Vec<u8>) {
        backend
            .put_blob(PutBlobInput {
                key: key.into(),
                body: Bytes::from(body),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
    }

    // ---- copy_plan unit tests (pure logic, no backend) -------------------

    #[test]
    fn copy_plan_no_source_is_empty() {
        let s = MpuState::new("k".into(), None, None, small_schedule());
        assert!(s.copy_plan(1024).is_empty());
    }

    #[test]
    fn copy_plan_no_high_water_is_empty() {
        let s = MpuState::new("k".into(), Some(100), None, small_schedule());
        // No parts touched → high_water=-1 → empty.
        assert!(s.copy_plan(1024).is_empty());
    }

    #[test]
    fn copy_plan_all_uploaded_no_copies() {
        let mut s = MpuState::new("k".into(), Some(12), None, small_schedule());
        // Source is 12 bytes = 3 full parts. Upload all 3.
        s.record_part_uploaded(0, "e1".into());
        s.record_part_uploaded(1, "e2".into());
        s.record_part_uploaded(2, "e3".into());
        assert!(s.copy_plan(1024).is_empty());
    }

    #[test]
    fn copy_plan_single_gap_in_middle() {
        let mut s = MpuState::new("k".into(), Some(12), None, small_schedule());
        s.record_part_uploaded(0, "e1".into());
        // skip part 1
        s.record_part_uploaded(2, "e3".into());
        let plan = s.copy_plan(1024);
        assert_eq!(
            plan,
            vec![CopyPlanEntry {
                part_index: 1,
                source_offset: 4,
                source_len: 4
            }]
        );
    }

    #[test]
    fn copy_plan_merges_adjacent_gaps() {
        // Source 20 bytes = 5 parts. Upload only part 0 and part 4.
        // Gaps 1,2,3 should merge into one CopyPlanEntry covering bytes 4..16.
        let mut s = MpuState::new("k".into(), Some(20), None, small_schedule());
        s.record_part_uploaded(0, "e0".into());
        s.record_part_uploaded(4, "e4".into());
        let plan = s.copy_plan(1024);
        assert_eq!(
            plan,
            vec![CopyPlanEntry {
                part_index: 1,
                source_offset: 4,
                source_len: 12
            }]
        );
    }

    #[test]
    fn copy_plan_respects_max_merge_bytes() {
        // Same as above but with a tiny max_merge of 8 bytes.
        let mut s = MpuState::new("k".into(), Some(20), None, small_schedule());
        s.record_part_uploaded(0, "e0".into());
        s.record_part_uploaded(4, "e4".into());
        let plan = s.copy_plan(8);
        assert_eq!(
            plan,
            vec![
                CopyPlanEntry {
                    part_index: 1,
                    source_offset: 4,
                    source_len: 8
                },
                CopyPlanEntry {
                    part_index: 3,
                    source_offset: 12,
                    source_len: 4
                },
            ]
        );
    }

    #[test]
    fn copy_plan_clips_last_gap_to_source_size() {
        // Source 10 bytes. Schedule = 4 bytes/part. high_water = 4 (as if a
        // dirty write extended the file). Parts 0,4 uploaded; gaps 1,2,3.
        // Source covers only bytes 0..10 → part 1 (4..8), part 2 (8..10
        // clipped from 8..12). Part 3 is entirely past source → not in plan.
        let mut s = MpuState::new("k".into(), Some(10), None, small_schedule());
        s.record_part_uploaded(0, "e0".into());
        s.record_part_uploaded(4, "e4".into());
        let plan = s.copy_plan(1024);
        // The merge stops where source ends.
        assert_eq!(
            plan,
            vec![CopyPlanEntry {
                part_index: 1,
                source_offset: 4,
                source_len: 6 // bytes 4..10
            }]
        );
    }

    #[test]
    fn build_completed_parts_skips_empty_slots() {
        let mut s = MpuState::new("k".into(), Some(20), None, small_schedule());
        s.record_part_uploaded(0, "e0".into());
        s.record_part_copied(1, 4, 12, "ec".into());
        // slots 2,3 stay empty (they were merged into slot 1's copy).
        s.record_part_uploaded(4, "e4".into());
        let parts = s.build_completed_parts().unwrap();
        let nums: Vec<_> = parts.iter().map(|p| p.part_number).collect();
        assert_eq!(nums, vec![1, 2, 5]);
    }

    #[test]
    fn build_completed_parts_empty_errors() {
        let s = MpuState::new("k".into(), None, None, small_schedule());
        assert!(matches!(
            s.build_completed_parts(),
            Err(FsError::Invalid(_))
        ));
    }

    // ---- single_put_commit driver ----------------------------------------

    #[tokio::test]
    async fn single_put_commit_writes_object() {
        let b = fresh_backend();
        single_put_commit(b.as_ref(), "small.txt", Bytes::from_static(b"hi"))
            .await
            .unwrap();
        let g = b.get_blob("small.txt", None).await.unwrap();
        assert_eq!(&g.body[..], b"hi");
    }

    // ---- end-to-end MPU lifecycle via the driver -------------------------

    #[tokio::test]
    async fn mpu_lifecycle_in_place_update_uses_copy_for_unchanged_parts() {
        // This is THE load-bearing test: GeeseFS-parity in-place update.
        // Pre-populate "big" with 30 MiB of source bytes.
        let b = fresh_backend();
        let cfg = Config::builder()
            .part_schedule(medium_schedule())
            .max_merge_copy_bytes(128 * 1024 * 1024)
            .build();
        let big_size: u64 = 30 * 1024 * 1024;
        let mut source = vec![0u8; big_size as usize];
        // fill with a recognisable pattern
        for (i, b) in source.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        put_source(&b, "big", source.clone()).await;
        let source_etag = b.head_blob("big").await.unwrap().e_tag;

        // Begin MPU on the same key.
        let id = b
            .multipart_begin(PutBlobInput {
                key: "big".into(),
                body: Bytes::new(),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();

        let mut state = MpuState::new(
            "big".into(),
            Some(big_size),
            Some(source_etag),
            medium_schedule(),
        );
        state.upload_id = Some(id.clone());

        // Modify part_index 2 only (bytes 10MiB..15MiB).
        let part_size = 5 * 1024 * 1024u64;
        let mut new_part2 = vec![0u8; part_size as usize];
        new_part2.fill(0xAB);
        let part2_etag = b
            .multipart_upload_part(
                "big",
                &id,
                3, // part_number = part_index + 1
                Bytes::from(new_part2.clone()),
            )
            .await
            .unwrap();
        state.record_part_uploaded(2, part2_etag.e_tag);
        // We need to advertise high_water = 5 (parts 0..=5 cover 30 MiB).
        // Easiest way: bump high_water by recording a stub for the last index
        // — but we don't want to mark it uploaded. Instead, expose a
        // helper... for the test we'll just nudge directly via re-record on
        // part 5 then "un-record":
        state.high_water = 5; // direct manipulation in tests is fine

        // Run commit. The driver should issue UploadPartCopy for parts
        // {0,1,3,4,5} merged into runs around the modified part 2.
        let cfg_arc = Arc::new(cfg);
        let _committed = commit(
            &mut state,
            b.clone() as Arc<dyn Backend>,
            cfg_arc.max_merge_copy_bytes,
            cfg_arc.max_parallel_copy,
            "big",
        )
        .await
        .unwrap();

        // Verify the resulting object: bytes [10MiB..15MiB) should be 0xAB,
        // everything else should match the original source pattern.
        let g = b.get_blob("big", None).await.unwrap();
        assert_eq!(g.body.len() as u64, big_size);
        for i in 0..big_size as usize {
            let expected = if (10 * 1024 * 1024..15 * 1024 * 1024).contains(&i) {
                0xAB
            } else {
                (i % 251) as u8
            };
            assert_eq!(
                g.body[i], expected,
                "byte {i} should be {expected:#x}, got {:#x}",
                g.body[i]
            );
        }

        // The MPU should be gone (no orphan).
        assert_eq!(b.mpu_count(), 0);
        // And the state's upload_id is cleared.
        assert!(state.upload_id.is_none());
    }

    #[tokio::test]
    async fn abort_clears_upload_id_idempotently() {
        let b = fresh_backend();
        let mut state = MpuState::new("k".into(), None, None, small_schedule());
        // No upload_id → no-op success.
        abort(&mut state, b.as_ref()).await.unwrap();

        let id = b
            .multipart_begin(PutBlobInput {
                key: "k".into(),
                body: Bytes::new(),
                metadata: HashMap::new(),
                content_type: None,
            })
            .await
            .unwrap();
        state.upload_id = Some(id);
        assert_eq!(b.mpu_count(), 1);
        abort(&mut state, b.as_ref()).await.unwrap();
        assert_eq!(b.mpu_count(), 0);
        assert!(state.upload_id.is_none());
        // Idempotent.
        abort(&mut state, b.as_ref()).await.unwrap();
    }

    #[tokio::test]
    async fn commit_without_upload_id_errors() {
        let b = fresh_backend();
        let mut state = MpuState::new("k".into(), None, None, small_schedule());
        let r = commit(&mut state, b.clone() as Arc<dyn Backend>, 1024, 4, "k").await;
        assert!(matches!(r, Err(FsError::Invalid(_))));
    }
}
