//! `PartBuf` — per-part buffer with state machine and dirty-range bookkeeping.
//!
//! Each MPU part lives as one `PartBuf`. Writes are absorbed into the buffer
//! and recorded as dirty ranges; the flusher consults `dirty` to decide
//! whether to upload the whole part or read-modify-write a partial part.
//!
//! ```text
//!     new_clean ──────────────► Clean ◄──────────────────┐
//!                                  │                     │
//!                                  │ apply_write         │ mark_clean
//!                                  ▼                     │
//!     new_empty_dirty ─────────► Dirty ──flush_start──► Flushing
//!                                  ▲                     │
//!                                  │ flush_failed        │ flush_ok
//!                                  └─────────────────────┤
//!                                                        ▼
//!                                                     Flushed
//! ```

use std::ops::Range;

use bytes::{Bytes, BytesMut};

use super::ranges::RangeSet;
use crate::errors::{FsError, FsResult};

/// State machine for a single part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartState {
    /// In sync with what we last fetched from S3 (or, after `mark_clean`,
    /// with what we successfully uploaded).
    Clean,
    /// Local writes have modified bytes in `body`; the dirty subranges live
    /// in `PartBuf::dirty`.
    Dirty,
    /// Currently being uploaded; bytes must not be mutated until the result
    /// arrives.
    Flushing,
    /// `UploadPart` (or `UploadPartCopy`) succeeded; the ETag in
    /// `PartBuf::etag` is what `CompleteMultipartUpload` will reference.
    Flushed,
}

/// One part of a file: its byte buffer, dirty bookkeeping, and state.
#[derive(Debug)]
pub struct PartBuf {
    /// 0-based part index. S3 wire `PartNumber` is `part_index + 1`.
    pub part_index: u32,
    /// Tier capacity for this part. The buffer's logical size is bounded by
    /// this; the *valid* length may be less (last part of a small file).
    pub part_size: u64,
    /// File offset of byte 0 of this part.
    pub part_start: u64,
    /// Number of valid bytes (≤ `part_size`).
    pub valid_len: u64,
    /// Backing storage. Always exactly `valid_len` bytes long; capacity may
    /// be `part_size`-aligned for cheap appends.
    body: BytesMut,
    /// Current state.
    pub state: PartState,
    /// Dirty byte ranges *within the part* (offsets are part-relative).
    pub dirty: RangeSet,
    /// ETag from the last successful upload of this part. `None` until the
    /// first successful flush.
    pub etag: Option<String>,
}

impl PartBuf {
    /// Construct a `Clean` part from bytes fetched from S3.
    ///
    /// `body.len()` becomes `valid_len`. `part_size` may be larger (we just
    /// remember the tier capacity so future writes at higher offsets within
    /// the part can extend.)
    pub fn new_clean(part_index: u32, part_size: u64, part_start: u64, body: Bytes) -> Self {
        let valid_len = body.len() as u64;
        let mut buf = BytesMut::with_capacity(part_size as usize);
        buf.extend_from_slice(&body);
        Self {
            part_index,
            part_size,
            part_start,
            valid_len,
            body: buf,
            state: PartState::Clean,
            dirty: RangeSet::new(),
            etag: None,
        }
    }

    /// Construct an empty `Dirty` part. Used when the file is being grown
    /// past EOF and the part is not yet present in S3 (no need to fetch
    /// before writing). All bytes are initially zero-valued in storage; only
    /// bytes covered by `dirty` should be considered authoritative.
    pub fn new_empty_dirty(part_index: u32, part_size: u64, part_start: u64) -> Self {
        Self {
            part_index,
            part_size,
            part_start,
            valid_len: 0,
            body: BytesMut::with_capacity(part_size as usize),
            state: PartState::Dirty,
            dirty: RangeSet::new(),
            etag: None,
        }
    }

    /// Read access to the underlying bytes (`valid_len` bytes long).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Cost in bytes for buffer-pool memory accounting. Counts the allocated
    /// capacity, not just `valid_len`, so eviction reflects real RAM use.
    pub fn alloc_bytes(&self) -> u64 {
        self.body.capacity() as u64
    }

    /// Apply a write at part-relative `offset_in_part`, copying from `data`.
    ///
    /// Extends `valid_len` if the write reaches past current EOF. Marks the
    /// affected range dirty and transitions state from `Clean → Dirty`.
    /// Errors if the write would exceed `part_size` or if state is not
    /// `Clean`/`Dirty` (i.e. don't write to a part that's `Flushing`).
    pub fn apply_write(&mut self, offset_in_part: u64, data: &[u8]) -> FsResult<()> {
        match self.state {
            PartState::Clean | PartState::Dirty => {}
            PartState::Flushing => {
                return Err(FsError::WouldBlock);
            }
            PartState::Flushed => {
                // Re-dirtying after flush is allowed — the upload was ours,
                // but the user wants to mutate again before commit.
            }
        }
        let end = offset_in_part
            .checked_add(data.len() as u64)
            .ok_or(FsError::Invalid("write overflow"))?;
        if end > self.part_size {
            return Err(FsError::Invalid("write past part_size"));
        }
        // Grow the body if needed.
        if end > self.valid_len {
            let extra = (end - self.valid_len) as usize;
            self.body.extend_from_slice(&vec![0u8; extra]);
            self.valid_len = end;
        }
        let dst = &mut self.body[offset_in_part as usize..end as usize];
        dst.copy_from_slice(data);
        self.dirty.insert(offset_in_part..end);
        self.state = PartState::Dirty;
        self.etag = None; // any prior upload is now stale
        Ok(())
    }

    /// Read part-relative bytes `[offset, offset+len)` into a new `Bytes`.
    /// Returns up to `valid_len` bytes; if the requested range extends past
    /// the valid end, the result is truncated.
    pub fn read(&self, offset_in_part: u64, len: u64) -> Bytes {
        if offset_in_part >= self.valid_len {
            return Bytes::new();
        }
        let end = (offset_in_part + len).min(self.valid_len) as usize;
        let start = offset_in_part as usize;
        Bytes::copy_from_slice(&self.body[start..end])
    }

    /// True iff every byte in `[0, valid_len)` is dirty. Cheap.
    pub fn is_fully_dirty(&self) -> bool {
        self.dirty.covers_range(0..self.valid_len)
    }

    /// Returns the dirty sub-ranges (part-relative).
    pub fn dirty_ranges(&self) -> &[Range<u64>] {
        self.dirty.ranges()
    }

    /// Returns the *clean* (non-dirty) sub-ranges within `[0, valid_len)`,
    /// i.e. the regions that need to be loaded from S3 during a partial
    /// flush's read-modify-write.
    pub fn clean_subranges(&self) -> Vec<Range<u64>> {
        self.dirty.complement_within(0..self.valid_len)
    }

    /// Transition: `Dirty` → `Flushing`. The caller (flusher) must have
    /// just snapshotted `body` for upload; after this, `apply_write` will
    /// fail with `WouldBlock` until the flush completes.
    pub fn mark_flushing(&mut self) -> FsResult<()> {
        if !matches!(self.state, PartState::Dirty) {
            return Err(FsError::Invalid("mark_flushing requires Dirty state"));
        }
        self.state = PartState::Flushing;
        Ok(())
    }

    /// Transition: `Flushing` → `Flushed`. Records the ETag returned by S3.
    /// Dirty ranges are cleared (the upload absorbed them).
    pub fn mark_flushed(&mut self, etag: String) -> FsResult<()> {
        if !matches!(self.state, PartState::Flushing) {
            return Err(FsError::Invalid("mark_flushed requires Flushing state"));
        }
        self.state = PartState::Flushed;
        self.etag = Some(etag);
        self.dirty.clear();
        Ok(())
    }

    /// Transition: `Flushing` → `Dirty` after a failed upload. Dirty ranges
    /// are preserved so the flusher can retry.
    pub fn mark_flush_failed(&mut self) -> FsResult<()> {
        if !matches!(self.state, PartState::Flushing) {
            return Err(FsError::Invalid("mark_flush_failed requires Flushing state"));
        }
        self.state = PartState::Dirty;
        Ok(())
    }

    /// Transition: `Flushed` → `Clean` after a successful
    /// `CompleteMultipartUpload` finalised the part.
    pub fn mark_clean(&mut self) -> FsResult<()> {
        if !matches!(self.state, PartState::Flushed) {
            return Err(FsError::Invalid("mark_clean requires Flushed state"));
        }
        self.state = PartState::Clean;
        // ETag is preserved — it's what `commit` will pass back if we ever
        // re-fetch and want optimistic concurrency.
        Ok(())
    }

    /// Snapshot the body as immutable `Bytes` for upload. Cheap (`Bytes::copy_from_slice`).
    pub fn snapshot(&self) -> Bytes {
        Bytes::copy_from_slice(&self.body)
    }
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)] // `&[a..b]` is a one-element slice of Range — intentional in these asserts
mod tests {
    use super::*;

    fn fresh_clean() -> PartBuf {
        PartBuf::new_clean(0, 16, 0, Bytes::from_static(b"0123456789abcdef"))
    }

    #[test]
    fn new_clean_snapshot_matches_input() {
        let p = fresh_clean();
        assert_eq!(p.state, PartState::Clean);
        assert_eq!(p.valid_len, 16);
        assert_eq!(p.body(), b"0123456789abcdef");
        assert!(p.dirty.is_empty());
        assert!(!p.is_fully_dirty());
    }

    #[test]
    fn new_empty_dirty_starts_zero_len() {
        let p = PartBuf::new_empty_dirty(0, 16, 0);
        assert_eq!(p.state, PartState::Dirty);
        assert_eq!(p.valid_len, 0);
        assert!(p.body().is_empty());
    }

    #[test]
    fn apply_write_marks_dirty_and_grows_body() {
        let mut p = PartBuf::new_empty_dirty(0, 16, 0);
        p.apply_write(0, b"abcd").unwrap();
        assert_eq!(p.state, PartState::Dirty);
        assert_eq!(p.valid_len, 4);
        assert_eq!(p.body(), b"abcd");
        assert_eq!(p.dirty_ranges(), &[0..4]);
    }

    #[test]
    fn apply_write_within_clean_part_marks_dirty() {
        let mut p = fresh_clean();
        p.apply_write(4, b"XYZ").unwrap();
        assert_eq!(p.state, PartState::Dirty);
        assert_eq!(p.body(), b"0123XYZ789abcdef");
        assert_eq!(p.dirty_ranges(), &[4..7]);
    }

    #[test]
    fn apply_write_past_part_size_errors() {
        let mut p = fresh_clean();
        let err = p.apply_write(15, b"XX").unwrap_err();
        assert!(matches!(err, FsError::Invalid(_)));
    }

    #[test]
    fn apply_write_while_flushing_returns_would_block() {
        let mut p = PartBuf::new_empty_dirty(0, 16, 0);
        p.apply_write(0, b"abcd").unwrap();
        p.mark_flushing().unwrap();
        let err = p.apply_write(4, b"x").unwrap_err();
        assert!(matches!(err, FsError::WouldBlock));
    }

    #[test]
    fn read_returns_valid_subrange() {
        let p = fresh_clean();
        assert_eq!(p.read(2, 4)[..], b"2345"[..]);
        // Past valid_len gets clipped.
        assert_eq!(p.read(14, 10)[..], b"ef"[..]);
        // Wholly past valid_len returns empty.
        assert!(p.read(20, 5).is_empty());
    }

    #[test]
    fn fully_dirty_after_full_overwrite() {
        let mut p = PartBuf::new_clean(0, 16, 0, Bytes::from_static(b"0123456789abcdef"));
        p.apply_write(0, b"FFFFFFFFFFFFFFFF").unwrap();
        assert!(p.is_fully_dirty());
        assert_eq!(p.dirty_ranges(), &[0..16]);
    }

    #[test]
    fn clean_subranges_are_complement_of_dirty() {
        let mut p = PartBuf::new_clean(0, 16, 0, Bytes::from_static(b"0123456789abcdef"));
        p.apply_write(2, b"X").unwrap();
        p.apply_write(8, b"Y").unwrap();
        // dirty: 2..3, 8..9 → clean: 0..2, 3..8, 9..16
        assert_eq!(p.clean_subranges(), vec![0..2, 3..8, 9..16]);
    }

    #[test]
    fn state_transitions_happy_path() {
        let mut p = PartBuf::new_empty_dirty(0, 16, 0);
        p.apply_write(0, b"abcd").unwrap();
        p.mark_flushing().unwrap();
        assert_eq!(p.state, PartState::Flushing);
        p.mark_flushed("etag-v1".into()).unwrap();
        assert_eq!(p.state, PartState::Flushed);
        assert_eq!(p.etag.as_deref(), Some("etag-v1"));
        assert!(p.dirty.is_empty());
        p.mark_clean().unwrap();
        assert_eq!(p.state, PartState::Clean);
    }

    #[test]
    fn state_transitions_failure_path() {
        let mut p = PartBuf::new_empty_dirty(0, 16, 0);
        p.apply_write(0, b"abcd").unwrap();
        p.mark_flushing().unwrap();
        p.mark_flush_failed().unwrap();
        // Returned to Dirty, dirty ranges preserved for retry.
        assert_eq!(p.state, PartState::Dirty);
        assert_eq!(p.dirty_ranges(), &[0..4]);
    }

    #[test]
    fn redirty_after_flushed_clears_etag() {
        let mut p = PartBuf::new_empty_dirty(0, 16, 0);
        p.apply_write(0, b"abcd").unwrap();
        p.mark_flushing().unwrap();
        p.mark_flushed("etag-v1".into()).unwrap();
        // Now apply another write — should re-dirty, drop etag.
        p.apply_write(4, b"ef").unwrap();
        assert_eq!(p.state, PartState::Dirty);
        assert!(p.etag.is_none());
    }

    #[test]
    fn invalid_state_transitions_error() {
        let mut p = PartBuf::new_empty_dirty(0, 16, 0);
        // Can't mark_flushing from Dirty-but-empty? Actually we can — Dirty
        // state allows flushing; let's test something that's truly invalid.
        assert!(p.mark_flushed("nope".into()).is_err()); // Dirty → not allowed
        assert!(p.mark_clean().is_err());                // Dirty → not allowed
    }

    #[test]
    fn alloc_bytes_reflects_capacity() {
        let p = PartBuf::new_empty_dirty(0, 16, 0);
        assert!(p.alloc_bytes() >= 16);
    }
}
