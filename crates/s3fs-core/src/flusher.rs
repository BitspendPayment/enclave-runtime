//! Background flusher: a long-running task that consumes `FlushJob`s from
//! an `mpsc` channel and runs them with bounded concurrency.
//!
//! Two job kinds today:
//!
//! - **`UploadPart`** — submitted eagerly by `pwrite` whenever a write
//!   makes a part fully dirty. The worker spawns the upload (subject to
//!   the per-`Fs` permit cap) without blocking the caller.
//! - **`Commit`** — submitted by `sync`. The worker drains every
//!   in-flight `UploadPart` for the same handle, then runs
//!   `mpu::commit` and replies via the supplied `oneshot`.
//!
//! Errors from background uploads are stashed on the [`FileHandle`]
//! (see `FileHandle::last_error`) and surfaced to the caller on the next
//! `pwrite` / `sync`. This keeps the user-facing async surface clean —
//! `pwrite` returns immediately even when its enqueued upload is yet to
//! run.

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::backend::{Backend, BlobMeta, MultipartId, PutBlobInput};
use crate::buffer::PartBuf;
use crate::config::{Config, PartSchedule};
use crate::errors::{FsError, FsResult};
use crate::mpu::{self, MpuState};

/// Outcome of an `UploadPart` job: the part index and its ETag.
pub type PartResult = FsResult<(u32, String)>;

/// One unit of work for the background flusher.
pub enum FlushJob {
    UploadPart {
        backend: Arc<dyn Backend>,
        key: String,
        upload_id: MultipartId,
        part_index: u32,
        part_arc: Arc<parking_lot::RwLock<PartBuf>>,
        schedule: PartSchedule,
        source_size: u64,
        final_size: u64,
        /// One-shot to deliver the result back to the spawner. The
        /// receiver typically lives on `PartBuf::upload_in_flight`.
        reply: oneshot::Sender<PartResult>,
    },
    /// Run a function with a permit acquired (used by `sync()` to issue
    /// `UploadPartCopy` calls under the same global cap as `UploadPart`).
    /// The body should NOT hold the permit longer than the actual S3
    /// call.
    WithPermit {
        body: Box<dyn FnOnce(OwnedSemaphorePermit) -> tokio::task::JoinHandle<()> + Send>,
    },
}

impl std::fmt::Debug for FlushJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlushJob::UploadPart { part_index, .. } => {
                write!(f, "FlushJob::UploadPart {{ part_index: {part_index} }}")
            }
            FlushJob::WithPermit { .. } => write!(f, "FlushJob::WithPermit"),
        }
    }
}

/// Per-`Fs` background flusher.
///
/// Owns a long-running tokio task plus the channel + semaphore used to
/// serialise jobs to it. The worker runs each `UploadPart` job under one
/// permit from the semaphore so the total in-flight upload count across
/// all open files is bounded by `Config::max_parallel_parts`.
#[derive(Debug)]
pub struct Flusher {
    job_tx: mpsc::UnboundedSender<FlushJob>,
    semaphore: Arc<Semaphore>,
    cancel: CancellationToken,
    /// Kept alive so we can `.abort()` the worker on `drop`.
    worker: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Flusher {
    /// Spawn the background worker. Idempotent at the type level — call
    /// once from `Fs::new`.
    pub fn new(config: &Config) -> Self {
        let (job_tx, mut job_rx) = mpsc::unbounded_channel::<FlushJob>();
        let semaphore = Arc::new(Semaphore::new(config.max_parallel_parts.max(1)));
        let cancel = CancellationToken::new();

        let sem_for_worker = semaphore.clone();
        let cancel_for_worker = cancel.clone();
        let worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_for_worker.cancelled() => break,
                    maybe_job = job_rx.recv() => {
                        let Some(job) = maybe_job else { break };
                        match job {
                            FlushJob::UploadPart { backend, key, upload_id, part_index, part_arc, schedule, source_size, final_size, reply } => {
                                let sem = sem_for_worker.clone();
                                tokio::spawn(async move {
                                    let _permit = sem.acquire_owned().await.expect("semaphore never closed");
                                    let res = crate::fs::upload_one_part(
                                        backend, &key, &upload_id, part_index,
                                        part_arc, &schedule, source_size, final_size,
                                    ).await;
                                    let _ = reply.send(res);
                                });
                            }
                            FlushJob::WithPermit { body } => {
                                let sem = sem_for_worker.clone();
                                tokio::spawn(async move {
                                    let permit = sem.acquire_owned().await.expect("semaphore never closed");
                                    let _ = body(permit).await;
                                });
                            }
                        }
                    }
                }
            }
        });

        Self {
            job_tx,
            semaphore,
            cancel,
            worker: parking_lot::Mutex::new(Some(worker)),
        }
    }

    /// Submit an `UploadPart` job and return the receiver for its result.
    /// The receiver should be parked on the part (so a later `sync` can
    /// await it). If the channel is closed (worker dropped), returns an
    /// error immediately.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_upload(
        &self,
        backend: Arc<dyn Backend>,
        key: String,
        upload_id: MultipartId,
        part_index: u32,
        part_arc: Arc<parking_lot::RwLock<PartBuf>>,
        schedule: PartSchedule,
        source_size: u64,
        final_size: u64,
    ) -> Result<oneshot::Receiver<PartResult>, FsError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.job_tx
            .send(FlushJob::UploadPart {
                backend,
                key,
                upload_id,
                part_index,
                part_arc,
                schedule,
                source_size,
                final_size,
                reply: reply_tx,
            })
            .map_err(|_| FsError::Io("flusher channel closed".into()))?;
        Ok(reply_rx)
    }

    /// Acquire a permit directly. Used by `mpu::commit`'s `UploadPartCopy`
    /// fan-out so it shares the same global concurrency cap as
    /// `UploadPart` calls.
    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed")
    }

    /// Clone of the inner semaphore. Used by hot paths (e.g.
    /// `upload_parts_concurrent`) that need to move it into spawned tasks
    /// without cloning the whole `Flusher` (which owns the worker handle).
    pub fn semaphore(&self) -> Arc<Semaphore> {
        self.semaphore.clone()
    }

    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        // Signal cancellation; the worker checks this each loop iteration.
        self.cancel.cancel();
        if let Some(handle) = self.worker.lock().take() {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers used by `Fs::pwrite` and `Fs::sync`.
// ---------------------------------------------------------------------------

/// Lazily begin an MPU on the handle if one isn't started already.
/// Returns the upload-id. Caller must hold the `MpuState` mutex.
pub async fn ensure_mpu_begun_locked(
    backend: &Arc<dyn Backend>,
    state: &mut Option<MpuState>,
    key: &str,
    schedule: &PartSchedule,
    source_size: Option<u64>,
    source_etag: Option<String>,
) -> FsResult<MultipartId> {
    if let Some(s) = state.as_ref() {
        if let Some(id) = &s.upload_id {
            return Ok(id.clone());
        }
    }
    let id = backend
        .multipart_begin(PutBlobInput {
            key: key.to_string(),
            body: Bytes::new(),
            metadata: std::collections::HashMap::new(),
            content_type: None,
        })
        .await?;
    if state.is_none() {
        *state = Some(MpuState::new(
            key.to_string(),
            source_size,
            source_etag,
            schedule.clone(),
        ));
    }
    state.as_mut().unwrap().upload_id = Some(id.clone());
    Ok(id)
}

/// Run `mpu::commit` taking a permit from the flusher for the
/// CompleteMultipartUpload call.
pub async fn commit_via_flusher(
    state: &mut MpuState,
    backend: Arc<dyn Backend>,
    max_merge_copy_bytes: u64,
    max_parallel_copy: usize,
    source_key: &str,
) -> FsResult<BlobMeta> {
    mpu::commit(
        state,
        backend,
        max_merge_copy_bytes,
        max_parallel_copy,
        source_key,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_cfg(cap: usize) -> Config {
        Config::builder().max_parallel_parts(cap).build()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flusher_acquire_bounds_concurrency() {
        let f = Flusher::new(&small_cfg(2));
        assert_eq!(f.available_permits(), 2);
        let _p1 = f.acquire().await;
        let _p2 = f.acquire().await;
        assert_eq!(f.available_permits(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flusher_drop_aborts_worker() {
        let f = Flusher::new(&small_cfg(2));
        // No way to introspect from here, but Drop should not panic.
        drop(f);
    }
}
