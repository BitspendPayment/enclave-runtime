//! Async rename queue.
//!
//! `Fs::rename` rewires the inode tree synchronously and returns
//! immediately; the underlying S3 work (CopyObject + DeleteObject for a
//! file, paginated recursion for a directory) runs on a long-lived
//! background worker.
//!
//! While the worker is in flight, the destination inode carries a
//! `RenameState { old_key, … }`; `InodeTree::current_s3_key` returns the
//! OLD key for any read/write so callers continue to see the existing
//! object. Once the worker finishes, `rename_state` is cleared and the
//! natural new key is used.
//!
//! Errors from the worker are stashed on `RenameState::error` and surface
//! on the next `Fs::sync` / `Fs::rename` for that inode.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::backend::{Backend, CopyBlobInput, ListBlobsInput};
use crate::errors::{FsError, FsResult};
use crate::inode::Inode;

/// One unit of work for the rename worker.
pub enum RenameJob {
    File {
        backend: Arc<dyn Backend>,
        inode: Arc<Inode>,
        old_key: String,
        new_key: String,
    },
    Dir {
        backend: Arc<dyn Backend>,
        inode: Arc<Inode>,
        old_prefix: String,
        new_prefix: String,
    },
}

impl std::fmt::Debug for RenameJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenameJob::File {
                old_key, new_key, ..
            } => write!(f, "RenameJob::File {{ {old_key} -> {new_key} }}"),
            RenameJob::Dir {
                old_prefix,
                new_prefix,
                ..
            } => write!(f, "RenameJob::Dir {{ {old_prefix} -> {new_prefix} }}"),
        }
    }
}

#[derive(Debug)]
pub struct RenameQueue {
    job_tx: mpsc::UnboundedSender<RenameJob>,
    cancel: CancellationToken,
    worker: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl RenameQueue {
    pub fn new() -> Self {
        let (job_tx, mut job_rx) = mpsc::unbounded_channel::<RenameJob>();
        let cancel = CancellationToken::new();
        let cancel_for_worker = cancel.clone();
        let worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_for_worker.cancelled() => break,
                    maybe_job = job_rx.recv() => {
                        let Some(job) = maybe_job else { break };
                        // Each job runs in its own task so a slow recursive
                        // dir rename doesn't head-of-line block file renames.
                        tokio::spawn(run_job(job));
                    }
                }
            }
        });
        Self {
            job_tx,
            cancel,
            worker: parking_lot::Mutex::new(Some(worker)),
        }
    }

    pub fn enqueue(&self, job: RenameJob) -> FsResult<()> {
        self.job_tx
            .send(job)
            .map_err(|_| FsError::Io("rename queue closed".into()))
    }
}

impl Default for RenameQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RenameQueue {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(h) = self.worker.lock().take() {
            h.abort();
        }
    }
}

async fn run_job(job: RenameJob) {
    match job {
        RenameJob::File {
            backend,
            inode,
            old_key,
            new_key,
        } => {
            let res = run_file_rename(backend, &inode, &old_key, &new_key).await;
            finish(&inode, res);
        }
        RenameJob::Dir {
            backend,
            inode,
            old_prefix,
            new_prefix,
        } => {
            let res = run_dir_rename(backend, &inode, &old_prefix, &new_prefix).await;
            finish(&inode, res);
        }
    }
}

async fn run_file_rename(
    backend: Arc<dyn Backend>,
    inode: &Arc<Inode>,
    old_key: &str,
    new_key: &str,
) -> FsResult<()> {
    let _g = inode.rename_lock.lock().await;
    backend
        .copy_blob(CopyBlobInput {
            source_key: old_key.to_string(),
            destination_key: new_key.to_string(),
            replace_metadata: None,
            replace_content_type: None,
        })
        .await?;
    backend.delete_blob(old_key).await?;
    Ok(())
}

async fn run_dir_rename(
    backend: Arc<dyn Backend>,
    inode: &Arc<Inode>,
    old_prefix: &str,
    new_prefix: &str,
) -> FsResult<()> {
    let _g = inode.rename_lock.lock().await;
    let mut continuation: Option<String> = None;
    loop {
        let listing = backend
            .list_blobs(ListBlobsInput {
                prefix: old_prefix,
                delimiter: None,
                continuation_token: continuation.as_deref(),
                max_keys: None,
                ..Default::default()
            })
            .await?;
        for item in &listing.items {
            let suffix = match item.key.strip_prefix(old_prefix) {
                Some(s) => s,
                None => continue,
            };
            let dst_key = format!("{new_prefix}{suffix}");
            backend
                .copy_blob(CopyBlobInput {
                    source_key: item.key.clone(),
                    destination_key: dst_key,
                    replace_metadata: None,
                    replace_content_type: None,
                })
                .await?;
            backend.delete_blob(&item.key).await?;
        }
        if !listing.is_truncated {
            break;
        }
        match listing.next_continuation_token {
            Some(t) => continuation = Some(t),
            None => break,
        }
    }
    Ok(())
}

/// Clear the inode's `rename_state` on success (so future ops use the new
/// key); on error, stash the error in `rename_state.error` so the next
/// `sync` for the inode surfaces it. Always notify `done` so any waiter
/// (e.g. tests, future explicit `wait_for_rename`) wakes up.
fn finish(inode: &Arc<Inode>, res: FsResult<()>) {
    let state = inode.rename_state();
    match res {
        Ok(()) => {
            *inode.rename_state.write() = None;
            if let Some(s) = state {
                s.done.notify_waiters();
            }
        }
        Err(e) => {
            if let Some(s) = state {
                *s.error.write() = Some(e);
                s.done.notify_waiters();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_aborts_worker_cleanly() {
        let q = RenameQueue::new();
        drop(q); // should not panic / hang
    }
}
