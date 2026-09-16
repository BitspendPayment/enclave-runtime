//! Durable, tenant-bound background work. One queue owner per mounted filesystem.
//!
//! A synced temporary file is atomically renamed to publish each record. The
//! record itself is the scheduling index; notifications are only an optimization.
//! Recovery tolerates unpublished temporary files, never malformed live records.
//! Execution is at least once: handlers must deduplicate their effects by run ID.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use s3fs_core::{Fs, Inode, OpenFlags};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use wasmtime_wasi::HostWallClock;

use crate::clock::WallClockAdapter;
use crate::state::State;
use crate::tenant::ensure_dir;

const MAX_PAYLOAD: usize = 64 * 1024;
const MAX_RECORD: usize = 1024 * 1024;
const MAX_ATTEMPTS: u32 = 5;
const DIR: &str = "/runtime/tasks";

#[derive(Debug, Clone)]
pub struct TaskLimits {
    pub concurrency: usize,
    pub max_records: usize,
    pub per_tenant: usize,
    pub timeout: Duration,
}
impl Default for TaskLimits {
    fn default() -> Self {
        Self {
            concurrency: 1,
            max_records: 1024,
            per_tenant: 64,
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub version: u32,
    pub tenant: [u8; 16],
    pub id: String,
    pub payload: Vec<u8>,
    pub run_at: u64,
    pub requested_run_at: u64,
    pub generation: [u8; 16],
    pub interval_ms: Option<u64>,
    pub status: Status,
    pub attempts: u32,
    pub occurrence: u64,
    pub result: Vec<u8>,
    pub error: Option<String>,
}
impl Task {
    pub fn run_id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.id,
            hex::encode(self.generation),
            self.occurrence
        )
    }
    fn key(&self) -> String {
        key(self.tenant, &self.id)
    }
    fn terminal(&self) -> bool {
        matches!(
            self.status,
            Status::Completed | Status::Failed | Status::Cancelled
        )
    }
}
fn key(tenant: [u8; 16], id: &str) -> String {
    format!("{}-{id}", hex::encode(tenant))
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Default)]
struct Records {
    tasks: BTreeMap<String, Task>,
    due: BTreeSet<(u64, String)>,
    active: BTreeSet<String>,
    last_tenant: Option<[u8; 16]>,
}
pub struct TaskQueue {
    fs: Arc<Fs>,
    dir: Arc<Inode>,
    clock: Arc<WallClockAdapter>,
    pub limits: TaskLimits,
    records: Mutex<Records>,
    changed: Notify,
}
impl TaskQueue {
    pub async fn open(
        fs: Arc<Fs>,
        clock: Arc<WallClockAdapter>,
        limits: TaskLimits,
    ) -> Result<Arc<Self>> {
        ensure!(
            limits.concurrency > 0
                && limits.max_records > 0
                && limits.per_tenant > 0
                && !limits.timeout.is_zero(),
            "task limits must be positive"
        );
        let runtime = ensure_dir(&fs, &fs.root(), "runtime").await?;
        let dir = ensure_dir(&fs, &runtime, "tasks").await?;
        let queue = Arc::new(Self {
            fs,
            dir,
            clock,
            limits,
            records: Mutex::new(Records::default()),
            changed: Notify::new(),
        });
        let mut records = queue.records.lock().await;
        for entry in queue.fs.read_dir(&queue.dir).await? {
            if entry.name.ends_with(".tmp") {
                queue.fs.unlink(&queue.dir, &entry.name).await?;
                continue;
            }
            ensure!(
                records.tasks.len() < queue.limits.max_records,
                "task store exceeds configured quota"
            );
            let h = queue
                .fs
                .open(&format!("{DIR}/{}", entry.name), OpenFlags::read_only())
                .await?;
            let bytes = queue.fs.pread(&h, 0, MAX_RECORD + 1).await;
            queue.fs.close(&h).await?;
            let bytes = bytes?;
            ensure!(bytes.len() <= MAX_RECORD, "oversized task record");
            let mut task: Task = serde_json::from_slice(&bytes).context("decoding task record")?;
            ensure!(
                task.version == 1
                    && valid_id(&task.id)
                    && task.key() == entry.name
                    && task.payload.len() <= MAX_PAYLOAD
                    && task.result.len() <= MAX_PAYLOAD
                    && task.interval_ms.is_none_or(|i| i >= 1000),
                "invalid task record"
            );
            // Retry interrupted attempts with their original occurrence ID.
            if task.status == Status::Running {
                task.status = if task.attempts >= MAX_ATTEMPTS {
                    Status::Failed
                } else {
                    Status::Pending
                };
                task.error = Some("enclave stopped during execution".into());
                queue.write(&task).await?;
                tracing::warn!(tenant = %hex::encode(task.tenant), task = %task.id,
                    status = ?task.status, attempts = task.attempts,
                    "background task attempt interrupted by a restart");
            }
            if task.status == Status::Pending {
                // Recovery jitter prevents a fleet of overdue tasks firing together.
                let due = task
                    .run_at
                    .max(queue.now().saturating_add(offset(&task.key(), 1000)));
                records.due.insert((due, task.key()));
            }
            records.tasks.insert(task.key(), task);
        }
        drop(records);
        Ok(queue)
    }
    pub fn now(&self) -> u64 {
        self.clock.now().as_millis().min(u64::MAX as u128) as u64
    }
    async fn write(&self, task: &Task) -> Result<()> {
        let bytes = serde_json::to_vec(task)?;
        ensure!(bytes.len() <= MAX_RECORD, "task record exceeds limit");
        let temp = format!("{}.tmp", task.key());
        // Remove an unpublished write left by a cancelled host call.
        match self.fs.unlink(&self.dir, &temp).await {
            Ok(()) | Err(s3fs_core::FsError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let h = self
            .fs
            .open(&format!("{DIR}/{temp}"), OpenFlags::create_new())
            .await?;
        let write = self.fs.pwrite(&h, 0, &bytes).await;
        let close = self.fs.close(&h).await;
        write?;
        close?; // close commits the complete contents before publication
        self.fs
            .rename(&self.dir, &temp, &self.dir, &task.key())
            .await?;
        Ok(())
    }
    pub async fn enqueue(
        &self,
        tenant: [u8; 16],
        id: String,
        payload: Vec<u8>,
        run_at: u64,
        interval_ms: Option<u64>,
    ) -> Result<()> {
        ensure!(valid_id(&id), "invalid task id");
        ensure!(payload.len() <= MAX_PAYLOAD, "task payload exceeds 64 KiB");
        ensure!(
            interval_ms.is_none_or(|i| i >= 1000),
            "interval must be at least 1000 ms"
        );
        crate::tenant::existing_tenant_root(&self.fs, tenant).await?;
        let mut r = self.records.lock().await;
        let k = key(tenant, &id);
        if let Some(old) = r.tasks.get(&k) {
            ensure!(
                old.payload == payload
                    && old.interval_ms == interval_ms
                    && old.requested_run_at == run_at,
                "task id already used with different input"
            );
            return Ok(());
        }
        ensure!(
            r.tasks.len() < self.limits.max_records
                && r.tasks.values().filter(|t| t.tenant == tenant).count() < self.limits.per_tenant,
            "task quota reached; forget terminal tasks"
        );
        let mut generation = [0; 16];
        getrandom::fill(&mut generation)
            .map_err(|e| anyhow::anyhow!("task identity entropy: {e}"))?;
        let task = Task {
            version: 1,
            tenant,
            id,
            payload,
            run_at,
            requested_run_at: run_at,
            generation,
            interval_ms,
            status: Status::Pending,
            attempts: 0,
            occurrence: 0,
            result: vec![],
            error: None,
        };
        self.write(&task).await?;
        r.due.insert((run_at, k.clone()));
        r.tasks.insert(k, task);
        self.changed.notify_one();
        Ok(())
    }
    pub async fn status(&self, tenant: [u8; 16], id: &str) -> Result<Task> {
        self.records
            .lock()
            .await
            .tasks
            .get(&key(tenant, id))
            .cloned()
            .context("no such task")
    }
    pub async fn cancel(&self, tenant: [u8; 16], id: &str) -> Result<()> {
        let mut r = self.records.lock().await;
        let k = key(tenant, id);
        let mut task = r.tasks.get(&k).cloned().context("no such task")?;
        task.status = Status::Cancelled;
        self.write(&task).await?;
        r.tasks.insert(k.clone(), task);
        r.due.retain(|(_, candidate)| candidate != &k);
        self.changed.notify_one();
        Ok(())
    }
    pub async fn forget(&self, tenant: [u8; 16], id: &str) -> Result<()> {
        let mut r = self.records.lock().await;
        let k = key(tenant, id);
        ensure!(
            !r.active.contains(&k) && r.tasks.get(&k).context("no such task")?.terminal(),
            "task is still active"
        );
        self.fs.unlink(&self.dir, &k).await?;
        r.tasks.remove(&k);
        Ok(())
    }
    async fn due(&self) -> Option<Task> {
        let mut r = self.records.lock().await;
        let now = self.now();
        // Deadlines decide eligibility; ready tenants then take turns. A
        // tenant with a backlog of old tasks must not monopolize the worker
        // until that entire backlog has drained. Inspect only due records,
        // bounded by max_records, and preserve deadline order within a tenant.
        let ((at, k), tenant) = r
            .due
            .iter()
            .take_while(|(at, _)| *at <= now)
            .filter_map(|entry| r.tasks.get(&entry.1).map(|task| (entry, task.tenant)))
            .min_by_key(|((at, _), tenant)| {
                (
                    r.last_tenant.is_some_and(|last| *tenant <= last),
                    *tenant,
                    *at,
                )
            })
            .map(|(entry, tenant)| (entry.clone(), tenant))?;
        r.due.remove(&(at, k.clone()));
        r.last_tenant = Some(tenant);
        r.active.insert(k.clone());
        r.tasks.get(&k).cloned()
    }
    pub(crate) async fn begin(&self, task: &Task) -> Result<bool> {
        let mut r = self.records.lock().await;
        let mut current = r
            .tasks
            .get(&task.key())
            .cloned()
            .context("task disappeared")?;
        if current.status != Status::Pending {
            return Ok(false);
        }
        current.status = Status::Running;
        current.attempts += 1;
        self.write(&current).await?;
        r.tasks.insert(current.key(), current);
        Ok(true)
    }
    async fn finish(&self, task: &Task, outcome: Result<Option<Vec<u8>>>) -> Result<()> {
        let mut r = self.records.lock().await;
        let k = task.key();
        let mut current = r.tasks.get(&k).cloned().context("task disappeared")?;
        r.active.remove(&k);
        if current.status == Status::Cancelled {
            return Ok(());
        }
        if matches!(outcome, Ok(None)) {
            // A busy tenant never spends a retry or writes another record.
            r.due.insert((self.now().saturating_add(100), k));
            return Ok(());
        }
        ensure!(
            current.status == Status::Running,
            "task could not persist its execution intent"
        );
        match outcome {
            Ok(Some(bytes)) => {
                current.result = bytes;
                current.error = None;
                if let Some(interval) = current.interval_ms {
                    current.status = Status::Pending;
                    current.attempts = 0;
                    current.occurrence = current
                        .occurrence
                        .checked_add(1)
                        .context("occurrence overflow")?;
                    // First full interval after now, with a stable per-job phase.
                    let now = self.now();
                    let phase = offset(&k, interval);
                    let position = now % interval;
                    let delay = if phase > position {
                        phase - position
                    } else {
                        interval - (position - phase)
                    };
                    current.run_at = now.saturating_add(delay);
                } else {
                    current.status = Status::Completed;
                }
            }
            Err(e) => {
                // `{:#}` keeps the causes: a trap or a deadline is otherwise
                // recorded as its outermost context and nothing of why.
                current.error = Some(format!("{e:#}").chars().take(512).collect());
                current.status = if current.attempts >= MAX_ATTEMPTS {
                    Status::Failed
                } else {
                    Status::Pending
                };
                current.run_at = self
                    .now()
                    .saturating_add(1000u64 << current.attempts.min(8));
            }
            Ok(None) => unreachable!(),
        }
        self.write(&current).await?;
        // A failure is logged with its reason. The record is sealed, so
        // otherwise the only thing an operator sees is that five attempts
        // failed. The text is what the guest could already print to its own
        // log; `?` escapes it so it cannot forge lines of its own.
        match &current.error {
            Some(error) => tracing::warn!(tenant = %hex::encode(current.tenant),
                task = %current.id, status = ?current.status, attempts = current.attempts,
                error = ?error, "background task attempt failed"),
            None => tracing::info!(tenant = %hex::encode(current.tenant), task = %current.id,
                status = ?current.status, attempts = current.attempts,
                "background task recorded"),
        }
        if current.status == Status::Pending {
            r.due.insert((current.run_at, k.clone()));
        }
        r.tasks.insert(k, current);
        Ok(())
    }
    pub async fn run(self: Arc<Self>, guest: Arc<crate::serve::ServeHandle>) -> Result<()> {
        let mut workers = tokio::task::JoinSet::new();
        loop {
            while workers.len() < self.limits.concurrency {
                let Some(task) = self.due().await else {
                    break;
                };
                let queue = self.clone();
                let guest = guest.clone();
                workers.spawn(async move {
                    let result = guest.run_background(&queue, &task).await;
                    queue.finish(&task, result).await
                });
            }
            let next = self.records.lock().await.due.first().map(|(at, _)| *at);
            let wait = Duration::from_millis(
                next.map(|at| at.saturating_sub(self.now()).max(1))
                    .unwrap_or(60_000)
                    .min(60_000),
            );
            tokio::select! {
                result = workers.join_next(), if !workers.is_empty() => { result.context("worker missing")???; },
                _ = self.changed.notified() => {},
                _ = tokio::time::sleep(wait), if workers.len() < self.limits.concurrency => {},
            }
        }
    }
}
fn offset(key: &str, interval: u64) -> u64 {
    let hash = nitro_attestation::sha256(key.as_bytes());
    u64::from_le_bytes(hash[..8].try_into().unwrap()) % interval
}

#[derive(Clone)]
pub struct TaskContext {
    pub queue: Arc<TaskQueue>,
    pub tenant: [u8; 16],
    pub interactive: bool,
}
fn context(state: &State, mutation: bool) -> Result<TaskContext> {
    let ctx = state
        .tasks
        .clone()
        .context("tasks require an authenticated tenant and enabled scheduler")?;
    ensure!(
        !mutation || ctx.interactive,
        "background work cannot authorize more work"
    );
    Ok(ctx)
}
/// The ABI is defined in wit/tasks/tasks.wit. No tenant ID is accepted.
pub fn add_to_linker(linker: &mut wasmtime::component::Linker<State>) -> wasmtime::Result<()> {
    let mut queue = linker.instance("enclave:tasks/queue@0.1.0")?;
    queue.func_wrap_async(
        "enqueue",
        |store, (id, payload, at, interval): (String, Vec<u8>, u64, Option<u64>)| {
            Box::new(async move {
                let result = async move {
                    let ctx = context(store.data(), true)?;
                    ctx.queue
                        .enqueue(ctx.tenant, id, payload, at, interval)
                        .await
                }
                .await;
                Ok((result.map_err(|e| e.to_string()),))
            })
        },
    )?;
    queue.func_wrap_async("status", |store, (id,): (String,)| {
        Box::new(async move {
            let result: Result<String> = async move {
                let ctx = context(store.data(), false)?;
                Ok(serde_json::to_string(
                    &ctx.queue.status(ctx.tenant, &id).await?,
                )?)
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    queue.func_wrap_async("cancel", |store, (id,): (String,)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.queue.cancel(ctx.tenant, &id).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    queue.func_wrap_async("forget", |store, (id,): (String,)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.queue.forget(ctx.tenant, &id).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{HostClock, TrustedClock};
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, MasterSecret};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Clone)]
    struct Clock(Arc<AtomicU64>);
    impl TrustedClock for Clock {
        fn now(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::Relaxed)))
        }
        fn resolution(&self) -> Duration {
            Duration::from_millis(1)
        }
        fn describe(&self) -> String {
            "test".into()
        }
    }
    async fn queue(limits: TaskLimits) -> (Arc<TaskQueue>, Clock) {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([9; 32]),
            [1; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        for tenant in [[1; 16], [2; 16]] {
            crate::tenant::tenant_root_by_id(&fs, tenant).await.unwrap();
        }
        let clock = Clock(Arc::new(AtomicU64::new(1000)));
        let queue = TaskQueue::open(
            fs,
            Arc::new(WallClockAdapter::new(Box::new(clock.clone())).unwrap()),
            limits,
        )
        .await
        .unwrap();
        (queue, clock)
    }
    async fn add(q: &TaskQueue, tenant: u8, id: &str, at: u64) {
        q.enqueue([tenant; 16], id.into(), vec![tenant], at, None)
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn identity_quota_and_idempotency_are_tenant_scoped() {
        let (q, _) = queue(TaskLimits {
            per_tenant: 1,
            ..Default::default()
        })
        .await;
        add(&q, 1, "same", 0).await;
        add(&q, 1, "same", 0).await;
        add(&q, 2, "same", 0).await;
        assert!(q
            .enqueue([1; 16], "same".into(), vec![2], 0, None)
            .await
            .is_err());
        assert!(q
            .enqueue([1; 16], "same".into(), vec![1], 5, None)
            .await
            .is_err());
        assert!(q
            .enqueue([1; 16], "other".into(), vec![], 0, None)
            .await
            .is_err());
        assert_eq!(q.status([2; 16], "same").await.unwrap().payload, vec![2]);
        assert!(q.cancel([3; 16], "same").await.is_err());
        assert!(q
            .enqueue([3; 16], "new".into(), vec![], 0, None)
            .await
            .is_err());
        q.cancel([1; 16], "same").await.unwrap();
        q.forget([1; 16], "same").await.unwrap();
        add(&q, 1, "other", 0).await;
        assert!(q
            .enqueue([2; 16], "../escape".into(), vec![], 0, None)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn ready_tenants_take_turns_instead_of_draining_one_backlog() {
        let (q, _) = queue(Default::default()).await;
        add(&q, 1, "old-a", 0).await;
        add(&q, 1, "old-b", 0).await;
        add(&q, 2, "newer", 500).await;
        assert_eq!(q.due().await.unwrap().tenant, [1; 16]);
        assert_eq!(q.due().await.unwrap().tenant, [2; 16]);
        assert_eq!(q.due().await.unwrap().tenant, [1; 16]);
    }

    #[tokio::test]
    async fn interrupted_execution_recovers_with_the_same_run_id() {
        let (q, clock) = queue(Default::default()).await;
        add(&q, 1, "job", 0).await;
        let task = q.due().await.unwrap();
        assert!(q.begin(&task).await.unwrap());
        let fs = q.fs.clone();
        let timer = q.clock.clone();
        drop(q);
        let recovered = TaskQueue::open(fs, timer, Default::default())
            .await
            .unwrap();
        clock.0.store(10_000, Ordering::Relaxed);
        let again = recovered.due().await.unwrap();
        assert_eq!(again.run_id(), task.run_id());
        assert_eq!(again.attempts, 1);
        recovered.begin(&again).await.unwrap();
        recovered
            .finish(&again, Ok(Some(b"done".to_vec())))
            .await
            .unwrap();
        let result = recovered.status([1; 16], "job").await.unwrap();
        assert_eq!(result.status, Status::Completed);
        assert_eq!(result.result, b"done");
        let reopened = TaskQueue::open(
            recovered.fs.clone(),
            recovered.clock.clone(),
            Default::default(),
        )
        .await
        .unwrap();
        assert!(reopened.due().await.is_none());
        assert_eq!(
            reopened.status([1; 16], "job").await.unwrap().result,
            b"done"
        );
    }
    #[tokio::test]
    async fn cancellation_wins_over_an_inflight_completion() {
        let (q, _) = queue(Default::default()).await;
        add(&q, 1, "job", 0).await;
        let task = q.due().await.unwrap();
        q.begin(&task).await.unwrap();
        q.cancel([1; 16], "job").await.unwrap();
        assert!(q.forget([1; 16], "job").await.is_err());
        q.finish(&task, Ok(Some(vec![]))).await.unwrap();
        assert_eq!(
            q.status([1; 16], "job").await.unwrap().status,
            Status::Cancelled
        );
        q.forget([1; 16], "job").await.unwrap();
        add(&q, 1, "job", 0).await;
        assert_ne!(
            q.status([1; 16], "job").await.unwrap().run_id(),
            task.run_id()
        );
    }
    #[tokio::test]
    async fn retries_back_off_and_eventually_stop() {
        let (q, clock) = queue(Default::default()).await;
        add(&q, 1, "job", 0).await;
        for attempt in 1..=MAX_ATTEMPTS {
            let task = q.due().await.unwrap();
            q.begin(&task).await.unwrap();
            q.finish(&task, Err(anyhow::anyhow!("failed")))
                .await
                .unwrap();
            let record = q.status([1; 16], "job").await.unwrap();
            assert_eq!(record.attempts, attempt);
            assert!(q.due().await.is_none());
            clock.0.store(record.run_at, Ordering::Relaxed);
        }
        assert!(q.due().await.is_none());
        assert_eq!(
            q.status([1; 16], "job").await.unwrap().status,
            Status::Failed
        );
    }
    /// The recorded error names why, not only the outermost context.
    #[tokio::test]
    async fn a_failure_records_its_cause() {
        let (q, _) = queue(Default::default()).await;
        add(&q, 1, "job", 0).await;
        let task = q.due().await.unwrap();
        q.begin(&task).await.unwrap();
        let error = anyhow::anyhow!("co-signer refused the run id").context("run-task failed");
        q.finish(&task, Err(error)).await.unwrap();
        let record = q.status([1; 16], "job").await.unwrap();
        assert_eq!(
            record.error.as_deref(),
            Some("run-task failed: co-signer refused the run id")
        );
    }
    /// The same backoff, but driven by a guest that really fails.
    ///
    /// `retries_back_off_and_eventually_stop` hands the error to `finish`
    /// directly, so the component is never asked. That shape cannot show the
    /// two things this one is for: that a failure *inside* the guest reaches
    /// the queue at all, and that the occurrence keeps its run id across every
    /// retry — the at-least-once promise, checked against a real guest rather
    /// than against a synthetic error.
    #[tokio::test]
    #[ignore = "requires built guest-http component"]
    async fn a_guest_that_returns_an_error_retries_until_the_occurrence_is_failed() {
        let (q, clock) = queue(Default::default()).await;
        let handle = guest(&q).await;
        q.enqueue([1; 16], "job".into(), b"fail".to_vec(), 0, None)
            .await
            .unwrap();
        let run_id = q.status([1; 16], "job").await.unwrap().run_id();

        for attempt in 1..=MAX_ATTEMPTS {
            let task = q.due().await.unwrap();
            assert_eq!(task.run_id(), run_id, "a retry was given a new run id");
            let result = handle.run_background(&q, &task).await;
            let error = format!("{:#}", result.as_ref().expect_err("the guest failed"));
            assert!(
                error.contains("example task failure"),
                "the guest's own message did not survive the host round trip: {error}"
            );
            q.finish(&task, result).await.unwrap();
            let record = q.status([1; 16], "job").await.unwrap();
            assert_eq!(record.attempts, attempt);
            assert!(q.due().await.is_none());
            clock.0.store(record.run_at, Ordering::Relaxed);
        }

        assert!(q.due().await.is_none());
        assert_eq!(
            q.status([1; 16], "job").await.unwrap().status,
            Status::Failed
        );

        // The guest writes one file per run id, and only on success. Nothing
        // here ever succeeded, so nothing should be there — which is what
        // separates five real invocations from one cached result replayed five
        // times. The directory itself exists because the guest creates it
        // before it looks at the payload.
        let root = crate::tenant::existing_tenant_root(&q.fs, [1; 16])
            .await
            .unwrap();
        let dir = q.fs.lookup_at(&root, "http-example").await.unwrap();
        let tasks = q.fs.lookup_at(&dir, "tasks").await.unwrap();
        let names: Vec<String> =
            q.fs.read_dir(&tasks)
                .await
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
        assert!(
            !names.iter().any(|n| n.starts_with("job")),
            "a task that only ever failed still wrote a result: {names:?}"
        );
    }
    #[tokio::test]
    async fn recurring_checks_coalesce_and_do_not_replay_missed_intervals() {
        let (q, clock) = queue(Default::default()).await;
        q.enqueue([1; 16], "job".into(), vec![], 0, Some(1000))
            .await
            .unwrap();
        let first = q.due().await.unwrap();
        q.begin(&first).await.unwrap();
        clock.0.store(1_000_000, Ordering::Relaxed);
        q.finish(&first, Ok(Some(vec![]))).await.unwrap();
        let next = q.status([1; 16], "job").await.unwrap();
        assert!(next.run_at > 1_000_000 && next.run_at <= 1_001_000);
        assert_eq!(next.occurrence, 1);
        assert!(q.due().await.is_none());
        clock.0.store(next.run_at, Ordering::Relaxed);
        assert_ne!(q.due().await.unwrap().run_id(), first.run_id());
    }
    #[tokio::test]
    async fn unpublished_files_are_ignored_but_live_corruption_is_refused() {
        let (q, _) = queue(Default::default()).await;
        let h =
            q.fs.open(&format!("{DIR}/orphan.tmp"), OpenFlags::create_new())
                .await
                .unwrap();
        q.fs.pwrite(&h, 0, b"incomplete").await.unwrap();
        q.fs.close(&h).await.unwrap();
        let recovered = TaskQueue::open(q.fs.clone(), q.clock.clone(), Default::default())
            .await
            .unwrap();
        assert!(recovered.due().await.is_none());
        let h =
            q.fs.open(&format!("{DIR}/bad"), OpenFlags::create_new())
                .await
                .unwrap();
        q.fs.close(&h).await.unwrap();
        assert!(
            TaskQueue::open(q.fs.clone(), q.clock.clone(), Default::default())
                .await
                .is_err()
        );
    }
    async fn guest(q: &Arc<TaskQueue>) -> Arc<crate::serve::ServeHandle> {
        guest_with_pool(q, Arc::new(crate::Tenancy::new(Default::default()))).await
    }
    async fn guest_with_pool(
        q: &Arc<TaskQueue>,
        pool: Arc<crate::Tenancy>,
    ) -> Arc<crate::serve::ServeHandle> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm");
        let bytes = std::fs::read(path).expect("build examples/guest-http for wasm32-wasip2");
        let (logs, _collector) = crate::guest_io::start(Arc::new(crate::TracingLogSink));
        let env = crate::GuestEnvironment::new(
            q.fs.clone(),
            Box::new(HostClock),
            Arc::new(nitro_nsm::fake::FakeNsm::new()),
            &[],
            &[],
            logs,
        )
        .unwrap();
        let engine = crate::ServeHandle::engine_with_watchdog().unwrap();
        let handle = crate::ServeHandle::new(&engine, &bytes, env)
            .unwrap()
            .with_tenancy(pool)
            .with_tasks(q.clone())
            .unwrap();
        handle.verify_instantiates().await.unwrap();
        Arc::new(handle)
    }
    async fn request(
        handle: &crate::ServeHandle,
        tenant: u8,
        method: &str,
        path: &str,
        payload: &[u8],
    ) -> (u16, Vec<u8>) {
        use http_body_util::BodyExt;
        let body = http_body_util::Full::new(bytes::Bytes::copy_from_slice(payload))
            .map_err(|e: std::convert::Infallible| -> wasmtime_wasi_http::p2::bindings::http::types::ErrorCode { match e {} })
            .boxed_unsync();
        let req = hyper::Request::builder()
            .method(method)
            .header("host", "enclave.test")
            .uri(path)
            .body(body)
            .unwrap();
        let response = handle
            .handle(
                wasmtime_wasi_http::p2::bindings::http::types::Scheme::Https,
                req,
                Some(&[tenant; 16]),
            )
            .await
            .unwrap();
        (
            response.status().as_u16(),
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }
    #[tokio::test]
    #[ignore = "requires built guest-http component"]
    async fn client_submits_then_restarted_worker_runs_only_that_tenant() {
        let (q, clock) = queue(Default::default()).await;
        let handle = guest(&q).await;
        assert_eq!(
            request(&handle, 1, "POST", "/tasks/job", b"alice").await.0,
            202
        );
        assert_eq!(request(&handle, 2, "GET", "/tasks/job", b"").await.0, 404);
        drop(handle);
        let reopened = TaskQueue::open(q.fs.clone(), q.clock.clone(), Default::default())
            .await
            .unwrap();
        clock.0.store(20_000, Ordering::Relaxed);
        let handle = guest(&reopened).await;
        let task = reopened.due().await.unwrap();
        let result = handle.run_background(&reopened, &task).await;
        reopened.finish(&task, result).await.unwrap();
        assert_eq!(
            reopened.status([1; 16], "job").await.unwrap().status,
            Status::Completed
        );
        let record = reopened.status([1; 16], "job").await.unwrap();
        assert_eq!(record.result, b"alice");
        assert!(q
            .fs
            .lookup_at(
                &crate::tenant::existing_tenant_root(&q.fs, [2; 16])
                    .await
                    .unwrap(),
                "http-example"
            )
            .await
            .is_err());
        assert_eq!(request(&handle, 1, "GET", "/tasks/job", b"").await.0, 200);
    }
    #[tokio::test]
    #[ignore = "requires built guest-http component"]
    async fn background_cannot_enqueue_and_cpu_loop_releases_tenant() {
        let (q, _) = queue(TaskLimits {
            timeout: Duration::from_millis(500),
            ..Default::default()
        })
        .await;
        let handle = guest(&q).await;
        q.enqueue(
            [1; 16],
            "authority".into(),
            b"check-authority".to_vec(),
            0,
            None,
        )
        .await
        .unwrap();
        let task = q.due().await.unwrap();
        let result = handle.run_background(&q, &task).await;
        assert!(result.is_ok(), "{result:?}");
        q.finish(&task, result).await.unwrap();
        assert!(q.status([1; 16], "unauthorized").await.is_err());
        q.enqueue([1; 16], "loop".into(), b"spin".to_vec(), 0, None)
            .await
            .unwrap();
        let task = q.due().await.unwrap();
        let result = handle.run_background(&q, &task).await;
        assert!(result.is_err());
        q.finish(&task, result).await.unwrap();
        assert_eq!(request(&handle, 1, "GET", "/memory", b"").await.0, 200);
    }
    #[tokio::test]
    async fn published_task_survives_a_fresh_filesystem_mount() {
        let backend = Arc::new(MemoryBackend::new());
        let master = MasterSecret::from_bytes([7; 32]);
        let fs = Fs::create(
            backend.clone(),
            backend.clone(),
            &master,
            [8; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        crate::tenant::tenant_root_by_id(&fs, [1; 16])
            .await
            .unwrap();
        let clock = Arc::new(WallClockAdapter::new(Box::new(HostClock)).unwrap());
        let q = TaskQueue::open(fs.clone(), clock.clone(), Default::default())
            .await
            .unwrap();
        add(&q, 1, "durable", 0).await;
        let run_id = q.status([1; 16], "durable").await.unwrap().run_id();
        drop(q);
        drop(fs);
        let fs = Fs::mount(
            backend.clone(),
            backend,
            &master,
            [8; 16],
            Arc::new(Config::default()),
            None,
        )
        .await
        .unwrap();
        let reopened = TaskQueue::open(fs, clock, Default::default())
            .await
            .unwrap();
        assert_eq!(
            reopened.status([1; 16], "durable").await.unwrap().run_id(),
            run_id
        );
    }

    /// Recurrence, through the scheduler's own sleep and wake.
    ///
    /// `recurring_checks_coalesce_and_do_not_replay_missed_intervals` drives
    /// `due` and `finish` by hand against a frozen clock, which is the only way
    /// to ask about coalescing — and is also exactly what removes the thing
    /// under test here: that the running loop re-arms itself and fires a second
    /// time with nobody poking it.
    ///
    /// So this one takes `HostClock` deliberately. Under the tests' frozen
    /// clock the loop would sleep the interval in real time and then find
    /// nothing due, because `now()` never moved — and wait for ever.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires built guest-http component"]
    async fn a_recurring_task_fires_again_through_the_running_scheduler() {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend,
            &MasterSecret::from_bytes([9; 32]),
            [1; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        crate::tenant::tenant_root_by_id(&fs, [1; 16])
            .await
            .unwrap();
        let q = TaskQueue::open(
            fs,
            Arc::new(WallClockAdapter::new(Box::new(HostClock)).unwrap()),
            Default::default(),
        )
        .await
        .unwrap();
        let handle = guest(&q).await;

        // The minimum the queue accepts, so the second occurrence is a second
        // away rather than a test that waits on nothing.
        q.enqueue([1; 16], "beat".into(), b"tick".to_vec(), 0, Some(1000))
            .await
            .unwrap();
        let worker = tokio::spawn(q.clone().run(handle));

        // Two files with distinct run ids, rather than `occurrence == 1`: a
        // counter moving only proves a record was rewritten, where two files
        // prove the guest's handler was entered a second time.
        let names = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                assert!(!worker.is_finished(), "scheduler stopped");
                if let Ok(root) = crate::tenant::existing_tenant_root(&q.fs, [1; 16]).await {
                    if let Ok(dir) = q.fs.lookup_at(&root, "http-example").await {
                        if let Ok(tasks) = q.fs.lookup_at(&dir, "tasks").await {
                            let names: Vec<String> =
                                q.fs.read_dir(&tasks)
                                    .await
                                    .unwrap()
                                    .into_iter()
                                    .map(|e| e.name)
                                    .filter(|n| n.starts_with("beat"))
                                    .collect();
                            if names.len() >= 2 {
                                return names;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("a recurring task never fired a second time");

        worker.abort();
        let _ = worker.await;

        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "two occurrences shared one run id: {names:?}"
        );
        // A success resets the attempt count. A recurrence that had been
        // quietly retrying would say otherwise.
        assert_eq!(q.status([1; 16], "beat").await.unwrap().attempts, 0);
    }
    #[tokio::test]
    #[ignore = "requires built guest-http component"]
    async fn busy_tenant_does_not_consume_a_retry_or_block_other_tenants() {
        let (q, _) = queue(TaskLimits {
            concurrency: 1,
            ..Default::default()
        })
        .await;
        let pool = Arc::new(crate::Tenancy::new(Default::default()));
        let checkout = pool.pool().checkout(&[1; 16]);
        let lock = checkout.slot().tenant().clone().lock_owned().await;
        let handle = guest_with_pool(&q, pool).await;
        add(&q, 1, "blocked", 0).await;
        add(&q, 2, "ready", 0).await;
        let worker = tokio::spawn(q.clone().run(handle));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(q.records.lock().await.active.len() <= 1);
                if q.status([2; 16], "ready").await.unwrap().status == Status::Completed {
                    break;
                }
                assert!(!worker.is_finished(), "scheduler stopped");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(q.status([1; 16], "blocked").await.unwrap().attempts, 0);
        assert_eq!(
            q.status([1; 16], "blocked").await.unwrap().status,
            Status::Pending
        );
        worker.abort();
        let _ = worker.await;
        drop(lock);
    }

    #[tokio::test]
    #[ignore = "requires built guest-http component"]
    async fn missing_tenant_is_never_recreated_by_a_worker() {
        let (q, _) = queue(Default::default()).await;
        let handle = guest(&q).await;
        add(&q, 1, "job", 0).await;
        let parent = q.fs.lookup_at(&q.fs.root(), "tenants").await.unwrap();
        q.fs.rmdir(&parent, &hex::encode([1; 16])).await.unwrap();
        let task = q.due().await.unwrap();
        assert!(handle.run_background(&q, &task).await.is_err());
        assert!(crate::tenant::existing_tenant_root(&q.fs, [1; 16])
            .await
            .is_err());
    }
    #[tokio::test]
    #[ignore = "requires built guest-http component"]
    async fn simultaneous_due_tasks_stay_within_the_worker_limit() {
        let (q, _) = queue(TaskLimits {
            concurrency: 3,
            ..Default::default()
        })
        .await;
        let handle = guest(&q).await;
        for tenant in 1..=16 {
            crate::tenant::tenant_root_by_id(&q.fs, [tenant; 16])
                .await
                .unwrap();
            for job in 0..3 {
                add(&q, tenant, &format!("job-{job}"), 0).await;
            }
        }
        let worker = tokio::spawn(q.clone().run(handle));
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let r = q.records.lock().await;
                assert!(
                    r.active.len() <= 3,
                    "background concurrency exceeded its limit"
                );
                assert!(!worker.is_finished(), "scheduler stopped");
                if r.tasks
                    .values()
                    .all(|task| task.status == Status::Completed)
                {
                    assert!(r
                        .tasks
                        .values()
                        .all(|task| task.result == vec![task.tenant[0]]));
                    break;
                }
                assert!(!r.tasks.values().any(|task| task.status == Status::Failed));
                drop(r);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the due batch did not drain");
        worker.abort();
        let _ = worker.await;
    }
}
