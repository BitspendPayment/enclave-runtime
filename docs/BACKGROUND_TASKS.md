# Background tasks

The runtime schedules durable work for individual tenants inside a running
enclave. A tenant with no due work needs no running guest instance. One active
enclave owns the queue; running multiple schedulers over the same filesystem
requires an ownership/fencing protocol that is not implemented here.

## Enable

The guest must export `run-task` and may import the queue interface defined in
[`wit/tasks/tasks.wit`](../wit/tasks/tasks.wit). The HTTP example implements both
its usual `wasi:http` interface and this background interface.

Enable `S3FS_BACKGROUND_TASKS=true` (or `--background-tasks true`) alongside
WebAuthn authentication and tenant isolation. In the Nix deployment, set
`backgroundTasks = true` in `deploy/nix/deployment.nix`. This image configuration
change changes PCR0; rebuilding the example guest changes PCR16. Update the
approved measurements through your normal deployment process.

| Setting | Default | Purpose |
|---|---:|---|
| `S3FS_BACKGROUND_CONCURRENCY` | 1 | Maximum active background workers |
| `S3FS_BACKGROUND_TIMEOUT_SECS` | 30 | Maximum duration of one guest attempt |
| `S3FS_BACKGROUND_MAX_RECORDS` | 1024 | Total durable records, including terminal tasks |
| `S3FS_BACKGROUND_PER_TENANT` | 64 | Records allowed per tenant |

All limits must be positive. Background workers have separate admission from
interactive requests and yield on epoch ticks. They use the same tenant lock,
so one tenant's background and interactive code cannot run simultaneously.
A busy tenant is deferred without spending an execution attempt. Due tenants
take turns, keeping deadline order within each tenant, so one tenant’s backlog
cannot monopolize all execution slots. These limits bound background work; they are not a global limit on interactive traffic or a
reservation of physical CPU cores. Guest linear memory is unrestricted for now.
There is no GPU task execution path.

## Guest contract

During an authenticated interactive call, the guest can call:

```text
enqueue(id, payload, run-at, interval-ms) -> result
status(id)                             -> result<JSON record>
cancel(id)                             -> result
forget(id)                             -> result
```

The runtime supplies the tenant identity from the executing instance. None of
these functions accepts a tenant ID. Anonymous calls and guest initializers
have no queue authority. Queue state lives at `/runtime/tasks` in the shared
encrypted filesystem, above every guest's filesystem scope.

An ID is a tenant-local idempotency key: 1–64 ASCII letters, digits, hyphens or
underscores. Repeating an enqueue with the same ID, payload, requested time and
interval returns the original task. Different input under that ID is refused.
The payload and result each have a 64 KiB limit. Task status includes the state,
attempt count, occurrence, result bytes and a bounded error message. Result
bytes are represented as a JSON array of byte values.

`run-at` is Unix time in milliseconds; zero means immediately. An optional
interval creates a recurring schedule and must be at least 1000 milliseconds.
The guest decides what the payload means and which operations its user may
schedule. A recurring polling task can inspect that tenant's own request files
in each callback. Use enqueue's payload as the durable request when possible:
writing a separate application file and enqueueing are **not** one transaction.

The runtime invokes this component export when the task is due:

```text
run-task(task-id, payload) -> result<result-bytes, error-string>
```

This export is not an HTTP endpoint. It receives the correct tenant's directory
as `/` and an execution deadline. It uses a fresh guest
instance under the same pool lock as HTTP calls; any warm HTTP instance is
dropped first so it cannot retain stale database handles across the mutation.
A missing tenant directory causes failure, never recreation.

The background callback can inspect task status, but cannot enqueue, cancel or
forget tasks. An authenticated interaction grants standing authorization to run
the submitted job later; the original short-lived interaction token is not
replayed. Revoking a passkey does not automatically cancel a tenant's schedules:
use cancellation to revoke that standing job authorization. The approved guest
must validate task types and payloads before enqueueing them. Jobs execute the
currently approved component after an upgrade, so keep payloads compatible or
cancel affected jobs before deploying an incompatible guest.

## Durability and retries

Each full record is written to a temporary file, committed, then atomically
renamed into place. The durable record is the scheduling index. There is no
second notification write whose loss could strand an acknowledged task.
Startup reconstructs the in-memory deadline queue from records and discards
unpublished temporary files; corrupt published records stop startup.

Delivery is **at least once**. An execution intent is persisted before calling
the guest, and the result is persisted after the callback returns. A crash
between an effect and its completion record can repeat the callback. The run ID
contains a random task generation plus an occurrence number; it stays the same
across retries, and changes for a later recurring occurrence or a new task after
`forget`. Deduplicate effects by this ID. Commit guest filesystem writes before
returning success. External effects need their own idempotency mechanism.

Failed attempts retry with exponential backoff, up to five attempts per
occurrence. A recovered running attempt consumes its existing attempt count.
Exhausted tasks become `failed`; recurring schedules stop on terminal failure.
Recurring successes schedule the next occurrence at a stable tenant/job phase.
Missed intervals coalesce into one check rather than being replayed. Overdue
records receive up to one second of recovery jitter, and concurrency remains
bounded even if all tasks are due.

Cancellation prevents future attempts and wins over a late completion record.
It does not undo side effects or forcibly interrupt an already executing
callback. A client's cancellation request may wait for the tenant's running
callback to release the shared lock. `forget` removes a terminal record to free
quota, and refuses records still owned by a worker. Terminal records are not
automatically deleted.

Scheduler storage failures stop the server rather than silently dropping work.
Stopping the enclave stops execution; the scheduler does not start the enclave
itself. Restart recovery shares the filesystem's existing rollback/freshness
assumptions; this queue does not add an external freshness witness.

## HTTP example

The example guest exposes these authenticated application routes:

| Request | Behavior |
|---|---|
| `POST /tasks/<id>` | Enqueue the body as the task payload; returns 202 |
| `GET /tasks/<id>` | Read that tenant's task record |
| `DELETE /tasks/<id>` | Cancel the task |
| `DELETE /tasks/<id>/forget` | Remove a terminal task record |

Optional `x-task-run-at` and `x-task-interval-ms` headers set the requested time
and interval. The callback writes one durable result file per run ID inside the
tenant's `/http-example/tasks/` directory, returning an existing result on retry.
Its `fail`, `spin` and `check-authority` payloads exercise retries, deadlines and
the prohibition on background code authorizing more work.

Build and test:

```sh
cargo build --manifest-path examples/guest-http/Cargo.toml --release --target wasm32-wasip2
cargo test -p enclave-runtime --lib tasks::tests -- --include-ignored
cargo test -p enclave-runtime --test serve_auth scheduled_work -- --include-ignored
```
