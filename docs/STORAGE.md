# Storage

The encrypted filesystem behind `wasi:filesystem`. A guest uses ordinary file APIs; this document describes what happens underneath, how the store's identity is checked at boot, how SQLite runs on it, and how to embed the engine without the runtime.

The engine began as **s3-wasi-fs** and remains independently usable through `s3fs-core`, without Wasmtime or enclave hardware.

## How it works

### From a pathname to a root record

```text
wasi:filesystem descriptors and streams
                 │
                 ▼
Fs: paths, links, directories, handles, buffered records
                 │
                 ▼
Directory B+tree ──► object IDs ──► dnode array
                                     │
                            indirect block trees
                                     │
                         encrypted blocks in slabs
                                     │
                         signed root record + chain
```

Files and directories are addressed by object ID. Directory entries live in a separator-indexed B+tree. Dnodes describe objects and point into variable-width indirect block trees. Modified paths are rebuilt copy-on-write, so a commit publishes a new tree while older roots continue to describe their original state.

Blocks carry AES-256-GCM authentication and BLAKE3 checksums. Their authentication binds them to their expected position, preventing a valid block from simply being moved elsewhere in the tree. Keys derive from a 32-byte master secret and filesystem identity through HKDF. The data bucket holds slab objects; the roots bucket holds the signed history and runtime bootstrap objects.

Verifying a root authenticates the pointers beneath it; each block is verified when read. Mounting does **not** eagerly read or scrub every file.

### Commit and recovery

A transaction stages changed blocks and dnodes, uploads its slabs, waits for those uploads, then publishes a signed root with a conditional PUT. Publishing that root is the visibility boundary. A failed upload must not publish a tree pointing to missing data. Failed file sync retains dirty buffers for a retry.

The current transaction protocol also publishes a claim before a newly opened session encrypts blocks, and reclaims after an abandoned or failed transaction. Its purpose is to avoid reusing `(transaction group, block sequence)` as an AEAD nonce after a crash or competing mount. S3 accepts a conditional PUT over a delete marker, so publication then reads back the retained version: a mount whose record was not written first loses, even when its PUT succeeded.

This is a **single-writer filesystem**. Independent writable mounts and multiple active schedulers are not a supported deployment model. A conflict poisons the losing mount rather than silently merging histories.

### Filesystem behavior

| Operation or property | Behavior |
|---|---|
| Read/write/stat/list/sync | Implemented through the core `Fs` API and WASI adapter. File writes are buffered; sync/close drives durability. |
| Rename | Directory-entry changes commit atomically; moving a directory does not copy every descendant. Moves into the directory's own subtree are rejected. |
| Sparse files | Growth creates holes; reads return zeroes without materializing all intervening blocks. |
| Hard links | Multiple directory entries reference one object, with a maintained link count. |
| Symlinks | Supported, with a default traversal limit of 40 and resolution confined to the guest's filesystem scope. |
| Unlink while open | The open handle retains access until its final close. |
| Identity and metadata | Object identity, link counts, and timestamps come from the filesystem rather than inferred S3 filenames. |
| Snapshots | Historical root records can be opened read-only through `Fs::open_snapshot` or the store API; they share unchanged blocks. They are not an automatic guest-visible snapshot directory. |
| Freshness | The session floor only rises. `--min-root-seq` supplies an external floor for a cold mount. |
| Space reclamation | Garbage collection is not implemented. Historical and orphaned slabs consume storage. |

The detailed [compatibility matrix](COMPATIBILITY.md) describes WASI/POSIX differences. This is a WASI filesystem implementation and embeddable Rust engine, not a host FUSE mount or a general replacement for a Linux filesystem.

### Defaults and cost model

| Store setting | Default |
|---|---:|
| Record size | 128 KiB |
| Maximum slab size | 64 MiB |
| Decrypted block-cache budget | 64 MiB |
| Concurrent slab PUTs | 8 |
| Root-chain links checked at mount | 1 |
| Per-root COMPLIANCE retention | 10 × 365 days |

[`StoreConfig`](../crates/s3fs-core/src/store/config.rs) validates these settings. Record sizes must be powers of two from 4 KiB through 1 MiB. Retention is finite: an operational retention policy must account for the history a deployment still relies on.

S3 round trips dominate durable mutations. Batching application work reduces commit overhead; smaller writes may still rewrite a whole record and its tree path. Tenant handlers can execute concurrently, but their commits share one transaction lock. Snapshot sharing avoids copying the whole filesystem, while retaining old state still costs space for its changed blocks.

## State identity at boot

A missing store is not automatically an invitation to create an empty replacement. The boot machine checks the retained state-origin receipt, the sealed-key object, the genesis root, and the record for the running runtime/guest pair.

The origin commitment includes the filesystem ID, data and roots buckets, prefix, genesis root hash, and the SHA-256 of the sealed-key representation. It is encoded with a domain tag and CBOR, then hashed with BLAKE3. The receipt attests to that commitment.

| Observed state | Outcome |
|---|---|
| No origin receipt and no existing state | Genesis: provision key material, create the store, publish origin and pair records. |
| State exists without its receipt, or receipt exists without required state | Refuse to boot. |
| Origin and this runtime/guest pair verify | Resume. |
| Origin verifies but this pair has no record | Upgrade path: record the new pair after key release and state verification. |
| Existing origin/pair record is inconsistent or invalid | Refuse to boot. |

Bucket identity and policy live in the measured image. Otherwise, a host could point an approved runtime at a different empty bucket and make a new store look legitimate.

[`Backend::get_retained_blob`](../crates/s3fs-core/src/backend/mod.rs) reads object versions beneath delete markers. The S3 backend follows version-list pagination and fetches a selected version by ID. Missing version-list permissions cause a failure rather than a false report that no record exists. The retained version is the oldest one listed, and root publication uses the same read to confirm it wrote first.

## Running SQLite

SQLite is the main application-level filesystem workload: real C code performs page-granular random I/O, rollback-journal updates, and integrity checks. [`guest-sqlite`](../examples/guest-sqlite/) covers DDL, transactions, savepoints, constraints, joins, CTEs, window functions, blobs, triggers, schema changes, `VACUUM`, JSON, FTS5, and R-Tree where available.

Build it using wasi-sdk:

```bash
scripts/wasi-sdk.sh
scripts/build-guest.sh sqlite

deploy/qemu-nitro/dev-enclave.sh \
  --guest examples/guest-sqlite/target/wasm32-wasip2/release/guest-sqlite.wasm \
  --guest-env S3FS_BACKGROUND_TASKS=false
```

SQLite exports the HTTP handler, not `run-task`, so the override disables the emulator's default background-task startup requirement. Using the printed pins, request `/` with `passkey-client` to run the workload. The response reports `OK` or a failure; timings go to guest output. Each run removes and recreates its benchmark database, so use a dedicated development tenant and do not treat `/` as a health check. `SQLITE_SCALE` controls the workload size; the current example defaults to 2,000 rows.

The two required pragmas are:

```rust
conn.pragma_update(None, "temp_store", "MEMORY")?;
conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
```

SQLite's temporary-directory probing and advisory locking assume syscalls that this WASI environment does not supply. Use the default rollback-journal mode (`DELETE`). WAL requires the shared-memory/mapping facilities this configuration lacks. Runtime serialization protects one tenant from concurrent callbacks; the guest must still avoid opening competing SQLite connections inside its own invocation.

### Recorded workload results

The following are the repository's earlier measurements against local MinIO with 20,000 accounts and 40,000 entries. They were **not rerun for this documentation update**, are not current release benchmarks, and should not be extrapolated to remote S3 latency.

| Phase | Elapsed | Rate |
|---|---:|---:|
| Bulk insert, 20,000 rows in one transaction | 142 ms | 140,884 rows/s |
| Point select by row ID | 2.5 ms | 405,948 queries/s |
| Indexed select | 1.3 ms | 785,850 queries/s |
| Update 500 rows in one transaction | 63 ms | 7,963 rows/s |
| Blob write | 128 ms | 18.5 MB/s |
| Blob read and verify | 41 ms | 57.8 MB/s |
| Incremental blob I/O, 512 KiB scattered | 242 ms | 2.2 MB/s |
| `VACUUM` | 471 ms | — |
| `PRAGMA integrity_check` | 136 ms | — |
| 25 inserts, autocommit | 1,796 ms | 14 rows/s |
| 25 inserts, one SQL transaction | 69 ms | 364 rows/s |

The practical lesson is to batch writes. A SQL transaction is not necessarily one block-store commit—journal and filesystem sync operations matter—but it can greatly reduce durable round trips compared with repeated autocommit statements.

## Use the storage engine directly

`s3fs-core` can be embedded independently. This complete example creates an in-memory filesystem, commits a file, remounts it, and reads it back. It needs `s3fs-core` and Tokio with macros and a runtime; no NSM, Wasmtime, Docker, or AWS credentials are involved.

```rust
use std::sync::Arc;
use s3fs_core::{backend::memory::MemoryBackend, Config, Fs, MasterSecret, OpenFlags};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = Arc::new(MemoryBackend::new());
    let roots = Arc::new(MemoryBackend::new());
    let secret = MasterSecret::from_bytes([7; 32]); // Example only.
    let fs_id = [3; 16];
    let config = Arc::new(Config::default());

    let fs = Fs::create(data.clone(), roots.clone(), &secret, fs_id, config.clone()).await?;
    let file = fs.open("/hello.txt", OpenFlags::create_new()).await?;
    fs.pwrite(&file, 0, b"hello from encrypted storage").await?;
    fs.sync(&file).await?;
    fs.close(&file).await?;
    drop(fs);

    let fs = Fs::mount(data, roots, &secret, fs_id, config, None).await?;
    let file = fs.open("/hello.txt", OpenFlags::read_only()).await?;
    let bytes = fs.pread(&file, 0, 64).await?;
    assert_eq!(bytes.as_ref(), b"hello from encrypted storage");
    fs.close(&file).await?;
    Ok(())
}
```

For S3, enable **`s3fs-core`'s** `aws` feature and supply separate `AwsS3Backend` instances for the data and roots buckets. Create the roots bucket with Object Lock support and appropriate retention. Keep the master secret and filesystem ID outside untrusted storage; they select the keys used to verify the store. Use `Fs::create` only for an intentional new filesystem and `Fs::mount` for an existing one.

An embedded consumer owns its provisioning, boot policy, freshness floor, and handle lifecycle. The runtime's origin receipts, tenant gate, and KMS orchestration are higher layers, not automatic side effects of calling the core API.
