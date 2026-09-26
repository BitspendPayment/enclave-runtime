# Compatibility Matrix

What a Wasm guest gets from `wasi:filesystem@0.2.6`, and where it differs from a local filesystem.

The storage engine is a ZFS-style copy-on-write block store: content is held in immutable, AEAD-encrypted blocks packed into slab objects, and the whole filesystem hangs off one signed, hash-chained root record. Every mutation is a single transaction group and therefore a single root record, which is where most of the guarantees below come from.

## ✅ POSIX-equivalent

| WASI op | Notes |
|---|---|
| `read`, `write`, `read-via-stream`, `write-via-stream`, `append-via-stream` | Buffered per handle at record granularity. |
| `sync`, `sync-data` | Commits a transaction group and publishes a new signed root. |
| `stat`, `stat-at` | Read from the dnode on every call, so they cannot go stale. `link-count` and all three timestamps are real values, not placeholders. |
| `set-times`, `set-times-at` | A field write in the dnode. No `CopyObject`, and nothing else to disagree with. |
| `set-size` | Truncate or grow, at any size. Growth is a hole and costs nothing. |
| `create-directory-at`, `remove-directory-at`, `unlink-file-at` | One commit each. |
| **`rename-at`** | **Atomic.** One directory-entry move inside one commit. A directory rename costs the same as a file rename. |
| `read-directory` | Name-ordered, straight from the directory's leaves — no sort step. |
| `symlink-at`, `readlink-at` | Targets up to 294 bytes live in the dnode; longer ones spill to data blocks. Cycle detection at depth 40. |
| `open-at` with `CREATE` / `EXCLUSIVE` / `TRUNCATE` | Create is atomic inside its transaction. |
| **`link-at`** | **Hard links.** A directory entry is an object id, so a link is one more entry and an increment of `nlink`. Files and symlinks only. |
| **`unlink-file-at` while an fd is open** | **POSIX behaviour.** The object stays readable and writable through existing handles until the last one closes. |
| `is-same-object`, `metadata-hash`, `metadata-hash-at` | Exact. Identity is `(object id, generation)`, which is stable across mounts because object ids are never reused. |

**Crash consistency.** The visible state is always a Merkle-verified snapshot, never a torn one. Slabs written by a commit that died before publishing its root are orphans: unreferenced, unreachable, harmless. There is no journal and no fsck.

**Integrity.** Every block read verifies a BLAKE3 checksum against its parent's block pointer and then opens an AEAD whose additional data binds the block to its exact position in the tree. A block cannot be corrupted, forged, substituted, or relocated without the read failing.

**Rollback.** Root records are written with `If-None-Match: *` into a bucket under Object Lock COMPLIANCE retention, and each carries the hash of its predecessor. An adversary with full write access to the buckets can make the filesystem unreadable, but cannot make it read *wrong* and cannot make it read *old*.

## ⚠️ Weakened semantics

| WASI op | Gap | Contract |
|---|---|---|
| Crash while a file is unlinked-but-open | The dnode leaks: allocated, nameless, unreachable. | Garbage, not corruption — the same trade a real filesystem makes with its orphan inode list. Reclaimed by the garbage collector when that lands. |
| Two writers to the same file | Each handle buffers independently; whichever syncs last wins. | Within one mount, use one handle per file. |
| Two mounts of the same buckets | Exactly one can win a given root sequence. The loser is **poisoned**: every subsequent operation fails, including reads. | Deliberate. Retrying would reuse a transaction group and repeat every AEAD nonce in it. Single writer per filesystem. |
| Unsynced writes on a crash | Lost. | The transaction-group model: durability is at `sync` / `close`, and what survives is always consistent. |
| Cold-mount freshness | A store that *hides* roots newer than the one it serves is not cryptographically excluded. Object Lock means those roots cannot be deleted, so this requires S3 itself to lie. | Pass `--min-root-seq` to set a floor from outside the store. Within a session the gap does not exist: the accepted sequence only ever rises. |
| `atime` | Only updated when a handle is synced. | No read-time metadata writes; a commit per read would be absurd. |

A hard link to a *directory* returns `not-permitted`, as on Linux: it would make the namespace a graph rather than a tree, and the dnode's parent link has room for exactly one answer.

## ❌ Not implemented

Nothing in `wasi:filesystem@0.2.6` is unsupported.

## Snapshots

Every root record is a complete, self-verifying snapshot. Copy-on-write means the blocks an older root names were never overwritten, so taking one costs nothing and keeping one costs only the storage its blocks already occupy.

```rust
let snaps = fs.snapshots(10).await?;              // newest first
let snap  = fs.open_snapshot(snaps[3].seq).await?;
let ino   = snap.lookup(&snap.root(), "deleted-file").await?;
let bytes = snap.read(&ino, 0, 4096).await?;
```

Reads through a snapshot verify exactly as the live mount does — same checksums, same position binding — because a snapshot is not a copy of anything. It is the same blocks, reached through an older root.

Opening one does not lower the live mount's rollback floor. Reading history must never become a way to make the store rewind.

## Operational notes

- **The bucket is not browsable.** Contents are opaque, encrypted, content-independent blocks. `aws s3 ls` shows slabs and roots, nothing resembling a path.
- **No garbage collection yet.** Copy-on-write means superseded blocks accumulate. Roots are ~700 bytes each and locked for the full retention term; slabs are the cost driver and live in an unlocked bucket precisely so they can be reclaimed later.
- **Keys are supplied, not discovered.** The master secret and the filesystem id are inputs. The keys that verify a root record derive from them, so reading either out of the store would mean trusting the store to say which key checks its own signature.

## Running SQLite

SQLite works, including `VACUUM`, triggers, foreign-key cascades, recursive
CTEs, window functions, and `PRAGMA integrity_check`. Two settings are needed,
and neither is a limitation of this filesystem:

```rust
conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;  // no fcntl under WASI
conn.pragma_update(None, "temp_store",   "MEMORY")?;     // no access(2) under WASI
```

`temp_store=MEMORY` is the non-obvious one. SQLite locates a directory for
temporary databases by probing candidates with `access(2)`, which WASI does not
provide — so every candidate is rejected, and `VACUUM` fails with a bare
`disk I/O error` that says nothing about a missing syscall. Setting
`temp_store_directory` does not help: that pragma validates the path the same
way and reports `not a writable directory`.

`journal_mode=DELETE` (the default) is fine and worth keeping: the rollback
journal is a real sidecar file, created, extended, truncated and unlinked on
every transaction. WAL is not usable — it needs shared memory that WASI has no
way to provide.

WAL is not usable — it coordinates through a shared-memory index that WASI has
no way to provide — and concurrent connections are out for the same reason
`locking_mode=EXCLUSIVE` is needed. Neither restricts anything real here: the
store is single-writer by design.

JSON, FTS5 and R-Tree are all present in the bundled build and all verified
working. [`examples/guest-sqlite`](../examples/guest-sqlite/) covers DDL,
transactions, savepoints, every constraint kind, joins, CTEs, window functions,
blobs including incremental `sqlite3_blob_open` I/O, `ATTACH`, `WITHOUT ROWID`,
generated columns, partial and expression indexes, `DROP`, `VACUUM`, and
`integrity_check` before and after a reopen. The README has the full notes and
the benchmark table.

## Test coverage

333 unit tests plus a MinIO integration suite covering the real S3 wire protocol, Object Lock retention, end-to-end write/read/remount, slab packing economics, tamper detection, and mount-floor enforcement. Design lineage: ZFS for the storage model, [GeeseFS](https://github.com/yandex-cloud/geesefs) for the original path-mapping engine this replaced.
