# Compatibility Matrix

The user-facing semantic contract: what `wasi:filesystem@0.2.x` ops do behind our implementation, and where they deviate from POSIX.

S3 is an object store, not a filesystem. Some POSIX semantics map cleanly, some require workarounds, some are fundamentally incompatible. This document is honest about all three categories.

---

## ✅ Fully POSIX-equivalent

| WASI op | Notes |
|---|---|
| `read`, `read-via-stream` | Ranged `GetObject` with buffer-pool cache. Streams are non-blocking; `Pollable::ready()` does the actual fetch. |
| `write`, `write-via-stream`, `append-via-stream` | `MultipartUpload` + `UploadPartCopy` for in-place updates of large files (GeeseFS-parity); single `PutObject` for small files. Streams queue + drain via `Pollable::ready()`. |
| `stat`, `stat-at` | Race-three lookup on cache miss (parallel HEAD + HEAD-with-slash + LIST). `DescriptorStat` returns mtime from `x-amz-meta-s3wasifs-mtime` if set, else S3's `LastModified`. |
| `read-directory` | Snapshot at iterator open via paginated `ListObjectsV2(prefix, delim='/')`. Per WASI semantics, entries added/removed mid-iteration may be missed (POSIX-allowed). |
| `create-directory-at` | Zero-byte `dir/` marker object. |
| `is-same-object` | Inode-ID comparison; correct **within one mount**. |
| `get-flags`, `get-type` | Trivial. `get-type` returns `regular-file` / `directory` / `symbolic-link`. |
| `metadata-hash{,-at}` | `siphash24(etag ‖ size)` for files; siphash of sorted child entries for directories. Changes when content / membership changes. |
| `advise` (`will-need`, `sequential`) | Honoured as buffer-pool prefetch hints. Other variants are no-ops (allowed by WASI). |
| `open-at` with `create-flags::create \| exclusive` (`O_EXCL`) | Atomic via S3 `PutObject` with `If-None-Match: *`. Conflict → `error-code::exist`. |
| `open-at` with `open-flags::truncate` | Synchronous zero-byte `PutObject` on open, regardless of whether the guest later writes. |
| `open-at` with `path-flags::symlink-follow` set | Recursive resolution, max-depth 40 (Linux `MAXSYMLINKS`). Cycles → `error-code::loop`. |
| `open-at` with `path-flags::symlink-follow` cleared on a symlink | Returns `error-code::loop` per WASI spec (POSIX `O_NOFOLLOW`). |
| `symlink-at` | Atomic via `If-None-Match: *`; conflict → `error-code::exist`. Stored as a small object with body = target string and `x-amz-meta-s3wasifs-type=symlink`. |
| `readlink-at` | Single `GetObject`; non-symlink target → `error-code::invalid` per POSIX. |
| `unlink-file-at` | `DeleteObject`. Inode marked `Deleted`; further ops on stale handles return `bad-descriptor`/`no-entry`. |
| `remove-directory-at` | List with `MaxKeys=2` for emptiness check, then `DeleteObject` of marker if present. Non-empty → `error-code::not-empty` (POSIX). |
| `rename-at` (file or symlink) | `CopyObject` + `DeleteObject`. Synchronous. |
| `rename-at` (directory) | Recursive: paginates `ListObjectsV2` over the source prefix, copies + deletes each key, rewires the inode tree. Empty destination is replaced; non-empty → `not-empty`; rename-into-self → `invalid`. |
| `set-size` | **Shrink:** flush pending writes, GET `[0..new_size)`, single `PutObject`. **Grow:** zero-fill via buffer pool (capped at 100 MiB to avoid OOM). |
| `set-times{,-at}` | Persists as `x-amz-meta-s3wasifs-{atime,mtime}` via `CopyObject` self-copy with `MetadataDirective=REPLACE`. Read back into `DescriptorStat` on next lookup. |
| `sync`, `sync-data` | Drain dirty parts → `copy_unmodified_parts` → `CompleteMultipartUpload`, OR single `PutObject` for sub-part / small-file paths. Durable when the call returns. |
| `preopens.get-directories` | Single entry: `(root_descriptor, mount_path)` where `mount_path` defaults to `/`. |

## ⚠️ Weakened semantics — guests will mostly not notice, but the gap is real

| WASI op | Gap | Mitigation / contract |
|---|---|---|
| `rename-at` | **Not POSIX-atomic.** `CopyObject` + `DeleteObject` is two calls; both keys briefly exist; a host crash leaves both. | Synchronous from caller's perspective. Errors surface from the rename call itself rather than later. |
| `unlink-file-at` while fd is open | **No POSIX "invisible deleted file" semantics.** Further ops on stale handles return `bad-descriptor`/`no-entry`. | Documented; matches GeeseFS. |
| Two writers to same key | **No fencing.** Last `MultipartUpload` committed wins; no torn data but no single-writer guarantee. | Inside an enclave there's typically one writer. If you need single-writer-per-key semantics, layer it above (DynamoDB CAS, lease service, etc.). |
| `is-same-object` across mounts | Inode IDs are per-process. Two mounts of the same bucket disagree on identity. | Within-mount works. |
| `set-times` and `LastModified` | We persist the user-set mtime as metadata, but every successful `CompleteMultipartUpload` / `PutObject` also bumps S3's own `LastModified`. The metadata mtime is what we report from `DescriptorStat`. | Acceptable for nearly all guests. |
| `set-size` grow > 100 MiB | Returns `error-code::invalid`. | Use `pwrite` of real bytes for genuine large grows. |
| `sync` of a sub-part write after MPU started | Currently triggers an MPU+`UploadPartCopy` rewrite path. Correct but slow when the dirty content is far smaller than `single_part_threshold`. | Performance gap, not correctness. |

## ❌ Cannot map — always returns `error-code::unsupported`

| WASI op | Why |
|---|---|
| `link-at` (hardlinks) | POSIX requires shared mutability across link members; S3 has no shared-identity-across-keys. The implementable approaches (indirection layer with refcount sidecar, or fan-out copy on every write) all impose either an extra GET per read, O(N) PUTs per write, or fragile crash-recovery state. **Permanent gap by design.** |

## Test coverage

- **162 unit tests** in `s3fs-core` and `s3fs-wasmtime` against the in-memory backend.
- **10 integration tests** in `s3fs-core/tests/minio_integration.rs` against MinIO via testcontainers (run with `--features aws --test minio_integration -- --ignored`).
- **End-to-end SQLite test**: `examples/guest-fsdemo` runs a real SQLite database on top of the S3-backed filesystem (CREATE TABLE, INSERT, COMMIT, re-open, SELECT, verify) and prints `OK`.

## Design references

- The race-three lookup, MPU `copyUnmodifiedParts` strategy, and tiered part schedule are direct ports of [GeeseFS](https://github.com/yandex-cloud/geesefs)'s patterns. See [its `core/` directory](https://github.com/yandex-cloud/geesefs/tree/master/core) for the original Go implementation.
- The `wasi:filesystem` WIT lives at [`wit/deps/filesystem.wit`](../wit/deps/filesystem.wit) (vendored from `wasmtime-wasi 44`'s `wasi@0.2.6`).
