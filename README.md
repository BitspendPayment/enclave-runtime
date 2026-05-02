# s3-wasi-fs

A WASI Preview 2 (`wasi:filesystem@0.2.x`) implementation backed by an S3 bucket. Designed for running a Wasmtime guest component inside an AWS Nitro Enclave with S3 as durable storage, but also usable as a normal Rust library on any host.

## Status

Early scaffolding. The plan is at [`/home/joshua/.claude/plans/what-about-if-i-glimmering-peach.md`](/home/joshua/.claude/plans/what-about-if-i-glimmering-peach.md).

## Workspace layout

| Crate | Purpose |
|---|---|
| `crates/s3fs-core` | Pure async S3-backed FS engine. No wasmtime dep. The `Backend` trait, MPU state machine, buffer pool, inode cache, and public `Fs` handle live here. |
| `crates/s3fs-wasmtime` | (planned) Wasmtime host bindings for `wasi:filesystem@0.2.x`. Plugs into a `Linker` and overrides only `wasi:filesystem`. |
| `crates/s3fs-runner` | (planned) Binary that loads a guest component and runs it against an S3 bucket. |
| `crates/s3fs-test-support` | (planned) MinIO via testcontainers; bucket bootstrap. |
| `examples/guest-fsdemo` | (planned) A Wasm component that exercises the surface end-to-end. |

## Compatibility Matrix

The user-facing semantic contract is the Compatibility Matrix in the plan file. In short:

- **Fully POSIX-equivalent** for read/write/stat/listdir/sync/symlink (incl. cycle detection)/mkdir/unlink/rmdir/`O_EXCL`/`O_TRUNC`/preopens.
- **Weakened semantics** for rename atomicity, unlink-while-open, single-writer-fencing, sub-part fsync (slow path), set-times (opt-in only).
- **Always `unsupported`**: `link-at` (hardlinks).
