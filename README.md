# s3-wasi-fs

A [WASI Preview 2](https://github.com/WebAssembly/WASI) `wasi:filesystem@0.2.x` implementation backed by S3.

A Wasm component running inside Wasmtime sees a normal POSIX filesystem; the bytes land in an S3 bucket. Designed for [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) where a guest needs durable storage but the enclave can't mount FUSE — but works anywhere Wasmtime runs.

## Status

Pre-1.0. Three workspace crates plus an example guest:

| Crate | Purpose |
|---|---|
| [`s3fs-core`](crates/s3fs-core/) | Pure async S3-backed filesystem engine. `Backend` trait with in-memory and AWS S3 backends, inode tree with race-three lookup, buffer pool, MPU state machine, public `Fs` handle. **Zero wasmtime dependency** — usable from any host. |
| [`s3fs-wasmtime`](crates/s3fs-wasmtime/) | Wasmtime host bindings. Plugs into a `Linker` and exposes `wasi:filesystem` to a guest. Reuses `wasmtime-wasi` for everything else. |
| [`s3fs-runner`](crates/s3fs-runner/) | CLI binary that loads a `.wasm` component and runs it against a configured S3 bucket. |
| [`examples/guest-fsdemo`](examples/guest-fsdemo/) | Example Wasm component. Exercises mkdir / write / sync / read / rename / SQLite end-to-end. |

**Test coverage:** 171 unit tests + 10 MinIO integration tests. End-to-end SQLite-on-S3 demo works.

## Quick start: run a Wasm guest against MinIO

```bash
# 1. Spin up MinIO
docker run -d --rm --name s3fs-mio -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data
aws --endpoint-url http://127.0.0.1:9000 \
  --region us-east-1 \
  s3api create-bucket --bucket demo

# 2. Build the example guest (requires wasi-sdk for bundled SQLite)
curl -sLO https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz
mkdir -p ~/wasi-sdk && tar xf wasi-sdk-25.0-x86_64-linux.tar.gz -C ~/wasi-sdk --strip-components=1
cd examples/guest-fsdemo
CC_wasm32_wasip2=$HOME/wasi-sdk/bin/clang \
AR_wasm32_wasip2=$HOME/wasi-sdk/bin/ar \
CFLAGS_wasm32_wasip2="--sysroot=$HOME/wasi-sdk/share/wasi-sysroot -DSQLITE_THREADSAFE=0 -DHAVE_USLEEP=1" \
  cargo build --release --target wasm32-wasip2

# 3. Build the runner and execute the guest
cd ../..
cargo build --release -p s3fs-runner
./target/release/s3fs-runner \
  --bucket demo \
  --region us-east-1 \
  --endpoint http://127.0.0.1:9000 \
  --access-key-id minioadmin \
  --secret-access-key minioadmin \
  --force-path-style \
  --component examples/guest-fsdemo/target/wasm32-wasip2/release/guest-fsdemo.wasm
# → prints "OK"
```

The guest writes a real SQLite database into the bucket through `wasi:filesystem`. After the run, `aws s3 ls s3://demo/` shows the bucket cleaned up by the guest's own `remove_dir_all` calls.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        wasm guest component                      │
│             (Rust binary using std::fs / SQLite / ...)           │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ wasi:filesystem@0.2.6
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  wasmtime + wasmtime-wasi (io / cli / clocks / random / sockets) │
│  + s3fs-wasmtime (filesystem only)                               │
│       Descriptor / DirectoryEntryStream resources                │
│       S3InputStream / S3OutputStream over wasi:io                │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ Fs handle API
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  s3fs-core::Fs                                                   │
│       openat path resolution + symlink follow (depth ≤ 40)       │
│       inode tree (race-three lookup, snapshot listings)          │
│       buffer pool (memory-bounded LRU, dirty pinning)            │
│       MPU state machine (lazy begin, copy_unmodified_parts,      │
│         parallel UploadPart/UploadPartCopy)                      │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ Backend trait
                                 ▼
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
           AwsS3Backend                  MemoryBackend
        (aws-sdk-s3, S3-compatible)     (in-memory, tests)
```

## Compatibility Matrix

The full matrix — what's POSIX-equivalent, what's weakened, what's unsupported — lives at [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md). Headlines:

- ✅ **All read/write/stat/listdir/sync/mkdir/unlink/rmdir/rename ops** including recursive directory rename.
- ✅ **Symlinks** with cycle detection (depth 40), atomic create via `If-None-Match: *`.
- ✅ **`O_EXCL`** atomic create via S3 conditional PUT.
- ✅ **`O_TRUNC`** synchronous zero-byte PUT on open.
- ✅ **`set_size`** (truncate + capped grow) and **`set_times{,-at}`** (persisted as `x-amz-meta-s3wasifs-{atime,mtime}`).
- ✅ **In-place updates** of large files via MPU + `UploadPartCopy` for unchanged parts (GeeseFS-parity).
- ✅ **Eager background `UploadPart`** — `pwrite` of a fully-filled part hands off to a long-running flusher task; `sync` drains the parked replies. Caps in-flight uploads at `max_parallel_parts` across the whole `Fs`.
- ✅ **Async rename** — `Fs::rename` rewires the inode tree synchronously and returns immediately; the worker handles `CopyObject` + `DeleteObject` (or paginated recursion for directories) in the background. Reads/writes against the new path during the in-flight window resolve to the old key via `current_s3_key`.
- ⚠️ **`rename`** is not POSIX-atomic (CopyObject + DeleteObject is two calls); a host crash mid-window leaves both keys.
- ⚠️ **`unlink` while fd is open** doesn't keep the file readable on stale handles.
- ⚠️ **Concurrent writers to the same key**: last writer wins (no fencing).
- ❌ **`link_at` (hardlinks)** — S3 has no shared-identity-across-keys.

## Building from source

```bash
git clone <this repo>
cd s3-wasi-fs
cargo build --release --workspace --features aws  # AWS feature builds AwsS3Backend
cargo test  --workspace --features aws --lib       # 171 unit tests
cargo clippy --workspace --features aws --all-targets -- -D warnings
```

To run the MinIO integration suite (requires Docker):

```bash
cargo test -p s3fs-core --features aws --test minio_integration -- --ignored --test-threads=1
# 10 tests, ~30s each (MinIO container per test)
```

## Embedding `s3fs-core` directly

The engine is usable without the wasmtime layer. Useful for FUSE adapters, gateways, or custom hosts.

```rust
use std::sync::Arc;
use s3fs_core::{
    backend::{AwsS3Backend, AwsS3BackendConfig, Backend},
    Config, Fs, OpenFlags,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let backend = AwsS3Backend::connect(AwsS3BackendConfig {
        bucket: "my-bucket".into(),
        region: "us-east-1".into(),
        endpoint: None,
        access_key_id: Some("AKIA...".into()),
        secret_access_key: Some("...".into()),
        session_token: None,
        force_path_style: false,
        request_timeout: std::time::Duration::from_secs(30),
    }).await?;

    let fs = Fs::new(
        Arc::new(backend) as Arc<dyn Backend>,
        Arc::new(Config::default()),
    );

    let handle = fs.open("data.txt", OpenFlags { read: true, write: true, create: true, ..Default::default() }).await?;
    fs.pwrite(&handle, 0, b"hello s3").await?;
    fs.sync(&handle).await?;
    fs.close(&handle).await?;
    Ok(())
}
```

## Enclave deployment notes

The original motivation: running this stack inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). Two integration points the enclave consumer is responsible for (these are NOT in this crate):

1. **Vsock-aware HTTP client.** `AwsS3BackendConfig` doesn't currently expose this seam — a future patch will add an `http_client: Option<SharedHttpClient>` field that the enclave repo can fill with a vsock-backed `hyper` client. The aws-sdk-s3 default uses TCP.
2. **Cred sourcing via Nitro KMS attestation.** Static creds get passed to `AwsS3BackendConfig` — the parent EC2 ships KMS-encrypted creds over vsock; the enclave decrypts via attested KMS Decrypt and hands the plaintext to the backend.

## License

Apache-2.0.
