# s3-wasi-fs

A [WASI Preview 2](https://github.com/WebAssembly/WASI) `wasi:filesystem@0.2.x` implementation backed by S3, with a ZFS-style copy-on-write block store underneath.

A Wasm component running inside Wasmtime sees a normal POSIX filesystem. Underneath, content is held in immutable AEAD-encrypted blocks packed into slab objects, and the entire filesystem hangs off a single signed, hash-chained **root record** written with a conditional PUT under S3 Object Lock. Verifying that record transitively verifies every byte beneath it, and the chain of records is what makes a rollback *detectable* rather than merely unlikely.

Designed for [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/), where the host is outside the trust boundary and storage has to be assumed hostile — but it works anywhere Wasmtime runs.

**What the store guarantees against an adversary holding full write access to the buckets:** they can make the filesystem unreadable. They cannot make it read *wrong*, and they cannot make it read *old*.

## Status

Pre-1.0. The storage engine is complete; the enclave integration is not.
[`docs/ROADMAP.md`](docs/ROADMAP.md) covers what remains: NSM attestation and
KMS key release (M8), garbage collection (M9), and the `enclave-runtime` crate
that runs a guest inside a Nitro Enclave (M10).

Three workspace crates plus an example guest:

| Crate | Purpose |
|---|---|
| [`s3fs-core`](crates/s3fs-core/) | The engine. `Backend` trait with in-memory and AWS S3 backends; a copy-on-write block store (`store::*`) with encrypted blocks, an indirect-block tree, a dnode array, and the transaction-group commit protocol; POSIX semantics on top (`Fs`). **Zero wasmtime dependency** — usable from any host. |
| [`s3fs-wasmtime`](crates/s3fs-wasmtime/) | Wasmtime host bindings. Plugs into a `Linker` and exposes `wasi:filesystem` to a guest. Reuses `wasmtime-wasi` for everything else. |
| [`s3fs-runner`](crates/s3fs-runner/) | CLI binary that loads a `.wasm` component and runs it against a configured S3 bucket. |
| [`examples/guest-fsdemo`](examples/guest-fsdemo/) | Example Wasm component. Exercises mkdir / write / sync / read / rename / SQLite end-to-end. |

**Test coverage:** 333 unit tests plus a MinIO integration suite (real S3 wire protocol, Object Lock retention, remount, tamper detection, rollback floor). End-to-end SQLite-on-S3 demo works.

## Quick start: run a Wasm guest against MinIO

```bash
# 1. Spin up MinIO
docker run -d --rm --name s3fs-mio -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data
aws --endpoint-url http://127.0.0.1:9000 --region us-east-1 \
  s3api create-bucket --bucket demo-data
# The roots bucket carries the anchor chain. In production create it with
# --object-lock-enabled-for-bucket and a COMPLIANCE default retention.
aws --endpoint-url http://127.0.0.1:9000 --region us-east-1 \
  s3api create-bucket --bucket demo-roots

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
  --bucket demo-data \
  --roots-bucket demo-roots \
  --region us-east-1 \
  --endpoint http://127.0.0.1:9000 \
  --access-key-id minioadmin \
  --secret-access-key minioadmin \
  --force-path-style \
  --master-key 0000000000000000000000000000000000000000000000000000000000000001 \
  --component examples/guest-fsdemo/target/wasm32-wasip2/release/guest-fsdemo.wasm
# → prints "OK"
```

`--master-key` is a development seam: every other key is derived from it by HKDF. In an
enclave it is replaced by a `kms:Decrypt` whose key policy binds release to the attestation
document's PCRs — the on-disk format is identical either way. It must be supplied rather
than read from the store, because the keys that verify a root record derive from it.

The guest writes a real SQLite database through `wasi:filesystem`. Unlike the previous
path-mapping engine, `aws s3 ls` shows no filenames afterwards: the data bucket holds
opaque encrypted slabs, and the roots bucket holds the signed anchor chain.

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
│       path resolution + symlink follow (depth 40)                │
│       per-handle record buffering; one commit per mutation       │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────┐
│  s3fs-core::store                                                │
│    root record   signed, hash-chained, Object Lock COMPLIANCE    │
│         │ meta-dnode blkptr  ← the Merkle root                   │
│    object set    dnode array, addressed by object id             │
│    indirect      copy-on-write block tree, variable-width        │
│    dir           separator-indexed B+tree of name-ordered entries│
│    slab          per-transaction-group packing; AES-256-GCM      │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ Backend trait
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
           AwsS3Backend                  MemoryBackend
        (aws-sdk-s3, S3-compatible)     (in-memory, tests)
```

## Compatibility Matrix

The full matrix — what's POSIX-equivalent, what's weakened, what's unsupported — lives at [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md). Headlines:

- ✅ **Every read/write/stat/listdir/sync/mkdir/unlink/rmdir op**, plus symlinks with cycle detection.
- ✅ **`rename` is atomic** — one directory-entry move inside one commit. A directory rename costs the same as a file rename, not `O(entries)` copies.
- ✅ **`stat` cannot go stale**, and `link-count` and all three timestamps are real values.
- ✅ **`is-same-object` / `metadata-hash` are exact** and agree across mounts.
- ✅ **`set-size` grows at any size for free** — growth is a hole.
- ✅ **Crash consistency**: the visible state is always a Merkle-verified snapshot, never torn. No journal, no fsck.
- ✅ **Tamper detection on every block read**, binding each block to its exact position in the tree.
- ✅ **Rollback detection** via a signed, hash-chained, Object-Lock-protected root sequence.
- ⚠️ **Single writer.** Two mounts racing a root sequence: one wins, the loser is poisoned. Retrying would reuse a transaction group and repeat its AEAD nonces.
- ⚠️ **Cold-mount freshness** needs `--min-root-seq`; a store that hides newer roots is not cryptographically excluded.
- ✅ **Hard links** — a directory entry is an object id, so `link-at` is one more entry and an `nlink` increment.
- ✅ **`unlink` while an fd is open** keeps the file readable and writable until the last handle closes.
- ✅ **Snapshots** — every root record is one, and reading an old one costs nothing to have kept.

## Building from source

```bash
git clone <this repo>
cd s3-wasi-fs
cargo build --release --workspace --features aws  # AWS feature builds AwsS3Backend
cargo test  --workspace --features aws --lib       # 333 unit tests
cargo clippy --workspace --features aws --all-targets -- -D warnings
```

To run the MinIO integration suite (requires Docker):

```bash
cargo test -p s3fs-core --features aws --test minio_integration -- --ignored --test-threads=1
# One MinIO container per test; covers Object Lock, remount, tamper detection
```

## Embedding `s3fs-core` directly

The engine is usable without the wasmtime layer. Useful for FUSE adapters, gateways, or custom hosts.

```rust
use std::sync::Arc;
use s3fs_core::{
    backend::{AwsS3Backend, AwsS3BackendConfig, Backend},
    Config, Fs, MasterSecret, OpenFlags,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let connect = |bucket: &str| AwsS3Backend::connect(AwsS3BackendConfig {
        bucket: bucket.into(),
        region: "us-east-1".into(),
        endpoint: None,
        access_key_id: Some("AKIA...".into()),
        secret_access_key: Some("...".into()),
        session_token: None,
        force_path_style: false,
        request_timeout: std::time::Duration::from_secs(30),
    });

    let fs = Fs::mount(
        Arc::new(connect("my-data").await?) as Arc<dyn Backend>,
        // Object Lock COMPLIANCE lives here: this is the rollback anchor.
        Arc::new(connect("my-roots").await?) as Arc<dyn Backend>,
        &MasterSecret::from_hex("00...01")?,
        [0u8; 16],       // filesystem id: the key-derivation salt
        Arc::new(Config::default()),
        None,            // or Some(seq) as an externally supplied freshness floor
    ).await?;

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
