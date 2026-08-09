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
| [`s3fs-host`](crates/s3fs-host/) | `wasi:filesystem@0.2.x` over the engine, plus the linker, guest-environment policy, and run loop both binaries share. The AWS mount path is behind an `aws` feature, so the bindings stay usable over any `Backend`. |
| [`s3fs-runner`](crates/s3fs-runner/) | Development CLI. Explicit flags; the guest gets no environment unless asked. |
| [`enclave-runtime`](crates/enclave-runtime/) | Deployment target. Configured by environment, guest loaded from a known path inside the enclave image. |
| [`examples/guest-smoke`](examples/guest-smoke/) | Minimal guest, no C toolchain needed. Exercises write / patch / rename / read_dir and the environment policy; run twice it proves durability. |
| [`examples/guest-sqlite`](examples/guest-sqlite/) | SQLite conformance and benchmark workload — DDL, transactions, savepoints, constraints, joins, CTEs, window functions, blobs, triggers, `ALTER TABLE`, `VACUUM`, `integrity_check`. Needs wasi-sdk. |
| [`examples/guest-fsdemo`](examples/guest-fsdemo/) | The original smaller SQLite demo. |

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
│  + s3fs-host::wasi (filesystem only)                             │
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

## Running SQLite

SQLite works, and is the main conformance test: a real C database doing
page-granular random I/O, rewriting a rollback journal every transaction, and
then telling us via `PRAGMA integrity_check` whether the bytes came back
correct. [`examples/guest-sqlite`](examples/guest-sqlite/) exercises it and
prints the table below.

### Two pragmas you must set

```rust
conn.pragma_update(None, "temp_store",   "MEMORY")?;     // no access(2) under WASI
conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;  // no fcntl under WASI
```

**`temp_store=MEMORY`** is the non-obvious one, and getting it wrong costs an
afternoon. SQLite locates a directory for temporary databases by probing
candidates (`SQLITE_TMPDIR`, `TMPDIR`, `/var/tmp`, `/tmp`) with `access(2)`.
WASI has no such call, so every candidate is rejected and `VACUUM` fails with a
bare `disk I/O error` that says nothing about a missing syscall. Setting
`temp_store_directory` instead does not help — that pragma validates the path
the same way and reports `not a writable directory`.

**`locking_mode=EXCLUSIVE`** because WASI provides no `fcntl` advisory locking.

### What cannot work

| | Why |
|---|---|
| **WAL journal mode** | WAL coordinates readers and writers through a shared-memory index (`-shm`). WASI has no shared memory and no `mmap`, so there is nothing to build it on. Use `journal_mode=DELETE` — the default — which is a real sidecar file and works fine. |
| **Concurrent connections** | No `fcntl` locking means SQLite cannot arbitrate between processes, hence `locking_mode=EXCLUSIVE`. This is not a real restriction here: the store is single-writer by design, and a second mount racing the same root sequence is poisoned rather than allowed to diverge. |

Neither is a limitation of this filesystem — both are consequences of WASI's
syscall surface, and both would apply to any WASI filesystem.

### Optional modules

All three are compiled into the bundled SQLite and **all three work**, verified
against the store rather than assumed:

| Module | Status |
|---|---|
| **JSON** | `json_extract`, and an index over a JSON expression. Built into SQLite from 3.38. |
| **FTS5** | 2 000 documents indexed, `MATCH` queried, then `rebuild` to regenerate every shadow table. The heaviest filesystem workload of the three. |
| **R-Tree** | 1 000 bounding boxes, range-queried. |

Availability depends on how the bundled SQLite was configured, so the guest
probes for each and reports what it found rather than assuming.

### Benchmark

20 000 accounts and 40 000 entries, against MinIO on localhost. Absolute
numbers will be worse against real S3 — the round trips get longer — but the
*shape* is the point.

| phase | elapsed | rate |
|---|---|---|
| bulk insert (20 000 rows, one txn) | 142 ms | 140 884 rows/s |
| point select by rowid | 2.5 ms | 405 948 queries/s |
| indexed select by name | 1.3 ms | 785 850 queries/s |
| update (500 rows, one txn) | 63 ms | 7 963 rows/s |
| blob write | 128 ms | 18.5 MB/s |
| blob read + verify | 41 ms | 57.8 MB/s |
| incremental blob I/O (512 KiB, scattered) | 242 ms | 2.2 MB/s |
| VACUUM | 471 ms | |
| `PRAGMA integrity_check` | 136 ms | |
| **25 inserts, autocommit** | **1 796 ms** | **14 rows/s** |
| **25 inserts, one transaction** | **69 ms** | **364 rows/s** |

**Batch your writes.** Those last two rows are the same 25 inserts, 26× apart.
Every statement outside an explicit transaction is its own commit, and a commit
is a transaction group: slab PUTs plus a signed root record published with a
conditional PUT. That is two or more round trips to object storage that no
local caching can avoid — durability is the whole point. Inside a transaction
they share one commit, which is why 20 000 batched inserts land in less time
than 25 unbatched ones.


## Time and entropy

### Time

An enclave's system clock is not its own. It is seeded by the hypervisor at
boot, has no NTP, and drifts — and the party that sets it is the parent
instance, which is exactly the party the enclave exists to distrust. AWS
addresses this by exposing the Nitro card's PTP hardware clock, synchronised to
the Amazon Time Sync Service, at `/dev/ptp0`.

`enclave-runtime` reads that device and serves it to the guest as
`wasi:clocks/wall-clock`, so a guest asking what time it is gets an answer the
host cannot quietly move. `set-times` with "now" uses the same clock, so the two
cannot disagree.

| `--clock-source` | Behaviour |
|---|---|
| `ptp` | Read `/dev/ptp0`; refuse to start without it. **An enclave image should set this.** |
| `host` | System clock, with a warning that time is untrusted. Development and CI. |
| `auto` *(default)* | PTP if the device opens, host otherwise — warning loudly when it falls back, so a misconfigured enclave never looks like a correct one. |

`--ptp-device` overrides the path. `--clock-check` prints readings and exits,
without mounting anything:

```console
$ enclave-runtime --clock-check --clock-source ptp
clock source: PTP hardware clock (/dev/ptp0)
resolution:   1ns

  reading                    vs CLOCK_REALTIME    read time
  1786258105.437379703            -520.851 ms      10.0 us
  1786258105.457452953            -520.851 ms      11.4 us
  ...
clock advanced monotonically across 5 readings
```

That output is from a real PHC on an ordinary laptop, and the two columns are
the point of the feature. **−520 ms** of skew shows the PHC really is an
independent clock, not `CLOCK_REALTIME` wearing a hat. **10–15 µs** per read,
against roughly 0.3 µs for the system clock, is the price: a guest calling
`wall-clock` in a tight loop will notice. If that ever matters, the fix is to
sample the PHC periodically and track between samples with `CLOCK_MONOTONIC` —
deliberately not built until a measurement asks for it.

**The monotonic clock stays on `CLOCK_MONOTONIC`.** It backs WASI's timer
subscriptions, so it must be cheap, and it must never step backwards — which a
clock disciplined by an external source can, and a wall clock is allowed to.

Verify on any machine with a PHC:

```bash
./deploy/ptp-check.sh              # passes the host's PHC into a container
./deploy/ptp-check.sh --mode qemu  # boots a VM and uses ptp_kvm instead
```

Neither emulates Nitro; they exercise the same device interface. Full fidelity
needs QEMU ≥ 9.1's `nitro-enclave` machine and an EIF, which belongs with
attestation in [the roadmap](docs/ROADMAP.md).


### Entropy

`wasi:random/random` is what a guest builds keys, nonces and session
identifiers from. By default `wasmtime-wasi` serves it from the kernel's
`getrandom(2)`. Inside an enclave that pool *is* seeded by the Nitro Security
Module — but nothing in the path says so, and nothing fails if it isn't.

`enclave-runtime` reads the NSM directly, through `/dev/nsm`: the same device
that signs attestation documents, reached with the same ioctl. Bytes come
**straight from the device on every call** — there is no software generator in
between, so the claim is "the NSM produced these" with nothing else to trust.

| `--random-source` | Behaviour |
|---|---|
| `nsm` | Read `/dev/nsm`; refuse to start without it. **An enclave image should set this.** |
| `host` | Kernel `getrandom(2)`, with a warning. Development and CI. |
| `auto` *(default)* | NSM if the device opens, kernel otherwise. |

A fallback here is logged at **error**, not warning. A clock that falls back is
degraded; entropy that falls back means every key the guest generates afterwards
rests on a source nobody chose.

Two things to know if you ever debug this. The raw NSM ioctl requires
**`CAP_SYS_ADMIN`**, so an unprivileged process gets `EPERM` from a device that
exists and is readable. And the device answers **256 bytes per call**, so a
larger request is a loop of ioctls — direct-from-device is deliberately not the
fast option.

`wasi:random/insecure` keeps `wasmtime-wasi`'s generator; making a
deliberately-not-cryptographic interface cost a device round trip would be
perverse. Its seed is drawn from the NSM once at startup so it is not
deterministic across runs.

`--self-check` reports both clock and entropy and exits without mounting
anything:

```console
$ enclave-runtime --self-check --clock-source ptp --random-source nsm
clock source: PTP hardware clock (/dev/ptp0)
  ...
entropy source: Nitro Security Module (/dev/nsm)
  sample:      b00c80e8c01f4edfd2af255037a94c16
  histogram:   peak 27, 0 of 256 values unseen (mean 16)
  read cost:   5.7 us for 64 bytes, 8.5 us for 4096
```

The histogram is not a randomness test — no cheap check is. It catches the
failures that actually happen: a stub returning zeros, a buffer never written,
a device answering the same block every time.


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
