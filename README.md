# s3-wasi-fs

A [WASI Preview 2](https://github.com/WebAssembly/WASI) `wasi:filesystem@0.2.x` implementation backed by S3, with a ZFS-style copy-on-write block store underneath.

A Wasm component running inside Wasmtime sees a normal POSIX filesystem. Underneath, content is held in immutable AEAD-encrypted blocks packed into slab objects, and the entire filesystem hangs off a single signed, hash-chained **root record** written with a conditional PUT under S3 Object Lock. Verifying that record transitively verifies every byte beneath it, and the chain of records is what makes a rollback *detectable* rather than merely unlikely.

Designed for [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/), where the host is outside the trust boundary and storage has to be assumed hostile — but it works anywhere Wasmtime runs.

**What the store guarantees against an adversary holding full write access to the buckets:** they can make the filesystem unreadable. They cannot make it read *wrong*, and they cannot make it read *old*.

## Status

Pre-1.0. The storage engine is complete, and so is the runtime that mounts it
inside an enclave and serves a guest over TLS. What remains is one thing that
matters: **the master secret is not really sealed yet.** Genesis mints it from
NSM entropy and stores only a sealed blob, but the only implementation of that
sealing writes the secret behind a marker saying it did not seal it — enough to
exercise every boot path under QEMU, and no protection at all. Real sealing is
KMS `Decrypt` with a `Recipient`, which needs Nitro hardware to test.
[`docs/ROADMAP.md`](docs/ROADMAP.md) has that (M8) and garbage collection (M9).

Four workspace crates plus example guests:

| Crate | Purpose |
|---|---|
| [`s3fs-core`](crates/s3fs-core/) | The engine. `Backend` trait with in-memory and AWS S3 backends; a copy-on-write block store (`store::*`) with encrypted blocks, an indirect-block tree, a dnode array, and the transaction-group commit protocol; POSIX semantics on top (`Fs`). **Zero wasmtime dependency** — usable from any host. |
| [`nitro-nsm`](crates/nitro-nsm/) | `/dev/nsm`: entropy and attestation requests. Its own crate so it links into a small static binary for an enclave image. |
| [`nitro-attestation`](crates/nitro-attestation/) | Parses and verifies attestation documents, and the `nitro-attest` client. Depends on nothing else here — a verifier has no `/dev/nsm` and is often not Linux. |
| [`enclave-runtime`](runtime/) | Everything above the engine: `wasi:filesystem@0.2.x`, the linker, the guest-environment policy, the vsock tap device, TLS termination and attestation of the auth exchange — plus the binary that ties them together. A library beside the binary so integration tests can reach it. |
| [`examples/guest-http`](examples/guest-http/) | The guest the serving path is tested against: reads and writes the filesystem, and is deliberately stateful so a second request proves the first one's writes committed. |
| [`examples/guest-sqlite`](examples/guest-sqlite/) | SQLite conformance and benchmark workload — DDL, transactions, savepoints, constraints, joins, CTEs, window functions, blobs, triggers, `ALTER TABLE`, `VACUUM`, `integrity_check`. Runs on request; needs wasi-sdk to build. |

**Test coverage:** `cargo test --workspace` runs 753 tests — unit tests across the workspace, a MinIO integration suite (real S3 wire protocol, Object Lock retention, remount, tamper detection, rollback floor), a boot-machine suite that walks every row of the state-origin table, and two suites that serve a real component over TLS and check the attestation binding. A further 80 skip themselves without MinIO, enclave hardware, or a `wasm32-wasip2` build of the example guest; reach those with `--features testing -- --include-ignored`, which is also what gives the TLS suites a self-signed certificate to serve, since a production build has no way to mint one.

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

# 2. Build the example guest. No C toolchain needed — guest-http is std-only.
cd examples/guest-http
cargo build --release --target wasm32-wasip2

# 3. Build the runtime and serve the guest
cd ../..
cargo build --release -p enclave-runtime --features aws
./target/release/enclave-runtime \
  --no-inherit-env \
  --bucket demo-data \
  --roots-bucket demo-roots \
  --region us-east-1 \
  --endpoint http://127.0.0.1:9000 \
  --access-key-id minioadmin \
  --secret-access-key minioadmin \
  --force-path-style \
  --master-key 0000000000000000000000000000000000000000000000000000000000000001 \
  --tls off \
  --http-listen 127.0.0.1:8080 \
  --guest-path examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm

# then, from another shell. Every request carries a nonce, whether or not the
# response it gets back is attested — so a client behaves the same either way:
nonce() { openssl rand 20 | basenc --base64url | tr -d '='; }
curl -H "x-enclave-nonce: $(nonce)" localhost:8080/           # what this guest is
curl -H "x-enclave-nonce: $(nonce)" localhost:8080/counter    # increments, and persists
```

`--no-inherit-env` matters outside an enclave. The default is to pass this
process's environment to the guest, minus `AWS_*` and `S3FS_*` — right for an
enclave image, where the environment *is* the curated deployment
configuration, and wrong on a developer's machine, where it forwards whatever
happens to be in your shell. The denylist withholds this runtime's own
credentials; it does not know about your `GITHUB_TOKEN`.

Name what the guest should get instead:

```bash
--no-inherit-env --guest-env LOG_LEVEL=debug --guest-env HOME
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
│  + enclave_runtime::wasi (filesystem only)                       │
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

It is a `wasi:http/proxy` guest like any other — the runtime serves that world
and no other — so the workload is asked for with a request rather than run as a
process: `GET /` runs every phase and answers `OK` or `FAIL: …`, while the
timings go to the guest's stdout and reach you through the runtime's own log
records. The workload is not idempotent; it builds on what the last run left,
which is the point when checking durability across restarts.

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

### Verifying it in an emulated enclave

`/dev/nsm` exists nowhere but an enclave, so unit tests use a fake and CI runs
`--random-source host`. Neither proves the device layer talks to a real NSM.
QEMU's `nitro-enclave` machine does, and [`deploy/qemu-nitro/`](deploy/qemu-nitro/)
builds an image and boots it:

```bash
./deploy/qemu-nitro/build-eif.sh     # static musl self-test → ramdisk → EIF
./deploy/qemu-nitro/run-selftest.sh  # boot it, check the console
```

The result, from the guest running inside the emulated enclave:

```
opening /dev/nsm
Nitro Security Module (/dev/nsm)
sample     3aa2e10393116ee4f9e7d71dfb2ff5b3
histogram  peak 28 of 4096 (mean 16)
read cost  0.0 us for 64 bytes, 4000.3 us for 4096
NSM-SELFTEST-OK
```

Roughly **62 µs per device call** — 4096 bytes is 64 round trips, since the NSM
answers 64 bytes at a time. The 64-byte figure reads as zero because the
enclave kernel's clock cannot resolve a single call. Direct-from-device is
deliberately not fast; there is no DRBG in front of it, so a guest drawing
kilobytes should draw them once and expand with its own KDF.

Four things have to line up, and each fails in a way that does not name itself:

- **QEMU built with `virtio-nsm`.** Only compiled when libcbor and gnutls are
  present at configure time, so distro packages do not have it even at version
  11. [`deploy/qemu-nitro/Dockerfile`](deploy/qemu-nitro/Dockerfile) builds 9.2
  from source and fails the *build* if the device is missing.
- **A vsock backend** on QEMU's chardev — the machine has no built-in one.
- **A heartbeat answer.** Enclave `init` writes `0xB7` to the parent on vsock
  port 9000 and waits for it back, with no timeout. Unanswered, the kernel
  boots and then nothing happens, which looks exactly like a broken image.
  Worse, `vhost-device-vsock`'s Unix-socket backend silently drops it: init
  dials **CID 3**, the Nitro parent convention, and that backend only serves
  the host CID. Hence `--forward-cid 1` and a real AF_VSOCK listener, which
  needs `vsock_loopback` loaded on the host (`sudo modprobe vsock_loopback`).
- **Mountpoints inside `rootfs/`.** init binds `/rootfs` onto itself and mounts
  the pseudo-filesystems inside it. Missing ones abort with
  `mount: /dev: No such file or directory`, which reads like a bootstrap fault
  and is not.

The EIF is built with `eif_build`, so it carries genuine PCR0/1/2
measurements — the same values a real enclave would attest to. That is the
groundwork for M8.

This needs `/dev/kvm` and so does not run on GitHub-hosted runners, the same
limitation the PTP harness has.


## Which state an enclave will load

An enclave that mounts the wrong filesystem is worse than one that fails, and
until recently this code could not tell the difference. `Store::open` ended
with `None => Store::format(…)`, so an enclave pointed at an emptied store
created a fresh filesystem and served it — correctly signed, correctly
hash-chained, and completely wrong. Every check the design makes passed,
because they all attested to the *new* filesystem while the guest saw an empty
database where its data should have been.

`store/root.rs` already documented the neighbouring risk, rollback: *"a cold
mount cannot distinguish 'the tip is N' from 'the tip is N, and the store is
hiding N+1'"*. This was the worse one it did not name.

### The state-origin receipt

Genesis now writes an NSM attestation document whose `user_data` commits to a
hash over this filesystem's identity, following
[ArkLabsHQ/enclave#151](https://github.com/ArkLabsHQ/enclave/pull/151):

```text
state_root = BLAKE3(CBOR[
    "s3fs/state-origin/v1",
    fs_uuid,                     which filesystem
    data_bucket, roots_bucket,
    bucket_prefix,               which store
    genesis_root_hash,           which history, pinned to the seq-0 record
    sha256(sealed master key),   which key — the CIPHERTEXT's hash, never the key
])
```

Every later boot recomputes it from what it just loaded and requires the
receipt to name exactly that. The host cannot forge one, because AWS signs it.

| receipt | store | this pair's record | |
|---|---|---|---|
| absent | empty | — | **genesis** — mint key, seal, create, write receipt and pair record |
| absent | present | — | **refuse** — state nobody accounted for |
| present | empty | — | **refuse** — state has been hidden |
| present | present | present, verifies | **resume** — writes nothing |
| present | present | absent | **upgrade** — attest and write this pair's record |
| present | present | present, does not verify | **refuse** — something else stands in its place |

The receipt says *which state*. It no longer says *which code*: that is the key
policy's decision, and the boot machine records it rather than making it — see
[Upgrades](#upgrades).

QEMU's emulated NSM does not sign — its source says so — so the harness must be
able to accept an unsigned receipt, and an escape hatch like that is worth
nothing if it can be switched on from outside. `S3FS_RECEIPT_TRUST` is set in
the image: `required` in the production EIF, `unsigned-emulator` only in
`eif-qemu`. It is therefore covered by PCR0, so *whether this enclave would
accept an unsigned receipt* is something a client reads off the attestation
rather than has to trust.

### Three things make a *missing* receipt mean something

The receipt is self-authenticating, so the host cannot forge one — but "no
receipt" is what authorises genesis, so the absence has to be as trustworthy as
the presence. None of these is sufficient alone:

- **Object Lock COMPLIANCE** — nobody, including the account root, can destroy
  the receipt once written. It can be *hidden*, which took some closing: see
  below.
- **Attested bucket identity** — the bucket names live in the image, so PCR0
  covers them. Without this the host points the enclave at an empty bucket and
  everything else passes. This is why
  [`deploy/nix/deployment.nix`](deploy/nix/deployment.nix) exists, and why
  changing a bucket changes PCR0.
- **TLS to S3, validated inside the enclave** — the parent proxies the bytes
  but cannot substitute them. It can block, which fails closed.

Still out of scope, unchanged: S3 lying about `HEAD`. That is AWS, whom we
already trust for the signature on the receipt itself.

#### A delete marker hides what it cannot destroy

Object Lock COMPLIANCE protects a *version*. It does not stop a `DeleteObject`
without a `versionId`, which inserts a **delete marker** — and a plain
`GetObject` then answers `NoSuchKey` while the retained version sits underneath,
genuinely undeletable. Verified against MinIO:

```console
$ aws s3api delete-object --bucket lockprobe --key roots/0
{ "DeleteMarker": true, "VersionId": "71eff5c3-…" }        # succeeds
$ aws s3api get-object --bucket lockprobe --key roots/0 -
NoSuchKey: The specified key does not exist.               # invisible
$ aws s3api delete-object --bucket lockprobe --key roots/0 --version-id afc3c2fd-…
InvalidRequest: Object is WORM protected and cannot be overwritten
```

For the boot machine, hidden is as good as deleted: mark both the receipt and
the sealed key and the enclave sees `(None, None)`, takes the genesis path, and
creates a fresh filesystem — precisely the substitution the receipt exists to
refuse. `RootStore::find_tip` has the same exposure, since it discovers the tip
by probing for keys.

Worse, a hidden key accepts a conditional create: `If-None-Match: *` tests the
*current* version, and a delete marker is a current version that is not an
object — so the PUT that serves as "am I the first here?" answers yes.

**Closed.** `Backend::get_retained_blob` finds the version through
`ListObjectVersions` and reads it by `versionId`, which a marker cannot conceal
because the version cannot be removed. The boot machine reads its origin records
that way, and so do `RootStore::exists` and `RootStore::load` — which also
closes the *rollback* half, since hiding the tip was the same trick. If the
enclave's role lacks `s3:ListBucketVersions`, the read errors rather than
answering "absent", so a missing permission refuses the mount instead of
silently starting over.

This was found because `object_lock_makes_a_root_record_undeletable` in the
MinIO suite was failing. It was asserting the comfortable claim; the fake
backend asserted it too, and modelled "a non-versioned bucket", which is
something S3 will not let you have with Object Lock at all.

### The master secret belongs to the state

It used to arrive as `S3FS_MASTER_KEY`, from the parent — and a parent that
supplies the key *has* the key. Genesis now mints it, seals it, and stores only
the sealed form; resume opens that. The receipt commits to `sha256` of the
**ciphertext**, never the secret, because a receipt is readable by anyone who
can read the bucket.

**Sealing is not finished.** `StaticKey` seals by *not* sealing — it writes the
secret behind a marker saying so, which exercises every boot mode without
hardware and protects nothing. Real sealing is KMS with a `Recipient` under a
policy conditioned on `kms:RecipientAttestation:PCR0` *and* `:PCR16`, and that
is where *"only the correct enclave boots"* is actually enforced: a wrong
enclave does not get a refused mount, it gets no key at all. It is the next
implementation of one trait and nothing above it changes.

### The guest is measured, not baked in

The guest component used to ship inside the image, so PCR0 covered it and every
guest change was an image rebuild. It is now fetched at boot from
`S3FS_GUEST_OBJECT`, a key in the roots bucket, and **measured before anything
asks for a key**:

```text
  fetch guest ──▶ extend PCR16 with sha256(guest) ──▶ lock PCR16 ──▶ boot ──▶ KMS
```

PCR0 covers the runtime and *where* the guest comes from; PCR16 covers *what*
arrived. The key policy pins both, on `kms:GenerateDataKey` and `kms:Decrypt`:

```json
"StringEqualsIgnoreCase": {
  "kms:RecipientAttestation:PCR0":  "<pcr.json .PCR0>",
  "kms:RecipientAttestation:PCR16": "<guest-release/guest-pcr16.json .PCR16>"
}
```

What that buys, and what it does not:

- **The object does not have to be trusted.** The parent can replace it. The
  replacement measures to a different PCR16, gets no key, and reads nothing.
- **PCR16 means something only beside PCR0.** The runtime writes it, so an
  enclave running someone else's runtime can put any value there. PCR0 is what
  says the runtime that wrote it is this one — which is why a client must pin
  both, and why `passkey-client` refuses to run without both.
- **The lock is the point.** An attestation document lists only locked
  registers. The runtime checks the register is zero and unlocked beforehand,
  that extending produced exactly `SHA384(0⁴⁸ ‖ sha256(guest))`, and that the
  device reports it locked with that value afterwards, and refuses to start
  otherwise.
- **Measuring a guest is not vetting it.** An approved guest can still write
  what it reads to stdout, which reaches CloudWatch. Approving a guest is
  trusting it with the data.

`nix build .#guest-release` produces `guest.wasm` and `guest-pcr16.json`, the
latter computed by `nitro-attest --measure` — the function clients verify with,
so the value in the policy and the value a client pins cannot disagree.

### Upgrades

**The key policy decides; the boot machine records.** There is no handoff
between images: an enclave KMS released the key to is, by that fact, allowed to
hold the state. A guest change is:

1. upload the new guest to the object key;
2. replace PCR16 in the key policy — replace, never add a second value beside
   it, or the old guest stays approved and returning to it needs nobody's
   say-so;
3. restart the enclave.

A restart between 1 and 2 fails closed: the enclave measures the new guest, KMS
refuses the key, nothing is exposed, and the service is down until the policy
catches up. A runtime change is the same with PCR0.

Each boot looks for a **pair record** under a key derived from
`sha256(PCR0 ‖ PCR16)`:

- **present** — verified against its signature, both registers and this
  `state_root`, and the boot is a plain resume that writes nothing;
- **absent** — the first boot of this runtime and guest on this state. It
  attests, stores the document under Object Lock, and logs `mode=Upgrade`. Two
  first boots racing each other leave one record, and both boot.

So the store holds one signed record for each distinct pair that has ever held
the state, not one per restart. It records *which* pairs, not *in what order*:
going back to an earlier pair finds that pair's record and writes nothing. The
order approvals were given in is in CloudTrail's record of key-policy edits.

This replaced `--authorise-successor`, which extended PCR31 to name the next
image and never locked it — so no document it produced on hardware could have
carried the register the successor was checked against.

## Background tasks

The runtime can run durable tasks for individual tenants, including recurring
checks, with bounded concurrency and execution deadlines. Tasks survive enclave
restarts and run under the same tenant isolation and lock as interactive calls.
The feature is opt-in and requires an authenticated guest implementing the
versioned background interface. See [Background tasks](docs/BACKGROUND_TASKS.md)
for configuration, the guest API, delivery guarantees, and the HTTP example.

## Notifications

A guest can wake its tenant's devices through Firebase Cloud Messaging — for
work that finished, or an approval somebody is waiting on. The guest cannot
reach the network itself, so the runtime holds the credential and sends on its
behalf.

**A wake signal carries no content.** No title, no body, no `notification`
object: the payload crosses the parent instance and Google, which are the two
parties this design excludes from a tenant's data, so what travels is an opaque
category and a tenant-local reference. The app wakes and fetches the detail over
its own attested connection.

Enrolling a device is an interactive-only call; raising a wake is not, because
a background task telling its owner to come and look is the point. See
[Notifications](docs/NOTIFICATIONS.md) for the settings, the guest API, delivery
behaviour, and what a stolen credential does and does not buy.

## Serving HTTP

The runtime terminates HTTPS itself and hands the guest plaintext. This follows
[nitriding](https://github.com/brave/nitriding-daemon), as does
[ArkLabsHQ/enclave](https://github.com/ArkLabsHQ/enclave), and the reason is
the whole point of the exercise: a reverse proxy on the parent instance would
read every request in the clear, and the parent is precisely the party an
enclave exists to exclude.

```text
     internet
        │  HTTPS :443
        ▼
┌──────────────────────────────────────────┐   EC2 parent instance
│  gvproxy   --listen vsock://:1024        │   (untrusted)
│            expose :443 → 192.168.127.2   │
└──────────────────────────────────────────┘
        │  AF_VSOCK CID 3, port 1024  (ethernet frames)
        ▼
┌──────────────────────────────────────────┐   enclave (attested)
│  gvforwarder → tap0  192.168.127.2       │
│                                          │
│  enclave-runtime                         │
│    rustls  :443  ← key born here         │
│      ├─ /enclave/*  → runtime            │
│      └─ everything else                  │
│           ▼  plaintext HTTP              │
│    wasmtime-wasi-http                    │
│           ▼                              │
│    guest.wasm  wasi:http/incoming-handler│
│      imports wasi:filesystem (s3fs)      │
│      imports NO sockets                  │
└──────────────────────────────────────────┘
```

### What the guest gets, and does not

It exports `wasi:http/incoming-handler` and receives a **parsed request**. It
never sees a socket, a connection, a certificate or a TLS record. It cannot
open one either: the linker grants no `wasi:sockets` permission, and
`wasi:http/outgoing-handler` is wired to an [`EgressPolicy`](runtime/src/serve/mod.rs)
that refuses every request.

That refusal is explicit rather than incidental. `wasmtime-wasi-http`'s
`default-send-request` feature is off, which turns `send_request` from a
defaulted method into one this crate must write — so the answer is a decision
with a test, not a consequence of which crate features happened to be on.

`examples/guest-http` is the worked example.

```console
$ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
$ S3FS_TLS=off S3FS_HTTP_LISTEN=127.0.0.1:8080 \
  S3FS_GUEST_PATH=examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm \
  ./target/release/enclave-runtime
$ nonce() { openssl rand 20 | basenc --base64url | tr -d '='; }
$ curl -H "x-enclave-nonce: $(nonce)" localhost:8080/counter    # 1
$ curl -H "x-enclave-nonce: $(nonce)" localhost:8080/counter    # 2 — committed
```

### Requests run one at a time by default

`Fs` is safe to share: handles under a `parking_lot::Mutex`, transaction state
under a `tokio::Mutex`. The *guest* may not be. As the compatibility matrix
above records, SQLite on WASI has to hold `locking_mode=EXCLUSIVE`, because
WASI has no `fcntl` and therefore no file locking — two instances over one
database would each believe they had it alone, and fail in a way that looks
like corruption rather than contention.

So concurrency is **per tenant**: one active guest request for each resolved
tenant identity, and different tenants running at the same time. SQLite's
exclusive lock is safe because a tenant's database is only ever opened by that
tenant's one in-flight request. There is no global ceiling to raise — two
tenants have nothing to queue on.

### One instance per request

No two requests ever share a guest instance. A fresh `Store` is built for each,
and both go when the response does.

That is where the boundary between two clients actually lives. A `Store` is
what separates two wasm instances; give two clients one instance and the
separation stops being a runtime guarantee and becomes guest code, so a bug
that confuses two clients is no longer a leak of one but a total compromise. A
trap has nothing to poison, and leaked resource handles die with the store,
both for the same reason.

The consequence for a guest is a single line: **storage is the only state there
is.** Nothing in memory outlives the call that created it, so whatever must
persist — for a cosigner, the nonce ledger before anything else — goes to the
filesystem, where it is Merkle-anchored, attested and still there after a
restart.

### Who is calling: a passkey, per interaction

**No unspent interaction token means the guest is never called**, and a token
exists only because a person authenticated with their passkey moments earlier.
No session, no cookie, no long-lived credential.

An **interaction** is one HTTP request and its response, or one bidirectional
stream until it closes or reaches its lifetime limit. That unit is the whole
design: a stream has no single request to hang an assertion on — its body *is*
the message sequence, and none of it exists when the channel opens — so the
approval has to name something that exists at approval time. It names the
interaction.

```console
POST /auth/request/options     { credential_id, method, path, query }
        ↓                      response is attested: check it, pin the certificate
   Face ID / Touch ID
        ↓
POST /auth/request/verify      { challenge_id, assertion }
        ↓                      → { token, expires_in_secs }
POST /sign                     Authorization: Bearer <token>
        ↓                      consumed atomically, before dispatch
   verified → tenant → guest
```

Three trips, and they have to be three. A passkey is a challenge-response, so
the assertion cannot exist until the challenge has been answered; the token
cannot exist until the assertion has been checked.

The first trip does double duty. It goes out on a connection nothing has
vouched for yet, which is exactly why it is the right thing to send first: it
carries the operation's route but no approval, so a party that intercepted it
learns what is intended and holds nothing it can act on. Its response is
attested, so **the round trip that fetches the challenge is the one that
identifies the enclave** — there is no separate probe route and none is wanted.

#### What is checked, and by whom

`webauthn-rs` verifies the assertion itself: `clientDataJSON` names
`webauthn.get` and the challenge that was issued, the origin matches **exactly**,
`rpIdHash` is this relying party, user *verification* happened rather than mere
presence, and the signature checks out under the stored key.

The runtime checks everything the protocol has no field for — that the
challenge exists, has not expired and has not been used; and that the
credential is one it knows and has not revoked.

The token it issues is 32 bytes from the NSM, stored only as `sha256(token)` so
possession of the store is not possession of a token, good once, and gone on
restart. Redeeming it removes it before anything about it is checked, so two
callers racing one token have exactly one winner and a token offered for the
wrong route is spent by the attempt.

#### What the approval does and does not name

**It names the interaction: method, path and query. It does not name the
body.**

This is a deliberate trade and it is worth stating flatly rather than burying.
A token issued for `POST /sign` authorizes whatever body follows, so a client
compromised between the approval and the request can substitute the payload.
The runtime will not catch that, because it is no longer looking.

What the runtime still refuses: moving a token to another route, spending one
twice, spending one after it expires, and spending one that belongs to another
tenant.

An authenticator displays nothing either way. The user approves *a prompt at a
moment*, and what that prompt now means is "let this app do this thing here",
not "sign these exact bytes". A design that needs the stronger claim needs the
guest to make it, per message — and the guest cannot yet, because verifying an
assertion needs runtime state it has no way to reach. See
[docs/STREAMING.md](docs/STREAMING.md); that gap should be closed before a real
key depends on it.

#### The topology this implies

The enclave serves nothing without an assertion, so it cannot serve the page
that calls it. For a native mobile app that is clean — the app ships through
the store. For a browser it is not: the HTML has to come from somewhere on the
same origin, and if the enclave will not serve it the parent instance or a CDN
must, and a malicious parent serving a malicious page defeats everything
downstream. This design assumes a mobile client.

#### Registration

Registration is open. Anyone who can reach `/auth/register/options` may present
a passkey and get a tenant, with no invitation, token or operator approval in
the way.

What that grants is deliberately narrow: a **new, empty tenant and nothing
else**. It cannot reach an existing tenant's data, approve a transaction, or add
a passkey to somebody else's account — each of those still needs an assertion
from a credential already registered there. Registration gates nothing;
passkeys gate access.

The cost of that choice is admission control over resource creation. A tenant is
a directory the enclave keeps, and a slot against `--max-tenants`, so anyone who
can open a connection can consume both. An operator who needs to bound that has
to do it in front of the enclave, because the runtime no longer does.

The tenant id is 32 bytes minted from the NSM, stored beside the credential —
not derived from it, so one tenant can hold several passkeys.

#### What a stream costs

A stream is an interaction, so it is approved the same way as anything else —
that unification is what removed a second, weaker approval path that used to
exist only because the old body-hash binding could not express a stream.

The cost is that **an open stream holds its tenant's single slot for its whole
life**. Concurrency is one active guest handler per tenant, because a tenant's
SQLite database is only safe while exactly one of their requests is in flight,
so that tenant's next request waits behind the stream. Different tenants are
unaffected. Two limits bound it: `--interaction-token-ttl-secs` for how long an
approval may sit unspent, and `--max-interaction-secs` for how long one may run
once started.

See [docs/STREAMING.md](docs/STREAMING.md) for the failure modes and what the
runtime does not promise — there is no retry, no resumption, no deduplication
and no exactly-once execution.

### A directory per client

Every authenticated client gets its own corner of the filesystem. There is
still **one** mounted filesystem, one block cache and one transaction stream;
what is per-client is a directory under `/tenants/<id>/`, a warm guest
instance, and a lock.

The identifier is derived, never stored: `HKDF(master, sha256(client SPKI))`.
The same client lands on the same directory on every boot from nothing but the
handshake, and without the master secret nobody can work out which directory is
whose.

Each client's guest is told which tenant it is serving through
`x-enclave-tenant`, written by the runtime from the verified assertion and
never read from the client.

#### The separation is the runtime's, not the guest's

Each client's instance is handed **its own directory as its preopen**, and the
resolver refuses every way a path can name something above it:

| | |
|---|---|
| absolute paths | restart at the tenant's root, so `/etc/passwd` means `<tenant>/etc/passwd` |
| `..` | stops at the tenant's root, however many are chained |
| absolute symlink targets | resolve from the tenant's root too |
| asking a descriptor for its parent | the tenant's root is its own parent |

Those are the only four routes out, and they hold inductively: a walk starts at
the tenant's root or below, and none of them can take it higher. `guest-http`
has an `/escape/<path>` route that opens whatever it is given with **no
validation at all**, and the test suite points it at other tenants' files to
prove the refusals come from the capability layer rather than from a
well-behaved guest.

#### What it costs, and what it does not

A client costs a directory — no mount, no second key derivation, no signed root
record to read, no extra cache. That is why this is worth doing with one
filesystem rather than many.

What it changes is concurrency. A client is serialised against *itself* and
nobody else, which is what makes a nonce reservation safe while letting two
clients' guests run at once. Their **commits still queue**, though: one
filesystem means one transaction lock, so the gain is in guest execution and
reads rather than in writes.

This is the model, not an option: a guest is written for it.

```console
$ S3FS_MAX_TENANTS=64 ... enclave-runtime
```

The lock a tenant holds is released when its guest **finishes** — body
included, not when its headers appear — so a tenant's next request waits for
the previous one to be genuinely done. A slow reader therefore occupies its own
tenant's slot and nobody else's.

**Callers with no resolved tenant share one slot.** Without a gate configured,
or on a path that does not identify itself, there is no identity to separate
requests by — so they serialise against each other over the runtime's own
filesystem. Unbounded would let anyone with a socket multiply wasm linear
memories, which is exactly the exhaustion the per-tenant lock prevents for
callers who *are* identified.

`--max-tenants` bounds warm *instances*, each of which costs a wasm linear
memory; past it the least recently used idle client is dropped, and one serving
a request is never evicted.

#### Why there is no separate register

An earlier design gave each client its own filesystem, which needed a register
to answer "should this client have one?" — because a host who hid a client's
root record would otherwise get a fresh, empty filesystem built for them, with
their policy reset and their nonce ledger emptied.

With one filesystem that question answers itself. `/tenants/<id>` either exists
in the Merkle tree or it does not; the tree is covered by one signed root
record, and that record is attested by the state-origin receipt at boot. Hiding
one client's directory means changing the root hash, which fails before a single
request is served. The filesystem is the register.

### The attestation binding

The TLS key is generated inside the enclave and never leaves it. **Every
`/auth/*` response carries a fresh attestation document** binding a nonce the
client chose and the SHA-256 of the certificate *that connection* was served, so
a client ties the connection in its hand to the code it attested without a
second round trip.

| Header | |
|---|---|
| `x-enclave-nonce` | request. base64url, no padding; 8–64 bytes decoded. **Required on every request**, whether or not the runtime attests — so a client behaves the same either way and a deployment cannot quietly stop attesting. Missing or malformed is a 400, before the guest is invoked. |
| `x-enclave-attestation` | response. base64 COSE_Sign1. Runtime-owned: it is `insert`ed, never appended, so a guest that sets it is overwritten. The response is also forced to `cache-control: no-store` — a cached document is a replayed one. |

Every response under `/auth/` gets one, whatever it says: the challenge, the
token, a refusal, and a 405 for `GET /auth/` — which is how a client attests the
enclave without asking it for anything, and what `nitro-attest --url` requests
when given no path. The document is generated *before* the request is routed,
because it binds nothing the route produces; if the NSM refuses, the request
fails with a 503 and nothing is routed.

**Guest responses carry none.** A client identifies the enclave on the auth
exchange and pins the certificate that exchange attested; the operation that
follows runs on a connection serving that certificate, and TLS proves the peer
still holds its key. A second document would repeat the first at the cost of an
NSM signature, and the device is the throughput ceiling. The header is stripped
from guest responses, so a guest cannot put one of its own there. A client that
pins the certificate this way must refuse a connection serving any other.

A request without a valid nonce is refused with a 400 before routing, and gets
no document: there is no client nonce to bind.

`user_data` follows nitriding's layout — two multihash-prefixed SHA-256
digests, 68 bytes:

```text
  0x12 0x20 ‖ sha256(TLS leaf DER) ‖ 0x12 0x20 ‖ sha256(guest component)
```

The certificate hash ties the TLS session to the document; the guest hash says
which application was behind it.

**Pin two measurements, and know which one the other rests on.** PCR0 is
measured by the hypervisor from the image and locked, so nothing running inside
the enclave can choose it — but the image no longer contains the guest. PCR16 is
the guest: the runtime extends it with the component's hash and locks it before
it can obtain a key. Because the runtime is what writes it, an attacker running
their own runtime produces a genuinely signed document claiming whatever PCR16,
and whatever `user_data` guest hash, you were going to check for.

So **pin PCR0 and PCR16 together**. PCR0 says the runtime is yours, which is what
makes its PCR16 mean anything; PCR16 says which application that runtime loaded,
which PCR0 can no longer say. `--guest` supplies PCR16 from the component and
checks the `user_data` hash too; without `--pcr0` beside it, it authenticates
the hardware and calls it the software.

`nitro-attest` requires both measurements when verifying a URL or saved
document. Only `--measure` and the explicit `--unsigned-emulator` mode are
exempt.

Verify an endpoint with one command:

```console
$ nitro-attest --url https://enclave.example --pcr0 8cac35ce… \
      --guest ./guest.wasm
module     i-0abc…-enc0123…
PCR0       8cac35ce…
PCR16      4f1d9b0a…
chain      verified to the AWS Nitro root
tls hash   3aa2e103…
guest hash 7ee636bc…
binding    the attested certificate is the one serving this connection
guest      matches ./guest.wasm (PCR16 and user_data)
OK
```

That last line is the one that matters. Without it a valid attestation
document proves only that *an* enclave exists somewhere — a proxy could fetch a
genuine one and serve it over its own TLS session. With it, the only party who
could have produced the document is the one holding the private key for the
connection in hand.

#### The connection, not the process

The document binds the certificate **this connection** was served, not whatever
certificate the runtime happens to hold now. Those differ across an ACME
renewal, and a client on an older connection being told the newer hash would
read as an attack when nothing was wrong.

So a connection loads its serving identity — config and leaf together — once,
at accept time, and keeps it for its life. TLS session resumption is disabled
for the same reason: rustls calls the certificate resolver while processing
every ClientHello but sends a certificate only on a full handshake, so on a
resumed connection "the certificate this connection is using" would not be a
well-defined thing to sign. The cost is one handshake signature per connection,
which is nothing beside the per-request one below.

#### What this does not prove

- **Nothing about the response body.** The document is generated before the
  guest runs and binds only the nonce and the certificate. It is a fresh
  enclave-to-TLS binding, *not* an independently signed receipt for what the
  guest said.
- **Nothing before the request was sent.** By the time the client sees the
  proof, its request is already inside the enclave. Verifying a connection means
  receiving a response on it, so something has to go first on a connection
  nothing has vouched for.

  The challenge request is that something, and it is the right thing to send:
  `POST /auth/request/options` carries the operation's hash but no approval, so
  a party that intercepted it learns what is intended and holds nothing it can
  act on. Its response is attested like every other, so **the round trip that
  was needed anyway is the one that identifies the enclave** — there is no
  separate probe route and none is wanted.

  The order matters. A person is asked to approve only *after* the far end has
  been identified, never before.

  The operation then needs no second document. The verified one binds a
  certificate, and TLS proves the peer holds that certificate's *private key* —
  which the certificate, being public, does not prove by itself. So the client
  completes the operation's handshake, checks it was served the same
  certificate, and only then sends: a changed far end means the request is never
  sent rather than sent and regretted. It is deliberately **not** retried, since
  the assertion is single-use and bound to that exact body, so a retry risks
  executing twice. This is why session resumption is refused — a resumed session
  need present no certificate, and pinning against a cached one checks nothing.
  See `passkey-client` for the flow in full.
- **Not verifiable from a browser page.** The check requires the client's own
  peer certificate, and ordinary JavaScript cannot read it. This is for native
  clients and `nitro-attest`.
- The client has to do its part, and the runtime cannot make it: a CSPRNG nonce
  per request, a comparison against the nonce it sent, and treating a *missing*
  header as a failure. Without the last of those, stripping the header
  downgrades every client that does not check.

#### Cost and limits

A document is an ECDSA P-384 signature on the NSM, so attestation is now a
**per-request** cost and NSM availability a per-request dependency. At most
four are in flight at once, on `spawn_blocking` so the ioctl never occupies a
Tokio worker; that bound is also the runtime's throughput ceiling. The
per-signature cost on real Nitro hardware is **not yet measured** — it is one
of the things the first hardware run has to report.

The header is checked once at startup against a 16 KiB ceiling, and the runtime
refuses to boot if a document does not fit. Against the test chain a whole
response head measures **2.4 KiB**; a real AWS document carries a longer CA
bundle, so expect **6–8 KiB**. Servers do not limit response headers here —
hyper imposes none and HTTP/1.1 is the only protocol compiled — so the
constraint is entirely the client's. **Configure at least 32 KiB.** Node is the
binding case at 16 KiB for the *whole* head by default (`--max-http-header-size`).

### Certificates

| `--tls` | |
|---|---|
| `acme` *(default)* | Let's Encrypt over **TLS-ALPN-01**, on the same :443 already forwarded. Needs `--tls-domain` and outbound network. |
| `off` | Plaintext. Inside an enclave this hands every request to the parent. |

There is no self-signed mode in any build, and asking for one is refused with a
reason rather than "expected one of …". A certificate the operator can mint is
one they can mint for an impostor too, so it cannot tell this enclave apart
from something impersonating it. A deployment with no public CA points
`--acme-directory` at a private one instead — which is exactly what the QEMU
end-to-end does, against a Pebble on the host.

Let's Encrypt buys browser compatibility, not trust. The operator controls the
domain and could obtain their own certificate for it and terminate TLS
themselves; the attestation binding is what closes that, because a client
checking it will not accept a certificate the enclave did not attest.

The ACME account key and the certificate's private key are sealed with
AES-256-GCM under a key derived from the master secret and written as ordinary
objects — the parent stores ciphertext. They are deliberately not in the
filesystem, because the guest's preopen is its **root**, and a guest holding
the TLS private key could impersonate the enclave. Caching is not optional:
Let's Encrypt allows five duplicate certificates per week, so an enclave
re-issuing on every boot would exhaust that and be unable to serve.

### The parent instance

An enclave has no NIC. Nothing above works until the parent turns vsock into an
interface, and an enclave that boots and then answers nothing is almost always
this:

```console
$ ./deploy/parent/run-parent.sh          # gvproxy + inbound :443 forwarding
$ nitro-cli run-enclave --eif-path s3fs.eif --cpu-count 2 --memory 2048
```

The parent carries ciphertext it cannot read — TLS to S3 and KMS is
established inside the enclave, and inbound HTTPS is terminated inside it. What
it does learn is metadata, and it can of course refuse to carry anything;
neither is new, since it already decides whether the enclave runs. What is not
safe is trusting its DNS, which is why every outbound connection validates
certificates.

### What is verified, and what is not

Covered on every push: the dispatch path against a real component over the
in-memory backend, and a real TLS connection whose response header is checked
to bind the certificate from the handshake — including the failures, where a
substituted certificate breaks the binding, an earlier document does not
satisfy a later nonce, a guest cannot overwrite the proof header, and a
connection open across a certificate renewal keeps binding the certificate it
was actually served.

**Not covered on every push:** ACME issuance, which needs a CA and a reachable
name. The QEMU end-to-end covers it against a local Pebble — order, challenge,
finalize, and the served chain verified against the CA's root — so what remains
untested is Let's Encrypt's own behaviour: its rate limits, its real chain, and
renewal timing. Chain validation to the AWS Nitro root is likewise
hardware-only, since QEMU signs with a key it generates.


## Guest output

A guest's `stdout` and `stderr` are not inherited from the enclave process.
They are custom WASI streams that frame what the guest writes into lines and
hand them to the runtime's logging pipeline, tagged with the stream they came
from:

```
guest write ──▶ line framing ──▶ bounded queue ──▶ collector ──▶ sink
                (per stream)     (drops when       (one task)    └─ tracing
                                  full)                          └─ future: vsock
```

Records arrive as structured `tracing` events under the target `guest`, with
`guest_stream` set to `stdout` or `stderr` and the text in a quoted, escaped
`guest_message` field — quoted because guest bytes must not be able to render
as fields the runtime never set:

```
INFO guest: guest output guest_stream="stdout" truncated=false guest_message="first line"
WARN guest: guest output guest_stream="stderr" truncated=false guest_message="on stderr"
INFO enclave_runtime::mount: mounted mode="genesis" root_seq=0 …
```

`stderr` is emitted at `warn` and `stdout` at `info` — which stream was written
to, not what the text means. **No severity is inferred from guest content**, or
a guest could pick its own log level.

**Guest logs are attacker-controlled data.** Everything on this path was chosen
by the guest, including text shaped exactly like the runtime's own log lines.
The two are separable only by the tracing target, which a guest cannot
influence, and guest text never reaches an event name or target — only a field
value. The console prints targets for exactly this reason: guest lines say
`guest`, everything else names a module in the runtime, so an operator reading
the console can see which lines are untrusted rather than having to know a
filter. `RUST_LOG=guest=warn` narrows or silences guest output independently.
**A guest log is not an audit record** and must never be read as one.

**Logging is best-effort and lossy under pressure.** A guest write never waits
on a log destination, so the queue is bounded and records are dropped when it
is full. The guest still sees a successful write: congestion is a host concern
and must not become a guest-visible failure, let alone a stall. Drops are
counted and reported in aggregate on an interval — never one warning per
dropped write, which would hand a guest an amplification primitive against the
log it is congesting.

What that guarantees, and what it does not:

| | |
|---|---|
| Bounded memory | 1024 queued records, each ≤ 16 KiB, plus one partial line ≤ 16 KiB per open stream. A guest writing a gigabyte without a newline costs 16 KiB and a truncation flag. |
| No stall | A sink that never returns cannot delay a guest write, and cannot hold up shutdown beyond a fixed 2-second drain. |
| No delivery guarantee | Output is lost when the queue fills, and anything still queued is lost if the enclave stops abruptly. |
| Lines, not bytes | Partial writes are joined; `\r\n` is normalised; invalid UTF-8 is replaced lossily rather than dropped; a final unterminated line is emitted when the stream closes. |
| Truncation is explicit | A record longer than 16 KiB is cut and carries `truncated = true`. |

`stdin` is closed rather than inherited. An enclave has no console to read from,
so an inherited `stdin` offered a guest nothing but a handle on whatever the
parent had attached to the process.

Delivery beyond this process — batching over vsock to a parent-side agent, and
from there to CloudWatch — sits behind the `GuestLogSink` trait and is not
built. When it is, note that an ordinary relay through the parent can read,
drop, reorder and forge records: TLS from the parent to CloudWatch is not
confidentiality *from the parent*. Authenticity would need sequence numbers and
a MAC or signature generated inside the enclave; confidentiality would need
records encrypted to a log consumer's key before they leave.

### Sending guest logs to CloudWatch

Guest output can go to CloudWatch Logs as well as the console. Set the group and
stream — both must already exist:

```bash
enclave-runtime --mode serve \
  --guest-log-group /my-enclave-production/guest \
  --guest-log-stream guest
```

`deploy/tofu` creates them and grants the role `logs:PutLogEvents` on that one
stream. The enclave cannot create a group or a stream, deliberately: a typo
fails its boot loudly rather than quietly filling a group nobody watches.

**The enclave calls CloudWatch itself.** It already calls S3, KMS and SSM the
same way — over the tap device and gvproxy — so relaying logs through a
parent-side process would add a wire format, a transport and a second binary to
reach a service this runtime can already reach. It would also be worse: a relay
reads the plaintext.

Credentials come from the SDK's default chain. The enclave has no NIC, but its
egress is NATed by gvproxy through the parent, where `169.254.169.254` is
reachable — so the chain resolves to the **parent instance's role**. That is why
the production image sets no keys.

| | |
|---|---|
| Never delays a request | A guest write never touches the network. `emit` stamps and enqueues; only the forwarder waits on AWS. |
| Bounded | 4096 queued records, then 16 pending batches. Beyond that output is dropped and counted. |
| Drops from both ends | The record queue drops what is *arriving* — `emit` must return in constant time. The batch deque drops the *oldest* — when CloudWatch has been away that long, recent output is what matters. |
| Retries | Own backoff, 250 ms to 30 s, with the SDK's retries disabled so the two do not compound. A refused batch is retried, not discarded. |
| Gives up loudly | A refusal that cannot heal — the stream is gone, or the role lacks the permission — stops the boot rather than retrying forever. |
| No delivery guarantee | Records older than an hour are dropped; so are events CloudWatch rejects inside a 200 response. Both are counted. Anything queued is lost if the enclave stops abruptly. |

Each event is JSON — `{"source":"guest","stream":"stdout","truncated":false,
"message":"…"}` — so guest text is a **field value** and cannot invent structure
a log query would attribute to the runtime. The runtime's own boot marker
carries `source:"runtime"` and the image PCR0, which is what says who is writing
to a stream that every boot shares.

**What the parent can still do.** TLS terminates inside the enclave against the
image's own CA bundle, so the parent cannot read or alter records in flight. It
*can* block or delay them — it carries the packets and answers DNS — and it
*can* forge records out of band, because the credentials are its own instance
role and it can write to the same stream itself. Closing that needs a distinct,
attested identity for the enclave, which does not exist yet. And the content was
never trustworthy anyway: a guest chose the text. **These are operational
records, not an audit trail.**

The cost, stated plainly: a CloudWatch SDK is now inside the boundary PCR0
measures. It brings no new crypto stack — KMS and SSM already pull `rustls` —
but it is more code in the attested image, in exchange for logs the parent
cannot read.

**Unverified production dependency.** Nothing here proves an enclave can reach
IMDS. The QEMU harness has no metadata service, so gvproxy's handling of
`169.254.169.254` has never been exercised — and *every* AWS call the enclave
makes depends on it, not only logging. IMDSv2 credential resolution and a real
`PutLogEvents` are to be validated on Nitro hardware before production, beside
the KMS tests in the same category.

The code is built to survive that being wrong. Connection failures, unresolved
credentials and expired tokens are all classified **transient**: they are
retried with backoff, counted, and never stop the enclave. Only
`ResourceNotFoundException` and `AccessDeniedException` are final, because only
those name a mistake waiting cannot fix. The startup handshake is bounded, so a
credential path that stalls costs guest logs and never the listener — if
gvproxy turns out not to forward IMDS, this degrades to console-only logging
rather than to an enclave that will not serve.


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

## Building and deploying

```console
$ nix build .#eif                    # the enclave image + pcr.json
$ packer build … deploy/ami          # an AMI with nitro-cli, gvproxy, the EIF
$ tofu apply -var ami_id=ami-…       # a parent instance running it
```

Two build tools, split along the trust boundary rather than by taste.

**Nix builds everything inside the enclave**, because PCR0 is a digest of
exactly those bytes and the number is only worth something if an independent
party can rebuild the image and get the same one. `nix build .#eif --rebuild`
verifies that. Earning it took `cpio --reproducible` (the `newc` header records
inode and device numbers, so even the two-file bootstrap ramdisk differed every
build), fixed uid/gid/mtime, sorted members, and `faketime` around `eif_build`,
which stamps wall-clock `BuildTime` into the image's metadata. Details in
[`deploy/nix/README.md`](deploy/nix/README.md).

**Packer builds the parent**, which is the party the enclave *excludes*. PCR0
covers the enclave, not its host, so reproducing the host buys no security
property — and AWS ships and supports `nitro-cli` and the allocator on Amazon
Linux 2023. No Docker on the parent: it is needed only by `nitro-cli
build-enclave`, and Nix builds the image.

`gvproxy` and the `gvforwarder` inside the EIF come from one nixpkgs package,
built static, so both ends of the vsock share a pin and can't drift.

### The end-to-end

[`deploy/qemu-nitro/run-e2e.sh`](deploy/qemu-nitro/run-e2e.sh) boots the image
under QEMU's `nitro-enclave` machine with a real gvproxy, and asserts what had
never been checked together:

```
1/8  the guest is unreachable without a passkey    401 on /, /counter, /memory
2/8  a passkey registers, and writes reach MinIO   counter: 1 then 2
2b/8 signed requests drive real filesystem work    8 files written, read,
                                                   overwritten and re-read
3/8  the attestation binds this connection,        binding    the attested
     its runtime and its guest                     certificate is the one
                                                   serving this connection
3b/8 a signed interaction verifies the enclave     binding    …
4/8  the attested PCR0 and PCR16 are the builds'   PCR0  build:    b3edc9c9…
                                                         attested: b3edc9c9…
5/8  a tenant keeps its instance; none are shared  alice 1,2 · bob 1
5b/8 an approval for one route authorizes no other
5c/8 guest output reaches the console, tagged untrusted
6/8  work approved once runs later, unsigned       scheduled work ran for its
                                                   owner alone
7/8  a second boot resumes rather than starting over
8/8  a substituted guest is measured, recorded as an upgrade, and refused
     by a client pinning the approved one
```

Leg 3 verifies the `/auth/` exchange the way a client would before sending
anything; leg 3b checks the document from the exchange a real, passkey-signed
interaction made.

The guest is not in the image: the harness builds `.#guest-release`, uploads
`guest.wasm` to MinIO, and checks the PCR16 the enclave attests against
`guest-pcr16.json`. Leg 7 then replaces the object and restarts. The enclave
boots — the emulator has no KMS to refuse it a key — with a PCR16 that
`nitro-attest --guest <the approved guest>` rejects.

The enclave gets an address by DHCP over the emulated vsock, mounts the
Merkle-anchored filesystem from MinIO on the host through gvproxy, obtains a
certificate over ACME, and serves the guest.

**The certificate is real ACME, not a shortcut.** A [Pebble](https://github.com/letsencrypt/pebble)
runs beside MinIO as the CA, and the enclave walks the whole path against it:
directory, account, order, TLS-ALPN-01 challenge, finalize, and the result
sealed into the block store. The challenge arrives inbound on the same port
the service uses — gvproxy forwards :443 into the enclave, and Pebble is told
to resolve `enclave.test` to that forward — which is the arrangement production
runs. The harness then verifies the served chain against Pebble's published
root, so "the CA issued this" is checked rather than assumed.

This replaced a self-signed certificate, and the reason is worth stating: the
old image proved a TLS mode a production build could not even parse. The only
test-shaped concession left is `S3FS_ACME_CA`, which points the enclave at
Pebble's root for the directory's own HTTPS — a flag a production binary does
not have.

**The signature is real, the key is not.** QEMU's emulated NSM does not sign
anything — its source says *"we don't actually sign the data, so we use -1 as
the 'alg' value"*, and -1 is not a COSE algorithm identifier. So the emulator
image mints a certificate chain at boot and re-signs the documents the device
produced, contents untouched, and reports the root on its console. Clients then
run their whole verification path — COSE ES384, the chain, the validity windows,
the pinned root, both PCRs — which is what they will run against hardware.

What that does *not* establish is who produced a document: the key is inside an
image its operator controls, so a verified document here means "this image said
so" rather than "a Nitro enclave with this measurement said so". Closing that
gap needs real hardware, and so does KMS refusing a key to a substituted guest.

### A development enclave

The same stack, left running, serving a component of your own:

```bash
deploy/qemu-nitro/dev-enclave.sh --guest path/to/your-component.wasm
```

[`dev-enclave.sh`](deploy/qemu-nitro/dev-enclave.sh) and `run-e2e.sh` share
their bring-up in [`deploy/qemu-nitro/lib.sh`](deploy/qemu-nitro/lib.sh), so what
a client is developed against is what CI checks. It prints the URL and the three
values a client pins — PCR0, PCR16 and the trust root — and waits.
[`docs/DEV_ENCLAVE.md`](docs/DEV_ENCLAVE.md) has the rest, including what is and
is not real about it.

### What the enclave consumer still owns

**Credential sourcing via KMS attestation.** Static credentials are passed in
today. M8 replaces that with `kms:Decrypt` carrying an attestation document,
gated on PCR0 — at which point nothing on the parent holds a key that reads the
filesystem. The vsock HTTP client that milestone once needed is no longer
required: gvproxy gives the enclave an ordinary IP stack, so the AWS SDK works
unmodified.

## License

Apache-2.0.
