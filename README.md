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
| [`enclave-runtime`](crates/enclave-runtime/) | Everything above the engine: `wasi:filesystem@0.2.x`, the linker, the guest-environment policy, the vsock tap device, TLS termination and the attestation endpoints — plus the binary that ties them together. A library beside the binary so integration tests can reach it. |
| [`examples/guest-smoke`](examples/guest-smoke/) | Minimal guest, no C toolchain needed. Exercises write / patch / rename / read_dir and the environment policy; run twice it proves durability. |
| [`examples/guest-sqlite`](examples/guest-sqlite/) | SQLite conformance and benchmark workload — DDL, transactions, savepoints, constraints, joins, CTEs, window functions, blobs, triggers, `ALTER TABLE`, `VACUUM`, `integrity_check`. Needs wasi-sdk. |
| [`examples/guest-fsdemo`](examples/guest-fsdemo/) | The original smaller SQLite demo. |

**Test coverage:** 502 tests — unit tests across the workspace, a MinIO integration suite (real S3 wire protocol, Object Lock retention, remount, tamper detection, rollback floor), a boot-machine suite that walks every row of the state-origin table, and two suites that serve a real component over TLS and check the attestation binding. There are no cargo features to select: `cargo test --workspace` runs everything; 23 of those tests skip themselves without MinIO or enclave hardware.

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

# 3. Build the runtime and execute the guest
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
  --guest-path examples/guest-fsdemo/target/wasm32-wasip2/release/guest-fsdemo.wasm
# → prints "OK"
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

| receipt | store | PCR0 | |
|---|---|---|---|
| absent | empty | — | **genesis** — mint key, seal, create, write receipt |
| absent | present | — | **refuse** — state nobody accounted for |
| present | empty | — | **refuse** — state has been hidden |
| present | present | mine | **resume** |
| present | present | other | **migration**, if authorised |

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
hardware and protects nothing. Real sealing is KMS `Decrypt` with a `Recipient`
under a policy conditioned on `kms:RecipientAttestation:PCR0`, and that is
where *"only the correct enclave boots"* is actually enforced: a wrong enclave
does not get a refused mount, it gets no key at all. It is the next
implementation of one trait and nothing above it changes.

### Upgrades

A resuming enclave demands the receipt carry its own PCR0, so any image change
would otherwise make the filesystem unmountable. The outgoing image authorises
the incoming one explicitly:

```console
$ enclave-runtime --authorise-successor <new PCR0>   # run against the OLD image
```

It extends **PCR31** with the successor's PCR0 — irreversibly, for that
enclave's life — then attests. The resulting receipt proves both who wrote it
and that they had committed to that specific successor beforehand, in two
independent places. A receipt naming one image does not admit another.

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
`wasi:http/outgoing-handler` is wired to an [`EgressPolicy`](crates/enclave-runtime/src/serve/mod.rs)
that refuses every request.

That refusal is explicit rather than incidental. `wasmtime-wasi-http`'s
`default-send-request` feature is off, which turns `send_request` from a
defaulted method into one this crate must write — so the answer is a decision
with a test, not a consequence of which crate features happened to be on.

`examples/guest-http` is the worked example.

```console
$ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
$ S3FS_MODE=serve S3FS_TLS=off S3FS_HTTP_LISTEN=127.0.0.1:8080 \
  S3FS_GUEST_PATH=examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm \
  ./target/release/enclave-runtime
$ curl localhost:8080/counter    # 1
$ curl localhost:8080/counter    # 2 — committed to the block store
```

### Requests run one at a time by default

`Fs` is safe to share: handles under a `parking_lot::Mutex`, transaction state
under a `tokio::Mutex`. The *guest* may not be. As the compatibility matrix
above records, SQLite on WASI has to hold `locking_mode=EXCLUSIVE`, because
WASI has no `fcntl` and therefore no file locking — two instances over one
database would each believe they had it alone, and fail in a way that looks
like corruption rather than contention.

So `--http-concurrency` defaults to `1`. Raise it for a guest that keeps no
cross-request state in the filesystem.

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

### Who is calling: a passkey, per request

**No valid, fresh, single-use WebAuthn assertion bound to this exact request
means the guest is never called.** No session, no cookie, no bearer token and
no certificate authorizes a guest request by itself.

That rule is absolute because of what this thing is. A cosigner's whole value
is that compromising the client is not enough — and a bearer credential the
client holds is exactly a thing that can be stolen and replayed. An assertion
cannot be, because the challenge it answers was issued for one operation and is
destroyed when it is used.

```console
POST /auth/request/options     { credential_id, method, path, query, body_sha256 }
        ↓                      runtime records what the challenge is for
   Face ID / Touch ID
        ↓
POST /sign                     x-webauthn-challenge-id, x-webauthn-assertion
        ↓                      runtime re-hashes the body it will forward
   verified → tenant → guest
```

#### What is checked, and by whom

`webauthn-rs` verifies the assertion itself: `clientDataJSON` names
`webauthn.get` and the challenge that was issued, the origin matches **exactly**,
`rpIdHash` is this relying party, user *verification* happened rather than mere
presence, and the signature checks out under the stored key.

The runtime checks everything the protocol has no field for — that the
challenge exists, has not expired and has not been used; that the credential is
one it knows and has not revoked; and that **the request that arrived is the
request the challenge was issued for**. Without that last one an approval for
one transaction would authorize another, which for a cosigner is the whole
attack.

The body is buffered so its hash can be checked, bounded by
`--max-request-body-bytes`, and the hash is taken from the bytes that will
actually be forwarded — never from anything the client says about them.

#### What a signature does and does not prove

An authenticator displays nothing. The user approves *a prompt at a moment*,
not a payload they read. "The user approved this exact operation" is precise
only because the runtime chose the challenge, remembered what it was for, and
will accept it for nothing else. The strength is in the binding, not the
ceremony.

#### The topology this implies

The enclave serves nothing without an assertion, so it cannot serve the page
that calls it. For a native mobile app that is clean — the app ships through
the store. For a browser it is not: the HTML has to come from somewhere on the
same origin, and if the enclave will not serve it the parent instance or a CDN
must, and a malicious parent serving a malicious page defeats everything
downstream. This design assumes a mobile client.

#### Enrollment

Registering a passkey creates a tenant, so it is gated by a single-use token an
operator provisions (`--enrollment-token`). The token authorizes **creating a
tenant and nothing else** — it cannot reach existing data, approve a
transaction, or add a passkey to somebody else's account.

That distinction carries weight, because inside an enclave the token arrives
through the parent instance, which is the party the enclave exists to exclude.
A parent that steals one can make a tenant of its own; it still cannot read
anyone else's, because reading needs a passkey it does not hold. Enrollment
gates resource creation; passkeys gate access.

The tenant id is 32 bytes minted from the NSM, stored beside the credential —
not derived from it, so one tenant can hold several passkeys.

#### Limits

Asking for a challenge is what makes a phone buzz, so it is rate-limited per
credential. Not per address: the enclave sits behind gvproxy, so every client
arrives from the same peer and an address limit would throttle everyone
together and single nobody out.

### A directory per client

`--warm-instances` gives every authenticated client its own corner of the
filesystem. There is still **one** mounted filesystem, one block cache and one
transaction stream; what is per-client is a directory under `/tenants/<id>/`, a
warm guest instance, and a lock.

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

What it does change is concurrency. Today one request runs at a time, globally.
With this on, a client is serialised against *itself* and nobody else, which is
what makes a nonce reservation safe while letting two clients' guests run at
once. Their **commits still queue**, though: one filesystem means one
transaction lock, so the gain is in guest execution and reads rather than in
writes. And any guest invariant that quietly relied on global serialisation now
breaks — which is why this is opt-in, and why PCR0 records it.

```console
$ S3FS_WARM_INSTANCES=1 S3FS_HTTP_CONCURRENCY=8 S3FS_MAX_TENANTS=64 \
  ... enclave-runtime
```

`--max-tenants` bounds warm *instances*, each of which costs a wasm linear
memory; past it the least recently used idle client is dropped, and one serving
a request is never evicted. Raise `--http-concurrency` alongside it, or every
client still queues behind every other whatever the per-client locks say.

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

The TLS key is generated inside the enclave and never leaves it. Its
certificate's hash goes into the attestation document, so a client can tie the
connection it holds to the code it attested:

| Endpoint | |
|---|---|
| `GET /enclave/attestation?nonce=<hex>` | base64 COSE_Sign1, `no-store` |
| `GET /enclave/config` | PCR0 and the two hashes, nothing secret |

`user_data` follows nitriding's layout — two multihash-prefixed SHA-256
digests, 68 bytes:

```text
  0x12 0x20 ‖ sha256(TLS leaf DER) ‖ 0x12 0x20 ‖ sha256(guest component)
```

The certificate hash ties the TLS session to the document; the guest hash says
which application was behind it. `/enclave/` is reserved and checked before the
guest sees a request — a guest that could answer there could serve any
attestation it liked. The nonce is **required**: a document without one cannot
be shown to be fresh, and serving one on demand invites exactly the replay the
nonce exists to prevent.

Verify an endpoint with one command:

```console
$ nitro-attest --url https://enclave.example/enclave/attestation \
      --pcr0 8cac35ce… --guest ./guest.wasm
module     i-0abc…-enc0123…
PCR0       8cac35ce…
chain      verified to the AWS Nitro root
tls hash   3aa2e103…
guest hash 7ee636bc…
binding    the attested certificate is the one serving this connection
OK
```

That last line is the one that matters. Without it a valid attestation
document proves only that *an* enclave exists somewhere — a proxy could fetch a
genuine one and serve it over its own TLS session. With it, the only party who
could have produced the document is the one holding the private key for the
connection in hand.

### Certificates: self-signed or Let's Encrypt

| `--tls` | |
|---|---|
| `self-signed` *(default)* | Generated at startup. Browsers refuse it; attestation-verifying clients do not care, because the binding proves more than a CA signature does. |
| `acme` | Let's Encrypt over **TLS-ALPN-01**, on the same :443 already forwarded. Needs `--tls-domain` and outbound network. |
| `off` | Plaintext. Inside an enclave this hands every request to the parent. |

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
in-memory backend, and a real TLS connection whose attestation document is
checked to bind the certificate from the handshake — including the failures,
where a substituted certificate breaks the binding and an earlier document does
not satisfy a later nonce.

**Not covered:** a successful ACME issuance. That needs a CA and a domain it can
reach; the path from a signed order to a served certificate is written and
unexercised. Chain validation to the AWS Nitro root is likewise hardware-only,
since QEMU signs with a key it generates.


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
under QEMU's `nitro-enclave` machine with a real gvproxy, and asserts three
things that had never been checked together:

```
1/3  the filesystem is mounted over gvproxy    counter: 1 then 2
2/3  the attestation binds this connection     binding    the attested
                                               certificate is the one
                                               serving this connection
3/3  the attested PCR0 is the build's          build:    b3edc9c9…
                                               attested: b3edc9c9…
```

The enclave gets an address by DHCP over the emulated vsock, mounts the
Merkle-anchored filesystem from MinIO on the host through gvproxy, terminates
TLS with a certificate generated inside itself, and serves the guest.

**What it does not prove.** QEMU's emulated NSM does not sign attestation
documents — its source says *"we don't actually sign the data, so we use -1 as
the 'alg' value"*, and -1 is not a COSE algorithm identifier. So no signature
and no certificate chain are checked, only the contents the runtime put there.
`nitro-attest --unsigned-emulator` says so on every run. The signature path
needs real Nitro hardware.

### What the enclave consumer still owns

**Credential sourcing via KMS attestation.** Static credentials are passed in
today. M8 replaces that with `kms:Decrypt` carrying an attestation document,
gated on PCR0 — at which point nothing on the parent holds a key that reads the
filesystem. The vsock HTTP client that milestone once needed is no longer
required: gvproxy gives the enclave an ordinary IP stack, so the AWS SDK works
unmodified.

## License

Apache-2.0.
