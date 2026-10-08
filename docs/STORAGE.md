# Storage

Everything the enclave keeps lives on one ZFS pool. That covers each tenant's files and the runtime's own records. The pool sits on a disk the untrusted parent serves over vsock, encrypted with a key the parent never sees. After each change the pool's state is pinned by a signed **anchor** in an Object-Locked S3 bucket. A guest uses ordinary file APIs: `wasi:filesystem` is `wasmtime-wasi`'s, over its tenant's own directory.

This replaced the runtime's original storage engine, s3fs: a copy-on-write filesystem of its own on S3. The design goal is the same: the host cannot read the state, alter it, or roll it back unnoticed. The machinery underneath is ZFS, which has decades of production use behind it.

## How it works

### The stack

```text
  /tenants/<id>          a dataset per tenant: the guest's only preopen
  /runtime/...           credentials, tasks, streams, devices
  pool "enclave"         checksum=sha256, sync=disabled, atime=off
  /dev/mapper/zcrypt     plain dm-crypt, aes-xts-plain64, key from the master secret
  /dev/nbd0              the parent's disk: NBD over vsock port 10809
```

- **The pool.** The enclave loads `spl.ko` and `zfs.ko` at boot. They are built against a kernel compiled from AWS's own enclave recipe; see [the parent side](#the-parent-side).
- **The disk.** The parent's NBD server is reached over vsock. The kernel refuses a vsock socket for NBD, so it is handed one end of a Unix socket pair, and two threads copy between that and the vsock connection.
- **The roots bucket** holds what must outlive any disk and that no host may rewrite. That is the anchor chain, the state-origin receipt and pair records, the sealed master key's pointer, the guest, and the sealed ACME cache.

### What the host can do to the disk

Without the dm-crypt key, the host can only replay sectors it once saw or scramble them. To ZFS both look like ordinary corruption, which its checksums exist to catch. Every block pointer carries its child's checksum (SHA-256 for datasets, fletcher4 for the pool's own metadata), so a stale or scrambled block fails its parent's check on read. Plain dm-crypt has no header, so nothing is parsed from the disk before it is decrypted.

That leaves three things the host can do:
- make the disk unreadable, which is denial of service and fails closed;
- see which sectors are touched, and when;
- serve an older disk entirely. That is the rollback the anchor exists for.

### The anchor

ZFS pins a pool state by its uberblock, but a txg number does not name one. After a rewound import, ZFS reuses the numbers of the txgs it abandoned, and the abandoned uberblocks are still on the disk for the host to serve. So each anchor writes a fresh random value into the pool itself:

1. `zpool sync`. If no txg has written anything since the last anchor, stop: there is nothing new to anchor.
2. `zfs set enclave:anchor=<seq>-<nonce>`. This is a sync task: it returns once everything written before it is on the disk.
3. `zpool sync` again. The property change's frees are deferred two txgs; without this sync every later call would see a write and anchor again.
4. Read the newest txg that wrote anything, from `/proc/spl/kstat/zfs/enclave/txgs`.
5. Sign `seq | prev hash | fs id | pool guid | txg | nonce` with the anchor key, and publish it to `zfs/anchors/<seq>` with a conditional PUT under Object Lock COMPLIANCE. Read the retained version back, since a delete marker could otherwise let a second writer's PUT through.

Anchors are serialised across the whole enclave. A failed anchor stops anchoring for good: retrying could publish over a lost race.

On boot, the runtime imports the pool **as of the anchored txg**, with `zpool import -T`, and then reads the property back from what ZFS actually loaded:

| Disk | What happens |
|---|---|
| At the anchor | Imported; the nonce matches. |
| Ahead of the anchor (the enclave died between syncing and publishing) | Rewound to the anchor; the nonce matches. The unanchored writes, which nobody was told about, are gone. |
| Behind the anchor (rolled back) | ZFS takes the newest txg at or below the anchor's, and that txg holds an older nonce. **Refused.** |
| An abandoned fork, the history a crash left behind | It never held the newest anchor's nonce. **Refused.** |

Anchors are found by their retained versions, by galloping then bisecting, because they are contiguous and none can be deleted. A host cannot hide the newest one behind a delete marker. A cold boot cannot know on its own whether the store is still adding them; `--min-root-seq` sets a floor from outside.

### When a write is durable

`sync=disabled`: `fsync` returns without making anything durable, because durability is the anchor. Nothing is acknowledged until the anchor covering it exists:

| Write made by | Anchored before |
|---|---|
| A request | The response ends. A streamed body streams as written, and only its end (with any trailers, such as gRPC's status) waits. A body with `Content-Length` is held whole, because a client counting bytes would otherwise act on it first. |
| A held connection's message run | Its reply is sent. |
| A background task | Its outcome is recorded, and so before any wake about it. |
| A passkey registration or revocation | The response; the tenant's dataset is created first, so one anchor covers both. |

A crash before the anchor rewinds to the previous one. What is lost was never acknowledged.

### Layout

| Path | What |
|---|---|
| `/tenants/<id>` | A dataset per tenant, created at registration. An id is the first 16 bytes of a SHA-256 of the passkey's credential id. A guest without a gate (development only) gets the all-zero id. |
| `/runtime/credentials/<id>` | Passkeys, CBOR, one file each. |
| `/runtime/tasks/`, `/runtime/streams/` | JSON records, each written to a temporary file and renamed over the record. |
| `/runtime/devices/<tenant>/<sha256(token)>` | Push registrations. |

No guest can reach `/runtime` or another tenant. A guest's only preopen is its own dataset, and `wasmtime-wasi` resolves paths through `cap-std`, which refuses `..` past the preopen, absolute paths and symlinks out of it.

### Defaults

| Setting | Value | Why |
|---|---|---|
| `checksum` | `sha256` | Collision-resistant checksums for dataset blocks |
| `sync` | `disabled` | Durability is the anchor, not the ZIL |
| `atime` | `off` | Reads must not write |
| `failmode` | `panic` | A pool that lost its disk stops the enclave; the next boot decides |
| `zfs_txg_timeout` | 3600 s | No txg on a timer; syncs come from anchors |
| `zfs_arc_max`, `zfs_dirty_data_max` | 256 MiB | Enclave memory is fixed |
| Anchor retention | 10 years (`--root-retention-secs`) | COMPLIANCE: nobody can shorten it |

### Cost

Measured on the QEMU emulator, with the disk served by `nbd-stub.py` over userspace vsock forwarding, so these numbers are pessimistic:

| What | Measured |
|---|---|
| Anchor, mean: the first `zpool sync` | 59 ms |
| Anchor, mean: both syncs, `zfs set` and the publish | 105 ms |
| Signed POST that writes a file, p50 (client round trip, assertion included) | 260 ms |
| Signed GET that writes nothing, p50 | 183 ms; no anchor is published |

100 POSTs and 100 GETs produced 100 anchors: a request that writes nothing pays one empty `zpool sync` and no S3 round trip.

## State identity at boot

A missing store is not an invitation to create an empty one. The boot checks the retained state-origin receipt, the sealed-key object, and the pair record for the running runtime and guest.

The receipt commits to BLAKE3 over CBOR of `("zfs/state-origin/v1", fs id, roots bucket, prefix, hash of anchor 0, sha256 of the sealed key)`.

| Observed state | Outcome |
|---|---|
| No receipt and no sealed key | **Genesis.** Mint the key, take the lease (a conditional PUT of the sealed key), create the pool on a blank disk and publish anchor 0, attest the receipt, and record the pair. |
| Receipt and key verify; this pair has a record | **Resume:** import at the newest anchor, as above. |
| Receipt and key verify; this pair has no record | **Upgrade:** record the new pair. |
| Only one of receipt and key | Refuse. |
| A pool on the disk but no anchor, or anchors but genesis | Refuse. |

The bucket's identity lives in the measured image: `ENCLAVE_ROOTS_BUCKET` is part of PCR0. Otherwise a host could point an approved runtime at an empty bucket and make a new store look legitimate.

## The parent side

| | Emulator | Nitro |
|---|---|---|
| Disk | A sparse file served by [`deploy/qemu-nitro/nbd-stub.py`](../deploy/qemu-nitro/nbd-stub.py) | A gp3 EBS volume ([`deploy/tofu`](../deploy/tofu/main.tf), `pool_size_gib`), served by stock nbdkit from the Amazon Linux 2023 repositories ([`nbdkit.service`](../deploy/ami/units/nbdkit.service)) |
| Kernel | [`nix/kernel-zfs.nix`](../nix/kernel-zfs.nix) | Same image |

[`nix/kernel-zfs.nix`](../nix/kernel-zfs.nix) is AWS's `aws-nitro-enclaves-sdk-bootstrap` recipe: Linux 6.6, their config, and their two patches, including the vsock fix that stops parent and enclave deadlocking when both send queues fill. It adds NBD and dm-crypt, and builds OpenZFS against the result. The build user and host are pinned, so the kernel's version string, and with it PCR0, is the same on every machine.

[`deploy/qemu-nitro/run-zfs-spike.sh`](../deploy/qemu-nitro/run-zfs-spike.sh) plays the hostile host:
- two tenants write, and cross-tenant paths are refused;
- a restart resumes;
- a rolled-back disk is refused;
- a crash between sync and publish rewinds;
- the abandoned fork is refused.

## Running SQLite

[`guest-sqlite`](../examples/guest-sqlite/) covers DDL, transactions, savepoints, constraints, joins, CTEs, window functions, blobs, triggers, schema changes, `VACUUM`, JSON, FTS5 and R-Tree. Build it with wasi-sdk:

```bash
scripts/wasi-sdk.sh
scripts/build-guest.sh sqlite

deploy/qemu-nitro/dev-enclave.sh \
  --guest examples/guest-sqlite/target/wasm32-wasip2/release/guest-sqlite.wasm \
  --guest-env ENCLAVE_BACKGROUND_TASKS=false
```

The two pragmas WASI requires are unchanged:

```rust
conn.pragma_update(None, "temp_store", "MEMORY")?;     // no access(2) under WASI
conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?; // no fcntl locks under WASI
```

Use the default rollback journal (`DELETE`). WAL needs shared memory that WASI does not provide. SQLite has not yet been measured on the pool; the earlier figures were for s3fs and no longer apply.

## Limits

- **One writer per pool.** One enclave imports it; there is no second mount to race.
- **Anchors are serial** across all tenants, and each is a pool sync plus an S3 round trip.
- **The image carries ZFS userspace.** The nixpkgs build references systemd, Python and nfs-utils, about 370 MB of the image. Repackaging only `zpool`, `zfs` and their libraries would recover most of it.
- **EBS is single-AZ.** Restoring a snapshot is a rollback, and the boot refuses it. Disaster recovery means recovering the newest disk, not an older one.
- **The host sees access patterns:** which sectors, when, and how much.
