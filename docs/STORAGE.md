# Storage

Each tenant's files live on a ZFS pool of their own, and the runtime's own records on a **control pool**. All the pools share one disk the untrusted parent serves over vsock, cut into equal regions, each region its own encrypted device with a key the parent never sees. After each change a pool's state is pinned by a signed **anchor** in an Object-Locked S3 bucket, one chain per pool. A guest uses ordinary file APIs: `wasi:filesystem` is `wasmtime-wasi`'s, over its tenant pool's `data` dataset and nothing else.

This replaced the runtime's original storage engine, s3fs: a copy-on-write filesystem of its own on S3. The design goal is the same: the host cannot read the state, alter it, or roll it back unnoticed. The machinery underneath is ZFS, which has decades of production use behind it.

## How it works

### The stack

```text
  /pools/<pool_id>/data          a tenant's pool, mounted here: the guest's only preopen
  /runtime/{credentials,tasks,streams,devices,catalog}   on the control pool
  pool "enclave"   (region 0)    the control pool: records and the tenant catalog
  pool "p<pool_id>" (region N)   a tenant's pool: one data dataset
  /dev/mapper/zcrypt-<id>        per-region plain dm-crypt, aes-xts-plain64, a key per pool
  /dev/nbd0                      the parent's disk, cut into equal regions: NBD over vsock 10809
```

### A pool per tenant

The disk is divided into fixed, 4 KiB-aligned regions (`region_bounds` in [`zfs.rs`](../runtime/src/zfs.rs)). Region 0 is the control pool; each tenant is allocated one of the rest on first use. A region is mapped as its own `dm-crypt` device, `zcrypt-<pool_id>`, with a key derived `HKDF(master, fs_uuid, "zfs/dmcrypt/v2" ‖ kind ‖ pool_id)` — domain-separated, so one region's key never decrypts another's. On it sits one pool, `p<pool_id>`, with a single `data` dataset the guest sees as `/`.

The **control pool** holds the runtime's records and the **catalog**: one entry per tenant giving its pool id, its region, and the hash of its pool's anchor 0. The catalog is on the control pool, out of every guest's reach, and validated at boot (regions distinct, in range, none the control pool's; pool ids distinct), so the host cannot point a tenant at another's pool. A tenant's pool id is random and minted once, so a deleted tenant's history can never be restarted under a guessed id.

An anchor names the pool it speaks for — a kind (control or tenant), the pool id, and the tenant id, all signed (`ZFSANCH2`) — and a boot refuses an anchor whose pool id is not the one it expected. Each pool anchors on its own chain, under `zfs/control/anchors/` or `zfs/pools/<pool_id>/anchors/`, with its own last-anchor lock, so two tenants anchor independently: one held mid-anchor does not stop another. A tenant pool is imported the first time that tenant is used and kept for the life of the process; the number of pools is bounded by how many regions the disk holds, and registration is refused once none is free.

Because a tenant's data is its own pool, the same-nonce cross-tenant steal the single pool was prone to — one tenant's write landing between another's anchor marker and its sync — cannot happen: an anchor only ever covers its own pool, and a tenant is serialised against itself. Each pool is still verified on import exactly as a boot verifies the control pool (below), so a rolled-back or forked tenant disk is refused when that tenant is next used.

**Capacity.** A region is `--region-mib` (200 MiB by default); a disk of _D_ holds ⌊_D_ / region⌋ pools, control included. A tenant that fills its region gets `ENOSPC`; the disk filling up refuses new registrations, not existing tenants. Growing capacity means a larger disk (more regions); a region is never grown in place, and there is one disk, not one volume per tenant.

- **The pool.** The enclave loads `spl.ko` and `zfs.ko` at boot. They are built against a kernel compiled from AWS's own enclave recipe; see [the parent side](#the-parent-side).
- **The disk.** The parent's NBD server is reached over vsock. The kernel refuses a vsock socket for NBD, so it is handed one end of a Unix socket pair, and two threads copy between that and the vsock connection.
- **The roots bucket** holds what must outlive any disk and that no host may rewrite. That is the anchor chain, the state-origin receipt and pair records, the sealed master key's pointer, the guest, and the sealed ACME cache.

### What the host can do to the disk

Without the dm-crypt key, the host can only replay sectors it once saw or scramble them. To ZFS both look like ordinary corruption, which its checksums exist to catch. Every block pointer carries its child's checksum (SHA-256 for datasets, fletcher4 for the pool's own metadata), so a stale or scrambled block fails its parent's check on read. Plain dm-crypt has no header, so nothing is parsed from the disk before it is decrypted.

That leaves three things the host can do:
- make the disk unreadable, which is denial of service and fails closed;
- see which sectors are touched, and when;
- serve an older disk entirely, or one mixing sectors from several. That is the rollback the anchor exists for.

#### What this rests on

- **dm-crypt is confidentiality, not integrity.** Plain AES-XTS authenticates nothing. What it buys is that the host cannot choose plaintext: it can put back a sector's old ciphertext, which decrypts to that sector's old contents, or change it, which decrypts to noise.
- **ZFS checksums are not MACs.** They are unkeyed. They catch a replayed or scrambled block because the host cannot make a block whose checksum matches what its parent expects. SHA-256 makes that collision-resistant for dataset blocks. The pool's own metadata uses fletcher4, which is not collision-resistant: there the claim rests on the host being limited to old versions of a sector or noise, never content it chose.
- **The uberblock is the root.** Its own checksum is SHA-256, but any uberblock this pool ever wrote is valid, so which state it names is settled by the anchor: the txg the kernel reports loading, and the nonce inside that state.

None of this has been checked against a host deliberately mixing old and new sectors of one pool; that is still to be tested.

### The anchor

ZFS pins a pool state by its uberblock, but a txg number does not name one: forks reuse numbers, and the uberblocks of every state the disk held may still be on it for the host to serve. So each anchor writes a fresh random value into the pool itself:

1. `zpool sync`. If no txg has written anything since the last anchor, stop: there is nothing new to anchor.
2. `zfs set enclave:anchor=<seq>-<nonce>-<previous anchor's hash>`, the marker. This is a sync task: it returns once everything written before it is on the disk.
3. `zpool sync` again. The property change's frees are deferred two txgs; without this sync every later call would see a write and anchor again.
4. Read the newest txg that wrote anything, from `/proc/spl/kstat/zfs/enclave/txgs`. This is the anchored txg.
5. Sign `seq | prev hash | fs id | pool guid | txg | nonce` with the anchor key, and publish it to `zfs/anchors/<seq>` with a conditional PUT under Object Lock COMPLIANCE. Read the retained version back, since a delete marker could otherwise let a second writer's PUT through.

Anchors are serialised across the whole enclave, and each runs in a task of its own, so a caller that gives up cannot cut one short. A failure before the marker changes nothing. Any failure from the marker on stops anchoring for good, an uncertain publish included: retrying could publish over a lost race.

The marker's txg is older than the anchored one, and other tenants write meanwhile. A write landing between the two is covered by the anchor, and its own anchor call finds nothing newer and is acknowledged. So the disk as of the marker holds the anchor's nonce without that write, and the nonce alone does not pin the state.

On boot, the runtime imports the newest state on the disk, unmounted, and reads which txg it loaded from the kernel's own notes on that import (`spa_load(enclave, …): using uberblock with txg=N`, in `/proc/spl/kstat/zfs/dbgmsg`, from the last load that ended `LOADED`). It reads the marker from the loaded pool, and admits the pool only if:
- its guid is the anchored pool's;
- the loaded txg is no older than the anchored txg;
- its marker is the newest anchor's, or that of the next anchor (one written but never published) naming the newest as its predecessor.

| Disk | What happens |
|---|---|
| At the anchor | Admitted. |
| Ahead of the anchor (the enclave synced, then died before publishing) | Admitted as it is. Nothing past the anchor was acknowledged, and nothing is rewound. |
| As of the anchor's marker, before its sync | Holds the right nonce, but loaded an older txg. **Refused.** |
| Behind the anchor (rolled back) | An older txg and an older marker. **Refused.** |
| An abandoned fork | Its marker is not the newest anchor's, nor one naming it. **Refused.** |

There is no rewind. Before this, boot imported with `zpool import -T <anchored txg>`, which takes the newest uberblock *at or below* that txg and, if that one fails to load, quietly tries older ones. Three txgs after an anchor, its blocks can already have been reused.

Anchors are found by their retained versions, by galloping then bisecting, because they are contiguous and none can be deleted. A host cannot hide the newest one behind a delete marker. A cold boot cannot know on its own whether the store is still adding them; `--min-root-seq` sets a floor from outside.

### When a write is durable

`sync=disabled`: `fsync` returns without making anything durable, because durability is the anchor. Nothing is acknowledged until the anchor covering it exists:

| Write made by | Anchored before |
|---|---|
| A request | The response ends. A streamed body streams as written, and only its end (with any trailers, such as gRPC's status) waits. A body with `Content-Length` is held whole, because a client counting bytes would otherwise act on it first. So is a response that cannot have a body (to a HEAD, or a 1xx, 204 or 304), which would otherwise be complete when its head went out. |
| A held connection's message run | Its reply is sent. |
| A background task | Its outcome is recorded, and so before any wake about it. |
| A passkey registration | The response. The tenant's pool is created and its catalog entry written and anchored on the control pool first, then the credential, so both are durable before the user is told they are registered. |
| A passkey revocation | The response; the credential is on the control pool, anchored before the response. |

After a crash, the boot goes on from whatever reached the disk. Writes no anchor covered may be there or not; none was acknowledged.

### Layout

| Path | What |
|---|---|
| `/pools/<pool_id>/data` | A tenant's pool, mounted here, created on first use. A tenant id is the first 16 bytes of a SHA-256 of the passkey's credential id; a guest without a gate (development only) gets the all-zero id. The pool id is random, in the catalog. |
| `/runtime/catalog/<tenant>` | One JSON entry per tenant: pool id, region, genesis hash. On the control pool. |
| `/runtime/credentials/<id>` | Passkeys, CBOR, one file each. On the control pool. |
| `/runtime/tasks/`, `/runtime/streams/` | JSON records, each written to a temporary file and renamed over the record. On the control pool. |
| `/runtime/devices/<tenant>/<sha256(token)>` | Push registrations. On the control pool. |

No guest can reach `/runtime` (it is on the control pool) or another tenant (it is a different pool, a different encrypted device). A guest's only preopen is its own pool's `data` dataset, and `wasmtime-wasi` resolves paths through `cap-std`, which refuses `..` past the preopen, absolute paths and symlinks out of it. The runtime's records stay on the control pool for now; moving each tenant's records into its own pool is a later step.

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
| No receipt and no sealed key | **Genesis.** Mint the key, take the lease (a conditional PUT of the sealed key), create the control pool in region 0 and publish its anchor 0, attest the receipt, and record the pair. Tenant pools come later, as tenants arrive. |
| Receipt and key verify; this pair has a record | **Resume:** import the control pool at its newest anchor, as above, and validate the catalog. Tenant pools are imported on demand, each verified the same way. |
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
- a crash between sync and publish resumes from the disk it left;
- the abandoned fork is refused;
- the disk as of an anchor's marker, before its sync, is refused.

The testing build stops at named points in an anchor and asks the host, over vsock port 9101, whether to go on (`hook` in [`zfs.rs`](../runtime/src/zfs.rs), answered by [`test-hooks.py`](../deploy/qemu-nitro/test-hooks.py)). A leg can hold an anchor there, copy the disk at that exact moment, or kill the enclave between two steps.

### The flaw the last leg is for

The boot once admitted the disk as of an anchor's marker. Leg 7 found it on the emulator:
1. Alice's anchor was held after its marker, and the disk was copied.
2. Bob's write was acknowledged behind it; one anchor (111, txg 846) covered both.
3. Served the copy, the kernel logged `spa_load(enclave, config untrusted): using uberblock with txg=845`.
4. The boot logged `zfs pool resumed at its anchor seq=111 txg=846`, and bob's acknowledged file was gone.

Leg 6 showed the same flaw in an honest crash. Three txgs past anchor 107, `-T 810` failed on txg 810 (`couldn't get 'config' value in MOS directory [error=5]`, its blocks already reused) and ZFS fell back to 809, the anchor's own marker. A boot requiring the exact txg would have refused that disk forever, which is why the boot now admits the newest state rather than rewinding.

## Running SQLite

[`guest-sqlite`](../examples/guest-sqlite/) covers DDL, transactions, savepoints, constraints, joins, CTEs, window functions, blobs, triggers, schema changes, `VACUUM`, JSON, FTS5 and R-Tree. Build it with wasi-sdk:

```bash
scripts/wasi-sdk.sh
scripts/build-guest.sh sqlite

deploy/qemu-nitro/dev-enclave.sh \
  --guest examples/guest-sqlite/target/wasm32-wasip2/release/guest-sqlite.wasm
```

The two pragmas WASI requires are unchanged:

```rust
conn.pragma_update(None, "temp_store", "MEMORY")?;     // no access(2) under WASI
conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?; // no fcntl locks under WASI
```

Use the default rollback journal (`DELETE`). WAL needs shared memory that WASI does not provide. SQLite has not yet been measured on the pool; the earlier figures were for s3fs and no longer apply.

## Limits

- **One writer per pool.** One enclave imports each pool; there is no second mount to race. A per-boot generation fence (`zfs/generations/<g>`) stops a second enclave the host starts from letting the first go on to acknowledge a write it has forked away from.
- **Anchors are per pool**, so two tenants anchor independently; each anchor is a pool sync plus an S3 round trip. A request also anchors the control pool when it leaves a record there (that cost drops to nothing for a pure-data request once the operation boundary tracks it).
- **A tenant's records are still on the control pool.** Until they move into the tenant's own pool, a request that writes one anchors the control pool too, which serialises those writes across tenants.
- **No tenant-pool eviction yet.** A tenant pool is kept imported for the life of the process; the cap is how many regions the disk holds.
- **The image carries ZFS userspace.** The nixpkgs build references systemd, Python and nfs-utils, about 370 MB of the image. Repackaging only `zpool`, `zfs` and their libraries would recover most of it.
- **EBS is single-AZ.** Restoring a snapshot is a rollback, and the boot refuses it. Disaster recovery means recovering the newest disk, not an older one.
- **The host sees access patterns:** which sectors, when, and how much.
