# Compatibility

What a Wasm guest gets from `wasi:filesystem`, and where it differs from a local filesystem.

The guest's filesystem is `wasmtime-wasi`'s own implementation over a real directory: its tenant's ZFS dataset, preopened as `/`. Operations behave as they do on a Linux ZFS mount, with the exceptions below. See [STORAGE.md](STORAGE.md) for what is underneath.

## The same as Linux on ZFS

Reads, writes, streams, `stat`, `set-times`, `set-size`, directories, `rename-at` (atomic), `link-at`, `symlink-at` and `readlink-at`, unlinking an open file, `is-same-object` and `metadata-hash` behave as ZFS does. There is no translation layer of our own in between.

## Different

| What | How | Why |
|---|---|---|
| `sync`, `sync-data` | Return without making anything durable (`sync=disabled`). | Durability is the anchor, taken before a response ends, a task's outcome is recorded, or a message reply is sent. A guest cannot be told its write is durable earlier than that, and is never told later. |
| A crash | Goes on from whatever reached the disk: writes no anchor covered may survive in part or not at all — as a crash on a local disk may keep part of an unsynced write. Anchors cover the whole pool, so another request's anchor may already have kept part of an unfinished request's writes. | Nothing unanchored was acknowledged. |
| Paths out of the preopen | `..` past it, absolute paths and symlinks out of it are refused by `cap-std`. | The tenant's directory is a capability. |
| `atime` | Not updated. | Reads must not write. |
| `.zfs` | ZFS's control directory (`snapdir=hidden`) may be reachable by name inside a tenant's own dataset. It holds nothing: no snapshots are taken. | A ZFS default, not exercised by the tests. |

## Not available

Shared memory, `mmap` and advisory locks are not in WASI, so SQLite needs `locking_mode=EXCLUSIVE` and `temp_store=MEMORY`, and cannot use WAL. See [STORAGE.md](STORAGE.md#running-sqlite).

## Storage format versions

The state-origin receipt names a layout version (`zfs/state-origin/vN`), so a store cannot be opened under a runtime that means something different by it.

| Version | Layout |
|---|---|
| v1 | One ZFS pool for the whole enclave, its anchors under `{prefix}zfs/`. |
| v2 | A control pool and a pool per tenant, anchors under `{prefix}zfs/control/` and `{prefix}zfs/pools/<id>/`. Current. |

A v2 runtime **refuses a v1 store rather than touching it**: it finds the v1 anchors, sees no v2 control pool, and stops with a message pointing here — before it claims a generation, imports, or writes anything. A v1 store is never resumed or reformatted in place. (The safety does not rest on the version string alone: a v1 store still holds its sealed key, so the boot takes the resume path, not genesis, and so can never mint a second history over it.)

### Migrating a v1 store to v2

There is no in-place migration; the layouts put the bytes in different places. The procedure is offline and keeps the original until the new store is proven:

1. Leave the v1 EBS volume and its roots-bucket prefix **untouched** — do not boot a v2 runtime against them.
2. Bring up v2 on a **new** volume and a **new** bucket prefix (a fresh genesis).
3. Re-establish each tenant from the application's own source of truth, or copy guest data out of the v1 store with a one-off v1-capable reader and back in through v2. Tenant pools are created on first use.
4. Retire the v1 volume and prefix only once the v2 store is verified serving.

Guest data does not carry across automatically: a tenant's v1 files lived in one shared pool, and v2 puts each tenant's in its own.

## Test coverage

The runtime's in-process suites run guests over a plain directory standing in for the pool (`zfs::Disk::Directory`):
- tenant isolation, including a hostile guest's escape attempts;
- restarts;
- tasks, streams and devices;
- streaming responses over HTTP/1.1, HTTP/2 and gRPC.

ZFS itself (the anchor, crash recovery, rollback and fork refusal) is exercised in the QEMU emulator by [`run-zfs-spike.sh`](../deploy/qemu-nitro/run-zfs-spike.sh) and the end-to-end suite.
