# Roadmap

The storage engine is complete (M0–M7, `b11f95b`) and so is the runtime that
loads a guest and gives it the filesystem (M10). What remains is the enclave's
own plumbing — proving to KMS which code is running — and reclaiming space.

| | | Status |
|---|---|---|
| M0–M7 | Merkle-anchored block store, POSIX layer, hard links, snapshots | ✅ done |
| **M8** | [NSM attestation and KMS key release](#m8--attestation-and-key-release) | needs enclave hardware |
| **M9** | [Garbage collection](#m9--garbage-collection) | not started |
| M10 | [`enclave-runtime`](#m10--the-enclave-runtime-) | ✅ done |

---

## M8 — Attestation and key release

Today the master secret arrives via `--master-key`. That is a development
seam and it is the last thing standing between this and a real enclave
deployment: a secret passed on the command line is visible to the parent
instance, which is precisely the party the enclave exists to exclude.

The on-disk format does not change. `KeyMaterial::derive` takes 32 bytes and
does not care where they came from, which was the point of shaping it that way
in M1.

### What has to be built

**1. NSM attestation documents.** The device layer already exists —
[`nitro-nsm`](../crates/nitro-nsm/src/lib.rs) opens `/dev/nsm` and does the raw
CBOR ioctl for `GetRandom`. Attestation is the same call with a different
payload, so what remains is encoding the `Attestation` request with a public key
the enclave generates at boot, and parsing the COSE_Sign1 document that comes
back.

It is a separate crate rather than a module of `s3fs-host` so it can be linked
into a small static musl binary for an enclave image — which is how the device
layer is verified today, in the QEMU harness described below.

**2. KMS `Decrypt` with `Recipient`.** The attestation document goes in the
`Recipient` field; KMS returns the plaintext encrypted to the enclave's public
key rather than in the clear, so the parent proxying the call never sees it.
The key policy binds release to the PCRs:

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<enclave image hash>"
    }
  }
}
```

Because the guest component is baked into the image (see M10), PCR0 covers
*both* the runtime and the guest. The key is released only to exactly this
code — that is the whole argument, and it is why the guest must not be
loaded over vsock.

**3. A vsock HTTP client.** An enclave has no network except vsock, so both
KMS and S3 go through a proxy on the parent. This needs a seam that does not
exist:

- [`AwsS3BackendConfig`](../crates/s3fs-core/src/backend/aws.rs) has no
  `http_client` field, so the SDK cannot be pointed at a vsock connector.
  Add `http_client: Option<SharedHttpClient>` and thread it into
  `connect_unchecked`.
- Static credentials there are built with `None` expiry
  ([aws.rs](../crates/s3fs-core/src/backend/aws.rs)), so a KMS-attested
  session token expires mid-run with no recovery. Needs a refresh path.

**3b. Cover the clock.** The guest's wall clock now comes from `/dev/ptp0`
(see the README), but two things remain. The Object Lock retention deadline in
[`RootStore::root_retention`](../crates/s3fs-core/src/store/root.rs) still uses
`SystemTime::now()` — and a COMPLIANCE deadline computed from a wrong clock
cannot be corrected afterwards by anyone, which makes it the sharpest version
of this problem in the codebase. And attestation should eventually cover *which*
clock was in use, so a relying party can tell a PTP-backed enclave from one that
fell back to host time.

**4. Bind the attestation into the anchor.** `RootRecord` already reserves an
`attestation` field. Recording the PCR digest that produced each commit turns
the root chain into an audit log of *which code* wrote each state, not merely
what the state was.

**5. Close the cold-mount gap.** `--min-root-seq` is currently supplied by
hand. Carrying it in the KMS encryption context would make the floor something
the enclave receives from a service the storage operator does not control —
the one thing that closes the residual risk documented in
[`store/root.rs`](../crates/s3fs-core/src/store/root.rs).

### Testing

Everything except the NSM calls can be tested without hardware: the vsock
client against a local listener, the credential refresh against MinIO, and the
key-source abstraction with a fake that returns fixed bytes.

The NSM calls themselves now have a home too. [`deploy/qemu-nitro/`](../deploy/qemu-nitro/)
builds an EIF and boots it on QEMU's `nitro-enclave` machine, where
`GetRandom` against the emulated device already passes. Attestation should
extend that harness rather than wait for hardware: `eif_build` produces genuine
PCR0/1/2, so the measurements an `Attestation` response must quote are already
known values. What the emulator cannot give is a document signed by the real
AWS Nitro root, so certificate-chain validation and the KMS `Recipient` round
trip still need `nitro-cli run-enclave`, and CI cannot cover either.

---

## M9 — Garbage collection

Copy-on-write means every superseded block is still there. Nothing reclaims
them, and nothing can until there is a way to decide what is dead.

The split buckets already put the cost where it can be addressed: root records
are ~700 bytes and locked for the full retention term, which is cheap forever;
slabs are the volume and live unlocked precisely so they *can* be deleted.

### The hard part

A slab is dead when no root you intend to keep references any block in it.
"Intend to keep" is a policy decision, not a fact about the data, and getting
it wrong deletes live data. Hence: not shipped rather than shipped
approximately.

Proposed `s3fs-runner gc --keep-roots N`:

1. Mark: walk the blkptr trees of the newest `N` roots, collecting live
   `(txg, slab)` pairs. Bounded by live data, not by history.
2. Sweep: `ListObjectsV2` over `slabs/`, delete any slab in no live set.
3. Never touch the roots bucket. It stays a complete, immutable, ten-year
   audit log of state hashes regardless — GC trades away the ability to
   *replay* old states, not the record that they existed.

Two things fold in naturally:

- **Orphaned dnodes.** A crash while a file is unlinked-but-open leaves an
  allocated, nameless, unreachable dnode. The mark phase already knows what is
  reachable from the root directory, so these fall out for free.
- **Orphaned slabs.** `next_safe_txg` steps over slabs from commits that died
  before publishing a root. They are unreferenced by construction.

### Cheaper stopgaps

- Raise `record_size` for write-heavy workloads: fewer, larger blocks means
  less metadata churn per byte rewritten.
- A lifecycle rule expiring `slabs/` objects older than the oldest root you
  care to keep. Crude and unsafe in general — a rarely-touched block can be
  both old and live — but usable if the workload rewrites everything
  periodically.

---

## M10 — The enclave runtime ✅

Shipped. `enclave-runtime` mounts the store, loads a guest from a known path,
and runs it; `s3fs-host` holds the `wasi:filesystem` implementation, the linker,
the guest-environment policy, and the run loop.

```
crates/
  s3fs-core         engine
  s3fs-host         wasi:filesystem + linker + env policy + run loop
  s3fs-runner       dev CLI, local and MinIO
  enclave-runtime   deployment target
```

Configuration is environment-first with matching flags, because inside an
enclave the image's `ENV` lines are the only configuration there is. The guest
inherits that environment minus anything under `AWS_` or `S3FS_` — credentials
and the runtime's own settings — which is the one rule that keeps the master
key away from the code the enclave exists to contain.

`deploy/Dockerfile` builds an image with the guest at `/enclave/guest.wasm`, so
PCR0 covers it. That is what will let M8's key policy attest to the code that
reads the data rather than only to the runtime that loads it.

### What M8 changes here

Almost nothing structural, by design:

- `StaticKey` becomes `KmsAttestedKey` — one more implementation of
  `s3fs_host::MasterKeySource`, and `S3FS_MASTER_KEY` stops being read at all.
- `AwsS3BackendConfig` gains the `http_client` field so the SDK can be pointed
  at the parent's vsock proxy, plus a credential refresh path.
- `RootRecord::attestation` starts carrying the PCR digest, turning the anchor
  chain into a record of *which code* wrote each state.
- `S3FS_MIN_ROOT_SEQ` moves into the KMS encryption context, so the freshness
  floor comes from a service the storage operator does not control.
