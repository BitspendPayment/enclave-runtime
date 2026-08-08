# Roadmap

The storage engine is complete: milestones M0–M7 landed in `b11f95b`. What
remains is the enclave itself.

| | | Status |
|---|---|---|
| M0–M7 | Merkle-anchored block store, POSIX layer, hard links, snapshots | ✅ done |
| **M8** | [NSM attestation and KMS key release](#m8--attestation-and-key-release) | needs enclave hardware |
| **M9** | [Garbage collection](#m9--garbage-collection) | not started |
| **M10** | [`enclave-runtime`](#m10--the-enclave-runtime) | not started |

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

**1. NSM attestation documents.** `aws-nitro-enclaves-nsm-api` to request one
from `/dev/nsm`, carrying a public key the enclave generates at boot.

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
client against a local listener, the credential refresh against MinIO, the
key-source abstraction with a fake that returns fixed bytes. The attestation
path needs a real `nitro-cli run-enclave`, and CI cannot cover it.

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

## M10 — The enclave runtime

A new crate that takes a guest component and gives it the filesystem, inside
an enclave. `s3fs-runner` stays as it is: the plain-host CLI for development
and MinIO testing, so the dev loop keeps working without NSM or vsock.

```
crates/
  s3fs-core         engine
  s3fs-wasmtime     WASI bindings
  s3fs-host         NEW  linker wiring + State, shared by both binaries
  s3fs-runner       dev CLI, local and MinIO
  enclave-runtime   NEW  vsock, NSM, KMS, guest ingestion
```

### `s3fs-host` — the shared part

Both binaries do the same three things: build a `State` implementing `WasiView`
and `S3WasiView` over one `ResourceTable`, add every `wasmtime-wasi` interface
*except* filesystem, then instantiate `wasi:cli/command` and call `run`.

That code currently lives once, in
[`s3fs-runner/src/main.rs`](../crates/s3fs-runner/src/main.rs), and includes
`add_wasi_minus_filesystem` — a hand-copied clone of
`wasmtime_wasi::p2::add_to_linker_with_options_async` with the two
`filesystem::*` lines removed. It will drift silently on any `wasmtime-wasi`
bump, and duplicating it into a second binary would double that hazard. It
should move into `s3fs-host` with a test that fails when the upstream
interface list changes.

### `enclave-runtime` — the deployment target

Boot sequence:

```
1. NSM: generate a keypair, request an attestation document
2. KMS Decrypt via vsock, Recipient = that document  →  master secret
3. Mount the store over the vsock S3 proxy, verify the root chain,
   enforce the sequence floor from the encryption context
4. Load the guest component from the enclave image
5. Instantiate, run, exit with the guest's status
```

**The guest ships inside the EIF.** Its bytes are covered by PCR0/PCR1, so the
key policy that releases the filesystem key is attesting to exactly which code
will read it. This is the property that makes the whole design worth having:
without it, the enclave proves that *some* code with the right image hash is
running, but not that the code touching your data is the code you audited.
Changing the guest means rebuilding the image and updating the key policy —
which is the intended friction, not an inconvenience to engineer around.

Also needed:

- A vsock proxy on the parent for S3 and KMS, plus its systemd unit and the
  `nitro-cli` invocation, documented so a deployment is reproducible.
- **Do not inherit the host environment into the guest.** `--guest-env` is
  already an explicit allowlist; the enclave binary should keep that and
  default to empty, since the KMS-released credentials live in that process.
- A health/attestation endpoint over vsock so the parent can verify the
  enclave came up and which root sequence it mounted, without being able to
  influence either.
