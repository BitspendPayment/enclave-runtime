#!/usr/bin/env bash
# A real C database driving the filesystem, and the benchmark table it prints.
#
# Page-granular random I/O, a rollback journal created and unlinked per
# transaction, VACUUM rewriting the whole file, and PRAGMA integrity_check to
# say whether the bytes came back correct. Nothing else in CI exercises the
# block store this way.
#
# The runtime serves `wasi:http/proxy` and nothing else, so the workload is
# asked for with a request rather than run as a process. TLS off and no relying
# party configured: this is about SQLite over the block store, not about the
# gate, which ci-guests.sh covers.
#
# **Not wired into CI, and it cannot be.** Since `bbbee4d` the runtime measures
# its guest into PCR16 before serving, and that reads the NSM:
#
#   runtime failed to start the guest
#   error="reading PCR16 before measuring the guest: no PCRs: entropy is
#          coming from the kernel, not an NSM"
#
# `measure_guest` is called unconditionally and has no flag to skip it — which
# is the point of it. A hosted runner has no /dev/nsm, so this script only runs
# where an enclave does. Run it by hand there; do not add it back to the
# workflow expecting it to pass.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

MINIO_CONTAINER=ci-minio-sql
MINIO_PORT=9002

"$REPO/scripts/wasi-sdk.sh"
"$REPO/scripts/build-guest.sh" sqlite

say "building enclave-runtime"
cargo build --release -p enclave-runtime

"$REPO/scripts/minio-up.sh" "$MINIO_CONTAINER" "$MINIO_PORT" sql-data sql-roots
trap '"$REPO/scripts/minio-down.sh" "$MINIO_CONTAINER"' EXIT

say "running the SQLite workload"
export SQLITE_SCALE="${SQLITE_SCALE:-20000}"
export S3FS_MASTER_KEY="00000000000000000000000000000000000000000000000000000000000000ef"
# Required, with no default: the runtime will not guess where a master key comes
# from. `static` is the development source that reads the key above — the same
# one the QEMU emulator image uses, and for the same reason, since KMS will not
# release a key against an unsigned attestation document.
export S3FS_MASTER_KEY_SOURCE=static
export S3FS_BUCKET=sql-data
export S3FS_ROOTS_BUCKET=sql-roots
export S3FS_ENDPOINT="http://127.0.0.1:$MINIO_PORT"
export S3FS_FORCE_PATH_STYLE=1
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_REGION=us-east-1
export S3FS_GUEST_PATH=examples/guest-sqlite/target/wasm32-wasip2/release/guest-sqlite.wasm
export S3FS_TLS=off
export S3FS_HTTP_LISTEN=127.0.0.1:8080

./target/release/enclave-runtime > runtime.log 2>&1 &
runtime=$!
trap 'kill "$runtime" 2>/dev/null || true; "$REPO/scripts/minio-down.sh" "$MINIO_CONTAINER"' EXIT

for _ in $(seq 1 60); do
    curl -sf -o /dev/null http://127.0.0.1:8080/ && break
    kill -0 "$runtime" 2>/dev/null || { echo "the runtime exited:"; cat runtime.log; exit 1; }
    sleep 1
done

# No --max-time: the workload is a long request by design, and the runtime's own
# --request-timeout is what bounds it. A wedged listener is bounded by the CI
# job's timeout-minutes instead, which covers the cases a client timeout cannot.
out=$(curl -sf http://127.0.0.1:8080/)
echo "$out"
echo "$out" | grep -qx OK

# The timing table went to the guest's stdout, which the runtime frames into its
# own log records.
echo "--- runtime log ---"
cat runtime.log
