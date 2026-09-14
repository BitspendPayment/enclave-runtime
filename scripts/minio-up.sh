#!/usr/bin/env bash
# Start MinIO and create the two buckets the runtime expects.
#
#   minio-up.sh <container> <host-port> <data-bucket> <roots-bucket>
#
# The SQLite CI job and deploy/qemu-nitro/run-e2e.sh each carried their own copy
# of this. Two recipes that have to agree, with nothing making them agree, is
# how the harness and CI end up testing subtly different stores.
#
# The roots bucket is created `--with-lock` deliberately: object lock is what
# makes a published root record impossible to roll back, so a store without it
# would pass tests that a real deployment could not.

set -euo pipefail

container="${1:?container name}"
port="${2:?host port}"
data="${3:?data bucket}"
roots="${4:?roots bucket}"

# Optional, and applied to every container this starts. A caller that cleans up
# by label — deploy/qemu-nitro/lib.sh does, so that the list of containers to
# remove cannot fall out of step with the list it starts — otherwise leaves this
# one running, because it is the one container it did not start itself.
label=()
[[ -n "${MINIO_LABEL:-}" ]] && label=(--label "$MINIO_LABEL")

docker rm -f "$container" >/dev/null 2>&1 || true
docker run -d --rm --name "$container" -p "$port:9000" "${label[@]}" \
    -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
    minio/minio server /data >/dev/null

# Ready, not merely started. `mc` against a half-open MinIO fails in ways that
# read as a bucket problem rather than a timing one, which is a bad half hour
# for whoever reads the log next.
ready=""
for _ in $(seq 60); do
    if curl -sf "http://127.0.0.1:$port/minio/health/ready" >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if [[ -z "$ready" ]]; then
    echo "MinIO never became ready on :$port" >&2
    docker logs "$container" 2>&1 | tail -20 >&2
    exit 1
fi

# Tolerant of buckets that already exist: this script is also how a developer
# restarts a store between runs, and "already there" is success.
docker run --rm --network host "${label[@]}" --entrypoint sh minio/mc -c "
    mc alias set m http://127.0.0.1:$port minioadmin minioadmin >/dev/null
    mc mb m/$data >/dev/null 2>&1 || true
    mc mb --with-lock m/$roots >/dev/null 2>&1 || true" >/dev/null \
    || { echo "could not create $data and $roots" >&2; exit 1; }

echo "MinIO ready on :$port with $data and $roots"
