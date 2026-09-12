#!/usr/bin/env bash
# Stop a MinIO started by minio-up.sh.
#
#   minio-down.sh <container>
#
# Never fails. It runs from a trap and from an `if: always()` step, where an
# error of its own would mask the failure that is actually worth reading.

set -euo pipefail

docker rm -f "${1:?container name}" >/dev/null 2>&1 || true
