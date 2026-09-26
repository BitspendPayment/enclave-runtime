#!/usr/bin/env bash
# The block store against a real S3 implementation.
#
# These tests start their own MinIO through testcontainers — one per test, which
# is why they run single-threaded and take a while. That is also why this script
# does not call minio-up.sh: a store started here would sit unused.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

"$REPO/scripts/minio-image.sh" >/dev/null

say "MinIO integration"
cargo test -p s3fs-core --features aws --test minio_integration -- --ignored --test-threads=1
