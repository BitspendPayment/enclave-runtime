#!/usr/bin/env bash
# The MinIO image every store here runs on, built from source.
#
#   image="$(scripts/minio-image.sh)"
#
# MinIO no longer publishes images anyone can pull: Docker Hub refuses
# `minio/minio` without a login, and quay.io has no tags at all. The releases
# are still tagged on GitHub, so the pinned one is built here — the server, and
# `mc` for the scripts that make buckets and upload guests — under a name nobody
# will mistake for an upstream image. The tag is the release the testcontainers
# module pins, so the integration tests only have to change the name.
#
# Builds only when the image is missing. Prints the image on stdout and
# everything else on stderr, so a caller can take the name and nothing more.

set -euo pipefail

MINIO_RELEASE=RELEASE.2025-02-28T09-55-16Z
# The last mc release before that server.
MC_RELEASE=RELEASE.2025-02-21T16-00-46Z
IMAGE="enclave-runtime/minio:$MINIO_RELEASE"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    # ponytail: rebuilt on every CI run, a few minutes; `docker save` it into
    # an actions/cache keyed on this script if those minutes start to matter.
    printf '\n== building %s from source ==\n' "$IMAGE" >&2
    docker build -t "$IMAGE" \
        --build-arg MINIO_RELEASE="$MINIO_RELEASE" \
        --build-arg MC_RELEASE="$MC_RELEASE" - >&2 <<'EOF'
FROM golang:1.23-alpine AS build
RUN apk add --no-cache git && mkdir /out
ARG MINIO_RELEASE
ARG MC_RELEASE
# Each project's own version stamping, so a log says which release is running.
RUN git clone --quiet --depth 1 --branch "$MINIO_RELEASE" https://github.com/minio/minio /src/minio \
 && cd /src/minio \
 && CGO_ENABLED=0 go build -tags kqueue -trimpath -ldflags "$(go run buildscripts/gen-ldflags.go)" -o /out/minio .
RUN git clone --quiet --depth 1 --branch "$MC_RELEASE" https://github.com/minio/mc /src/mc \
 && cd /src/mc \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$(go run buildscripts/gen-ldflags.go)" -o /out/mc .

FROM alpine:3.20
COPY --from=build /out/ /usr/bin/
# Declared, as the upstream image declares it: testcontainers publishes only
# the ports an image exposes.
EXPOSE 9000
ENTRYPOINT ["minio"]
EOF
fi
echo "$IMAGE"
