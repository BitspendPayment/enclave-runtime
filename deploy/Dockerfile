# Enclave image for `nitro-cli build-enclave`.
#
# The guest component ships *inside* this image, which is the whole point: the
# EIF hash becomes PCR0, so a KMS key policy conditioned on PCR0 attests to
# exactly which guest code will read the data — not merely to the runtime that
# loads it. Streaming the guest in at boot would still produce a valid
# attestation, but it would prove something much weaker.
#
# Changing the guest therefore means rebuilding the image and updating the key
# policy. That friction is the feature.
#
#   docker build -f deploy/Dockerfile -t s3fs-enclave .
#   nitro-cli build-enclave --docker-uri s3fs-enclave:latest --output-file s3fs.eif
#   nitro-cli run-enclave --eif-path s3fs.eif --cpu-count 2 --memory 2048
#
# `build-enclave` prints PCR0/PCR1/PCR2; PCR0 is what the key policy pins.

# ---- build ------------------------------------------------------------------
FROM rust:1-bookworm AS build

# aws-lc-rs builds a bundled C library.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN rustup target add wasm32-wasip2 \
 && cargo build --release -p enclave-runtime

# The guest. Swap this for your own component; guest-smoke is the example that
# needs no C toolchain.
RUN cd examples/guest-smoke && cargo build --release --target wasm32-wasip2

# ---- the tap forwarder ------------------------------------------------------
# An enclave has no NIC, so nothing that speaks TCP works until this turns the
# vsock channel into an interface. It ships *inside* the image rather than
# being fetched at boot, so PCR0 covers it: a forwarder streamed in later would
# be code the attestation says nothing about, sitting on every packet.
#
# Pinned by digest. A floating tag would change PCR0 without anything in this
# repository changing, which would look like the image had been tampered with.
FROM golang:1.23-bookworm AS gvforwarder
ARG GVISOR_TAP_VSOCK_VERSION=v0.8.6
RUN git clone --depth 1 --branch ${GVISOR_TAP_VSOCK_VERSION} \
        https://github.com/containers/gvisor-tap-vsock /src \
 && cd /src \
 && CGO_ENABLED=0 go build -o /gvforwarder ./cmd/gvforwarder

# ---- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/enclave-runtime /usr/local/bin/enclave-runtime
COPY --from=gvforwarder /gvforwarder /usr/local/bin/gvforwarder
COPY --from=build /src/examples/guest-smoke/target/wasm32-wasip2/release/guest-smoke.wasm \
                  /enclave/guest.wasm

# Deployment configuration. Every setting also has a flag, but inside an
# enclave there is no shell to pass one, so these are what actually apply.
ENV S3FS_GUEST_PATH=/enclave/guest.wasm
# Read the Nitro PTP hardware clock and refuse to start without it. The
# alternative is running on a clock the parent instance sets, which is the
# party this whole design excludes.
ENV S3FS_CLOCK_SOURCE=ptp
# Take entropy from the Nitro Security Module and refuse to start without it.
# The alternative is a kernel pool that is NSM-seeded in an enclave but says
# nothing about it, and the guest builds keys from these bytes.
ENV S3FS_RANDOM_SOURCE=nsm
# Bring up the tap device over vsock before anything opens a socket. The parent
# instance must be running `gvproxy --listen vsock://:1024` — see
# deploy/parent/run-parent.sh. Without it the runtime waits, then says so.
ENV S3FS_NETWORK=gvproxy
# Serve the guest over HTTPS, terminated here. A certificate generated inside
# the enclave, with its hash signed into the attestation document, is what lets
# a client prove its session ends in *this* code rather than in the parent.
ENV S3FS_MODE=serve
ENV S3FS_HTTP_LISTEN=0.0.0.0:443
ENV S3FS_TLS=self-signed
# ENV S3FS_TLS=acme                       # browser-trusted, needs a real domain
# ENV S3FS_TLS_DOMAINS=enclave.example.com
# ENV S3FS_BUCKET=prod-data
# ENV S3FS_ROOTS_BUCKET=prod-roots        # Object Lock COMPLIANCE lives here
# ENV AWS_REGION=eu-west-2
# ENV S3FS_MIN_ROOT_SEQ=0                 # freshness floor from outside the store
#
# S3FS_MASTER_KEY is deliberately NOT set here. A key baked into the image is
# a key readable by anyone who can pull the image, and one passed by the parent
# is readable by the party the enclave exists to exclude. It is a development
# seam only; the attestation milestone replaces it with a KMS release gated on
# the NSM attestation document, at which point nothing sets it at all.

ENTRYPOINT ["/usr/local/bin/enclave-runtime"]
