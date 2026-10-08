# Enclave image for `nitro-cli build-enclave`.
#
# The guest component is NOT in this image. The runtime fetches it at boot from
# `ENCLAVE_GUEST_OBJECT`, a key in the roots bucket, extends PCR16 with its hash
# and locks that register before it asks KMS for anything. This image — PCR0 —
# covers the runtime and *where* the guest comes from; PCR16 covers *what*
# arrived. A key policy pinning both still attests to exactly which guest code
# will read the data, not merely to the runtime that loads it.
#
# Changing the guest therefore means uploading it and replacing PCR16 in the
# key policy, not rebuilding this image. The approval was always the feature;
# the rebuild never was.
#
#   docker build -f deploy/Dockerfile -t enclave-runtime .
#   nitro-cli build-enclave --docker-uri enclave-runtime:latest --output-file enclave.eif
#   nitro-cli run-enclave --eif-path enclave.eif --cpu-count 2 --memory 2048
#
# `build-enclave` prints PCR0/PCR1/PCR2; PCR0 is what the key policy pins for
# the runtime. The guest is built, measured and uploaded on its own:
#
#   (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
#   GUEST=examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm
#   nitro-attest --measure "$GUEST"          # the PCR16 the key policy pins
#   aws s3 cp "$GUEST" s3://<roots bucket>/guest/guest.wasm

# ---- build ------------------------------------------------------------------
FROM rust:1-bookworm AS build

# aws-lc-rs builds a bundled C library.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release -p enclave-runtime

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

# Deployment configuration. Every setting also has a flag, but inside an
# enclave there is no shell to pass one, so these are what actually apply.
#
# Where the guest comes from, as a key in ENCLAVE_ROOTS_BUCKET. The location is
# measured here, by PCR0; what is found there is measured into PCR16 at boot,
# so the object does not have to be trusted — a substituted one gets no key.
ENV ENCLAVE_GUEST_OBJECT=guest/guest.wasm
# Opt in for a guest implementing enclave:tasks/background@0.1.0, with WebAuthn
# configured. See docs/BACKGROUND_TASKS.md for standing authorization semantics.
# ENV ENCLAVE_BACKGROUND_TASKS=true
# ENV ENCLAVE_BACKGROUND_CONCURRENCY=1
# Read the Nitro PTP hardware clock and refuse to start without it. The
# alternative is running on a clock the parent instance sets, which is the
# party this whole design excludes.
ENV ENCLAVE_CLOCK_SOURCE=ptp
# Take entropy from the Nitro Security Module and refuse to start without it.
# The alternative is a kernel pool that is NSM-seeded in an enclave but says
# nothing about it, and the guest builds keys from these bytes.
ENV ENCLAVE_RANDOM_SOURCE=nsm
# Bring up the tap device over vsock before anything opens a socket. The parent
# instance must be running `gvproxy --listen vsock://:1024` — see
# deploy/parent/run-parent.sh. Without it the runtime waits, then says so.
ENV ENCLAVE_NETWORK=gvproxy
# Serve the guest over HTTPS, terminated here. A certificate generated inside
# the enclave, with its hash signed into the attestation document, is what lets
# a client prove its session ends in *this* code rather than in the parent.
ENV ENCLAVE_HTTP_LISTEN=0.0.0.0:443
# ACME, and only ACME. A self-signed certificate is one an operator can mint
# too, so it cannot tell this enclave apart from something impersonating it —
# the runtime refuses the setting rather than generating one.
ENV ENCLAVE_TLS=acme
ENV ENCLAVE_TLS_DOMAINS=enclave.example.com
# ENV ENCLAVE_ROOTS_BUCKET=prod-roots        # Object Lock COMPLIANCE lives here
# ENV AWS_REGION=eu-west-2
# ENV ENCLAVE_MIN_ROOT_SEQ=0                 # freshness floor from outside the store
#
# The master secret is minted by KMS inside the enclave and released only
# against an attestation whose PCR0 and PCR16 match the key policy. A wrong
# image or a wrong guest does not get a refused mount; it gets no key at all.
ENV ENCLAVE_MASTER_KEY_SOURCE=kms
# ENV ENCLAVE_KMS_KEY_ID=arn:aws:kms:eu-west-2:...:key/...
# ENV ENCLAVE_MASTER_KEY_PARAMETER=/enclave-runtime/prod/<fs-id>/master-key
# ENV ENCLAVE_ENVIRONMENT=production        # part of the encryption context
#
# ENCLAVE_MASTER_KEY is deliberately NOT set, and the runtime *refuses to start*
# if it is set alongside the line above. A key baked into the image is readable
# by anyone who can pull the image, and one passed by the parent is readable by
# the party the enclave exists to exclude — so the combination is an error
# rather than a precedence rule.

ENTRYPOINT ["/usr/local/bin/enclave-runtime"]
