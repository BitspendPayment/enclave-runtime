# QEMU with the nitro-enclave machine, plus the tooling to build an EIF.
#
# Distro packages are not usable: Debian sid ships QEMU 11 and the machine type
# is present, but `-device help` has no virtio-nsm, because the NSM device is
# only compiled when libcbor and gnutls are found at configure time. Without it
# the machine boots but has no Nitro Security Module, which is the one thing
# this harness exists to exercise. So QEMU is built from source with both.
#
# Built in a container rather than on the host so it needs no root there, and
# so the toolchain is pinned rather than whatever the developer happens to have.
#
# Two stages. The first has the compilers and is 3.7 GB; the second copies the
# installed QEMU onto a slim base with its shared libraries and is what
# `docker build` produces — about 680 MB, 100 MB compressed, which is what
# makes a bundle that carries the image worth downloading. Nothing runs from
# the first stage but the build.
FROM debian:trixie AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl xz-utils cpio \
        build-essential ninja-build meson pkg-config python3 python3-venv \
        libglib2.0-dev libpixman-1-dev libslirp-dev \
        libcbor-dev libgnutls28-dev \
    && rm -rf /var/lib/apt/lists/*

ARG QEMU_TAG=v9.2.0
RUN git clone --depth 1 --branch ${QEMU_TAG} https://gitlab.com/qemu-project/qemu.git /qemu

WORKDIR /qemu/build
# Only x86_64 softmmu: a full target list triples the build for nothing.
RUN ../configure \
        --target-list=x86_64-softmmu \
        --enable-kvm \
        --enable-gnutls \
        --disable-docs --disable-guest-agent --disable-sdl --disable-gtk \
        --disable-vnc --disable-werror \
 && ninja -j"$(nproc)" \
 && ninja install

# Fail the build rather than the run if the NSM device is missing: that is the
# single thing this image is for, and a silent absence would be discovered much
# later, inside a boot that hangs for unrelated-looking reasons.
RUN qemu-system-x86_64 -device help 2>&1 | grep -q virtio-nsm \
      || (echo "FATAL: QEMU built without virtio-nsm; libcbor/gnutls were not detected" >&2; exit 1) \
 && qemu-system-x86_64 -M help | grep -iq nitro \
      || (echo "FATAL: QEMU built without the nitro-enclave machine" >&2; exit 1)

RUN qemu-system-x86_64 --version | head -1 > /qemu-version \
 && qemu-system-x86_64 -M help | grep -i nitro >> /qemu-version \
 && qemu-system-x86_64 -device help 2>&1 | grep -i nsm >> /qemu-version

# The image the harness runs: QEMU and what it links against, and no toolchain.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0t64 libpixman-1-0 libslirp0 libcbor0.10 libgnutls30t64 \
        libfdt1 libzstd1 zlib1g libaio1t64 liburing2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local /usr/local
COPY --from=build /qemu-version /qemu-version
# Fails the build, not the boot, if a library is missing.
RUN ! ldd /usr/local/bin/qemu-system-x86_64 | grep -q "not found" \
 && qemu-system-x86_64 -M help | grep -qi nitro

WORKDIR /work
