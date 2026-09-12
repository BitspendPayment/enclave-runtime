#!/usr/bin/env bash
# The whole stack, in an emulated enclave.
#
# deploy/qemu-nitro/run-e2e.sh is the harness and asserts its own preconditions;
# this script is what puts them in place on a machine that has none of them. On
# a workstation that already boots enclaves, everything below is a no-op and the
# harness runs directly.
#
# Nested virtualisation on GitHub-hosted runners works but is not supported by
# GitHub, so this is the one job here that can fail for reasons outside this
# repository. Everything it needs is installed explicitly rather than assumed,
# so that when it does fail the log says which part was missing.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

WORK="${WORK:-$REPO/target/qemu-nitro}"
IMAGE="${QEMU_IMAGE:-s3fs-qemu-nitro:latest}"

# Pinned, like the Pebble image beside it. An unpinned build tool makes the
# harness's behaviour depend on whatever crates.io served that morning, which is
# the one thing here that was still floating.
VSOCK_VERSION="${VSOCK_VERSION:-0.3.0}"

# The in-process suites first, against the same guest, before anything is
# booted. They are minutes where the emulated enclave is the better part of an
# hour, and they fail on the layer at fault — a TLS or gRPC framing bug found
# here names itself, where the same bug found through QEMU is a timeout with a
# console log to read. Folded into this job rather than kept as their own so
# there is one integration signal, not two.
"$REPO/scripts/ci-guests.sh"

# The block store against a real S3 implementation, folded in for the same
# reason. It starts its own MinIO through testcontainers, so it needs nothing
# from the harness below and nothing from the store the enclave will mount.
"$REPO/scripts/ci-storage.sh"

# /dev/kvm exists on hosted runners but is root-owned; the runner user needs it.
# Guarded so a workstation where KVM already works is left alone — this rule is
# a CI accommodation, not something to apply to a developer's machine.
if [[ -e /dev/kvm && ! -r /dev/kvm ]]; then
    say "granting access to /dev/kvm"
    echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
        | sudo tee /etc/udev/rules.d/99-kvm4all.rules >/dev/null
    sudo udevadm control --reload-rules
    sudo udevadm trigger --name-match=kvm
fi

# The harness forwards the enclave's vsock connections to host loopback, which
# needs the loopback transport present.
if [[ ! -e /dev/vsock ]]; then
    say "loading vsock_loopback"
    sudo modprobe vsock_loopback || fail "could not load vsock_loopback"
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    say "building the QEMU image"
    docker build -t "$IMAGE" deploy/qemu-nitro
fi

# Idempotent, and cached in CI by the directory it installs into.
if [[ ! -x "$WORK/tools/bin/vhost-device-vsock" ]]; then
    say "installing vhost-device-vsock $VSOCK_VERSION"
    cargo install vhost-device-vsock --version "$VSOCK_VERSION" --root "$WORK/tools" --locked
fi

exec deploy/qemu-nitro/run-e2e.sh
