#!/usr/bin/env bash
# Common to every script here.
#
# These recipes used to live inline in .github/workflows/ci.yml, which meant the
# only way to run a CI job was to push and wait. Everything in this directory
# runs the same way on a laptop as it does on a runner — that is the whole point
# of the directory existing.
#
# Sourced, not executed: `. "$(dirname "$0")/lib.sh"`.

set -euo pipefail

# Resolved from this file's real path rather than asked of git: a script invoked
# through a symlink or from another directory still lands here, and a bundle
# that carries these scripts (`dev-enclave.sh --pack`) is not a git checkout at
# all — `wasi-sdk.sh` has to run from one just the same.
REPO="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
export REPO

# The same shape deploy/qemu-nitro/run-e2e.sh prints, so a run that spans both
# reads as one log rather than two conventions meeting in the middle.
say() { printf '\n== %s ==\n' "$*"; }

fail() {
    printf '\nFAIL: %s\n' "$*" >&2
    exit 1
}

# Put in place what deploy/qemu-nitro needs and asserts: KVM the runner user can
# open, the vsock loopback transport, the QEMU image, and vhost-device-vsock.
# On a workstation that already boots enclaves every step is a no-op.
#
# Nested virtualisation on GitHub-hosted runners works but is not supported by
# GitHub, so this is the one thing here that can fail for reasons outside this
# repository. Everything is installed explicitly rather than assumed, so that
# when it does fail the log says which part was missing.
prepare_enclave_host() {
    local work="${WORK:-$REPO/target/qemu-nitro}"
    local image="${QEMU_IMAGE:-s3fs-qemu-nitro:latest}"
    # Pinned, like the Pebble image beside it. An unpinned build tool makes the
    # harness's behaviour depend on whatever crates.io served that morning.
    local vsock_version="${VSOCK_VERSION:-0.3.0}"

    # /dev/kvm exists on hosted runners but is root-owned; the runner user needs
    # it. Guarded so a workstation where KVM already works is left alone — this
    # rule is a CI accommodation, not something to apply to a developer's machine.
    if [[ -e /dev/kvm && ! -r /dev/kvm ]]; then
        say "granting access to /dev/kvm"
        echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules >/dev/null
        sudo udevadm control --reload-rules
        sudo udevadm trigger --name-match=kvm
    fi

    # The harness forwards the enclave's vsock connections to host loopback,
    # which needs the loopback transport present.
    if [[ ! -e /dev/vsock ]]; then
        say "loading vsock_loopback"
        sudo modprobe vsock_loopback || fail "could not load vsock_loopback"
    fi

    if ! docker image inspect "$image" >/dev/null 2>&1; then
        say "building the QEMU image"
        docker build -t "$image" "$REPO/deploy/qemu-nitro"
    fi

    # Idempotent, and cached in CI by the directory it installs into.
    if [[ ! -x "$work/tools/bin/vhost-device-vsock" ]]; then
        say "installing vhost-device-vsock $vsock_version"
        cargo install vhost-device-vsock --version "$vsock_version" --root "$work/tools" --locked
    fi
}
