#!/usr/bin/env bash
# Verify that enclave-runtime can read a PTP hardware clock.
#
# /dev/ptp0 is root-owned, so this needs a context where we are root. Two are
# offered, and they prove different things:
#
#   container  Passes the host's real PHC into a container via --device. This
#              is the stronger test: the PHC is genuinely a different clock
#              from CLOCK_REALTIME, so a non-zero skew proves we are reading
#              the device rather than falling through to the system clock.
#              Needs membership of the `docker` group.
#
#   qemu       Boots a VM and uses ptp_kvm to expose a /dev/ptp0 inside it.
#              Exercises the same device interface, but the clock behind
#              ptp_kvm *is* the host's clock, so the skew is ~0 and it cannot
#              distinguish "read the PHC" from "read CLOCK_REALTIME". Useful
#              where no PHC exists, or where docker is unavailable.
#
# Neither emulates Nitro. Full fidelity needs QEMU >= 9.1's `nitro-enclave`
# machine and an EIF, which belongs with NSM and KMS in M8.
#
#   ./deploy/ptp-check.sh                 # container (default)
#   ./deploy/ptp-check.sh --mode qemu
set -euo pipefail

MODE=container
DEVICE=/dev/ptp0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --device) DEVICE="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/release/enclave-runtime"
# clock-check never mounts anything, but the CLI requires these.
DUMMY_ARGS=(--clock-check --clock-source ptp --bucket unused
            --master-key 00000000000000000000000000000000000000000000000000000000000000ab)

[[ -x "$BIN" ]] || { echo "build it first: cargo build --release -p enclave-runtime" >&2; exit 1; }

case "$MODE" in
container)
    command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
    [[ -e "$DEVICE" ]] || { echo "$DEVICE does not exist on this host" >&2; exit 1; }

    echo "== PTP via container, device $DEVICE =="
    # The AWS SDK's TLS provider panics at construction when it finds no trust
    # store, even for a plain-HTTP endpoint, so the host's certs come along.
    docker run --rm --device "$DEVICE" \
        -v /etc/ssl/certs:/etc/ssl/certs:ro \
        -v "$BIN:/enclave-runtime:ro" \
        ubuntu:24.04 /enclave-runtime "${DUMMY_ARGS[@]}" --ptp-device "$DEVICE"
    ;;

qemu)
    command -v qemu-system-x86_64 >/dev/null || {
        echo "qemu-system-x86_64 not found: apt install qemu-system-x86" >&2; exit 1; }
    command -v cloud-localds >/dev/null || {
        echo "cloud-localds not found: apt install cloud-image-utils" >&2; exit 1; }
    [[ -w /dev/kvm ]] || {
        echo "/dev/kvm is not writable. ptp_kvm needs KVM; TCG emulation will" >&2
        echo "not produce the device, so this mode cannot work without it." >&2
        exit 1; }

    WORK="${TMPDIR:-/tmp}/s3fs-ptp-qemu"
    mkdir -p "$WORK"
    IMG="$WORK/noble.img"
    SEED="$WORK/seed.iso"

    if [[ ! -f "$IMG" ]]; then
        echo "== fetching Ubuntu cloud image =="
        curl -sSL -o "$WORK/noble.orig.img" \
            https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
        cp "$WORK/noble.orig.img" "$IMG"
        qemu-img resize "$IMG" +2G
    fi

    # cloud-init loads ptp_kvm, runs the check, prints a sentinel, powers off.
    # Everything runs as root, which is the whole reason for the VM.
    cat > "$WORK/user-data" <<EOF
#cloud-config
runcmd:
  - modprobe ptp_kvm || echo "PTP-CHECK-FAIL: ptp_kvm did not load"
  - [ -e /dev/ptp0 ] || echo "PTP-CHECK-FAIL: no /dev/ptp0 after modprobe"
  - /mnt/host/enclave-runtime ${DUMMY_ARGS[*]} || echo "PTP-CHECK-FAIL: clock-check failed"
  - echo "PTP-CHECK-DONE"
  - poweroff
EOF
    echo "instance-id: s3fs-ptp" > "$WORK/meta-data"
    cloud-localds "$SEED" "$WORK/user-data" "$WORK/meta-data"

    echo "== booting VM; ptp_kvm exposes the host clock as /dev/ptp0 inside =="
    qemu-system-x86_64 \
        -enable-kvm -m 1024 -smp 2 -nographic \
        -drive "file=$IMG,format=qcow2,if=virtio" \
        -drive "file=$SEED,format=raw,if=virtio" \
        -virtfs "local,path=$(dirname "$BIN"),mount_tag=host,security_model=mapped-xattr" \
        | tee "$WORK/console.log"

    grep -q "PTP-CHECK-DONE" "$WORK/console.log" || { echo "VM did not finish" >&2; exit 1; }
    ! grep -q "PTP-CHECK-FAIL" "$WORK/console.log" || { echo "check failed, see $WORK/console.log" >&2; exit 1; }
    echo "== ok =="
    ;;

*)
    echo "unknown mode: $MODE (expected container or qemu)" >&2; exit 2 ;;
esac
