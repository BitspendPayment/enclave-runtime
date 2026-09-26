#!/usr/bin/env bash
# Boot the self-test EIF under QEMU's `nitro-enclave` machine and check that the
# guest drew usable random bytes from the emulated Nitro Security Module.
#
# This is the only place in the tree where `/dev/nsm` is exercised for real.
# Everything else — unit tests, the MinIO end-to-end — runs against a fake or
# against host entropy, because the device exists nowhere but an enclave.
#
# Three processes have to line up:
#
#   vhost-device-vsock   the vsock backend; QEMU's nitro-enclave machine has no
#                        built-in vhost-vsock device and will not start without
#                        one on its chardev
#   heartbeat.py         answers init's boot heartbeat on port 9000; without it
#                        the kernel boots and then nothing happens, ever
#   qemu-system-x86_64   the emulator, from the pinned image, since distro QEMU
#                        is built without virtio-nsm
#
# Needs /dev/kvm. GitHub-hosted runners have none, so this stays a local check,
# the same limitation the PTP harness has.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${WORK:-$REPO/target/qemu-nitro}"
RUNDIR="$WORK/run"
IMAGE="${QEMU_IMAGE:-s3fs-qemu-nitro:latest}"
TIMEOUT="${TIMEOUT:-120}"
CONSOLE="$RUNDIR/console.log"

# Built by Nix now, so the image is reproducible and the shell script that
# used to assemble it is gone. `build-eif.sh` remains only as documentation of
# the layout; `nix build` is what produces the bytes.
command -v nix >/dev/null || { echo "nix is not on PATH; see deploy/nix/README.md" >&2; exit 1; }
nix build "$REPO#eif-selftest" --out-link "$WORK/eif-selftest" 2>&1 | tail -2
EIF_DIR="$(readlink -f "$WORK/eif-selftest" 2>/dev/null || true)"
# nix-portable keeps its store outside /nix except inside its own namespace; on
# a normal Nix install the first branch always wins.
[[ -d "$EIF_DIR" ]] || EIF_DIR="$HOME/.nix-portable$(readlink "$WORK/eif-selftest")"
EIF="$EIF_DIR/selftest.eif"
[[ -f "$EIF" ]] || { echo "cannot resolve the built EIF" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "no /dev/kvm — the nitro-enclave machine needs KVM" >&2; exit 1; }

rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"

VSOCK_BIN="$WORK/tools/bin/vhost-device-vsock"
[[ -x "$VSOCK_BIN" ]] || { echo "missing $VSOCK_BIN (cargo install vhost-device-vsock)" >&2; exit 1; }

pids=()
cleanup() {
    for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT

[[ -e /dev/vsock ]] || {
    cat >&2 <<'EOF'
no /dev/vsock — the host needs vsock_loopback loaded:
    sudo modprobe vsock_loopback
The enclave init dials CID 3, which vhost-device-vsock's unix-socket backend
refuses to route ("dropping packet for unknown cid: 3"), so the heartbeat has
to be answered on a real host vsock.
EOF
    exit 1
}

# Port 9000 is where init expects the parent.
python3 "$REPO/deploy/qemu-nitro/heartbeat.py" 9000 \
    > "$RUNDIR/heartbeat.log" 2>&1 &
pids+=($!)

# forward-cid=1 turns guest-originated connections into host vsock connections
# on the loopback CID, which is the only arrangement that reaches a listener
# for CID 3. It is mutually exclusive with --uds-path.
RUST_LOG="${VSOCK_LOG:-info}" "$VSOCK_BIN" \
    --guest-cid 4 \
    --socket "$RUNDIR/vhost.socket" \
    --forward-cid 1 \
    > "$RUNDIR/vsock.log" 2>&1 &
pids+=($!)

for _ in $(seq 50); do [[ -S "$RUNDIR/vhost.socket" ]] && break; sleep 0.1; done
[[ -S "$RUNDIR/vhost.socket" ]] || { echo "vhost-device-vsock never came up:" >&2; cat "$RUNDIR/vsock.log" >&2; exit 1; }

echo "== booting $EIF =="
# --network none is deliberate: an enclave has no NIC, and the harness should
# not quietly give the guest one.
set +e
timeout "$TIMEOUT" docker run --rm \
    --device /dev/kvm \
    --network none \
    -v "$EIF_DIR:/eif:ro" \
    -v "$RUNDIR:/run/vsock" \
    "$IMAGE" \
    qemu-system-x86_64 \
        -M nitro-enclave,vsock=chr0,id=selftest \
        -kernel /eif/selftest.eif \
        -chardev socket,id=chr0,path=/run/vsock/vhost.socket \
        -m 1G -smp 2 -nographic -no-reboot \
    2>&1 | tee "$CONSOLE"
set -e

echo
echo "== result =="
if grep -q "NSM-SELFTEST-OK" "$CONSOLE"; then
    echo "PASS: the guest drew random bytes from the emulated NSM"
    grep -E "NSM-SELFTEST|nsm" "$CONSOLE" || true
    exit 0
fi

echo "FAIL: no NSM-SELFTEST-OK on the console" >&2
echo "--- heartbeat ---" >&2; cat "$RUNDIR/heartbeat.log" >&2
echo "--- vsock ---"     >&2; tail -20 "$RUNDIR/vsock.log" >&2
exit 1
