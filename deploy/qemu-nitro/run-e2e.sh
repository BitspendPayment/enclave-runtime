#!/usr/bin/env bash
# The whole stack, in an emulated enclave.
#
# Everything below has been verified in pieces — the block store against MinIO,
# TLS and the attestation binding in unit tests, NSM entropy under QEMU. None
# of it had ever run together, because until gvproxy the emulated enclave had
# no way to reach anything.
#
#   host                                        QEMU enclave
#   ────                                        ────────────
#   MinIO :9000 ◀── gvproxy ──192.168.127.254──  s3fs mount
#   gvproxy --listen vsock://:1024 ────────────▶ gvforwarder → tap0 .2
#           expose :8443 → 192.168.127.2:443 ──▶ rustls :443
#   vhost-device-vsock --forward-cid 1
#   heartbeat.py :9000  ───────────────────────▶ init's boot heartbeat
#   nitro-attest ──────────────────────────────▶ /enclave/attestation
#
# What it proves, in order of how much it cost to get here:
#
#   1. PCR0 in the signed attestation document equals the PCR0 `nix build`
#      printed. The measurement a client would pin is the measurement the
#      reproducible build claimed.
#   2. user_data binds the certificate from this connection's own handshake,
#      so the TLS session terminates in the attested enclave.
#   3. The guest's counter advances, so writes crossed gvproxy to MinIO and
#      came back — the filesystem really is mounted over the emulated vsock.
#
# What this harness CANNOT prove, stated up front because it is easy to assume
# otherwise: QEMU's emulated NSM does not sign attestation documents. Its
# source says so — "we don't actually sign the data, so we use -1 as the 'alg'
# value" — and -1 is not a COSE algorithm identifier. So there is no signature
# to verify and no certificate chain to follow.
#
# The document's *contents* are still worth checking, because they are what the
# runtime put there: the nonce it was asked for, the PCR0 of the image it is
# running, and the hash of the certificate it is serving. Those are our code.
# The signature is AWS hardware's job and needs hardware to test.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${WORK:-$REPO/target/qemu-nitro}"
RUNDIR="$WORK/e2e"
IMAGE="${QEMU_IMAGE:-s3fs-qemu-nitro:latest}"
TIMEOUT="${TIMEOUT:-240}"
CONSOLE="$RUNDIR/console.log"

# Host-side port that gvproxy forwards into the enclave's :443.
HTTPS_PORT="${HTTPS_PORT:-8443}"

say() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
# Preconditions, each with the fix rather than just the symptom.
# ---------------------------------------------------------------------------
command -v nix >/dev/null || { echo "nix is not on PATH; see deploy/nix/README.md" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "no /dev/kvm — the nitro-enclave machine needs KVM" >&2; exit 1; }
[[ -e /dev/vsock ]] || {
    echo "no /dev/vsock — the host needs: sudo modprobe vsock_loopback" >&2
    exit 1
}
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
    echo "missing QEMU image $IMAGE — build it:" >&2
    echo "  docker build -t $IMAGE deploy/qemu-nitro" >&2
    exit 1
}

VSOCK_BIN="$WORK/tools/bin/vhost-device-vsock"
[[ -x "$VSOCK_BIN" ]] || { echo "missing $VSOCK_BIN (cargo install vhost-device-vsock --root $WORK/tools)" >&2; exit 1; }

rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"

pids=()
cleanup() {
    for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
    docker rm -f e2e-minio >/dev/null 2>&1 || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# The image, and the measurement it claims.
# ---------------------------------------------------------------------------
say "building the enclave image"
nix build "$REPO#eif-qemu" --out-link "$RUNDIR/eif" --print-build-logs 2>&1 | tail -3

# nix-portable keeps its store outside /nix except inside its own namespace, so
# `result/` may not resolve here. Ask nix for the path and translate it if the
# symlink is dangling — on a machine with a normal Nix install the first branch
# is always the one taken.
EIF_DIR="$(readlink -f "$RUNDIR/eif" 2>/dev/null || true)"
if [[ ! -d "$EIF_DIR" ]]; then
    EIF_DIR="$HOME/.nix-portable$(readlink "$RUNDIR/eif")"
fi
[[ -d "$EIF_DIR" ]] || { echo "cannot resolve the built EIF" >&2; exit 1; }

EIF="$EIF_DIR/s3fs-qemu.eif"
EXPECTED_PCR0="$(jq -r .PCR0 "$EIF_DIR/pcr.json")"
echo "EIF   $EIF ($(du -h "$EIF" | cut -f1))"
echo "PCR0  $EXPECTED_PCR0"

# Built with the host's cargo rather than Nix. The verifier is a client-side
# tool that nothing attests, so it gains nothing from a reproducible build —
# and a Nix-built dynamic binary links against a glibc in the Nix store, which
# will not run on a machine that has no such store path. Only what goes
# *inside* the enclave has to come from Nix.
say "building the verifier"
( cd "$REPO" && cargo build --release -p nitro-attestation --features cli ) 2>&1 | tail -2
ATTEST="$REPO/target/release/nitro-attest"
[[ -x "$ATTEST" ]] || { echo "nitro-attest did not build" >&2; exit 1; }

# ---------------------------------------------------------------------------
# The store the enclave will mount.
# ---------------------------------------------------------------------------
say "starting MinIO"
docker rm -f e2e-minio >/dev/null 2>&1 || true
docker run -d --rm --name e2e-minio -p 9000:9000 \
    -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
    minio/minio server /data >/dev/null
for _ in $(seq 1 60); do
    curl -sf http://127.0.0.1:9000/minio/health/ready >/dev/null && break
    sleep 1
done
docker run --rm --network host --entrypoint sh minio/mc -c "
    mc alias set m http://127.0.0.1:9000 minioadmin minioadmin >/dev/null
    mc mb m/e2e-data >/dev/null 2>&1 || true
    mc mb --with-lock m/e2e-roots >/dev/null 2>&1 || true" >/dev/null
echo "MinIO ready with e2e-data and e2e-roots"

# ---------------------------------------------------------------------------
# The parent side: heartbeat, vsock transport, and the network.
# ---------------------------------------------------------------------------
say "starting the parent-side services"

# init writes 0xB7 to the parent on port 9000 and waits. Unanswered, the kernel
# boots and then nothing happens at all.
python3 "$REPO/deploy/qemu-nitro/heartbeat.py" 9000 > "$RUNDIR/heartbeat.log" 2>&1 &
pids+=($!)

# forward-cid 1 turns the guest's vsock connections into host vsock loopback
# connections, which is the only arrangement that reaches a listener for the
# CID 3 the enclave dials.
RUST_LOG="${VSOCK_LOG:-info}" "$VSOCK_BIN" \
    --guest-cid 4 \
    --socket "$RUNDIR/vhost.socket" \
    --forward-cid 1 \
    > "$RUNDIR/vsock.log" 2>&1 &
pids+=($!)

for _ in $(seq 50); do [[ -S "$RUNDIR/vhost.socket" ]] && break; sleep 0.1; done
[[ -S "$RUNDIR/vhost.socket" ]] || { echo "vhost-device-vsock never came up:" >&2; cat "$RUNDIR/vsock.log" >&2; exit 1; }

# The enclave's only route to anything. Without it the runtime waits for the
# gateway and then says so.
#
# The same pin as the gvforwarder inside the image, and built static for the
# same reason: it has to run here, and later on Amazon Linux, neither of which
# has a Nix store.
nix build "$REPO#gvproxy" --out-link "$RUNDIR/gvproxy" 2>&1 | tail -1
GV_DIR="$(readlink -f "$RUNDIR/gvproxy" 2>/dev/null || true)"
[[ -d "$GV_DIR" ]] || GV_DIR="$HOME/.nix-portable$(readlink "$RUNDIR/gvproxy")"

"$GV_DIR/bin/gvproxy" \
    --listen "vsock://:1024" \
    --listen "unix://$RUNDIR/network.sock" \
    > "$RUNDIR/gvproxy.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do [[ -S "$RUNDIR/network.sock" ]] && break; sleep 0.1; done
[[ -S "$RUNDIR/network.sock" ]] || { echo "gvproxy never opened its API socket:" >&2; cat "$RUNDIR/gvproxy.log" >&2; exit 1; }
echo "gvproxy listening on host vsock port 1024"

# ---------------------------------------------------------------------------
# Boot.
# ---------------------------------------------------------------------------
say "booting the enclave"
docker run --rm -d --name e2e-qemu \
    --device /dev/kvm \
    --network none \
    -v "$EIF_DIR:/eif:ro" \
    -v "$RUNDIR:/run/vsock" \
    "$IMAGE" \
    qemu-system-x86_64 \
        -M nitro-enclave,vsock=chr0,id=e2e \
        -kernel /eif/s3fs-qemu.eif \
        -chardev socket,id=chr0,path=/run/vsock/vhost.socket \
        -m 3G -smp 2 -nographic -no-reboot >/dev/null
pids+=(0)  # placeholder; the container is cleaned up by name

docker logs -f e2e-qemu > "$CONSOLE" 2>&1 &

# The runtime colourises its logs, so escape sequences land between a field
# name and its value — `addr<esc>[0m<esc>[2m=` — and a grep for "addr=" simply
# never matches. Everything that reads the console goes through this.
plain() { sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$CONSOLE" 2>/dev/null; }

fail() {
    echo
    echo "FAIL: $*" >&2
    echo "--- console (last 40) ---" >&2; plain | tail -40 >&2
    echo "--- gvproxy ---" >&2;          tail -10 "$RUNDIR/gvproxy.log" >&2
    echo "--- heartbeat ---" >&2;        cat "$RUNDIR/heartbeat.log" >&2
    docker rm -f e2e-qemu >/dev/null 2>&1 || true
    exit 1
}

# The enclave takes its address by DHCP from gvproxy, then mounts over the
# network before it listens, so this waits on the whole chain rather than on
# the boot alone.
say "waiting for the enclave to come up"
ready=""
for _ in $(seq "$TIMEOUT"); do
    # "serving " with the bound address, not the earlier "serving guest" —
    # that one is logged before the listener exists and racing it produces a
    # connection-refused that looks like a networking fault.
    if plain | grep -qE "serving +addr="; then ready=1; break; fi
    plain | grep -qE "Kernel panic|failed to start the guest" && fail "the enclave died during boot"
    sleep 1
done
[[ -n "$ready" ]] || fail "the enclave never started serving within ${TIMEOUT}s"

plain | grep -E "enclave networking is up|mounted |serving +addr=" | tail -3

# Forward a host port into the enclave. Done after boot so the enclave can be
# restarted without restarting the proxy.
say "forwarding :$HTTPS_PORT into the enclave"
curl -sf --unix-socket "$RUNDIR/network.sock" \
    http://localhost/services/forwarder/expose \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"local\":\":${HTTPS_PORT}\",\"remote\":\"192.168.127.2:443\"}" \
    || fail "gvproxy refused to forward :$HTTPS_PORT"

for _ in $(seq 30); do
    curl -sk --max-time 2 "https://127.0.0.1:$HTTPS_PORT/" >/dev/null 2>&1 && break
    sleep 1
done

# ---------------------------------------------------------------------------
# The assertions.
# ---------------------------------------------------------------------------
say "1/3  the filesystem is mounted over gvproxy"
first="$(curl -sk --max-time 20 "https://127.0.0.1:$HTTPS_PORT/counter")" || fail "no answer from the guest"
second="$(curl -sk --max-time 20 "https://127.0.0.1:$HTTPS_PORT/counter")" || fail "no answer from the guest"
echo "counter: $first then $second"
[[ "${second//[^0-9]/}" -eq $(( ${first//[^0-9]/} + 1 )) ]] \
    || fail "the counter did not advance ($first → $second); writes are not reaching MinIO"

say "2/3  the attestation binds this connection's certificate"
"$ATTEST" \
    --url "https://127.0.0.1:$HTTPS_PORT/enclave/attestation" \
    --unsigned-emulator \
    --pcr0 "$EXPECTED_PCR0" \
    | tee "$RUNDIR/attest.log" \
    || fail "attestation verification failed"

grep -q "binding    the attested certificate" "$RUNDIR/attest.log" \
    || fail "the document did not bind the certificate this connection was served"

say "3/3  the attested PCR0 is the one the build produced"
# `nitro-attest --pcr0` already enforced this, so reaching here means it held.
# Printing both is what makes the claim checkable by eye rather than taken on
# trust from an exit code.
echo "build:    $EXPECTED_PCR0"
echo "attested: $(grep -oE '^PCR0 +[0-9a-f]+' "$RUNDIR/attest.log" | awk '{print $2}')"

docker rm -f e2e-qemu >/dev/null 2>&1 || true

cat <<EOF

== PASS ==
  filesystem mounted over vsock through gvproxy, writes durable in MinIO
  TLS terminated in the enclave, certificate hash bound into the document
  the document's PCR0 matches the reproducible build

NOT proven here. QEMU's emulated NSM does not sign attestation documents, so
no signature and no certificate chain were checked — only the contents the
runtime asked for. A document from this harness is worth what the connection
it arrived over is worth. The signature path needs real Nitro hardware.
EOF
