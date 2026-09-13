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
#   MinIO :9000 ◀── gvproxy ──192.168.127.254──  s3fs mount, and the guest
#   gvproxy --listen vsock://:1024 ────────────▶ gvforwarder → tap0 .2
#           expose :8443 → 192.168.127.2:443 ──▶ rustls :443
#   vhost-device-vsock --forward-cid 1
#   heartbeat.py :9000  ───────────────────────▶ init's boot heartbeat
#   nitro-attest ──────────────────────────────▶ x-enclave-attestation
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
#   4. The guest came from the store, not the image. The enclave measured the
#      object it fetched into PCR16 and locked it; the attested PCR16 is the one
#      the release build computed; and a substituted object boots an enclave
#      that a client pinning the approved guest refuses.
#
# What this harness CANNOT prove, stated up front because it is easy to assume
# otherwise: QEMU's emulated NSM does not sign attestation documents. Its
# source says so — "we don't actually sign the data, so we use -1 as the 'alg'
# value" — and -1 is not a COSE algorithm identifier. So there is no signature
# to verify and no certificate chain to follow.
#
# The document's *contents* are still worth checking, because they are what the
# runtime put there: the nonce it was asked for, the PCR0 of the image it is
# running, the PCR16 of the guest it measured, and the hash of the certificate
# it is serving. Those are our code. The signature is AWS hardware's job and
# needs hardware to test — and so does KMS refusing a substituted guest, since
# the emulator image cannot use KMS at all.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${WORK:-$REPO/target/qemu-nitro}"
RUNDIR="$WORK/e2e"
IMAGE="${QEMU_IMAGE:-s3fs-qemu-nitro:latest}"
TIMEOUT="${TIMEOUT:-240}"
CONSOLE="$RUNDIR/console.log"

# Host-side port that gvproxy forwards into the enclave's :443. Pebble also
# validates the TLS-ALPN-01 challenge against it, so it is both the service
# port and the challenge port — as it is in production, where both are 443.
HTTPS_PORT="${HTTPS_PORT:-8443}"

# The ACME test CA. Pinned by digest: this image supplies the issuance path the
# e2e claims to prove, and "latest" would let that claim change under us.
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199}"

say() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
# Preconditions, each with the fix rather than just the symptom.
# ---------------------------------------------------------------------------
command -v nix >/dev/null || { echo "nix is not on PATH; see deploy/nix/README.md" >&2; exit 1; }

# Flakes copy only what git tracks, so an untracked file is invisible to the
# build no matter that it is right there on disk. The failure lands deep inside
# the EIF derivation as a bare "cp: cannot stat", naming a store path that does
# not contain it — true, and useless. Checked here instead.
for f in pebble/ca.pem pebble/cert.pem pebble/key.pem fcm/service-account.json; do
    git -C "$REPO" ls-files --error-unmatch "deploy/qemu-nitro/$f" >/dev/null 2>&1 || {
        echo "deploy/qemu-nitro/$f is not tracked by git, so nix cannot see it." >&2
        echo "  git add deploy/qemu-nitro/" >&2
        exit 1
    }
done
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
    # `kill 0` signals the whole process group, this script included, so a stray
    # 0 in this array ends the harness by SIGTERM instead of letting it exit —
    # which is how a run that had already printed PASS still reported 143.
    for p in "${pids[@]:-}"; do
        if [[ "$p" =~ ^[0-9]+$ ]] && (( p > 0 )); then
            kill "$p" 2>/dev/null || true
        fi
    done
    # `docker logs -f` never ends on its own, so the job table has to be killed
    # rather than waited on.
    local remaining
    remaining="$(jobs -p 2>/dev/null || true)"
    if [[ -n "$remaining" ]]; then
        # shellcheck disable=SC2086
        kill $remaining 2>/dev/null || true
    fi
    docker rm -f e2e-minio e2e-pebble e2e-qemu e2e-qemu-resume e2e-qemu-substitute >/dev/null 2>&1 || true
    return 0
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

# The guest is not in the image. It is built on its own and uploaded to the
# store, and the enclave measures what it fetches into PCR16 — so the build
# says what PCR16 should be, the same way `pcr.json` says what PCR0 should be.
say "building the guest release"
nix build "$REPO#guest-release" --out-link "$RUNDIR/guest" --print-build-logs 2>&1 | tail -3
GUEST_DIR="$(readlink -f "$RUNDIR/guest" 2>/dev/null || true)"
if [[ ! -d "$GUEST_DIR" ]]; then
    GUEST_DIR="$HOME/.nix-portable$(readlink "$RUNDIR/guest")"
fi
[[ -d "$GUEST_DIR" ]] || { echo "cannot resolve the built guest" >&2; exit 1; }
EXPECTED_PCR16="$(jq -r .PCR16 "$GUEST_DIR/guest-pcr16.json")"
echo "PCR16 $EXPECTED_PCR16"

# Plain copies the containers can mount, and a second guest that differs from
# the first only by an appended custom section: a valid component with a
# different hash, which is all a substituted object needs to be.
mkdir -p "$RUNDIR/guests"
install -m 0644 "$GUEST_DIR/guest.wasm" "$RUNDIR/guests/guest.wasm"
install -m 0644 "$GUEST_DIR/guest.wasm" "$RUNDIR/guests/substitute.wasm"
printf '\x00\x0b\x0asubstitute' >> "$RUNDIR/guests/substitute.wasm"

# Built with the host's cargo rather than Nix. The verifier is a client-side
# tool that nothing attests, so it gains nothing from a reproducible build —
# and a Nix-built dynamic binary links against a glibc in the Nix store, which
# will not run on a machine that has no such store path. Only what goes
# *inside* the enclave has to come from Nix.
say "building the verifier"
( cd "$REPO" && cargo build --release -p nitro-attestation --features cli ) 2>&1 | tail -2
ATTEST="$REPO/target/release/nitro-attest"
[[ -x "$ATTEST" ]] || { echo "nitro-attest did not build" >&2; exit 1; }

# The release build measured the guest with a Nix-built nitro-attest; this one
# was built here. They must agree, or a key policy and a client would pin
# different numbers for the same guest.
[[ "$("$ATTEST" --measure "$RUNDIR/guests/guest.wasm" | jq -r .PCR16)" == "$EXPECTED_PCR16" ]] \
    || { echo "the release build and this verifier disagree about the guest's PCR16" >&2; exit 1; }
SUBSTITUTE_PCR16="$("$ATTEST" --measure "$RUNDIR/guests/substitute.wasm" | jq -r .PCR16)"
[[ "$SUBSTITUTE_PCR16" != "$EXPECTED_PCR16" ]] \
    || { echo "the substitute guest measures the same as the real one" >&2; exit 1; }

# The client half of the WebAuthn gate. Nothing reaches the guest without a
# fresh assertion bound to that exact request, and a shell script cannot sign
# one — so the harness drives the gate with a software passkey.
( cd "$REPO" && cargo build --release -p enclave-runtime --features testing \
    --bin passkey-client ) 2>&1 | tail -2
PASSKEY="$REPO/target/release/passkey-client"
[[ -x "$PASSKEY" ]] || { echo "passkey-client did not build" >&2; exit 1; }
# Two identities, each with its own passkey file, so the harness can show that
# one tenant cannot see another's data.
# `--unsigned-emulator`: QEMU's NSM does not sign its documents at all, so
# there is no signature to check and nothing here establishes *who* produced
# one. What the client still checks is what the runtime put in — the nonce, the
# certificate this connection was served, and both measurements — and those are
# our code's work. Against real hardware this flag must not appear.
PASSKEY_ARGS=(--unsigned-emulator --pcr0 "$EXPECTED_PCR0" --pcr16 "$EXPECTED_PCR16")
signed()  { "$PASSKEY" --url "https://127.0.0.1:$HTTPS_PORT" --state "$RUNDIR/alice.json" "${PASSKEY_ARGS[@]}" "$@"; }
signed2() { "$PASSKEY" --url "https://127.0.0.1:$HTTPS_PORT" --state "$RUNDIR/bob.json"   "${PASSKEY_ARGS[@]}" "$@"; }

# ---------------------------------------------------------------------------
# The store the enclave will mount, and the guest it will fetch.
# ---------------------------------------------------------------------------
say "starting MinIO"
# The same recipe the SQLite CI job uses. It lived here in full until both
# copies had to agree with nothing making them agree.
"$REPO/scripts/minio-up.sh" e2e-minio 9000 e2e-data e2e-roots

# Where the emulator image looks: `deployment.guestObject` in e2e-roots.
upload_guest() {
    docker run --rm --network host -v "$RUNDIR/guests:/guests:ro" --entrypoint sh minio/mc -c "
        mc alias set m http://127.0.0.1:9000 minioadmin minioadmin >/dev/null
        mc cp /guests/$1 m/e2e-roots/guest/guest.wasm >/dev/null" >/dev/null \
        || { echo "could not upload $1 to the store" >&2; exit 1; }
}
upload_guest guest.wasm
echo "MinIO ready with e2e-data and e2e-roots, and the guest at e2e-roots/guest/guest.wasm"

# ---------------------------------------------------------------------------
# The parent side: heartbeat, vsock transport, and the network.
# ---------------------------------------------------------------------------
say "starting the parent-side services"

# init writes 0xB7 to the parent on port 9000 and waits. Unanswered, the kernel
# boots and then nothing happens at all.
python3 "$REPO/deploy/qemu-nitro/heartbeat.py" 9000 > "$RUNDIR/heartbeat.log" 2>&1 &
pids+=($!)

# Firebase is not reachable from here and would refuse an invented registration
# token if it were. The stub answers the two endpoints the runtime calls and
# records every message, so the harness can assert on what the runtime *sent*.
FCM_RECORD="$RUNDIR/fcm-messages.jsonl"
python3 "$REPO/deploy/qemu-nitro/fcm-stub.py" "$FCM_RECORD" > "$RUNDIR/fcm-stub.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do
    curl -sf -o /dev/null -X POST --data '{}' http://127.0.0.1:9101/token && break
    sleep 0.1
done
curl -sf -o /dev/null -X POST --data '{}' http://127.0.0.1:9101/token \
    || { echo "the FCM stub never answered:" >&2; cat "$RUNDIR/fcm-stub.log" >&2; exit 1; }

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

# The CA. Pebble is a real RFC 8555 server, so the enclave runs the same
# issuance path it runs against Let's Encrypt: directory, account, order,
# TLS-ALPN-01 challenge, finalize, and a certificate sealed into the cache.
#
# `--network host` because two things must reach it: the enclave, which dials
# gvproxy's host address 192.168.127.254:14000, and this script on loopback.
# `--add-host` is what makes the challenge work — Pebble resolves the
# identifier `enclave.test` to the loopback address where gvproxy forwards
# :443 into the enclave, so validation arrives on the port the service uses.
#
# Two knobs are turned off because they exist to make clients prove they retry,
# and a flaky CA here would read as a flaky runtime: PEBBLE_VA_NOSLEEP skips a
# random pre-validation delay, PEBBLE_WFE_NONCEREJECT the deliberate 5% bad
# nonce. rustls-acme handles both; this harness is not the place to find out.
say "starting Pebble, the ACME test CA"
docker rm -f e2e-pebble >/dev/null 2>&1 || true
cat > "$RUNDIR/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "/pebble/cert.pem",
    "privateKey": "/pebble/key.pem",
    "httpPort": 80,
    "tlsPort": $HTTPS_PORT,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF
docker run -d --rm --name e2e-pebble \
    --network host \
    --add-host "enclave.test:127.0.0.1" \
    -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$REPO/deploy/qemu-nitro/pebble:/pebble:ro" \
    -v "$RUNDIR/pebble-config.json:/pebble-config.json:ro" \
    "$PEBBLE_IMAGE" -config /pebble-config.json >/dev/null \
    || { echo "Pebble did not start" >&2; exit 1; }

for _ in $(seq "$TIMEOUT"); do
    curl -sk --max-time 2 "https://127.0.0.1:14000/dir" >/dev/null 2>&1 && break
    sleep 1
done
curl -sk --max-time 5 "https://127.0.0.1:14000/dir" >/dev/null 2>&1 \
    || { echo "Pebble never answered:" >&2; docker logs e2e-pebble 2>&1 | tail -20 >&2; exit 1; }
echo "Pebble serving its directory on :14000, validating :$HTTPS_PORT"

# Before the enclave boots, not after. The enclave starts its ACME order as
# soon as it has a network, and the challenge is a connection *inbound* to
# :443 — so if this forward does not exist yet, the first order fails and the
# harness waits out a retry backoff for no reason.
say "forwarding :$HTTPS_PORT into the enclave"
curl -sf --unix-socket "$RUNDIR/network.sock" \
    http://localhost/services/forwarder/expose \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"local\":\":${HTTPS_PORT}\",\"remote\":\"192.168.127.2:443\"}" \
    || { echo "gvproxy refused to forward :$HTTPS_PORT" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Boot.
# ---------------------------------------------------------------------------
say "booting the enclave"

# /dev/kvm is handed to the container, but qemu still picks its own accelerator
# unless told; a silent fall back to TCG leaves the guest kernel unable to
# calibrate its TSC and the boot stalls there past any timeout. That is what
# made this harness fail roughly half its runs while the runtime under test was
# fine, so the accelerator is named rather than hoped for.
boot_enclave() {
    docker run --rm -d --name "$1" \
        --device /dev/kvm \
        --network none \
        -v "$EIF_DIR:/eif:ro" \
        -v "$RUNDIR:/run/vsock" \
        "$IMAGE" \
        qemu-system-x86_64 \
            -M nitro-enclave,vsock=chr0,id=e2e \
            -accel kvm -cpu host \
            -kernel /eif/s3fs-qemu.eif \
            -chardev socket,id=chr0,path=/run/vsock/vhost.socket \
            -m 3G -smp 2 -nographic -no-reboot >/dev/null
    docker logs -f "$1" > "$2" 2>&1 &
}
boot_enclave e2e-qemu "$CONSOLE"

# The runtime colourises its logs, so escape sequences land between a field
# name and its value — `addr<esc>[0m<esc>[2m=` — and a grep for "addr=" simply
# never matches. Everything that reads a console goes through this.
# Read through process substitution, never `plain | grep -q`. `grep -q` exits on
# its first match and closes the pipe; the `sed` upstream then dies of SIGPIPE,
# and under `set -o pipefail` that makes the whole pipeline report failure even
# though the pattern matched. It bites in proportion to how much of the file is
# left unread, so a pattern early in this console fails while a later one passes
# — which is exactly how it was found.
plain_of() { sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$1" 2>/dev/null; }
plain() { plain_of "$CONSOLE"; }

fail() {
    echo
    echo "FAIL: $*" >&2
    echo "--- console (last 40) ---" >&2; plain | tail -40 >&2
    echo "--- gvproxy ---" >&2;          tail -10 "$RUNDIR/gvproxy.log" >&2
    echo "--- heartbeat ---" >&2;        cat "$RUNDIR/heartbeat.log" >&2
    exit 1
}

# The enclave takes its address by DHCP from gvproxy, fetches and measures its
# guest, then mounts over the network before it listens, so this waits on the
# whole chain rather than on the boot alone.
wait_for_serving() {
    local ready=""
    for _ in $(seq "$TIMEOUT"); do
        # "serving " with the bound address, not the earlier "serving guest" —
        # that one is logged before the listener exists and racing it produces
        # a connection-refused that looks like a networking fault.
        if grep -qE "serving +addr=" <(plain); then ready=1; break; fi
        grep -qE "Kernel panic|failed to start the guest" <(plain) && fail "the enclave died during boot"
        sleep 1
    done
    [[ -n "$ready" ]] || fail "the enclave never started serving within ${TIMEOUT}s"
}
say "waiting for the enclave to come up"
wait_for_serving

plain | grep -E "enclave networking is up|guest measured into PCR16|mounted |serving +addr=" | tail -4

# Measured before anything asked for a key, and measured as the release build
# said it would be.
grep -q "pcr16=$EXPECTED_PCR16" <(plain) \
    || fail "the enclave did not report measuring the release guest into PCR16"

# Nothing answers HTTPS until an ACME order completes — directory, account,
# order, challenge, finalize — so this loop is the issuance path finishing, not
# just a process starting. On a later boot the sealed cache has the
# certificate already, and it answers at once.
wait_for_https() {
    local answered=""
    # Bounded by TIMEOUT rather than a literal: a full ACME order on a slow
    # machine is the longest wait here, and a fixed 90 was a CI-only failure
    # waiting to be discovered on a busy runner.
    for _ in $(seq "$TIMEOUT"); do
        if curl -sk --max-time 2 "https://127.0.0.1:$HTTPS_PORT/" >/dev/null 2>&1; then
            answered=yes
            break
        fi
        sleep 1
    done
    [[ -n "$answered" ]]
}
say "waiting for Pebble to issue the serving certificate"
wait_for_https || {
    echo "no certificate was ever issued; the ACME path did not complete" >&2
    echo "--- pebble ---" >&2;  docker logs e2e-pebble 2>&1 | tail -30 >&2
    echo "--- console ---" >&2; plain | grep -i acme | tail -30 >&2
    exit 1
}
echo "the enclave is serving a certificate it obtained over ACME"

# And it is genuinely the CA's, not something the enclave minted for itself.
# Pebble publishes the issuing chain on its management port, so this verifies
# the served chain against that root the way any PKI client would — which is
# the part a self-signed image could never test.
curl -sk --max-time 5 "https://127.0.0.1:15000/roots/0" > "$RUNDIR/pebble-root.pem" \
    || { echo "could not fetch Pebble's root" >&2; exit 1; }
curl -sk --max-time 5 "https://127.0.0.1:15000/intermediates/0" > "$RUNDIR/pebble-int.pem" \
    || { echo "could not fetch Pebble's intermediate" >&2; exit 1; }
echo | openssl s_client -connect "127.0.0.1:$HTTPS_PORT" -servername enclave.test -showcerts \
    2>/dev/null | sed -n '/BEGIN CERT/,/END CERT/p' > "$RUNDIR/served-chain.pem"
[[ -s "$RUNDIR/served-chain.pem" ]] || { echo "the enclave presented no certificate" >&2; exit 1; }

openssl verify -CAfile "$RUNDIR/pebble-root.pem" -untrusted "$RUNDIR/pebble-int.pem" \
    "$RUNDIR/served-chain.pem" \
    || { echo "the served certificate does not chain to the CA that issued it" >&2; exit 1; }

# The name, from the SAN rather than the subject: an ACME certificate carries
# no CN at all — identity lives in subjectAltName — so printing the subject
# would print an empty string and look like a bug.
names="$(openssl x509 -in "$RUNDIR/served-chain.pem" -noout -ext subjectAltName \
    | tail -n +2 | tr -d ' ')"
issuer="$(openssl x509 -in "$RUNDIR/served-chain.pem" -noout -issuer)"
echo "served for $names"
echo "issued by $issuer"
[[ "$names" == *enclave.test* ]] \
    || { echo "the certificate is not for enclave.test: $names" >&2; exit 1; }
[[ "$issuer" == *Pebble* ]] \
    || { echo "the certificate was not issued by Pebble: $issuer" >&2; exit 1; }

# ---------------------------------------------------------------------------
# The assertions.
# ---------------------------------------------------------------------------
say "1/8  the guest is unreachable without a passkey assertion"
# The rule, at the front because everything after it depends on it holding:
# nothing reaches the guest without a fresh assertion bound to that request.
#
# The nonce is sent so the *gate* is what refuses. Every request needs one,
# and it is checked before routing — so without it these would be 400s, and
# this leg would pass while proving nothing about the gate.
nonce() { openssl rand 20 | basenc --base64url | tr -d '='; }
for path in / /counter /memory; do
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 \
        -H "x-enclave-nonce: $(nonce)" \
        "https://127.0.0.1:$HTTPS_PORT$path")"
    [[ "$code" == "401" ]] \
        || fail "$path answered $code without an assertion; the gate is not wired up"
done
echo "unauthenticated requests refused: 401"

# And a request with no nonce at all never reaches the gate either.
code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 \
    "https://127.0.0.1:$HTTPS_PORT/counter")"
[[ "$code" == "400" ]] \
    || fail "a request with no nonce answered $code; it should be refused before routing"
echo "un-nonced requests refused: 400"

say "2/8  a passkey enrols and its signed requests reach the guest"
rm -f "$RUNDIR/alice.json" "$RUNDIR/bob.json"
signed enrol >/dev/null || fail "registration failed"

first="$(signed get --path /counter)" || fail "no answer from the guest"
second="$(signed get --path /counter)" || fail "no answer from the guest"
echo "counter: $first then $second"
[[ "${second//[^0-9]/}" -eq $(( ${first//[^0-9]/} + 1 )) ]] \
    || fail "the counter did not advance ($first → $second); writes are not reaching MinIO"

say "2b/8 signed requests drive a real amount of filesystem work"
# Two round trips to /counter prove the mount answers. They do not prove much
# about the filesystem underneath it, which is the part with a Merkle block
# store, encryption and a root record behind it.
#
# So: a spread of files written, read back, overwritten and read again, each one
# a separate signed interaction — which is also the only way this harness can
# exercise the store, since every request has to pass the gate. Enough to force
# real block allocation and rewriting; not so much that the ceremony cost
# dominates the run.
FILES=8
for i in $(seq 1 "$FILES"); do
    signed post --path "/files/work-$i.txt" --body "contents $i" >/dev/null \
        || fail "writing /files/work-$i.txt failed"
done
for i in $(seq 1 "$FILES"); do
    got="$(signed get --path "/files/work-$i.txt")" || fail "reading /files/work-$i.txt failed"
    [[ "$got" == "contents $i" ]] \
        || fail "/files/work-$i.txt read back as \"$got\""
done
# Overwriting in place is the case that rewrites blocks rather than appending
# new ones, and the one a copy-on-write store can get wrong while every fresh
# write still looks correct.
for i in $(seq 1 "$FILES"); do
    signed post --path "/files/work-$i.txt" --body "rewritten $i" >/dev/null \
        || fail "overwriting /files/work-$i.txt failed"
done
for i in $(seq 1 "$FILES"); do
    got="$(signed get --path "/files/work-$i.txt")" || fail "re-reading /files/work-$i.txt failed"
    [[ "$got" == "rewritten $i" ]] \
        || fail "/files/work-$i.txt kept a stale value \"$got\" after being overwritten"
done
echo "$FILES files written, read, overwritten and re-read through the gate"

say "3/8  the attestation binds this connection's certificate, runtime and guest"
# There is no attestation endpoint: the document rides on the `/auth/` exchange,
# in `x-enclave-attestation`. That is where a client identifies the enclave
# before approving anything, and it needs no credential — so this is the check a
# client makes on the connection it then goes on to use.
"$ATTEST" \
    --url "https://127.0.0.1:$HTTPS_PORT/auth/" \
    --unsigned-emulator \
    --pcr0 "$EXPECTED_PCR0" \
    --guest "$RUNDIR/guests/guest.wasm" \
    | tee "$RUNDIR/attest.log" \
    || fail "attestation verification failed"

grep -q "binding    the attested certificate" "$RUNDIR/attest.log" \
    || fail "the document did not bind the certificate this connection was served"

say "3b/8 a signed interaction verifies the enclave before it trusts it"
# The proof comes from the `/auth/` exchange, not from the guest's response:
# that exchange is where a client identifies the enclave, before it hands over
# an assertion and before the interaction runs. Guest responses deliberately
# carry no document — the client has pinned the certificate by then, and TLS
# proves the peer still holds its key.
#
# `--dump-proof` keeps the three things a verifier cannot recover afterwards:
# the document, the certificate that connection was served, and the nonce the
# request sent.
rm -rf "$RUNDIR/proof"
signed --dump-proof "$RUNDIR/proof" get --path /counter >/dev/null \
    || fail "the signed interaction failed"
[[ -s "$RUNDIR/proof/document.b64" ]] \
    || fail "the challenge exchange carried no attestation document"

"$ATTEST" \
    --document "$RUNDIR/proof/document.b64" \
    --peer-certificate "$RUNDIR/proof/certificate.der" \
    --nonce "$(cat "$RUNDIR/proof/nonce.hex")" \
    --unsigned-emulator \
    --pcr0 "$EXPECTED_PCR0" \
    --guest "$RUNDIR/guests/guest.wasm" \
    | tee "$RUNDIR/attest-guest.log" \
    || fail "the challenge exchange's document did not verify"

grep -q "binding    the attested certificate" "$RUNDIR/attest-guest.log" \
    || fail "the document did not bind that connection's certificate"

say "4/8  the attested PCR0 and PCR16 are the ones the builds produced"
# `nitro-attest --pcr0 --guest` already enforced both, so reaching here means
# they held. Printing them is what makes the claim checkable by eye rather than
# taken on trust from an exit code.
echo "PCR0  build:    $EXPECTED_PCR0"
echo "      attested: $(grep -oE '^PCR0 +[0-9a-f]+' "$RUNDIR/attest.log" | awk '{print $2}')"
echo "PCR16 release:  $EXPECTED_PCR16"
echo "      attested: $(grep -oE '^PCR16 +[0-9a-f]+' "$RUNDIR/attest.log" | awk '{print $2}')"

# ---------------------------------------------------------------------------
# 5/8 — one instance per tenant, and one approval per interaction.
# ---------------------------------------------------------------------------
say "5/8  a tenant keeps its instance, and no two tenants share one"

# `/memory` counts in the guest's linear memory and writes nowhere. What it
# answers is the whole per-tenant model in one number.
#
# The image runs with warm instances, so the *same* tenant asking twice must
# see the count rise — that is the instance being kept. A *different* tenant
# must see 1, because the boundary between two clients is a `Store` and not
# anything the guest does. An earlier version of this leg asserted the
# opposite, having been written before warm instances existed; it contradicted
# the image it was testing.
m1="$(signed get --path /memory)"
m2="$(signed get --path /memory)"
echo "alice memory: $m1 then $m2"
[[ "${m2//[^0-9]/}" -eq $(( ${m1//[^0-9]/} + 1 )) ]] \
    || fail "a tenant's instance was not kept between its requests ($m1, $m2)"

signed2 enrol >/dev/null || fail "the second registration failed"
b1="$(signed2 get --path /memory)"
echo "bob memory: $b1"
[[ "${b1//[^0-9]/}" -eq 1 ]] \
    || fail "a second tenant landed in the first tenant's instance ($b1)"

# And their storage is separate too: the same path, different contents.
signed  post --path /files/who.txt --body "alice" >/dev/null || fail "alice could not write"
signed2 post --path /files/who.txt --body "bob"   >/dev/null || fail "bob could not write"
a_sees="$(signed  get --path /files/who.txt)"
b_sees="$(signed2 get --path /files/who.txt)"
echo "alice reads: $a_sees / bob reads: $b_sees"
[[ "$a_sees" == "alice" && "$b_sees" == "bob" ]] \
    || fail "one tenant read another's file (alice=$a_sees bob=$b_sees)"

say "5b/8 an approval for one route does not authorize another"
# The property the interaction token exists for. A token names the interaction
# it was issued for — method, path and query — so spent on any other it is
# refused, and what it carried never reaches the filesystem.
#
# Captured whole and split here rather than piped through `head`: `head` exits
# after one line, and a client still writing the rest dies of SIGPIPE, which
# `pipefail` would report as this leg failing.
sub_out="$(signed substitute --approved /files/approved.txt \
        --sent /files/substituted.txt --body "substituted")"
sub="${sub_out%%$'\n'*}"
[[ "$sub" == "401" ]] || fail "a token was spent on a route it was not issued for (status $sub)"
if signed get --path /files/substituted.txt >/dev/null 2>&1; then
    fail "the substituted request reached the filesystem"
fi
echo "a token moved to another route was refused: 401, and nothing was written"

# ---------------------------------------------------------------------------
# 5c/8 — guest output, in a real enclave.
# ---------------------------------------------------------------------------
# The guest's stdout and stderr are no longer inherited: the runtime frames them
# into lines and emits them as its own structured events. Unit tests prove the
# framing and integration tests prove the wiring; only here is it running inside
# the enclave, on the console the parent actually reads.
#
# What matters is that guest text arrives *marked as guest text*. It is chosen
# by the guest, so it must never be mistakable for something the runtime said.
say "5c/8 guest output reaches the console tagged as untrusted"
signed get --path /log >/dev/null || fail "the guest refused to log"

# Wait for the guest's *last* line, not its first.
#
# `docker logs` fills this console asynchronously, so "some guest output has
# arrived" says nothing about the rest of it — and every assertion below is
# about a line the guest wrote later. Waiting on the first line and then
# grepping for the third is a race that passes on a quiet machine and fails on
# a busy one, which is how it was found.
#
# The unterminated tail is last: it is emitted when the stream object drops,
# after the response, and after stderr was flushed during the request. Once it
# is here, everything else already is.
tail_seen=""
for _ in $(seq "$TIMEOUT"); do
    grep -q 'guest_message="no trailing newline"' <(plain) && { tail_seen=1; break; }
    sleep 1
done
[[ -n "$tail_seen" ]] || fail "the guest's unterminated last line never arrived"

# Two guest writes joined into one line, and CRLF normalised.
grep -q 'guest_message="first line"' <(plain) \
    || fail "two guest writes were not joined into one line"
grep -q 'guest_message="windows"' <(plain) \
    || fail "CRLF was not normalised"
# A blank line the guest wrote is still a record.
grep -q 'guest_message=""' <(plain) \
    || fail "the guest's empty line was dropped"

# The distinction the design rests on, kept all the way to the console.
grep -q 'guest_stream="stdout".*guest_message="first line"' <(plain) \
    || fail "guest stdout was not tagged as stdout"
grep -q 'guest_stream="stderr".*guest_message="on stderr"' <(plain) \
    || fail "guest stderr was not tagged as stderr"

# Untrusted text must be *visibly* untrusted, not merely filterable. Runtime
# events name a module in this runtime; guest output names `guest`, and nothing
# a guest writes can change which target its line carries.
if plain | grep 'guest output' | grep -qv ' guest: guest output'; then
    echo "--- offending lines ---" >&2
    plain | grep 'guest output' | grep -v ' guest: guest output' | head -5 >&2
    fail "a guest line reached the console without the guest target"
fi
# Guest text is one quoted, escaped field value. It was not always: naming the
# field `message` collided with the event's own message and printed guest bytes
# bare in the structured part of the line, where `truncated=true` from a guest
# rendered as a field nobody set. This is that fix, held in place.
if plain | grep 'guest output' | grep -qvE 'guest_message="'; then
    fail "guest output reached the console outside a quoted field"
fi

grep -q 'enclave_runtime::' <(plain) \
    || fail "no runtime event carried a module target to be distinguished from"
if plain | grep 'enclave_runtime::' | grep -q ' guest: '; then
    fail "a runtime event carried the guest target"
fi

echo "guest output arrived framed, tagged by stream, and marked as guest"


# ---------------------------------------------------------------------------
# 6/8 — work that outlives the interaction that asked for it.
# ---------------------------------------------------------------------------
# Everything above is request and response: a client signs, the guest answers,
# and the approval is spent by the time the connection closes. Background work
# is the one place that shape does not hold. The assertion authorises an
# enqueue, and what it authorised runs later on the enclave's own schedule —
# with nobody signing anything at that moment, because there is no one there to
# sign. That is the whole of standing authority, and it is the part a
# request/response test cannot reach.
#
# Worth proving in an enclave rather than only in-process: the scheduler runs
# against the mounted filesystem and the per-tenant lock, and neither of those
# is what a unit test exercises.
say "6/8  work approved once runs later, without a second assertion"

# Enrolled first, or there is nobody to wake when the task finishes. This is an
# ordinary signed interaction: enrolling is interactive-only, so it could not
# have been done by the background work itself.
FCM_TOKEN="e2e-device:APA91bEnclaveRuntimeHarnessToken0123456789"
signed post --path /devices --body "$FCM_TOKEN" >/dev/null \
    || fail "enrolling a device was refused"
[[ "$(signed get --path /devices)" == "1" ]] \
    || fail "the device did not enrol"

signed post --path /tasks/e2e-job --body "scheduled work" >/dev/null \
    || fail "the scheduled task was refused"

# The work belongs to the passkey that asked for it. Bob holds a perfectly good
# credential and is still told there is no such task, because a task id is
# scoped to its tenant rather than being a name everyone shares.
if signed2 get --path /tasks/e2e-job >/dev/null 2>&1; then
    fail "a second tenant could see another tenant's task"
fi

# Polled, not slept on. The first occurrence is due immediately, but
# "immediately" still means a worker picking it up, instantiating the guest, and
# writing the result through the filesystem to MinIO.
completed=""
for _ in $(seq "$TIMEOUT"); do
    record="$(signed get --path /tasks/e2e-job)" || fail "the task record became unreadable"
    case "$(jq -r .status <<<"$record")" in
        completed) completed=1; break ;;
        failed)    fail "the scheduled task failed: $record" ;;
    esac
    sleep 1
done
[[ -n "$completed" ]] || fail "the scheduled task never ran within ${TIMEOUT}s"

# And it ran the work actually asked for, rather than merely reaching a terminal
# state. The result is the payload the guest echoed back, carried as bytes.
result="$(jq -r '.result | implode' <<<"$record")"
[[ "$result" == "scheduled work" ]] \
    || fail "the task completed but produced \"$result\""
echo "scheduled work ran for its owner alone, with no second assertion signed"

say "6b/8 the finished task woke its owner, and told Google nothing"
# The wake was raised inside `run-task`, by background work, with nobody signing
# anything at that moment — and it left the enclave as a *data-only* message.
#
# That absence is the property: an FCM payload crosses the parent instance and
# then Google, so a title or a body would disclose to both exactly what this
# enclave exists to keep from them. The app wakes and fetches the detail over
# its own attested connection.
recorded=""
for _ in $(seq "$TIMEOUT"); do
    [[ -s "$FCM_RECORD" ]] && { recorded=1; break; }
    sleep 1
done
[[ -n "$recorded" ]] || fail "the finished task never woke anybody"

wake="$(head -1 "$FCM_RECORD")"
echo "$wake" | jq -e '.message.notification == null' >/dev/null \
    || fail "the wake carried a notification block: $wake"
[[ "$(echo "$wake" | jq -r '.message.data.category')" == "task-done" ]] \
    || fail "unexpected category: $wake"
[[ "$(echo "$wake" | jq -r '.message.data.ref')" == "e2e-job" ]] \
    || fail "the wake did not name the task: $wake"
[[ "$(echo "$wake" | jq -r '.message.token')" == "$FCM_TOKEN" ]] \
    || fail "the wake went to a device nobody enrolled: $wake"
[[ "$(echo "$wake" | jq -r '.message.apns.payload.aps."content-available"')" == "1" ]] \
    || fail "the wake would not have woken an iOS app: $wake"

# And nothing a person would read went with it. The only strings in `data` are
# the two labels the guest chose and a schema version.
keys="$(echo "$wake" | jq -r '.message.data | keys | join(",")')"
[[ "$keys" == "category,ref,v" ]] || fail "the wake carried more than its labels: $keys"
echo "a data-only wake reached the enrolled device: category=task-done ref=e2e-job"

# ---------------------------------------------------------------------------
# 7/8 — the boot machine, across a restart.
# ---------------------------------------------------------------------------
# The first boot found an empty store and created a filesystem. That used to be
# what happened for *any* store that answered "nothing", including one whose
# contents had been hidden. The second boot has to recognise the state as its
# own and resume — which is only possible if the receipt the first boot wrote
# verifies against the state now present — and, running the same guest, find
# its pair record and write nothing.
say "7/8  a second boot resumes rather than starting over"

# `docker logs -f` fills the console file asynchronously, so a single grep can
# run before the line it is looking for has been written — the assertions above
# reach the enclave over the network and do not wait for its console. Poll,
# with a bound, the way the readiness check above already does.
genesis=""
for _ in $(seq "$TIMEOUT"); do
    grep -q 'mode=Genesis' <(plain) && { genesis=1; break; }
    sleep 1
done
[[ -n "$genesis" ]] || fail "the first boot should have been a genesis"
GENESIS_CONSOLE="$CONSOLE"

docker rm -f e2e-qemu >/dev/null 2>&1 || true
sleep 2

CONSOLE="$RUNDIR/console-resume.log"
boot_enclave e2e-qemu-resume "$CONSOLE"

resumed=""
for _ in $(seq "$TIMEOUT"); do
    grep -q "state origin established" <(plain) && { resumed=1; break; }
    grep -qE "Kernel panic|failed to start the guest" <(plain) && break
    sleep 1
done
[[ -n "$resumed" ]] || fail "the second boot never established a state origin"

plain | grep -E "state origin established" | tail -1
grep -q "mode=Resume" <(plain) \
    || fail "the second boot did not resume — it should not have created anything"
grep -q "pcr16=$EXPECTED_PCR16" <(plain) \
    || fail "the second boot did not measure the same guest"

# Same filesystem, same identity: the receipt names this state and no other.
first_root="$(plain_of "$GENESIS_CONSOLE" | grep -oE 'state_root=[0-9a-f]+' | head -1)"
second_root="$(plain | grep -oE 'state_root=[0-9a-f]+' | head -1)"
echo "genesis $first_root"
echo "resume  $second_root"
[[ "$first_root" == "$second_root" ]] \
    || fail "the state_root changed across a restart"

# ---------------------------------------------------------------------------
# 8/8 — a substituted guest.
# ---------------------------------------------------------------------------
# The parent controls the store the guest is fetched from, so it can replace the
# object. What it cannot do is make the replacement look like the approved
# guest: the enclave measures whatever arrives into PCR16 before anything asks
# for a key. That is shown here from both sides — the enclave records a runtime
# and guest this state has not held before, and a client pinning the approved
# guest refuses to talk to it.
#
# What this cannot show is KMS refusing it, which is the half that keeps the
# data out of reach. The emulator image uses the static key source, because KMS
# will not accept an unsigned document, so this enclave boots and serves. On
# hardware, under a policy pinning the approved PCR16, the same substitution
# gets no key and reads nothing.
say "8/8  a substituted guest is measured, recorded, and refused by a pinned client"
docker rm -f e2e-qemu-resume >/dev/null 2>&1 || true
upload_guest substitute.wasm
sleep 2

CONSOLE="$RUNDIR/console-substitute.log"
boot_enclave e2e-qemu-substitute "$CONSOLE"
wait_for_serving

grep -q "pcr16=$SUBSTITUTE_PCR16" <(plain) \
    || fail "the enclave did not measure the object it fetched into PCR16"
grep -q "mode=Upgrade" <(plain) \
    || fail "a guest this state had never held was not recorded as an upgrade"
wait_for_https || fail "the enclave running the substitute never answered HTTPS"

if "$ATTEST" --url "https://127.0.0.1:$HTTPS_PORT/auth/" --unsigned-emulator \
        --pcr0 "$EXPECTED_PCR0" --guest "$RUNDIR/guests/guest.wasm" \
        > "$RUNDIR/attest-substitute.log" 2>&1; then
    fail "a client pinning the approved guest accepted an enclave running another"
fi
grep -q "PCR16 mismatch" "$RUNDIR/attest-substitute.log" \
    || fail "the client refused, but not on PCR16: $(tail -1 "$RUNDIR/attest-substitute.log")"
echo "a client pinning the approved guest refused: PCR16 mismatch"

# And it is not hiding what it runs: pinned to the substitute, the same client
# accepts. The enclave attests the guest it fetched, whichever that was.
"$ATTEST" --url "https://127.0.0.1:$HTTPS_PORT/auth/" --unsigned-emulator \
    --pcr0 "$EXPECTED_PCR0" --guest "$RUNDIR/guests/substitute.wasm" \
    > "$RUNDIR/attest-substitute-pinned.log" \
    || fail "the enclave does not attest the guest it actually fetched"
echo "it attests the substitute it is running: PCR16 $SUBSTITUTE_PCR16"

docker rm -f e2e-qemu-substitute >/dev/null 2>&1 || true

cat <<EOF

== PASS ==
  filesystem mounted over vsock through gvproxy, writes durable in MinIO
  the serving certificate was obtained over real ACME and chains to the CA
  TLS terminated in the enclave, certificate hash bound into the document
  the document's PCR0 matches the reproducible build
  the guest was fetched from the store, measured into PCR16 and locked, and
    the attested PCR16 matches the release build
  the guest was unreachable without a passkey assertion
  a passkey enrolled and its signed requests were served
  an approval for one route did not authorize another
  a tenant kept its warm instance, and no two tenants shared one
  one tenant could not read another's file
  guest stdout and stderr arrived framed and marked as untrusted
  work approved by one interaction ran later, for its owner alone, with no
    second assertion signed
  that finished task woke an enrolled device with a data-only message that
    carried no title, no body and nothing a person would read
  genesis wrote an attested state origin, and a restart resumed it
  a substituted guest was measured and recorded as an upgrade, and a client
    pinning the approved guest refused it

Guest logging is proven only as far as the console, in leg 5c. The enclave can
also ship guest output to CloudWatch, and nothing here exercises that: this
harness has no AWS account and no route to one, so the log group is left unset
and no client is built. That hop needs a real deployment, like the KMS path.

NOT proven here. QEMU's emulated NSM does not sign attestation documents, so
no signature and no certificate chain were checked — only the contents the
runtime asked for. A document from this harness is worth what the connection
it arrived over is worth. The signature path needs real Nitro hardware, and so
does KMS refusing the key to a substituted guest.
EOF
