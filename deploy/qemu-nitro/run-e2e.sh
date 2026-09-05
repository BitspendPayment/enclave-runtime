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
    docker rm -f e2e-minio e2e-qemu e2e-qemu-resume >/dev/null 2>&1 || true
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

# Built with the host's cargo rather than Nix. The verifier is a client-side
# tool that nothing attests, so it gains nothing from a reproducible build —
# and a Nix-built dynamic binary links against a glibc in the Nix store, which
# will not run on a machine that has no such store path. Only what goes
# *inside* the enclave has to come from Nix.
say "building the verifier"
( cd "$REPO" && cargo build --release -p nitro-attestation --features cli ) 2>&1 | tail -2
ATTEST="$REPO/target/release/nitro-attest"
[[ -x "$ATTEST" ]] || { echo "nitro-attest did not build" >&2; exit 1; }

# The client half of the WebAuthn gate. Nothing reaches the guest without a
# fresh assertion bound to that exact request, and a shell script cannot sign
# one — so the harness drives the gate with a software passkey.
( cd "$REPO" && cargo build --release -p enclave-runtime --features testing \
    --bin passkey-client ) 2>&1 | tail -2
PASSKEY="$REPO/target/release/passkey-client"
[[ -x "$PASSKEY" ]] || { echo "passkey-client did not build" >&2; exit 1; }
# Must match S3FS_ENROLLMENT_TOKEN in the emulator image.
ENROLLMENT_TOKEN="qemu-e2e-enrollment-token"
ENROLLMENT_TOKEN_2="qemu-e2e-enrollment-token-2"
# Two identities, each with its own passkey file, so the harness can show that
# one tenant cannot see another's data.
signed()  { "$PASSKEY" --url "https://127.0.0.1:$HTTPS_PORT" --state "$RUNDIR/alice.json" "$@"; }
signed2() { "$PASSKEY" --url "https://127.0.0.1:$HTTPS_PORT" --state "$RUNDIR/bob.json"   "$@"; }

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

# /dev/kvm is handed to the container, but qemu still picks its own accelerator
# unless told; a silent fall back to TCG leaves the guest kernel unable to
# calibrate its TSC and the boot stalls there past any timeout. That is what
# made this harness fail roughly half its runs while the runtime under test was
# fine, so the accelerator is named rather than hoped for.
docker run --rm -d --name e2e-qemu \
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
docker logs -f e2e-qemu > "$CONSOLE" 2>&1 &

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
    if grep -qE "serving +addr=" <(plain); then ready=1; break; fi
    grep -qE "Kernel panic|failed to start the guest" <(plain) && fail "the enclave died during boot"
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
say "1/7  the guest is unreachable without a passkey assertion"
# The rule, at the front because everything after it depends on it holding:
# nothing reaches the guest without a fresh assertion bound to that request.
for path in / /counter /memory; do
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 \
        "https://127.0.0.1:$HTTPS_PORT$path")"
    [[ "$code" == "401" ]] \
        || fail "$path answered $code without an assertion; the gate is not wired up"
done
echo "unauthenticated requests refused: 401"

say "2/7  a passkey enrols and its signed requests reach the guest"
rm -f "$RUNDIR/alice.json" "$RUNDIR/bob.json"
signed enrol --token "$ENROLLMENT_TOKEN" >/dev/null \
    || fail "enrollment failed; is S3FS_ENROLLMENT_TOKEN set in the image?"

first="$(signed get --path /counter)" || fail "no answer from the guest"
second="$(signed get --path /counter)" || fail "no answer from the guest"
echo "counter: $first then $second"
[[ "${second//[^0-9]/}" -eq $(( ${first//[^0-9]/} + 1 )) ]] \
    || fail "the counter did not advance ($first → $second); writes are not reaching MinIO"

say "3/7  the attestation binds this connection's certificate"
"$ATTEST" \
    --url "https://127.0.0.1:$HTTPS_PORT/enclave/attestation" \
    --unsigned-emulator \
    --pcr0 "$EXPECTED_PCR0" \
    | tee "$RUNDIR/attest.log" \
    || fail "attestation verification failed"

grep -q "binding    the attested certificate" "$RUNDIR/attest.log" \
    || fail "the document did not bind the certificate this connection was served"

say "4/7  the attested PCR0 is the one the build produced"
# `nitro-attest --pcr0` already enforced this, so reaching here means it held.
# Printing both is what makes the claim checkable by eye rather than taken on
# trust from an exit code.
echo "build:    $EXPECTED_PCR0"
echo "attested: $(grep -oE '^PCR0 +[0-9a-f]+' "$RUNDIR/attest.log" | awk '{print $2}')"

# ---------------------------------------------------------------------------
# 5/6 — one instance per request, and one approval per operation.
# ---------------------------------------------------------------------------
say "5/7  a tenant keeps its instance, and no two tenants share one"

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

signed2 enrol --token "$ENROLLMENT_TOKEN_2" >/dev/null \
    || fail "the second enrollment failed"
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

say "5b/7 an approval for one payload does not authorize another"
# The property the whole binding exists for. An assertion issued for one body,
# sent with a different one, must be refused — and the substituted body must
# never reach the filesystem.
sub="$(signed substitute --path /files/e2e.txt \
        --approved "approved" --sent "substituted" | head -1)"
[[ "$sub" == "401" ]] || fail "a substituted body was authorized (status $sub)"
if signed get --path /files/e2e.txt >/dev/null 2>&1; then
    fail "the substituted body reached the filesystem"
fi
echo "substituted body refused: 401, and nothing was written"

# ---------------------------------------------------------------------------
# 5c/7 — guest output, in a real enclave.
# ---------------------------------------------------------------------------
# The guest's stdout and stderr are no longer inherited: the runtime frames them
# into lines and emits them as its own structured events. Unit tests prove the
# framing and integration tests prove the wiring; only here is it running inside
# the enclave, on the console the parent actually reads.
#
# What matters is that guest text arrives *marked as guest text*. It is chosen
# by the guest, so it must never be mistakable for something the runtime said.
say "5c/7 guest output reaches the console tagged as untrusted"
signed get --path /log >/dev/null || fail "the guest refused to log"

for _ in $(seq 30); do
    grep -q 'guest output' <(plain) && break
    sleep 1
done

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

# The guest's last line had no terminator. It is emitted when the stream object
# is dropped, which is a moment or two after the response — so this polls
# rather than assuming, the same way the readiness check does.
tail_seen=""
for _ in $(seq 30); do
    grep -q 'guest_message="no trailing newline"' <(plain) && { tail_seen=1; break; }
    sleep 1
done
[[ -n "$tail_seen" ]] || fail "the guest's unterminated last line never arrived"

echo "guest output arrived framed, tagged by stream, and marked as guest"


# ---------------------------------------------------------------------------
# 6/6 — the boot machine, across a restart.
# ---------------------------------------------------------------------------
# The first boot found an empty store and created a filesystem. That used to be
# what happened for *any* store that answered "nothing", including one whose
# contents had been hidden. The second boot has to recognise the state as its
# own and resume — which is only possible if the receipt the first boot wrote
# verifies against the state now present.
say "6/7  a second boot resumes rather than starting over"

# `docker logs -f` fills the console file asynchronously, so a single grep can
# run before the line it is looking for has been written — the assertions above
# reach the enclave over the network and do not wait for its console. Poll,
# with a bound, the way the readiness check above already does.
genesis=""
for _ in $(seq 60); do
    grep -q 'mode=Genesis' <(plain) && { genesis=1; break; }
    sleep 1
done
[[ -n "$genesis" ]] || fail "the first boot should have been a genesis"

docker rm -f e2e-qemu >/dev/null 2>&1 || true
sleep 2

RESUME_CONSOLE="$RUNDIR/console-resume.log"
docker run --rm -d --name e2e-qemu-resume \
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
docker logs -f e2e-qemu-resume > "$RESUME_CONSOLE" 2>&1 &

resumed=""
for _ in $(seq "$TIMEOUT"); do
    grep -q "state origin established" <(plain_of "$RESUME_CONSOLE") && { resumed=1; break; }
    grep -qE "Kernel panic|failed to start the guest" <(plain_of "$RESUME_CONSOLE") && break
    sleep 1
done
if [[ -z "$resumed" ]]; then
    echo "FAIL: the second boot never established a state origin" >&2
    plain_of "$RESUME_CONSOLE" | tail -25 >&2
    docker rm -f e2e-qemu-resume >/dev/null 2>&1 || true
    exit 1
fi

plain_of "$RESUME_CONSOLE" | grep -E "state origin established" | tail -1
if ! grep -q "mode=Resume" <(plain_of "$RESUME_CONSOLE"); then
    echo "FAIL: the second boot did not resume — it should not have created anything" >&2
    plain_of "$RESUME_CONSOLE" | grep -E "mode=|refus" | tail -5 >&2
    docker rm -f e2e-qemu-resume >/dev/null 2>&1 || true
    exit 1
fi

# Same filesystem, same identity: the receipt names this state and no other.
first_root="$(plain | grep -oE 'state_root=[0-9a-f]+' | head -1)"
second_root="$(plain_of "$RESUME_CONSOLE" | grep -oE 'state_root=[0-9a-f]+' | head -1)"
echo "genesis $first_root"
echo "resume  $second_root"
[[ "$first_root" == "$second_root" ]] \
    || { echo "FAIL: the state_root changed across a restart" >&2; exit 1; }

docker rm -f e2e-qemu-resume >/dev/null 2>&1 || true
docker rm -f e2e-qemu >/dev/null 2>&1 || true

cat <<EOF

== PASS ==
  filesystem mounted over vsock through gvproxy, writes durable in MinIO
  TLS terminated in the enclave, certificate hash bound into the document
  the document's PCR0 matches the reproducible build
  the guest was unreachable without a passkey assertion
  a passkey enrolled and its signed requests were served
  an approval for one payload did not authorize another
  a tenant kept its warm instance, and no two tenants shared one
  one tenant could not read another's file
  guest stdout and stderr arrived framed and marked as untrusted
  genesis wrote an attested state origin, and a restart resumed it

Guest logging is proven only as far as the console, in leg 5c. The enclave can
also ship guest output to CloudWatch, and nothing here exercises that: this
harness has no AWS account and no route to one, so the log group is left unset
and no client is built. That hop needs a real deployment, like the KMS path.

NOT proven here. QEMU's emulated NSM does not sign attestation documents, so
no signature and no certificate chain were checked — only the contents the
runtime asked for. A document from this harness is worth what the connection
it arrived over is worth. The signature path needs real Nitro hardware.
EOF
