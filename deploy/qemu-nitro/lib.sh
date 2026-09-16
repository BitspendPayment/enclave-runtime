# Standing up the whole stack in an emulated enclave.
#
# Sourced, never run. Two things need this and they need exactly the same
# thing: `run-e2e.sh`, which brings the stack up and then asserts against it,
# and `dev-enclave.sh`, which brings it up and leaves it running for somebody to
# develop a client against. Every difference between them belongs after the
# enclave is serving, so everything before that lives here.
#
#   host                                        QEMU enclave
#   ────                                        ────────────
#   MinIO :9000 ◀── gvproxy ──192.168.127.254──  s3fs mount, and the guest
#   gvproxy --listen vsock://:1024 ────────────▶ gvforwarder → tap0 .2
#           expose :8443 → 192.168.127.2:443 ──▶ rustls :443
#   vhost-device-vsock --forward-cid 1
#   heartbeat.py :9000  ───────────────────────▶ init's boot heartbeat
#   Pebble :14000 ◀────────────────────────────  ACME order, TLS-ALPN-01
#
# ---------------------------------------------------------------------------
# What a caller sets before sourcing, all optional:
#
#   PREFIX        names the run: $WORK/$PREFIX, and every container and docker
#                 label. Default `e2e`. It keeps two runs' files and containers
#                 apart; it does not let them run at the same time, because
#                 MinIO's :9000, the FCM stub's :9101 and the enclave's vsock CID
#                 are fixed — the last two by the image, which dials them.
#   HTTPS_PORT    host port gvproxy forwards to the enclave's :443, and the
#                 port Pebble validates against. Default 8443.
#   GUEST_WASM    a component to serve instead of the one Nix builds. This is
#                 what makes the emulator useful to somebody else's guest.
#   WITH_SUBSTITUTE  also stage a second, altered guest, for a caller that
#                 wants to show what happens when the object is replaced.
#   TIMEOUT       seconds for each wait. Default 240.
#
# What it gets back, after `enclave_bring_up`:
#
#   EXPECTED_PCR0 / EXPECTED_PCR16   what the builds said the measurements are
#   TRUST_ROOT                       DER the enclave's documents chain to
#   ATTEST / PASSKEY                 client binaries, built here
#   PASSKEY_ARGS                     the trust flags both clients need
#   signed / signed2                 two identities, each with its own passkey
#   CONSOLE, RUNDIR, plain, fail, say, nonce, boot_enclave, upload_guest,
#   wait_for_serving, wait_for_https
# ---------------------------------------------------------------------------

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${WORK:-$REPO/target/qemu-nitro}"
PREFIX="${PREFIX:-e2e}"
RUNDIR="${RUNDIR:-$WORK/$PREFIX}"
IMAGE="${QEMU_IMAGE:-s3fs-qemu-nitro:latest}"
TIMEOUT="${TIMEOUT:-240}"
CONSOLE="$RUNDIR/console.log"

# Host-side port that gvproxy forwards into the enclave's :443. Pebble also
# validates the TLS-ALPN-01 challenge against it, so it is both the service
# port and the challenge port — as it is in production, where both are 443.
HTTPS_PORT="${HTTPS_PORT:-8443}"

# The ACME test CA. Pinned by digest: this image supplies the issuance path the
# harness claims to exercise, and "latest" would let that change under us.
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199}"

# Every container this run creates carries it, so cleanup can find them without
# a hard-coded list that the next container to be added would not appear in.
LABEL="enclave-harness=$PREFIX"

# These do *not* follow PREFIX, and must not. They are baked into the emulator
# image as S3FS_BUCKET and S3FS_ROOTS_BUCKET (flake.nix, `eif-qemu`), which
# means they are covered by PCR0 — an enclave image is its configuration as much
# as its code. A run that named its buckets after itself would stand up a store
# the enclave does not look in, and the enclave would fail at mount with
# "connecting to the data bucket: not found".
DATA_BUCKET=e2e-data
ROOTS_BUCKET=e2e-roots

say() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
# Preconditions, each with the fix rather than just the symptom.
# ---------------------------------------------------------------------------
enclave_preflight() {
    command -v nix >/dev/null || {
        echo "nix is not on PATH; see deploy/nix/README.md" >&2; exit 1; }

    # Flakes copy only what git tracks, so an untracked file is invisible to the
    # build no matter that it is right there on disk. The failure lands deep
    # inside the EIF derivation as a bare "cp: cannot stat", naming a store path
    # that does not contain it — true, and useless. Checked here instead.
    local f
    for f in pebble/ca.pem pebble/cert.pem pebble/key.pem fcm/service-account.json; do
        git -C "$REPO" ls-files --error-unmatch "deploy/qemu-nitro/$f" >/dev/null 2>&1 || {
            echo "deploy/qemu-nitro/$f is not tracked by git, so nix cannot see it." >&2
            echo "  git add deploy/qemu-nitro/" >&2
            exit 1
        }
    done

    # And the general case, which cost twenty minutes to learn: a *source* file
    # that git does not track is invisible to the build no matter that the
    # workspace compiles here. A new module declared in lib.rs and never added
    # fails as `file not found for module`, from a sandbox, after everything
    # before it has been rebuilt. Caught in a second instead.
    #
    # Scoped to the trees that feed the image, and to the extensions whose
    # absence breaks resolution rather than merely losing a file: a stray
    # untracked note somewhere should not stop a run, and an untracked module,
    # crate manifest, WIT package or flake input always should.
    local untracked
    untracked="$(git -C "$REPO" ls-files --others --exclude-standard \
        -- 'runtime/**/*.rs'   'runtime/**/*.toml' \
           'crates/**/*.rs'    'crates/**/*.toml' \
           'examples/**/*.rs'  'examples/**/*.toml' \
           '**/*.wit'          '**/*.nix' 2>/dev/null || true)"
    if [[ -n "$untracked" ]]; then
        echo "these source files are not tracked by git, so nix will not see them:" >&2
        echo "$untracked" | sed 's/^/  /' >&2
        echo "  git add <them>, or remove them" >&2
        exit 1
    fi
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
    [[ -x "$VSOCK_BIN" ]] || {
        echo "missing $VSOCK_BIN (cargo install vhost-device-vsock --root $WORK/tools)" >&2
        exit 1
    }

    # Checked immediately before the `rm -rf`, because RUNDIR is overridable and
    # this is the one line here that destroys something. `$WORK/` with an empty
    # PREFIX, or an exported RUNDIR pointing anywhere else, would take the tools
    # installed under target/qemu-nitro with it — or worse.
    case "$RUNDIR" in
        "$WORK"/?*) ;;
        *)
            echo "refusing to clear $RUNDIR: it must be a directory under $WORK" >&2
            exit 1
            ;;
    esac
    [[ "$RUNDIR" != *..* ]] || { echo "refusing to clear $RUNDIR: it contains .." >&2; exit 1; }

    rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"
}

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
    # By label, not by name. A name list has to be kept in step with every
    # container the harness learns to start, and the one that gets forgotten is
    # the one left running.
    local stragglers
    stragglers="$(docker ps -aq --filter "label=$LABEL" 2>/dev/null || true)"
    if [[ -n "$stragglers" ]]; then
        # shellcheck disable=SC2086
        docker rm -f $stragglers >/dev/null 2>&1 || true
    fi
    return 0
}

# ---------------------------------------------------------------------------
# The image, the guest, and the measurements they claim.
# ---------------------------------------------------------------------------

# nix-portable keeps its store outside /nix except inside its own namespace, so
# `result/` may not resolve. Ask nix for the path and translate it if the
# symlink is dangling — on a machine with a normal Nix install the first branch
# is always the one taken.
resolve_out_link() {
    local link="$1" dir
    dir="$(readlink -f "$link" 2>/dev/null || true)"
    if [[ ! -d "$dir" ]]; then
        dir="$HOME/.nix-portable$(readlink "$link")"
    fi
    [[ -d "$dir" ]] || { echo "cannot resolve $link" >&2; exit 1; }
    printf '%s' "$dir"
}

# `| tail -3` on the build, which is what this replaces, kept the last three
# lines of a nix log — which on failure are the derivation summary and not the
# compiler error forty lines above it. The log is kept whole and only the tail
# shown, so a failure can say what actually went wrong.
nix_build() {
    local attr="$1" link="$2" log="$RUNDIR/nix-${1//[^a-zA-Z0-9]/-}.log"
    if ! nix build "$REPO#$attr" --out-link "$link" --print-build-logs > "$log" 2>&1; then
        echo "nix build of $attr failed:" >&2
        grep -E 'error(\[|:)' "$log" | head -20 >&2 || true
        echo "  full log: $log" >&2
        exit 1
    fi
    tail -3 "$log"
}

nix_expr() {
    local what="$1" link="$2" expr="$3" log="$RUNDIR/nix-eif-qemu.log"
    if ! nix build --impure --expr "$expr" --out-link "$link" --print-build-logs > "$log" 2>&1; then
        echo "nix build of $what failed:" >&2
        grep -E 'error(\[|:)' "$log" | head -20 >&2 || true
        echo "  full log: $log" >&2
        exit 1
    fi
    tail -3 "$log"
}

enclave_build_image() {
    say "building the enclave image"
    if [[ -n "${WEBAUTHN_RP_ID:-}" ]]; then
        # The same image with another relying party. Not a package — flake outputs take no
        # arguments — so the flake's `lib.eifQemu` is called directly, which reading the flake by
        # path needs --impure for. dev-enclave.sh has already held both values to shapes that
        # cannot break out of the string.
        local origins="" o
        IFS=, read -ra list <<<"${WEBAUTHN_ALLOWED_ORIGINS:-}"
        for o in "${list[@]}"; do origins+=" \"$o\""; done
        nix_expr "eif-qemu for $WEBAUTHN_RP_ID" "$RUNDIR/eif" \
            "((builtins.getFlake \"git+file://$REPO\").lib.\${builtins.currentSystem}.eifQemu { rpId = \"$WEBAUTHN_RP_ID\"; allowedOrigins = [$origins ]; })"
    else
        nix_build eif-qemu "$RUNDIR/eif"
    fi
    EIF_DIR="$(resolve_out_link "$RUNDIR/eif")"
    EIF="$EIF_DIR/s3fs-qemu.eif"
    EXPECTED_PCR0="$(jq -r .PCR0 "$EIF_DIR/pcr.json")"
    echo "EIF   $EIF ($(du -h "$EIF" | cut -f1))"
    echo "PCR0  $EXPECTED_PCR0"
}

# The guest is not in the image. It is uploaded to the store and the enclave
# measures what it fetches into PCR16 — so the build says what PCR16 should be,
# the same way `pcr.json` says what PCR0 should be.
enclave_build_guest() {
    mkdir -p "$RUNDIR/guests"
    if [[ -n "${GUEST_WASM:-}" ]]; then
        # Somebody else's component. Nothing claims what it measures to, so the
        # measurement comes from the verifier below rather than from a build.
        say "staging the guest"
        [[ -f "$GUEST_WASM" ]] || { echo "no such component: $GUEST_WASM" >&2; exit 1; }
        install -m 0644 "$GUEST_WASM" "$RUNDIR/guests/guest.wasm"
        echo "guest $GUEST_WASM ($(du -h "$GUEST_WASM" | cut -f1))"
    else
        say "building the guest release"
        nix_build guest-release "$RUNDIR/guest"
        GUEST_DIR="$(resolve_out_link "$RUNDIR/guest")"
        EXPECTED_PCR16="$(jq -r .PCR16 "$GUEST_DIR/guest-pcr16.json")"
        install -m 0644 "$GUEST_DIR/guest.wasm" "$RUNDIR/guests/guest.wasm"
        echo "PCR16 $EXPECTED_PCR16"
    fi

    if [[ -n "${WITH_SUBSTITUTE:-}" ]]; then
        # A second guest differing from the first only by an appended custom
        # section: a valid component with a different hash, which is all a
        # substituted object needs to be.
        install -m 0644 "$RUNDIR/guests/guest.wasm" "$RUNDIR/guests/substitute.wasm"
        printf '\x00\x0b\x0asubstitute' >> "$RUNDIR/guests/substitute.wasm"
    fi
}

# Built with the host's cargo rather than Nix. These are client-side tools that
# nothing attests, so they gain nothing from a reproducible build — and a
# Nix-built dynamic binary links against a glibc in the Nix store, which will
# not run on a machine that has no such store path. Only what goes *inside* the
# enclave has to come from Nix.
enclave_build_clients() {
    say "building the verifier"
    ( cd "$REPO" && cargo build --release -p nitro-attestation --features cli ) 2>&1 | tail -2
    ATTEST="$REPO/target/release/nitro-attest"
    [[ -x "$ATTEST" ]] || { echo "nitro-attest did not build" >&2; exit 1; }

    if [[ -n "${EXPECTED_PCR16:-}" ]]; then
        # The release build measured the guest with a Nix-built nitro-attest;
        # this one was built here. They must agree, or a key policy and a client
        # would pin different numbers for the same guest.
        [[ "$("$ATTEST" --measure "$RUNDIR/guests/guest.wasm" | jq -r .PCR16)" == "$EXPECTED_PCR16" ]] \
            || { echo "the release build and this verifier disagree about the guest's PCR16" >&2; exit 1; }
    else
        EXPECTED_PCR16="$("$ATTEST" --measure "$RUNDIR/guests/guest.wasm" | jq -r .PCR16)"
        echo "PCR16 $EXPECTED_PCR16"
    fi

    if [[ -n "${WITH_SUBSTITUTE:-}" ]]; then
        SUBSTITUTE_PCR16="$("$ATTEST" --measure "$RUNDIR/guests/substitute.wasm" | jq -r .PCR16)"
        [[ "$SUBSTITUTE_PCR16" != "$EXPECTED_PCR16" ]] \
            || { echo "the substitute guest measures the same as the real one" >&2; exit 1; }
    fi

    # The client half of the WebAuthn gate. Nothing reaches the guest without a
    # fresh assertion bound to that exact request, and a shell script cannot
    # sign one — so the harness drives the gate with a software passkey.
    ( cd "$REPO" && cargo build --release -p enclave-runtime --features testing \
        --bin passkey-client ) 2>&1 | tail -2
    PASSKEY="$REPO/target/release/passkey-client"
    [[ -x "$PASSKEY" ]] || { echo "passkey-client did not build" >&2; exit 1; }
}

# Two identities, each with its own passkey file, so a caller can show that one
# tenant cannot see another's data.
#
# `PASSKEY_ARGS` is empty until the enclave has booted and reported the root its
# documents chain to — see `enclave_trust_root`. Both functions read it at call
# time for that reason, and because each reboot mints a new chain.
signed()  { "$PASSKEY" --url "https://127.0.0.1:$HTTPS_PORT" --state "$RUNDIR/alice.json" "${PASSKEY_ARGS[@]}" "$@"; }
signed2() { "$PASSKEY" --url "https://127.0.0.1:$HTTPS_PORT" --state "$RUNDIR/bob.json"   "${PASSKEY_ARGS[@]}" "$@"; }

# ---------------------------------------------------------------------------
# The store the enclave will mount, and the guest it will fetch.
# ---------------------------------------------------------------------------
enclave_start_store() {
    say "starting MinIO"
    # The same recipe the SQLite CI job used. It lived in run-e2e.sh in full
    # until both copies had to agree with nothing making them agree.
    MINIO_LABEL="$LABEL" "$REPO/scripts/minio-up.sh" \
        "$PREFIX-minio" 9000 "$DATA_BUCKET" "$ROOTS_BUCKET"
    upload_guest guest.wasm
    echo "MinIO ready with $DATA_BUCKET and $ROOTS_BUCKET, and the guest at $ROOTS_BUCKET/guest/guest.wasm"
}

# Where the emulator image looks: `deployment.guestObject` in the roots bucket.
upload_guest() {
    docker run --rm --network host --label "$LABEL" -v "$RUNDIR/guests:/guests:ro" \
        --entrypoint sh minio/mc -c "
        mc alias set m http://127.0.0.1:9000 minioadmin minioadmin >/dev/null
        mc cp /guests/$1 m/$ROOTS_BUCKET/guest/guest.wasm >/dev/null" >/dev/null \
        || { echo "could not upload $1 to the store" >&2; exit 1; }
}

# ---------------------------------------------------------------------------
# The parent side: heartbeat, notifications, vsock transport, and the network.
# ---------------------------------------------------------------------------
enclave_start_parent() {
    say "starting the parent-side services"

    # init writes 0xB7 to the parent on port 9000 and waits. Unanswered, the
    # kernel boots and then nothing happens at all.
    python3 "$REPO/deploy/qemu-nitro/heartbeat.py" 9000 > "$RUNDIR/heartbeat.log" 2>&1 &
    pids+=($!)

    # Firebase is not reachable from here and would refuse an invented
    # registration token if it were. The stub answers the two endpoints the
    # runtime calls and records every message, so a caller can assert on what
    # the runtime *sent*.
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
    [[ -S "$RUNDIR/vhost.socket" ]] \
        || { echo "vhost-device-vsock never came up:" >&2; cat "$RUNDIR/vsock.log" >&2; exit 1; }

    # The enclave's only route to anything. Without it the runtime waits for the
    # gateway and then says so.
    #
    # The same pin as the gvforwarder inside the image, and built static for the
    # same reason: it has to run here, and later on Amazon Linux, neither of
    # which has a Nix store.
    nix_build gvproxy "$RUNDIR/gvproxy" >/dev/null
    GV_DIR="$(resolve_out_link "$RUNDIR/gvproxy")"

    "$GV_DIR/bin/gvproxy" \
        --listen "vsock://:1024" \
        --listen "unix://$RUNDIR/network.sock" \
        > "$RUNDIR/gvproxy.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 50); do [[ -S "$RUNDIR/network.sock" ]] && break; sleep 0.1; done
    [[ -S "$RUNDIR/network.sock" ]] \
        || { echo "gvproxy never opened its API socket:" >&2; cat "$RUNDIR/gvproxy.log" >&2; exit 1; }
    echo "gvproxy listening on host vsock port 1024"
}

# The CA. Pebble is a real RFC 8555 server, so the enclave runs the same
# issuance path it runs against Let's Encrypt: directory, account, order,
# TLS-ALPN-01 challenge, finalize, and a certificate sealed into the cache.
#
# `--network host` because two things must reach it: the enclave, which dials
# gvproxy's host address 192.168.127.254:14000, and this script on loopback.
# `--add-host` is what makes the challenge work — Pebble resolves the identifier
# `enclave.test` to the loopback address where gvproxy forwards :443 into the
# enclave, so validation arrives on the port the service uses.
#
# Two knobs are turned off because they exist to make clients prove they retry,
# and a flaky CA here would read as a flaky runtime: PEBBLE_VA_NOSLEEP skips a
# random pre-validation delay, PEBBLE_WFE_NONCEREJECT the deliberate 5% bad
# nonce. rustls-acme handles both; this harness is not the place to find out.
enclave_start_ca() {
    say "starting Pebble, the ACME test CA"
    docker rm -f "$PREFIX-pebble" >/dev/null 2>&1 || true
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
    docker run -d --rm --name "$PREFIX-pebble" --label "$LABEL" \
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
        || { echo "Pebble never answered:" >&2; docker logs "$PREFIX-pebble" 2>&1 | tail -20 >&2; exit 1; }
    echo "Pebble serving its directory on :14000, validating :$HTTPS_PORT"
}

# Before the enclave boots, not after. The enclave starts its ACME order as soon
# as it has a network, and the challenge is a connection *inbound* to :443 — so
# if this forward does not exist yet, the first order fails and the harness
# waits out a retry backoff for no reason.
enclave_expose_https() {
    say "forwarding :$HTTPS_PORT into the enclave"
    curl -sf --unix-socket "$RUNDIR/network.sock" \
        http://localhost/services/forwarder/expose \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"local\":\":${HTTPS_PORT}\",\"remote\":\"192.168.127.2:443\"}" \
        || { echo "gvproxy refused to forward :$HTTPS_PORT" >&2; exit 1; }
}

# ---------------------------------------------------------------------------
# Boot.
# ---------------------------------------------------------------------------

# /dev/kvm is handed to the container, but qemu still picks its own accelerator
# unless told; a silent fall back to TCG leaves the guest kernel unable to
# calibrate its TSC and the boot stalls there past any timeout. That is what
# made this harness fail roughly half its runs while the runtime under test was
# fine, so the accelerator is named rather than hoped for.
boot_enclave() {
    docker run --rm -d --name "$1" --label "$LABEL" \
        --device /dev/kvm \
        --network none \
        -v "$EIF_DIR:/eif:ro" \
        -v "$RUNDIR:/run/vsock" \
        "$IMAGE" \
        qemu-system-x86_64 \
            -M nitro-enclave,vsock=chr0,id="$PREFIX" \
            -accel kvm -cpu host \
            -kernel /eif/s3fs-qemu.eif \
            -chardev socket,id=chr0,path=/run/vsock/vhost.socket \
            -m 3G -smp 2 -nographic -no-reboot >/dev/null
    docker logs -f "$1" > "$2" 2>&1 &
}

# The runtime colourises its logs, so escape sequences land between a field name
# and its value — `addr<esc>[0m<esc>[2m=` — and a grep for "addr=" simply never
# matches. Everything that reads a console goes through this.
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

nonce() { openssl rand 20 | basenc --base64url | tr -d '='; }

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

# Capture the root this boot's attestation documents chain to, and point the
# clients at it.
#
# The emulator image sets `S3FS_COSIGN_ATTESTATIONS`, so the runtime re-signs
# what QEMU's NSM produces — QEMU does not sign at all, and a client meeting an
# unsigned document has to skip the signature, the chain and the validity
# windows, which is most of what a client does. The contents stay the device's;
# only the envelope is added. It says nothing about *who* produced a document,
# because the key is minted inside an image whoever runs it controls. What it
# buys is that the client code being developed here is the code that will run
# against hardware, rather than a relaxed variant of it.
#
# The root is minted fresh at every boot and reported on the console, which is
# why this is called again after each reboot rather than once.
enclave_trust_root() {
    local console="${1:-$CONSOLE}"
    local b64=""
    for _ in $(seq "$TIMEOUT"); do
        # `|| true` is load-bearing under `set -o pipefail`. Before the line has
        # been written grep matches nothing and exits 1; once it has, `head`
        # closes the pipe and grep exits 141 instead. Either takes the whole
        # script down inside this assignment, and *silently* — a failed
        # assignment prints nothing, so the run ends with the last thing it said
        # being the step header. That is exactly how this was found.
        b64="$(plain_of "$console" | grep -oE 'trust_root=[A-Za-z0-9+/=]+' | head -1 | cut -d= -f2- || true)"
        [[ -n "$b64" ]] && break
        sleep 1
    done
    [[ -n "$b64" ]] || fail "the enclave never reported a trust root; is S3FS_COSIGN_ATTESTATIONS set in the image?"

    TRUST_ROOT="$RUNDIR/trust-root.der"
    printf '%s' "$b64" | base64 -d > "$TRUST_ROOT" \
        || { echo "the reported trust root is not base64" >&2; exit 1; }
    openssl x509 -inform der -in "$TRUST_ROOT" -noout >/dev/null 2>&1 \
        || { echo "the reported trust root is not a certificate" >&2; exit 1; }

    # No `--allow-untrusted-root`, deliberately. With it, `verify` accepts
    # whatever root a document arrived with and reports it as self-signed, so a
    # "pinned" root pins nothing. Without it the presented root must equal this
    # one — the same comparison a client makes against AWS's — and passing
    # --pcr0 and --pcr16 becomes mandatory.
    PASSKEY_ARGS=(--trust-root "$TRUST_ROOT" --pcr0 "$EXPECTED_PCR0" --pcr16 "$EXPECTED_PCR16"
        --rp-id "${WEBAUTHN_RP_ID:-enclave.test}")
}

# Nothing answers HTTPS until an ACME order completes — directory, account,
# order, challenge, finalize — so this loop is the issuance path finishing, not
# just a process starting. On a later boot the sealed cache has the certificate
# already, and it answers at once.
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

# And it is genuinely the CA's, not something the enclave minted for itself.
# Pebble publishes the issuing chain on its management port, so this verifies
# the served chain against that root the way any PKI client would — which is the
# part a self-signed image could never test.
enclave_check_certificate() {
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

    # The name, from the SAN rather than the subject: an ACME certificate
    # carries no CN at all — identity lives in subjectAltName — so printing the
    # subject would print an empty string and look like a bug.
    local names issuer
    names="$(openssl x509 -in "$RUNDIR/served-chain.pem" -noout -ext subjectAltName \
        | tail -n +2 | tr -d ' ')"
    issuer="$(openssl x509 -in "$RUNDIR/served-chain.pem" -noout -issuer)"
    echo "served for $names"
    echo "issued by $issuer"
    [[ "$names" == *enclave.test* ]] \
        || { echo "the certificate is not for enclave.test: $names" >&2; exit 1; }
    [[ "$issuer" == *Pebble* ]] \
        || { echo "the certificate was not issued by Pebble: $issuer" >&2; exit 1; }
}

# Everything above, in the one order that works. The ordering constraints are
# recorded at each step; this is the only place they are all satisfied at once.
enclave_bring_up() {
    enclave_preflight
    trap cleanup EXIT

    enclave_build_image
    enclave_build_guest
    enclave_build_clients

    enclave_start_store
    enclave_start_parent
    enclave_start_ca
    enclave_expose_https

    say "booting the enclave"
    boot_enclave "$PREFIX-qemu" "$CONSOLE"

    say "waiting for the enclave to come up"
    wait_for_serving
    plain | grep -E "enclave networking is up|guest measured into PCR16|mounted |serving +addr=" | tail -4

    # Measured before anything asked for a key, and measured as the build said
    # it would be.
    grep -q "pcr16=$EXPECTED_PCR16" <(plain) \
        || fail "the enclave did not report measuring the expected guest into PCR16"

    enclave_trust_root

    say "waiting for Pebble to issue the serving certificate"
    wait_for_https || {
        echo "no certificate was ever issued; the ACME path did not complete" >&2
        echo "--- pebble ---" >&2;  docker logs "$PREFIX-pebble" 2>&1 | tail -30 >&2
        echo "--- console ---" >&2; plain | grep -i acme | tail -30 >&2
        exit 1
    }
    echo "the enclave is serving a certificate it obtained over ACME"
    enclave_check_certificate
}
