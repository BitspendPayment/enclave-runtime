#!/usr/bin/env bash
# A real enclave, on this machine, for developing a client against.
#
# Same stack as the e2e — the same emulated Nitro machine, the same ACME
# issuance from a real CA, the same block store, the same attested boot — but
# it stays up, and it will run *your* guest. The e2e brings this up to assert
# against it and then tears it down; this brings it up and gets out of the way.
#
#   deploy/qemu-nitro/dev-enclave.sh --guest path/to/component.wasm
#
# It prints what a client needs to talk to it, and then waits. Ctrl-C stops
# everything it started.
#
# ---------------------------------------------------------------------------
# What is real here, and what is not
#
# Real: the enclave boots as an EIF under QEMU's nitro-enclave machine, takes
# its address by DHCP over emulated vsock, mounts the encrypted block store over
# that link, fetches your component from the store and measures it into PCR16
# before it can obtain a key, orders a certificate from a CA over RFC 8555
# TLS-ALPN-01, and gates every request on a WebAuthn assertion bound to that
# request. A client verifies the attestation document by signature, certificate
# chain, validity window, pinned root and both measurements — the same code path
# with the same flags it will use against hardware.
#
# Not real: the key that signs those documents. QEMU's NSM does not sign
# anything, so this image mints a chain at boot and re-signs what the device
# produced. The key is inside an image you control, so a verified document here
# means "this image said so" and not "a Nitro enclave said so". The root changes
# every boot for that reason — there is deliberately nothing here to hardcode.
# KMS is not real either: it will not release a key against a document it cannot
# trace to a Nitro root, so this image uses a static master key.
#
# What that leaves is everything except the hardware's signature, which is the
# part you cannot develop against anyway.
# ---------------------------------------------------------------------------
set -euo pipefail

GUEST_WASM=""
PREFIX="${PREFIX:-dev}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
WEBAUTHN_RP_ID=""
WEBAUTHN_ALLOWED_ORIGINS=""

usage() {
    cat >&2 <<EOF
usage: ${0##*/} [--guest COMPONENT.wasm] [--port PORT] [--name NAME]
                     [--rp-id DOMAIN] [--allowed-origin ORIGIN]...

  --guest   a wasm component to serve. Without one, the example guest in
            examples/guest-http is built and used.
  --port    host port forwarded to the enclave's :443. Default $HTTPS_PORT.
  --name    names this run's containers and its directory under
            target/qemu-nitro. Default $PREFIX. It keeps runs apart on disk;
            only one can be up at a time.
  --rp-id   the WebAuthn relying party the image is built with. Default
            enclave.test. A phone creates a passkey only for a domain whose
            /.well-known/assetlinks.json names the app, so testing an app means
            passing that domain. Independent of the certificate, which stays
            enclave.test. A different image, so a different PCR0.
  --allowed-origin
            an origin assertions may claim besides https://<rp id>. Repeatable.
            An Android app claims android:apk-key-hash:<unpadded base64url
            SHA-256 of its signing certificate>.
EOF
    exit 2
}

# Each value is required rather than defaulted to empty, and `--name` is
# checked against a pattern. lib.sh derives RUNDIR from it and clears that
# directory before a run, so an empty or `..`-bearing name would have it delete
# a directory nobody asked it to — including the tools installed under
# target/qemu-nitro.
need() { [[ -n "${2:-}" ]] || { echo "$1 needs a value" >&2; usage; }; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --guest) need "$1" "${2:-}"; GUEST_WASM="$2"; shift 2 ;;
        --port)  need "$1" "${2:-}"; HTTPS_PORT="$2"; shift 2 ;;
        --name)  need "$1" "${2:-}"; PREFIX="$2";     shift 2 ;;
        --rp-id) need "$1" "${2:-}"; WEBAUTHN_RP_ID="$2"; shift 2 ;;
        --allowed-origin)
                 need "$1" "${2:-}"
                 WEBAUTHN_ALLOWED_ORIGINS="${WEBAUTHN_ALLOWED_ORIGINS:+$WEBAUTHN_ALLOWED_ORIGINS,}$2"
                 shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[[ "$PREFIX" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] \
    || { echo "--name must be letters, digits, _ or -, and start with a letter or digit" >&2; exit 1; }
[[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] && (( HTTPS_PORT > 0 && HTTPS_PORT < 65536 )) \
    || { echo "--port must be a port number" >&2; exit 1; }

# An absolute path, resolved before lib.sh changes anything: the component is
# named relative to wherever the caller ran this from, which is very unlikely to
# be this directory.
if [[ -n "$GUEST_WASM" ]]; then
    GUEST_WASM="$(readlink -f "$GUEST_WASM")" \
        || { echo "no such component: $GUEST_WASM" >&2; exit 1; }
fi

# Both end up inside a Nix expression, so they are held to exactly the shapes they can take.
[[ -z "$WEBAUTHN_RP_ID" || "$WEBAUTHN_RP_ID" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
    || { echo "--rp-id must be a domain name" >&2; exit 1; }
IFS=, read -ra origins <<<"$WEBAUTHN_ALLOWED_ORIGINS"
for o in "${origins[@]}"; do
    [[ "$o" =~ ^(https://[a-z0-9.-]+(:[0-9]+)?|android:apk-key-hash:[A-Za-z0-9_-]{43})$ ]] \
        || { echo "--allowed-origin $o: expected https://<host> or android:apk-key-hash:<43 characters>" >&2; exit 1; }
done
if [[ -n "$WEBAUTHN_ALLOWED_ORIGINS" && -z "$WEBAUTHN_RP_ID" ]]; then
    echo "--allowed-origin needs --rp-id: an app's origin is only ever vouched for by its own domain" >&2
    exit 1
fi

export GUEST_WASM PREFIX HTTPS_PORT WEBAUTHN_RP_ID WEBAUTHN_ALLOWED_ORIGINS
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

enclave_bring_up

# The passkey the summary below is written against, so the command it prints
# works as printed. Registration is open — any passkey may enrol and gets its
# own tenant — so this is one identity among however many a client goes on to
# create, not a credential the enclave holds.
#
# `enrol`, not a signed request to some route: this serves whichever component
# was handed to it, and a guest of somebody else's has no route this script
# could know to ask for. Enrolment goes to the runtime and never reaches the
# guest, so it works against any of them.
say "enrolling a passkey, so there is something to try"
signed enrol >/dev/null || fail "the enclave refused to enrol a passkey"

cat <<EOF

== the enclave is up ==

  url      https://127.0.0.1:$HTTPS_PORT
  host     enclave.test   (the name on the certificate)
  rp id    ${WEBAUTHN_RP_ID:-enclave.test}${WEBAUTHN_ALLOWED_ORIGINS:+   allowing $WEBAUTHN_ALLOWED_ORIGINS}

What a client has to pin. All three, and none of them stands in for another:
PCR0 is the image, taken by the hypervisor and unforgeable from inside; PCR16 is
your component, measured by the runtime before it could obtain a key; the trust
root is what the documents chain to.

  --pcr0        $EXPECTED_PCR0
  --pcr16       $EXPECTED_PCR16
  --trust-root  $TRUST_ROOT

The certificate is issued by Pebble, which no public root signs, so a client
also needs Pebble's root — or has to pin the certificate out of the attestation
document, which is what a real client should do anyway:

  --ca          $RUNDIR/pebble-root.pem

Try it with the client this repo builds. It signs a WebAuthn assertion for each
request, which is the only way anything reaches the guest:

  $PASSKEY \\
      --url https://127.0.0.1:$HTTPS_PORT --state $RUNDIR/alice.json \\
      --trust-root $TRUST_ROOT \\
      --pcr0 $EXPECTED_PCR0 --pcr16 $EXPECTED_PCR16 --rp-id ${WEBAUTHN_RP_ID:-enclave.test} \\
      get --path /counter

The path /counter is one the example guest serves; against your own component,
ask for one of its own. The enrol subcommand reaches only the runtime, so it
works whichever guest is loaded.

Or verify the attestation on its own, without touching the guest:

  $ATTEST --url https://127.0.0.1:$HTTPS_PORT/auth/ \\
      --trust-root $TRUST_ROOT \\
      --pcr0 $EXPECTED_PCR0 --pcr16 $EXPECTED_PCR16

Console:  $CONSOLE
Store:    http://127.0.0.1:9000  (minioadmin/minioadmin, buckets $DATA_BUCKET and $ROOTS_BUCKET)
Wakes:    $FCM_RECORD  (every notification the guest raised, as JSON)

To run a new build of your guest, stop this and start it again with the new
component. That is a fresh start, not a reload: the store under $RUNDIR is
rebuilt, so the enclave boots into genesis rather than resuming, and PCR16
changes — a client still pinning the old one will refuse it, which is the point.

  $REPO/deploy/qemu-nitro/dev-enclave.sh --guest <new.wasm>

Ctrl-C to stop everything.
EOF

# The trap in lib.sh does the tearing down; this only has to stay alive for it.
# `wait` rather than a sleep loop, so Ctrl-C is handled at once.
while true; do
    if ! docker inspect -f '{{.State.Running}}' "$PREFIX-qemu" 2>/dev/null | grep -q true; then
        echo
        echo "the enclave stopped. Last of its console:" >&2
        plain | tail -20 >&2
        exit 1
    fi
    sleep 5 &
    wait $!
done
