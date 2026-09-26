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
GUEST_EGRESS_ORIGINS=""
BACKGROUND_TIMEOUT_SECS=""
GUEST_ENV=""
TLS_DOMAIN=""
ACME_STAGING=""
ACME_CONTACT=""
FCM_PROJECT=""
FCM_SERVICE_ACCOUNT=""
QEMU_MEMORY="${QEMU_MEMORY:-3G}"
STORE_BIND=""
PUBLISH_HOOK=""
PACK_DIR=""
BUNDLE=""

usage() {
    cat >&2 <<EOF
usage: ${0##*/} [--guest COMPONENT.wasm] [--port PORT] [--name NAME]
                     [--rp-id DOMAIN] [--allowed-origin ORIGIN]...
                     [--keep-store [--fresh]]
                     [--guest-egress ORIGIN]... [--background-timeout SECS]
                     [--guest-env NAME=VALUE]...
                     [--domain NAME [--acme-staging] [--acme-contact EMAIL]]
                     [--fcm-project ID --fcm-service-account FILE]
                     [--memory SIZE] [--store-bind ADDR] [--publish-hook CMD]
                     [--pack DIR | --prebuilt DIR]

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
  --keep-store
            keep the store — tenants, passkeys, everything guests wrote — in
            target/qemu-nitro/<name>-store, so the next start with the same name
            resumes it instead of booting into genesis. A new guest is an
            upgrade of the same store. The trust root and the attestation chain
            are still new every boot, so clients re-read their pins.
  --fresh   with --keep-store, discard the kept store first.
  --guest-egress ORIGIN
            an origin the guest may send requests to, as http(s)://host[:port].
            Repeatable. None by default, and then the guest has no outbound
            network. The host running this script is 192.168.127.254 from
            inside the enclave. A different image, so a different PCR0.
  --background-timeout SECS
            how long one background task may run (the runtime's default is 30).
  --guest-env NAME=VALUE
            a variable for the guest, e.g. ASP_URL=http://192.168.127.254:7070.
            Repeatable. Baked into the image, so measured by PCR0.

  For an emulator on a public host — test infrastructure, not a trust boundary: whoever runs the
  host can read every tenant's data and sign attestation documents. See docs/DEV_ENCLAVE.md.

  --domain NAME
            serve NAME with a certificate from Let's Encrypt, validated over
            TLS-ALPN-01 on this host's --port, which therefore has to be 443 and
            reachable from the internet, with NAME resolving here. No Pebble.
  --acme-staging
            Let's Encrypt's staging CA: prove the setup before spending the
            production CA's rate limit. Its certificates are trusted by nothing.
  --acme-contact EMAIL
            the address Let's Encrypt sends expiry notices to.
  --fcm-project ID --fcm-service-account FILE
            real Firebase notifications, with that service account's JSON key,
            instead of the stub. The key is baked into the image.
  --memory SIZE
            the enclave's memory, as QEMU's -m. Default $QEMU_MEMORY.
  --store-bind ADDR
            publish MinIO on ADDR only, e.g. 127.0.0.1 — its credentials are
            the well-known defaults.
  --publish-hook CMD
            run CMD with this run's directory once the enclave is up: the trust
            root is new every boot, so whatever pins it needs the new one.
  --pack DIR
            build the image and every host binary into DIR and stop. Image
            options apply; run options do not.
  --prebuilt DIR
            run from a DIR --pack made, on a host with Docker, KVM and vsock but
            no Nix, cargo or git. Image options are fixed by the pack and refused.
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
        --keep-store) KEEP_STORE=1; shift ;;
        --guest-egress)
                 need "$1" "${2:-}"
                 GUEST_EGRESS_ORIGINS="${GUEST_EGRESS_ORIGINS:+$GUEST_EGRESS_ORIGINS,}$2"
                 shift 2 ;;
        --background-timeout) need "$1" "${2:-}"; BACKGROUND_TIMEOUT_SECS="$2"; shift 2 ;;
        --guest-env) need "$1" "${2:-}"; GUEST_ENV="${GUEST_ENV:+$GUEST_ENV,}$2"; shift 2 ;;
        --fresh) FRESH_STORE=1; shift ;;
        --allowed-origin)
                 need "$1" "${2:-}"
                 WEBAUTHN_ALLOWED_ORIGINS="${WEBAUTHN_ALLOWED_ORIGINS:+$WEBAUTHN_ALLOWED_ORIGINS,}$2"
                 shift 2 ;;
        --domain) need "$1" "${2:-}"; TLS_DOMAIN="$2"; shift 2 ;;
        --acme-staging) ACME_STAGING=1; shift ;;
        --acme-contact) need "$1" "${2:-}"; ACME_CONTACT="$2"; shift 2 ;;
        --fcm-project) need "$1" "${2:-}"; FCM_PROJECT="$2"; shift 2 ;;
        --fcm-service-account) need "$1" "${2:-}"; FCM_SERVICE_ACCOUNT="$2"; shift 2 ;;
        --memory) need "$1" "${2:-}"; QEMU_MEMORY="$2"; shift 2 ;;
        --store-bind) need "$1" "${2:-}"; STORE_BIND="$2"; shift 2 ;;
        --publish-hook) need "$1" "${2:-}"; PUBLISH_HOOK="$2"; shift 2 ;;
        --pack) need "$1" "${2:-}"; PACK_DIR="$2"; shift 2 ;;
        --prebuilt) need "$1" "${2:-}"; BUNDLE="$2"; shift 2 ;;
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
IFS=, read -ra egress <<<"$GUEST_EGRESS_ORIGINS"
for o in "${egress[@]}"; do
    [[ "$o" =~ ^https?://[a-z0-9.-]+(:[0-9]{1,5})?$ ]] \
        || { echo "--guest-egress $o: expected http(s)://host[:port]" >&2; exit 1; }
done
IFS=, read -ra guest_env <<<"$GUEST_ENV"
for kv in "${guest_env[@]}"; do
    [[ "$kv" =~ ^[A-Z_][A-Z0-9_]*=[A-Za-z0-9:/._-]*$ ]] \
        || { echo "--guest-env $kv: expected NAME=VALUE (letters, digits and :/._- in the value)" >&2; exit 1; }
    [[ "$kv" != S3FS_* && "$kv" != AWS_* ]] \
        || { echo "--guest-env $kv: S3FS_ and AWS_ variables are withheld from guests" >&2; exit 1; }
done
[[ -z "$BACKGROUND_TIMEOUT_SECS" || "$BACKGROUND_TIMEOUT_SECS" =~ ^[1-9][0-9]{0,5}$ ]] \
    || { echo "--background-timeout must be a number of seconds" >&2; exit 1; }
if [[ -n "$WEBAUTHN_ALLOWED_ORIGINS" && -z "$WEBAUTHN_RP_ID" ]]; then
    echo "--allowed-origin needs --rp-id: an app's origin is only ever vouched for by its own domain" >&2
    exit 1
fi

[[ -z "$TLS_DOMAIN" || "$TLS_DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
    || { echo "--domain must be a domain name" >&2; exit 1; }
[[ -z "$ACME_STAGING$ACME_CONTACT" || -n "$TLS_DOMAIN$BUNDLE" ]] \
    || { echo "--acme-staging and --acme-contact need --domain: Pebble takes neither" >&2; exit 1; }
[[ -z "$ACME_CONTACT" || "$ACME_CONTACT" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] \
    || { echo "--acme-contact must be an email address" >&2; exit 1; }
if [[ -n "$FCM_PROJECT$FCM_SERVICE_ACCOUNT" ]]; then
    [[ -n "$FCM_PROJECT" && -n "$FCM_SERVICE_ACCOUNT" ]] \
        || { echo "--fcm-project and --fcm-service-account go together" >&2; exit 1; }
    [[ "$FCM_PROJECT" =~ ^[a-z0-9-]+$ ]] || { echo "--fcm-project must be a Firebase project id" >&2; exit 1; }
    FCM_SERVICE_ACCOUNT="$(readlink -f "$FCM_SERVICE_ACCOUNT")" && [[ -f "$FCM_SERVICE_ACCOUNT" ]] \
        || { echo "no such service account file" >&2; exit 1; }
    # A Nix path literal: no spaces or quotes to break out of the expression.
    [[ "$FCM_SERVICE_ACCOUNT" =~ ^/[A-Za-z0-9/._-]+$ ]] \
        || { echo "--fcm-service-account path must be letters, digits and /._-" >&2; exit 1; }
    jq -e '.type == "service_account" and .project_id != null' "$FCM_SERVICE_ACCOUNT" >/dev/null \
        || { echo "--fcm-service-account is not a service account key" >&2; exit 1; }
fi
[[ "$QEMU_MEMORY" =~ ^[1-9][0-9]*[MG]$ ]] || { echo "--memory must be like 1536M or 3G" >&2; exit 1; }
[[ -z "$STORE_BIND" || "$STORE_BIND" =~ ^[0-9.]+$ ]] || { echo "--store-bind must be an IPv4 address" >&2; exit 1; }
[[ -z "$PACK_DIR" || -z "$BUNDLE" ]] || { echo "--pack and --prebuilt are exclusive" >&2; exit 1; }
if [[ -n "$PACK_DIR" ]]; then
    mkdir -p "$PACK_DIR" && PACK_DIR="$(readlink -f "$PACK_DIR")"
fi
if [[ -n "$BUNDLE" ]]; then
    # The image is what it was packed as. An image option here would describe an enclave that is
    # not the one about to boot, and the summary and the passkey client would believe it.
    [[ -z "$WEBAUTHN_RP_ID$WEBAUTHN_ALLOWED_ORIGINS$GUEST_EGRESS_ORIGINS$BACKGROUND_TIMEOUT_SECS$GUEST_ENV$TLS_DOMAIN$ACME_STAGING$ACME_CONTACT$FCM_PROJECT" ]] \
        || { echo "--prebuilt fixes the image: pass image options to --pack instead" >&2; exit 1; }
    BUNDLE="$(readlink -f "$BUNDLE")" && [[ -f "$BUNDLE/image.env" ]] \
        || { echo "--prebuilt $BUNDLE: not a bundle (no image.env)" >&2; exit 1; }
    [[ -n "$GUEST_WASM" ]] || { echo "--prebuilt needs --guest: a bundle carries no guest" >&2; exit 1; }
    # shellcheck source=/dev/null
    source "$BUNDLE/image.env"
fi

if [[ -n "${FRESH_STORE:-}" && -z "${KEEP_STORE:-}" ]]; then
    echo "--fresh only means something with --keep-store: without it every start is fresh" >&2
    exit 1
fi

export GUEST_WASM PREFIX HTTPS_PORT WEBAUTHN_RP_ID WEBAUTHN_ALLOWED_ORIGINS KEEP_STORE FRESH_STORE \
    GUEST_EGRESS_ORIGINS BACKGROUND_TIMEOUT_SECS GUEST_ENV TLS_DOMAIN ACME_STAGING ACME_CONTACT \
    FCM_PROJECT FCM_SERVICE_ACCOUNT QEMU_MEMORY STORE_BIND PACK_DIR BUNDLE
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

if [[ -n "$PACK_DIR" ]]; then
    enclave_pack
    exit 0
fi

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

if [[ -n "$PUBLISH_HOOK" ]]; then
    say "publishing this boot's pins"
    # Not fatal: the enclave is up and serving either way, and a hook that failed says so itself.
    $PUBLISH_HOOK "$RUNDIR" || echo "the publish hook failed; clients still hold the previous pins" >&2
fi

if [[ -n "${KEEP_STORE:-}" ]]; then
    store_note="The store in $STORE_DIR is kept: it resumes, with its tenants and
their data, and the new guest is an upgrade of it. --fresh discards it."
else
    store_note="That is a fresh start, not a reload: the store is rebuilt, so the
enclave boots into genesis rather than resuming. --keep-store keeps it."
fi

if [[ -n "$FCM_PROJECT" ]]; then
    wakes="Firebase project $FCM_PROJECT"
else
    wakes="$FCM_RECORD  (every notification the guest raised, as JSON)"
fi
if [[ -n "$TLS_DOMAIN" ]]; then
    certificate_note="The certificate is from Let's Encrypt."
    [[ -z "$ACME_STAGING" ]] || certificate_note="The certificate is from Let's Encrypt's staging CA, which nothing trusts."
else
    certificate_note="The certificate is issued by Pebble, which no public root signs, so a client
also needs Pebble's root — or has to pin the certificate out of the attestation
document, which is what a real client should do anyway:

  --ca          $RUNDIR/pebble-root.pem"
fi

cat <<EOF

== the enclave is up ==

  url      https://${TLS_DOMAIN:-127.0.0.1}:$HTTPS_PORT
  host     ${TLS_DOMAIN:-enclave.test}   (the name on the certificate)
  rp id    ${WEBAUTHN_RP_ID:-enclave.test}${WEBAUTHN_ALLOWED_ORIGINS:+   allowing $WEBAUTHN_ALLOWED_ORIGINS}
  egress   ${GUEST_EGRESS_ORIGINS:-none — the guest has no outbound network}

What a client has to pin. All three, and none of them stands in for another:
PCR0 is the image, taken by the hypervisor and unforgeable from inside; PCR16 is
your component, measured by the runtime before it could obtain a key; the trust
root is what the documents chain to.

  --pcr0        $EXPECTED_PCR0
  --pcr16       $EXPECTED_PCR16
  --trust-root  $TRUST_ROOT

$certificate_note

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
Wakes:    $wakes

To run a new build of your guest, stop this and start it again with the new
component. $store_note PCR16 changes either way, and the trust root is new every
boot — a client still pinning the old ones will refuse this enclave, which is the
point.

  $REPO/deploy/qemu-nitro/dev-enclave.sh --guest <new.wasm>${KEEP_STORE:+ --keep-store}

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
