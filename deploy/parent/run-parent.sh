#!/usr/bin/env bash
# What the EC2 parent instance runs so an enclave can reach, and be reached by,
# the network.
#
# An enclave has no NIC. Everything it sends leaves over vsock and arrives
# here, so nothing in the enclave works — not S3, not ACME, not DNS, not an
# inbound request — until these are running. An enclave that boots and then
# answers nothing is almost always this.
#
#   internet :443
#       │
#       ▼
#   ┌─────────────────────────────────────────────┐  parent (untrusted)
#   │ gvproxy  --listen vsock://:1024             │
#   │          expose :443 → 192.168.127.2:443    │
#   └─────────────────────────────────────────────┘
#       │  AF_VSOCK, ethernet frames
#       ▼
#   ┌─────────────────────────────────────────────┐  enclave (attested)
#   │ gvforwarder → tap0 192.168.127.2            │
#   │ enclave-runtime, TLS terminated here        │
#   └─────────────────────────────────────────────┘
#
# The parent carries ciphertext it cannot read: TLS to S3, KMS and the ACME
# provider is established inside the enclave and terminated at the far end, and
# inbound HTTPS is terminated by the enclave itself. What the parent does see
# is metadata — who is talked to, when, how much — and it can of course refuse
# to carry anything at all. Neither is new; it already decides whether the
# enclave runs.
set -euo pipefail

VSOCK_PORT="${VSOCK_PORT:-1024}"
ENCLAVE_IP="${ENCLAVE_IP:-192.168.127.2}"
API_SOCKET="${API_SOCKET:-/tmp/gvproxy-network.sock}"
# Ports to forward from this instance into the enclave. 443 is the HTTPS
# listener; ACME's TLS-ALPN-01 challenge arrives on the same one, which is why
# no second port is needed.
FORWARD_PORTS="${FORWARD_PORTS:-443}"

command -v gvproxy >/dev/null || {
    cat >&2 <<'EOF'
gvproxy not found. Install it from containers/gvisor-tap-vsock:

    go install github.com/containers/gvisor-tap-vsock/cmd/gvproxy@latest

or take a release binary. The matching `gvforwarder` goes *inside* the enclave
image, not here — see deploy/Dockerfile.
EOF
    exit 1
}

rm -f "$API_SOCKET"

echo "== starting gvproxy on vsock port $VSOCK_PORT =="
gvproxy \
    --listen "vsock://:${VSOCK_PORT}" \
    --listen "unix://${API_SOCKET}" \
    &
GVPROXY_PID=$!
trap 'kill "$GVPROXY_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
    [[ -S "$API_SOCKET" ]] && break
    sleep 0.2
done
[[ -S "$API_SOCKET" ]] || { echo "gvproxy never opened its API socket" >&2; exit 1; }

# Inbound forwarding is a runtime call rather than a flag: gvproxy exposes it
# over the same API socket, and doing it after startup means the enclave can be
# restarted without restarting the proxy.
for port in $FORWARD_PORTS; do
    echo "== forwarding :$port → ${ENCLAVE_IP}:$port =="
    curl -sf --unix-socket "$API_SOCKET" \
        http://localhost/services/forwarder/expose \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"local\":\":${port}\",\"remote\":\"${ENCLAVE_IP}:${port}\"}" \
        || { echo "failed to expose port $port" >&2; exit 1; }
done

echo
echo "gvproxy is up. Start the enclave with:"
echo "  nitro-cli run-enclave --eif-path s3fs.eif --cpu-count 2 --memory 2048"
echo
echo "Forwarded: $FORWARD_PORTS → $ENCLAVE_IP"
echo "API:       $API_SOCKET"
wait "$GVPROXY_PID"
