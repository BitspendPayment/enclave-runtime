#!/usr/bin/env bash
# Start the enclave and open the door to it.
#
# Two steps that have to happen in this order and are easy to get wrong:
#
#   1. `nitro-cli run-enclave` boots the EIF. It returns as soon as the enclave
#      is running, not when the application inside it is listening.
#   2. gvproxy is told to forward :443 into the enclave. This is a call to its
#      API socket rather than a flag, which means the enclave can be restarted
#      without restarting the network under it.
#
# The forwarding is deliberately *not* done before the enclave exists: gvproxy
# would accept the request and then refuse every connection, which looks like a
# firewall problem rather than a missing enclave.
set -euo pipefail

EIF="${EIF:-/opt/enclave/s3fs.eif}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MIB="${MEMORY_MIB:-3072}"
ENCLAVE_IP="${ENCLAVE_IP:-192.168.127.2}"
FORWARD_PORTS="${FORWARD_PORTS:-443}"
API_SOCKET="${API_SOCKET:-/run/gvproxy/network.sock}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"

log() { echo "enclave-start: $*"; }

[[ -f "$EIF" ]] || { log "no image at $EIF"; exit 1; }

# What this machine is about to run, so the journal records the measurement
# rather than only the fact that something started. An operator comparing a
# client's attested PCR0 against a rebuild starts here.
if [[ -f /opt/enclave/pcr.json ]]; then
    log "PCR0 $(jq -r .PCR0 /opt/enclave/pcr.json)"
fi

# A previous enclave surviving a restart would hold the allocator's memory and
# the next `run-enclave` would fail for lack of it.
if nitro-cli describe-enclaves | jq -e '.[0]' >/dev/null 2>&1; then
    log "terminating a previously running enclave"
    nitro-cli terminate-enclave --all >/dev/null
fi

log "starting enclave from $EIF (${CPU_COUNT} vCPU, ${MEMORY_MIB} MiB)"
nitro-cli run-enclave \
    --eif-path "$EIF" \
    --cpu-count "$CPU_COUNT" \
    --memory "$MEMORY_MIB" \
    --enclave-cid "$ENCLAVE_CID"

for _ in $(seq 1 60); do
    [[ -S "$API_SOCKET" ]] && break
    sleep 1
done
[[ -S "$API_SOCKET" ]] || { log "gvproxy's API socket never appeared at $API_SOCKET"; exit 1; }

for port in $FORWARD_PORTS; do
    log "forwarding :$port to ${ENCLAVE_IP}:$port"
    curl -sf --unix-socket "$API_SOCKET" \
        http://localhost/services/forwarder/expose \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"local\":\":${port}\",\"remote\":\"${ENCLAVE_IP}:${port}\"}" \
        || { log "gvproxy refused to forward :$port"; exit 1; }
done

log "enclave is running and :$FORWARD_PORTS is forwarded"
