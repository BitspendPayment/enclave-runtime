#!/usr/bin/env bash
# The ZFS storage spike, end to end on the emulator.
#
# Tenant data on ZFS, over a disk image the "parent" serves on vsock
# (nbd-stub.py, standing in for nbdkit and EBS), anchored in the roots bucket
# after every request (runtime/src/zfs.rs). This plays the hostile host against
# it — rolling the disk back, serving an abandoned fork, killing the enclave
# between a sync and its anchor, serving the disk from between an anchor's
# marker and its sync — and measures what an anchor costs.
#
#   deploy/qemu-nitro/run-zfs-spike.sh          a fresh store
#   BENCH=200 deploy/qemu-nitro/run-zfs-spike.sh
set -euo pipefail

PREFIX=zfs
KEEP_STORE=1
FRESH_STORE=1
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

enclave_bring_up
CURRENT="$PREFIX-qemu"
IMG="$STORE_DIR/zfs.img"
N=0

# Stop this enclave, boot the image built last, and wait for it to serve or to
# refuse. Sets BOOT to "served" or "refused"; a refusal is the outcome some legs
# want, so it is not a failure here.
reboot() {
    docker rm -f "$CURRENT" >/dev/null 2>&1 || true
    sleep 2
    N=$((N + 1))
    CURRENT="$PREFIX-qemu-$N"
    CONSOLE="$RUNDIR/console-$N.log"
    boot_enclave "$CURRENT" "$CONSOLE"
    BOOT=""
    for _ in $(seq "$TIMEOUT"); do
        if grep -qE "serving +addr=" <(plain); then BOOT=served; break; fi
        if grep -qE "failed to start the guest|Kernel panic" <(plain); then BOOT=refused; break; fi
        sleep 1
    done
    [[ -n "$BOOT" ]] || fail "boot $N neither served nor refused within ${TIMEOUT}s"
    [[ "$BOOT" == served ]] && enclave_trust_root
    plain | grep -E "zfs pool anchored|zfs genesis|refusing the pool|importing the pool" | tail -2 || true
}

# Stopped, so the image is not being written while it is copied.
stop() { docker rm -f "$CURRENT" >/dev/null 2>&1 || true; sleep 2; }
snapshot() { stop; cp --sparse=always "$IMG" "$STORE_DIR/$1.img"; }
# Without stopping: only while the enclave is held at a hook, writing nothing.
snapshot_live() { cp --sparse=always "$IMG" "$STORE_DIR/$1.img"; }
restore() { stop; cp --sparse=always "$STORE_DIR/$1.img" "$IMG"; }

say "1/7  two tenants write, each in its own dataset, and every write is anchored"
rm -f "$RUNDIR/alice.json" "$RUNDIR/bob.json"
signed enrol >/dev/null || fail "alice could not enrol"
signed2 enrol >/dev/null || fail "bob could not enrol"
signed  post --path /files/a.txt --body "alice-a" >/dev/null || fail "alice could not write"
signed2 post --path /files/mine.txt --body "bob" >/dev/null || fail "bob could not write"
[[ "$(signed get --path /files/a.txt)" == "alice-a" ]] || fail "alice did not read her write back"
[[ "$(signed2 get --path /files/mine.txt)" == "bob" ]] || fail "bob did not read his write back"
mapfile -t tenants < <(plain | grep -oE 'tenant=[0-9a-f]{32}' | cut -d= -f2 | awk '!seen[$0]++')
ALICE="${tenants[0]:-}"
[[ -n "$ALICE" && -n "${tenants[1]:-}" ]] || fail "could not find both tenants' ids on the console"
grep -q "zfs anchored" <(plain) || fail "no request was anchored"
echo "alice=$ALICE; $(plain | grep -c 'zfs anchored') anchors so far"

say "2/7  tenants cannot reach each other"
for route in escape stat; do
    for target in "../$ALICE/http-example/a.txt" \
                  "/tenants/$ALICE/http-example/a.txt" \
                  "../../tenants/$ALICE/http-example/a.txt" \
                  ".zfs/../../$ALICE/http-example/a.txt" \
                  "../../../../proc/self/status"; do
        out="$(signed2 get --path "/$route/$target" 2>&1 || true)"
        if grep -qE "^(read|stat) " <<<"$out"; then
            fail "bob reached $target through /$route/: $out"
        fi
        # The guest's own refusal, naming the target: proof the path reached
        # the handler unnormalised rather than missing the route altogether.
        grep -qF "refused $target" <<<"$out" \
            || fail "/$route/$target never reached the guest as written: $out"
    done
done
signed2 get --path "/stat/http-example/mine.txt" | grep -q "^stat " || fail "bob cannot stat his own file"
echo "every cross-tenant path refused; bob's own file reachable"

say "3/7  what an anchor costs"
BENCH="${BENCH:-100}"
bench() {
    local verb="$1" i start end
    : > "$RUNDIR/bench-$verb.txt"
    for i in $(seq "$BENCH"); do
        start=$(date +%s%N)
        if [[ "$verb" == post ]]; then
            signed post --path "/files/bench-$i" --body x >/dev/null
        else
            signed get --path "/files/bench-$i" >/dev/null
        fi
        end=$(date +%s%N)
        echo $(( (end - start) / 1000000 )) >> "$RUNDIR/bench-$verb.txt"
    done
    sort -n "$RUNDIR/bench-$verb.txt" | awk -v v="$verb" '{a[NR]=$1} END {
        printf "%s (client round trip, signing included): n=%d p50=%dms p95=%dms max=%dms\n",
            v, NR, a[int(NR*0.5)+1], a[int(NR*0.95)], a[NR] }'
}
bench post
bench get
plain | grep "zfs anchored" | grep -oE "(sync_ms|total_ms)=[0-9]+" | paste - - \
    | awk -F'[\t=]' '{s+=$2; t+=$4; n++} END { if (n) printf "anchors: n=%d mean sync=%.1fms mean sync+publish=%.1fms\n", n, s/n, t/n }'

say "4/7  a restart imports the pool at its anchor"
reboot
[[ "$BOOT" == served ]] || fail "the enclave refused its own pool"
[[ "$(signed get --path /files/a.txt)" == "alice-a" ]] || fail "a.txt did not survive the restart"
echo "a.txt survived: alice-a"

say "5/7  a rolled-back disk is refused"
snapshot old                      # holds a.txt
reboot
signed post --path /files/b.txt --body "alice-b" >/dev/null || fail "alice could not write b.txt"
snapshot good                     # holds b.txt, anchored
restore old
reboot
[[ "$BOOT" == refused ]] || fail "the enclave served a disk older than its newest anchor"
plain | grep -oE "refusing the pool[^\"]*" | head -1 || true
restore good
reboot
[[ "$BOOT" == served ]] || fail "the enclave refused the good disk"
[[ "$(signed get --path /files/b.txt)" == "alice-b" ]] || fail "b.txt is gone from the good disk"
echo "old disk refused; good disk accepted, b.txt present"

say "6/7  a crash between a sync and its anchor rewinds; the abandoned fork is refused"
hooks_start
hook_rule after-sync abort
if signed post --path /files/lost.txt --body "never acknowledged" >/dev/null 2>&1; then
    fail "a write was acknowledged by an enclave told to die before anchoring it"
fi
for _ in $(seq 30); do grep -q "test hook: dying here" <(plain) && break; sleep 1; done
grep -q "test hook: dying here" <(plain) || fail "the enclave did not die between sync and publish"
hooks_stop
snapshot fork                     # synced past the anchor: holds lost.txt
reboot
[[ "$BOOT" == served ]] || fail "the enclave could not rewind to its anchor"
if signed get --path /files/lost.txt >/dev/null 2>&1; then
    fail "an unacknowledged write survived the rewind"
fi
[[ "$(signed get --path /files/b.txt)" == "alice-b" ]] || fail "b.txt did not survive the rewind"
signed post --path /files/c.txt --body "alice-c" >/dev/null || fail "alice could not write after the rewind"
snapshot current
echo "rewound: lost.txt gone, b.txt kept, c.txt anchored"
restore fork                      # the host serves the abandoned history
reboot
[[ "$BOOT" == refused ]] || fail "the enclave accepted an abandoned fork"
plain | grep -oE "refusing the pool[^\"]*" | head -1 || true
restore current
reboot
[[ "$BOOT" == served ]] || fail "the enclave refused its current disk"
[[ "$(signed get --path /files/c.txt)" == "alice-c" ]] || fail "c.txt is gone"
echo "abandoned fork refused; current disk accepted, c.txt present"

# An anchor's nonce reaches the disk in one txg (the marker) and the anchor
# names a later one (its sync). Another tenant's write that lands between them
# is acknowledged by that anchor, so a disk from between the two holds the
# anchor's nonce but not that write. The host serves it.
say "7/7  a disk from between an anchor's marker and its sync is refused"
hooks_start
hook_rule after-marker hold
before=$(plain | grep -c "zfs anchored" || true)
signed post --path /files/m.txt --body "alice-m" > "$RUNDIR/alice-m.out" 2>&1 &
alice=$!
hook_wait after-marker            # alice's nonce is on the disk; her anchor holds the lock
snapshot_live marker
signed2 post --path /files/acked.txt --body "bob-acked" > "$RUNDIR/bob-acked.out" 2>&1 &
bob=$!
hook_wait anchor-wait             # bob's guest has written; his anchor waits on alice's
hook_release after-marker
wait "$alice" || fail "alice's write failed: $(cat "$RUNDIR/alice-m.out")"
wait "$bob" || fail "bob's write was not acknowledged: $(cat "$RUNDIR/bob-acked.out")"
hooks_stop
published=$(( $(plain | grep -c "zfs anchored" || true) - before ))
plain | grep "zfs anchored" | tail -"$published"
[[ "$published" == 1 ]] \
    || fail "bob's write took an anchor of its own ($published anchors), so the shortcut was not taken: revise the diagnosis"
[[ "$(signed2 get --path /files/acked.txt)" == "bob-acked" ]] || fail "bob cannot read his acknowledged write"
snapshot acked                    # holds acked.txt, anchored
restore marker
reboot
if [[ "$BOOT" == served ]]; then
    plain | grep -E "zfs import: (dbgmsg|txgs)|zfs pool resumed" || true
    got="$(signed2 get --path /files/acked.txt 2>&1 || true)"
    fail "REPRODUCED: the enclave served the disk from between the marker and its sync; bob's acknowledged acked.txt now reads: $got"
fi
plain | grep -oE "refusing the pool[^\"]*" | head -1 || true
restore acked
reboot
[[ "$BOOT" == served ]] || fail "the enclave refused the disk holding bob's write"
[[ "$(signed2 get --path /files/acked.txt)" == "bob-acked" ]] || fail "acked.txt is gone"
echo "the marker's disk refused; the anchored disk accepted, acked.txt present"

echo
echo "PASS: ZFS spike: anchored writes, isolation, resume, rollback refused, rewind, fork refused, marker disk refused"
