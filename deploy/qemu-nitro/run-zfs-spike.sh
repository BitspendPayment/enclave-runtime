#!/usr/bin/env bash
# The ZFS storage spike, end to end on the emulator.
#
# Tenant data on ZFS, over a disk image the "parent" serves on vsock
# (nbd-stub.py, standing in for nbdkit and EBS), anchored in the roots bucket
# after every request (runtime/src/zfs.rs). This plays the hostile host against
# it — rolling the disk back, killing the enclave between a sync and its
# anchor, serving an abandoned fork — measures what an anchor costs, and shows
# two tenants' pools anchoring independently.
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

say "1/7  two tenants write, each in its own pool, and every write is anchored"
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

say "2/7  tenants cannot reach each other across their pools"
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

# Nothing is rewound: a crash leaves what reached the disk, and the boot goes
# on from it. Two histories can then grow from one anchor. Once one of them is
# anchored again, the other is an abandoned fork.
say "6/7  a crash between a sync and its anchor resumes; the abandoned fork is refused"
snapshot base                     # at the newest anchor
reboot
hooks_start
hook_rule after-sync abort
if signed post --path /files/lost.txt --body "never acknowledged" >/dev/null 2>&1; then
    fail "a write was acknowledged by an enclave told to die before anchoring it"
fi
for _ in $(seq 30); do grep -q "test hook: dying here" <(plain) && break; sleep 1; done
grep -q "test hook: dying here" <(plain) || fail "the enclave did not die between sync and publish"
hooks_stop
snapshot fork                     # past the anchor: lost.txt, and the next anchor's unpublished marker
reboot
[[ "$BOOT" == served ]] || fail "the enclave refused the disk it crashed on"
plain | grep -E "zfs pool admitted" | tail -1
stop                              # nothing asked of it, so nothing anchored on this history
restore base                      # the other history from the same anchor
reboot
[[ "$BOOT" == served ]] || fail "the enclave refused the disk at its anchor"
[[ "$(signed get --path /files/b.txt)" == "alice-b" ]] || fail "b.txt is gone"
if signed get --path /files/lost.txt >/dev/null 2>&1; then
    fail "lost.txt is on a disk that never held it"
fi
signed post --path /files/c.txt --body "alice-c" >/dev/null || fail "alice could not write c.txt"
snapshot current                  # this history is anchored now
echo "the crashed disk was admitted; from the anchor's own disk, c.txt anchored"
restore fork                      # the host serves the other history
reboot
[[ "$BOOT" == refused ]] || fail "the enclave accepted an abandoned fork"
plain | grep -oE "refusing the pool[^\"]*" | head -1 || true
restore current
reboot
[[ "$BOOT" == served ]] || fail "the enclave refused its current disk"
[[ "$(signed get --path /files/c.txt)" == "alice-c" ]] || fail "c.txt is gone"
echo "abandoned fork refused; current disk accepted, c.txt present"

# The same-nonce steal that sank the single pool — one tenant's write landing
# between another's marker and its sync, acknowledged by an anchor that does
# not hold it — cannot happen here: each tenant has its own pool, its own
# marker, its own last-anchor lock. This shows the independence that makes it
# so: one tenant held mid-anchor does not stop another from anchoring.
say "7/7  two tenants anchor independently"
hooks_start
hook_rule after-marker hold       # the first anchor to reach a marker holds there
signed post --path /files/held.txt --body "alice-held" > "$RUNDIR/alice-held.out" 2>&1 &
alice=$!
hook_wait after-marker            # alice holds her pool's lock, mid-anchor
# Bob's pool is a different pool with a different lock, so his write must
# complete while alice is held — not wait the whole hold out.
signed2 post --path /files/free.txt --body "bob-free" > "$RUNDIR/bob-free.out" 2>&1 &
bob=$!
for _ in $(seq 60); do kill -0 "$bob" 2>/dev/null || break; sleep 1; done
if kill -0 "$bob" 2>/dev/null; then
    hook_release after-marker; wait "$alice" "$bob" 2>/dev/null || true; hooks_stop
    fail "bob's write did not finish while alice was held: the pools are not independent"
fi
wait "$bob" || fail "bob's independent write failed: $(cat "$RUNDIR/bob-free.out")"
hook_release after-marker
wait "$alice" || fail "alice's held write failed: $(cat "$RUNDIR/alice-held.out")"
hooks_stop
[[ "$(signed2 get --path /files/free.txt)" == "bob-free" ]] || fail "bob's write is gone"
[[ "$(signed  get --path /files/held.txt)" == "alice-held" ]] || fail "alice's write is gone"
echo "bob anchored while alice was held: tenants anchor independently"

echo
echo "PASS: ZFS spike: per-tenant pools, isolation, resume, rollback refused, crash resumed, fork refused, independent anchoring"
