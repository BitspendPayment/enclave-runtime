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
# otherwise. Every client here runs its full verification path — COSE ES384,
# the certificate chain, the validity windows, the pinned root, both PCRs — and
# that is real: it is the same code, with the same flags, that will run against
# hardware. What it is not is proof that a *Nitro enclave* produced anything.
#
# QEMU's NSM does not sign at all. Its source says so — "we don't actually sign
# the data, so we use -1 as the 'alg' value" — and -1 is not a COSE algorithm
# identifier. The emulator image therefore mints a chain at boot and re-signs
# the documents the device produced, contents untouched. The key lives inside an
# image whoever boots it controls, so a verified document here means "this image
# said so", where on hardware it means "a Nitro enclave with this measurement
# said so". That gap needs hardware and nothing here can close it.
#
# So the contents are what this harness is really checking, and they are the
# part that is our code: the nonce the client asked for, the PCR0 of the image
# running, the PCR16 of the guest measured, and the hash of the certificate
# being served. KMS refusing a substituted guest is the other thing that needs
# real hardware — the emulator image cannot use KMS at all, because KMS will not
# accept a document it did not see a Nitro root behind.
set -euo pipefail

# The bring-up is shared with `dev-enclave.sh`, which stands up exactly this
# stack and then leaves it running instead of asserting against it. Everything
# up to "the enclave is serving" lives in lib.sh for that reason.
PREFIX=e2e
# A second guest, altered, for leg 8. Nothing else here needs one, so lib.sh
# does not stage it unless asked.
WITH_SUBSTITUTE=1
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

enclave_bring_up

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
    --trust-root "$TRUST_ROOT" \
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
    --trust-root "$TRUST_ROOT" \
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

docker rm -f "$PREFIX-qemu" >/dev/null 2>&1 || true
sleep 2

CONSOLE="$RUNDIR/console-resume.log"
boot_enclave "$PREFIX-qemu-resume" "$CONSOLE"
# A new boot mints a new signing chain, so the root the last one reported is
# now the wrong one. Refreshed here rather than at first use, so a client run
# against this enclave fails on what it is checking and not on a stale pin.
enclave_trust_root

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
docker rm -f "$PREFIX-qemu-resume" >/dev/null 2>&1 || true
upload_guest substitute.wasm
sleep 2

CONSOLE="$RUNDIR/console-substitute.log"
boot_enclave "$PREFIX-qemu-substitute" "$CONSOLE"
wait_for_serving
enclave_trust_root

grep -q "pcr16=$SUBSTITUTE_PCR16" <(plain) \
    || fail "the enclave did not measure the object it fetched into PCR16"
grep -q "mode=Upgrade" <(plain) \
    || fail "a guest this state had never held was not recorded as an upgrade"
wait_for_https || fail "the enclave running the substitute never answered HTTPS"

if "$ATTEST" --url "https://127.0.0.1:$HTTPS_PORT/auth/" --trust-root "$TRUST_ROOT" \
        --pcr0 "$EXPECTED_PCR0" --guest "$RUNDIR/guests/guest.wasm" \
        > "$RUNDIR/attest-substitute.log" 2>&1; then
    fail "a client pinning the approved guest accepted an enclave running another"
fi
grep -q "PCR16 mismatch" "$RUNDIR/attest-substitute.log" \
    || fail "the client refused, but not on PCR16: $(tail -1 "$RUNDIR/attest-substitute.log")"
echo "a client pinning the approved guest refused: PCR16 mismatch"

# And it is not hiding what it runs: pinned to the substitute, the same client
# accepts. The enclave attests the guest it fetched, whichever that was.
"$ATTEST" --url "https://127.0.0.1:$HTTPS_PORT/auth/" --trust-root "$TRUST_ROOT" \
    --pcr0 "$EXPECTED_PCR0" --guest "$RUNDIR/guests/substitute.wasm" \
    > "$RUNDIR/attest-substitute-pinned.log" \
    || fail "the enclave does not attest the guest it actually fetched"
echo "it attests the substitute it is running: PCR16 $SUBSTITUTE_PCR16"

docker rm -f "$PREFIX-qemu-substitute" >/dev/null 2>&1 || true

cat <<EOF

== PASS ==
  filesystem mounted over vsock through gvproxy, writes durable in MinIO
  the serving certificate was obtained over real ACME and chains to the CA
  TLS terminated in the enclave, certificate hash bound into the document
  every document verified by signature and certificate chain against a pinned
    root, the check a client makes against AWS's
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

NOT proven here. Every document above was signature-checked and chain-checked
against a pinned root, which is the client path that matters — but the key that
signed them was minted by the image at boot, not held by Nitro hardware. So a
document here says "this image said so", not "a Nitro enclave said so". Closing
that gap needs real hardware, and so does KMS refusing the key to a substituted
guest.
EOF
