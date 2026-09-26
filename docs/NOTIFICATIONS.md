# Notifications

A guest can ask the runtime to wake its tenant's devices through Firebase Cloud
Messaging. It is for the moments that matter — work that finished, an approval
somebody is waiting on — and it exists because a guest has no other way to reach
a person between requests.

The guest does not send anything. It cannot: [`serve::EgressPolicy`] refuses
every outgoing request a guest makes, deliberately. The runtime holds the
credential and owns the connection.

## A wake signal carries nothing

**There is no title, no body, and no `notification` object. Not behind a flag.**

An FCM payload travels through the parent instance — the party an enclave exists
to exclude — and then through Google. Anything put in it is disclosed to both. So
a wake carries an opaque `category`, an optional tenant-local `reference`, and a
schema version:

```json
{"message": {"token": "…",
             "data": {"v": "1", "category": "approval-needed", "ref": "txn-9f2"},
             "android": {"priority": "high", "ttl": "3600s"},
             "apns": {"headers": {"apns-push-type": "background", "apns-priority": "5"},
                      "payload": {"aps": {"content-available": 1}}}}}
```

The app wakes and fetches the detail over its own attested connection, where the
parent is excluded again. That costs a round trip and is the entire point.

It is also the right shape mechanically: a `notification` block is rendered by
the OS *without* the app running, so a wake carrying one would show text and fail
to wake anything.

Labels are identifiers, not prose — 1–64 characters of `[A-Za-z0-9_-]`. If a
category name would itself be sensitive, choose an opaque one; Google sees the
label, the timing and the destination regardless.

## Enable

Set a project and exactly one credential source. Empty means off.

| Setting | Purpose |
|---|---|
| `S3FS_FCM_PROJECT_ID` | The Firebase project. Baked into the image, so PCR0 covers it |
| `S3FS_FCM_SERVICE_ACCOUNT` | The service-account JSON itself. Development |
| `S3FS_FCM_SERVICE_ACCOUNT_PARAMETER` | An SSM parameter holding that JSON. Production |
| `S3FS_FCM_ENDPOINT` | Send somewhere else. Tests and the emulator only |

Both credential sources at once is refused rather than ranked: a deployment that
set both has one of them wrong, and guessing which is the wrong kind of help. A
literal credential is parsed — key included — at startup, so a malformed one
fails at boot rather than the first time somebody is waiting to be woken.

Notifications require authentication and tenant isolation, for the same reason
background tasks do: the tenant a wake belongs to comes from a verified
assertion, and without a gate there is none.

In the Nix deployment set `fcmProjectId` and `fcmServiceAccountParameter` in
`deploy/nix/deployment.nix`. Both change PCR0.

## Guest contract

```text
register-device(token)              -> result<_, string>    interactive only
forget-device(token)                -> result<_, string>    interactive only
devices()                           -> result<u32, string>
wake(category, reference)           -> result<_, string>    background allowed
```

No function takes a tenant id. The runtime supplies it from the executing
instance, so a guest cannot name another tenant's devices.

**Enrolling is interactive-only; waking is not.** That asymmetry is deliberate
and is the one thing here that differs from `enclave:tasks/queue`, where every
mutation is interactive-only. Enrolling a device grants standing ability to reach
somebody, and background work must not be able to grant itself that — nor to
silence its owner by un-enrolling. But raising a wake *from* background work is
the primary use: a task that finishes at three in the morning telling its owner
to come and look. It grants nothing; it spends an enrolment an interactive call
already made.

`devices()` returns a count and never the tokens. A registration token is a
capability to wake that device from anywhere, so it does not re-enter guest
memory once enrolled.

## Delivery

Best effort, and unacknowledged. `wake` returns as soon as the signal is queued;
it never waits on the network, because it runs inside a host call holding the
tenant's only instance slot.

- Repeat wakes for one `(tenant, category)` **coalesce** — a second signal for a
  category still waiting *is* the one already waiting.
- A full queue **drops and counts** rather than blocking. A drop is not something
  the guest can act on, so it is not reported to it; exceeding the per-tenant cap
  of distinct in-flight categories *is* returned as an error, because that one is
  actionable.
- Transient failures retry with backoff. Credential failures count as transient:
  an expired token heals on the next refresh, and treating it as fatal would turn
  routine rotation into an outage.
- A token FCM reports as `UNREGISTERED` is **pruned, never retried**. It is
  terminal by definition, it would spend the tenant's backoff budget while their
  other devices queue behind it, and it would occupy one of eight slots for ever.
- Queued wakes are **not durable**. A restart loses them, on purpose: in `tasks`
  the record *is* the work, whereas here it would be a stale pointer to work that
  already happened, and the next wake or the next poll supersedes it.

A tenant may enrol eight devices. At the cap the oldest is evicted rather than
the newest refused — this is a cache of places a person can be reached, not a
credential list, and somebody on their ninth phone must still be able to enrol
it.

## What a stolen credential buys

The service account reaches the runtime through the parent instance, which is the
party the enclave excludes. State it plainly.

A parent that steals it **can** send wake signals to registration tokens it
obtains elsewhere, as this project; and it can delay, drop or reorder the
enclave's own sends, which it could already do because it carries every packet.

It **cannot** read any tenant's data, or the device tokens themselves — those
live in `/runtime/devices` inside the encrypted filesystem, under a key KMS
releases only against a matching PCR0 and PCR16. It cannot impersonate the
enclave to a client, which needs an attestation document it cannot produce. And a
forged wake means nothing, because a wake carries no state: the app's response to
one is to fetch over the attested channel, where the parent is shut out again.

The credential protects a doorbell. Keeping it in SSM rather than the image means
it can rotate without moving PCR0, which is proportionate to that.

## The example guest

`examples/guest-http` exposes:

| Request | Behavior |
|---|---|
| `POST /devices` | Enrol the body as a registration token |
| `GET /devices` | How many devices this tenant has enrolled |
| `DELETE /devices` | Forget the token in the body |

and raises `wake("task-done", <task id>)` at the end of `run-task`, which is
where the interactive/background split is visible in practice.

## Build and test

```sh
cargo build --manifest-path examples/guest-http/Cargo.toml --release --target wasm32-wasip2
cargo test -p enclave-runtime --lib notify::
cargo test -p enclave-runtime --lib tasks::tests -- --include-ignored
```

Nothing in the suite reaches Google: the wire is covered by a transport double
that records exactly what would have been sent. **The FCM path is unverified
against the real service** — the same honesty `guest_io::cloudwatch` applies to
its own credential path. What is exercised end to end is leg `6b/8` of
[`deploy/qemu-nitro/run-e2e.sh`](../deploy/qemu-nitro/run-e2e.sh), where a
finished background task wakes an enrolled device inside an emulated enclave and
a stub records that the message carried no content.
