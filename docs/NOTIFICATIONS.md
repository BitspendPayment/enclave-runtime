# Notifications

A guest can ask the runtime to wake its tenant's devices through AWS End User
Messaging Push — the service that was Amazon Pinpoint — which delivers to
Android through Firebase Cloud Messaging. It is for the moments that matter —
work that finished, an approval somebody is waiting on — and it exists because a
guest has no other way to reach a person between requests.

The guest does not send anything, and holds no credential that could. The runtime
signs as the instance's own role and owns the connection. The Firebase
credential lives on the push application's FCM channel, inside AWS, so no image
carries it.

## A wake signal carries nothing

**There is no title, no body, and no `notification` object. Not behind a flag.**

A wake travels through the parent instance — the party an enclave exists to
exclude — then through AWS, then through Google. Anything put in it is disclosed
to all three. So a wake carries an opaque `category`, an optional tenant-local
`reference`, and a schema version. It is sent as one `SendMessages` call per
device, with the FCM v1 message as `RawContent` and nothing beside it:

```json
{"Addresses": {"<token>": {"ChannelType": "GCM"}},
 "MessageConfiguration": {"GCMMessage": {"RawContent":
   "{\"fcmV1Message\": {\"message\": {
       \"data\": {\"v\": \"1\", \"category\": \"approval-needed\", \"ref\": \"txn-9f2\"},
       \"android\": {\"priority\": \"high\", \"ttl\": \"3600s\"},
       \"apns\": {\"headers\": {\"apns-push-type\": \"background\", \"apns-priority\": \"5\"},
                \"payload\": {\"aps\": {\"content-available\": 1}}}}}}"}}}
```

`RawContent` and only that: the service's structured fields wrap what they carry —
`Data` reaches the phone as one string under `pinpoint.jsonBody` — so an app
reading `data.category` would never find it, and the wake would be reported
delivered and dropped.

The app wakes and fetches the detail over its own attested connection, where the
parent is excluded again. That costs a round trip and is the entire point.

It is also the right shape mechanically: a `notification` block is rendered by
the OS *without* the app running, so a wake carrying one would show text and fail
to wake anything.

Labels are identifiers, not prose — 1–64 characters of `[A-Za-z0-9_-]`. If a
category name would itself be sensitive, choose an opaque one; AWS and Google
see the label, the timing and the destination regardless.

## Enable

One setting. Empty means off.

| Setting | Purpose |
|---|---|
| `ENCLAVE_PUSH_APP_ID` | The push application. Baked into the image, so PCR0 covers it. Not a secret |
| `ENCLAVE_PUSH_ENDPOINT` | Send to a stub instead, signed with a placeholder. Only a `testing` build has it |

Requests go to `pinpoint.<region>.amazonaws.com` in the runtime's region, signed
(SigV4, service `mobiletargeting`) at the trusted clock's time as the instance's
role. The role comes from the metadata service and nowhere else: the image names
`http://192.168.127.253` as its address, which gvproxy maps for the runtime alone
(`deploy/ami/units/gvproxy.yml`), and no guest can reach it.

At boot the runtime reads the application's FCM channel. One that is disabled,
holds no Firebase service account, or would authenticate with the legacy server
key — `KEY`, the channel's default, which Google has turned off — refuses the
boot; a channel that cannot be reached only warns.

Notifications require authentication and tenant isolation, for the same reason
background tasks do: the tenant a wake belongs to comes from a verified
assertion, and without a gate there is none.

In the Nix deployment set `pushAppId` in `deploy/nix/deployment.nix`, and
`push_app_id` in `deploy/tofu`, which lets the parent's role send through that
one application. Set the channel up once, from the CLI — it keeps the service
account out of tofu state:

```sh
aws pinpoint create-app --create-application-request Name=wakes
aws pinpoint update-gcm-channel --application-id <id> --gcm-channel-request \
  "$(jq -n --rawfile s service-account.json \
        '{ServiceJson: $s, DefaultAuthenticationMethod: "TOKEN", Enabled: true}')"
```

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
- Transient failures retry with backoff. A refused signature counts as
  transient and fetches the role's credentials again: a credential that expired
  in flight heals, and treating it as fatal would turn routine rotation into an
  outage.
- A token the service reports gone — a `PERMANENT_FAILURE` for that address with
  status 404 or 410, or an `UNREGISTERED` message, inside a 200 — is **pruned,
  never retried**. It is terminal by definition, it would spend the tenant's
  backoff budget while their other devices queue behind it, and it would occupy
  one of eight slots for ever. Other permanent failures are dropped and counted,
  not pruned: pruning is not undone, and a wallet that thinks its token enrolled
  never offers it again until FCM rotates it.
- Queued wakes are **not durable**. A restart loses them, on purpose: in `tasks`
  the record *is* the work, whereas here it would be a stale pointer to work that
  already happened, and the next wake or the next poll supersedes it.

A tenant may enrol eight devices. At the cap the oldest is evicted rather than
the newest refused — this is a cache of places a person can be reached, not a
credential list, and somebody on their ninth phone must still be able to enrol
it.

## What a borrowed role buys

The runtime signs as the parent instance's role, so the parent can sign as it too.
State it plainly.

A parent **can** send wake signals through this one application, to registration
tokens it obtains elsewhere; and it can delay, drop or reorder the enclave's own
sends, which it could already do because it carries every packet.

It **cannot** read any tenant's data, or the device tokens themselves — those
live in `/runtime/devices` inside the encrypted filesystem, under a key KMS
releases only against a matching PCR0 and PCR16. It cannot read the Firebase
credential either: the channel never returns it. It cannot impersonate the
enclave to a client, which needs an attestation document it cannot produce. And a
forged wake means nothing, because a wake carries no state: the app's response to
one is to fetch over the attested channel, where the parent is shut out again.

The role protects a doorbell, and IAM scopes it to one application and revokes it
without a new image.

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

Nothing in the suite reaches AWS: the wire is covered by a transport double that
records exactly what would have been sent, and pins its signature. **The push
path is unverified against the real service** — its response shapes are from
the API model, not from a live answer, and the dead-token status under token
authentication is undocumented — the same honesty `guest_io::cloudwatch` applies
to its own credential path. What is exercised end to end is leg `6b/8` of
[`deploy/qemu-nitro/run-e2e.sh`](../deploy/qemu-nitro/run-e2e.sh), where a
finished background task wakes an enrolled device inside an emulated enclave and
a stub records that the request was signed for the service, carried only
`RawContent`, and that the message carried no content.
