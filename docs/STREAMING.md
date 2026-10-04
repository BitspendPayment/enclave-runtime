# Bidirectional streams

A signing session is interactive: each round's messages depend on the last
round's replies. That needs a channel open in both directions at once, not a
sequence of requests. This is how one works here, what opening one is allowed
to authorize, and what it costs.

The prototype carries **no cryptography**. `examples/guest-grpc` exchanges
dummy signing-session messages so the transport and the authorization are
settled before a key depends on either.

## What works

A guest holds the request body and the response body at the same time and
answers each message as it arrives. This is specified behaviour rather than a
trick: `wasi:http`'s `response-outparam.set` is documented to *"allow execution
to continue after the response has been sent"*, and `incoming-request.consume`
borrows the request rather than consuming it, so the two resource trees are
independent.

The runtime negotiates HTTP/2 by ALPN, per connection. There is no
configuration for it, and HTTP/1.1 clients are unaffected.

## Authorization: one model, and what it names

A stream and an ordinary request are approved the same way. That unification is
recent and deliberate: a stream's body **is** its message sequence, so it could
never be bound by a body hash, and rather than keep a second weaker path for it,
the approval now names something both shapes have — the interaction.

```console
POST /auth/request/options   { credential_id, method, path, query }
        ↓                     response is attested: check it, pin the certificate
   Face ID / Touch ID
        ↓
POST /auth/request/verify    { challenge_id, assertion }  →  { token, expires_in_secs }
        ↓
<the interaction>            Authorization: Bearer <token>
```

### What it authorizes

**One interaction, at that method, path and query.** Not one message, and not
one payload.

The token commits to no bytes. A token issued for `POST /sign` authorizes
whatever body follows, so a client compromised between the approval and the
request can substitute the payload — the runtime will not catch it, because it
is no longer looking. That is the trade this model makes, and it is stated here
rather than left to be discovered.

What the runtime still refuses: moving a token to another route, spending one
twice, spending one after it expires, and spending one belonging to another
tenant. Redeeming removes it before anything about it is checked, so two callers
racing one token have exactly one winner and a token offered for the wrong route
is spent by the attempt.

### Per-message approval: not built, and not buildable today

If a guest wants "the person approved *these bytes*", it must obtain that
itself, per message, inside the interaction. **The runtime cannot do it**: it
hands the body through without reading it, and teaching it to parse a guest's
message format would make it care about a protocol it deliberately knows
nothing about.

**But the guest cannot do it either, yet.** Verifying a passkey assertion needs
the stored credential, the challenge that was issued, the relying-party
configuration, and the ability to mark that challenge used. All four live in the
runtime, and a guest is given standard WASI and nothing else — there is no host
function it can call to ask.

`examples/guest-grpc` deliberately carries **no** approval fields on
`ClientMsg`. An earlier draft carried `challenge_id` and `assertion` and refused
messages without them, which promised a check nothing performed; fields that
look like a credential and are never verified read as a guarantee, and are worse
than their absence.

Closing this needs a new host import — a way for a guest to hand the runtime an
assertion and get back yes or no. **It should be designed before a real key
depends on it**, because until then "someone opened an interaction" is the only
thing between a compromised client and whatever the guest will do.

### What a stolen token buys

It is single-use, expires in `--interaction-token-ttl-secs` (60s by default), and
is bound to one route. Spending one gets: one interaction with that tenant's
guest, and whatever the guest will do
without a further check. It gets nothing about another tenant, and no replay —
the token is gone the moment it is used.

## What it costs: one stream occupies one tenant slot

Concurrency is **one active guest handler per tenant**. That is the isolation
model, not a limit to be raised — a tenant's SQLite database is only safe
because exactly one of their requests is ever in flight (WASI has no `fcntl`,
so `locking_mode=EXCLUSIVE` is the only option).

A stream is a request. **An open stream holds its tenant's slot for its entire
life**, and that tenant's next request waits behind it. Different tenants are
unaffected and run concurrently.

Anonymous callers share a single lock, so a stream with no gate configured
would starve every other anonymous caller. **Streams are refused outright when
no gate is configured.**

## Lifetime and failure

| event | what happens |
|---|---|
| **half-close** (client sends END_STREAM) | the orderly end: the guest finishes and emits `grpc-status` trailers |
| **client cancels or disconnects** | the guest's next write fails, the call ends, the instance is dropped and never reused, the tenant lock frees |
| **head timeout** (`request_timeout`) | bounds only the *response head*. It does not apply once the head is out, so it never ends a healthy stream |
| **no traffic either way** | the epoch watchdog asks whether bytes moved, not how long the call ran. Sustained silence while executing wasm ends the call |
| **interaction deadline** (`--max-interaction-secs`, 300s) | a wall clock, checked whether or not wasm is executing — so it reaches a guest blocked in a host call, which the epoch never can. Ends the interaction and frees the tenant |
| **guest spins** | trapped by the epoch, on the same schedule as before streams existed |
| **guest traps** | the instance is discarded, never reused — a partially-executed call leaves a store that cannot be re-entered |
| **`grpc-timeout` header** | **not enforced by the runtime.** Forwarded to the guest, which owns it. The runtime's deadlines are its own, so a client cannot lengthen them |
| **`wasi:http` 600s between-bytes** | hardcoded in `wasmtime-wasi-http` and not configurable. A ceiling above ours |

## Sessions, retries, duplicates

The `session_id` is the client's; the runtime never reads it. A stream that
dies takes its in-memory session with it — **nothing about a session survives a
stream except what the guest committed to storage**, which is the same rule as
every other request.

The runtime does not retry, resume, or deduplicate anything. **There is no
exactly-once guarantee and no automatic replay of signing rounds.** A client
that reconnects opens a *new* stream with a *new* stream-open assertion, and
any message it re-sends is simply a new message.
Duplicates are the guest's to detect by sequence number, and its round handling
must be idempotent because the transport promises nothing.

## Attestation

The `x-enclave-attestation` document is on the response head, which for gRPC is
the initial metadata. A client should verify it — against the nonce it chose
and the leaf from its own handshake — **before sending anything
signing-sensitive**.

One document per stream, at open. **It attests the connection**: that this
enclave terminates it and is alive now. It says nothing about individual
messages and nothing about signing results, because it is generated before the
guest runs.

## What proves the enclave to the service

Everything above is a client calling in. The held connections of
[`enclave:streams/connection`](../wit/stream/stream.wit) run the other way: the
runtime dials the service and holds `GET <origin>/escrow/stream?id=<wire id>`
open for server-sent events, and sends each message as
`POST <origin>/escrow/send?id=<wire id>`. There the enclave is the client, and
the service has to tell this image from anyone who has learned a wire id — a
customer running a cosigner of their own, say.

So the runtime signs both. Each carries `x-enclave-attestation`: an NSM
attestation document (COSE_Sign1), standard base64 with padding — the header
and encoding of an `/auth/*` response. Its `user_data` is 32 bytes:

```text
SHA-256( "enclave-runtime/stream/v1" 0x00  kind 0x00  wire_id 0x00  SHA-256(body) )
```

| request | `kind` | `wire_id` | `body` |
|---|---|---|---|
| `GET /escrow/stream` | `open` | the `id` query parameter | empty |
| `POST /escrow/send` | `send` | the `id` query parameter | the request body, byte for byte |

The wire id is `<tenant hex>-<stream id>`, URL-safe as sent. Its tenant half
comes from the authenticated invocation, never from the guest, so a document
also says whose connection a message belongs to. There is no nonce — the
service first hears of a request when it arrives, and asking it for one would
cost a round trip per message — and no public key. A pinned vector, from
`stream_user_data` in `runtime/src/stream.rs`: with wire id
`01010101010101010101010101010101-esc`, `open` over no bytes is
`f9a46679b41ae322117cb08515fefa42b1c53a7d24aa472eedde9650a6d7fb82` and `send`
over `hello` is
`c828be10c689f688431ce5ecb5ca9870a03f8ac375956733fa755150bdd6fa7c`.

### What a service checks, before acting on the body

1. **Signature and chain** to the root it pins: AWS's Nitro root in
   production. In development, the root the dev enclave mints and prints at
   each boot ([DEV_ENCLAVE.md](DEV_ENCLAVE.md)) — which proves only that the
   image produced the document, not who ran it.
2. **PCR0 and PCR16, both pinned.** PCR0 is the runtime image, PCR16 the guest
   it measured. Neither alone is an identity: any runtime can write a
   convincing PCR16, and PCR0 does not contain the guest.
3. **Freshness**: the document's `timestamp` within five minutes of the
   service's clock. With no nonce, this is the only bound on replay.
4. **`user_data`**, recomputed from the `id` it was sent and the exact body it
   received, compared byte for byte.
5. **For `open`, only a newer document replaces a held stream.** A `GET` whose
   document is no newer than the one the live stream for that wire id was
   opened with is refused, or a `GET` replayed inside the window could take a
   live connection over.
6. **A missing header is a refusal**, never a downgrade. A runtime with no
   attestor configured sends none, and is meant to be refused.

### What it costs

**One NSM signature per message, and one per dial**, under the same
four-at-a-time limit as `/auth/*` responses: the device is one device.

**The header is a few KB**: about 3.3 KB of base64 from the dev enclave, and
6–8 KB expected on hardware, whose certificate bundle is larger. The runtime
refuses to start if a document would exceed 16 KiB. Anything in front of the
service must accept a request header of **~16 KB** — nginx's default
`large_client_header_buffers 4 8k` leaves no room for a document from hardware.

### What it does not prove

- **Which service it was for.** Nothing names the origin: a document one
  service received is good, for five minutes, at any other that accepts the
  same wire id.
- **That a `send` is new.** One replayed inside the window is a duplicate, not
  a forgery, and delivery is at least once anyway — handlers deduplicate as
  they already must.
- **Anything about the service.** What arrives down the held stream is
  authenticated by TLS, not by this.

## Known limits

- **One task, alternating.** The guest reads and writes in turn rather than
  truly simultaneously. Sufficient for a request/response signing protocol; a
  guest needing to emit unsolicited frames while blocked on a read would need
  more.
- **Per-message authorization is designed, not built.** See above.
- **`grpc-timeout` is forwarded, never enforced.** The runtime's deadlines are
  its own so a client cannot lengthen them by asking; interpreting a client's
  deadline is the guest's, because only the guest knows what its work is worth.
- **HTTP/1.1 trailers need a `Trailer:` header** or hyper drops them silently.
  The guest sets one. HTTP/2 needs no such thing.
