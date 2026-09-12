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
