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

## Authorization: a channel is not a signature

An ordinary request is approved by a WebAuthn assertion bound to
`{method, path, query, sha256(body)}`. The body hash is the part that makes the
approval mean *this* operation — without it, an approval for one payload
authorizes any payload at that route.

**A stream's body is the message sequence, and none of it exists when the
channel opens.** There is nothing to hash. So a stream is opened with a
different, weaker approval, issued by a different endpoint:

```console
POST /auth/stream/options   { credential_id, method, path, query }
        ↓                    no body hash, because there is no body yet
   Face ID / Touch ID
        ↓
POST <path>                 x-webauthn-challenge-id, x-webauthn-assertion,
                            x-enclave-stream: open
```

### What it authorizes

**Opening one channel, on that method, path and query. Nothing else.** The same
shape as an enrollment token, which creates a tenant and does nothing else.

It commits to no bytes, so it approves no operation. **Every message inside the
stream that asks the enclave to sign anything must carry its own fresh,
single-use assertion bound to that message.** Treating an open channel as
standing permission to sign would be exactly the substitution the body hash
exists to prevent — one approval, spent on operations the person never saw.

That per-message check is the guest's, and it is **not implemented here**. The
prototype carries `challenge_id` and `assertion` fields on `ClientMsg` and
demonstrates refusing without them; verifying them needs a runtime hook that
does not exist yet, and it must be designed before any real key is involved.

### What stops the weaker approval leaking into the strong path

Two independent things, and both must agree:

- The bindings are **different values** — `BodyBinding::Unbound` never equals
  `BodyBinding::Exact(_)`, for any hash. No `if` enforces this, so none can be
  forgotten.
- The request must carry `x-enclave-stream`, a runtime-owned header stripped
  before the guest sees it. Header without an unbound approval, or an unbound
  approval without the header, is refused.

Deliberately *not* keyed on `content-type: application/grpc` or a path prefix:
the content type is application data the guest also reads, and a path prefix
would bake a service name into a runtime that knows nothing about the guest's
routes.

### What a stolen stream-open assertion buys

It is single-use, expires in 60 seconds, is bound to one route, and is
rate-limited per credential. Spending one gets: one open channel to that
tenant's guest, and whatever the guest will do without a further assertion —
which is the guest's boundary to hold. It gets nothing about another tenant,
and no replay: the challenge is gone the moment it is used.

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
any message it re-sends is a new message needing its own per-message assertion.
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
