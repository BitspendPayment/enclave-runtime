# Integrating a client against this runtime

For a team with an existing Nitro client, pointing an app at this enclave for
the first time.

If you have been talking to a **nitriding** enclave, the short version is: the
endpoints, the `user_data` layout and the trust model are all different, and
there is a per-request passkey assertion that nitriding has no equivalent of.
This is not a base-URL change. It is maybe a day of client work, and most of it
is in one file.

You can have the enclave running locally, serving your own guest, in about ten
minutes — see [Run it](#run-it) — and develop against the same verification code
path you will run in production.

## What is different, in one table

|  | nitriding | this runtime |
|---|---|---|
| get the document | `GET /enclave/attestation?nonce=` | `x-enclave-attestation` header on any `/auth/*` response |
| enclave info | `GET /v1/enclave-info` | none; everything is in the document |
| `user_data` | `"sha256:" + tlsKeyHash + ";" + "sha256:" + appKeyHash` | 68 bytes: `0x1220 ‖ sha256(tls_cert_der) ‖ 0x1220 ‖ sha256(guest_component)` |
| pinned | PCR0 | PCR0 **and** PCR16 |
| per-request auth | none | a WebAuthn assertion bound to that exact method and path |
| tenancy | yours to build | one tenant per passkey, enforced by the runtime |

The last two rows are the ones that change the app, not just the crate.

## Run it

Needs Linux with KVM, Docker and Nix. Once per boot:

```bash
sudo modprobe vsock_loopback
```

Once ever:

```bash
docker build -t s3fs-qemu-nitro:latest deploy/qemu-nitro
cargo install vhost-device-vsock --root target/qemu-nitro/tools
```

Then, with your component:

```bash
cargo build --release --target wasm32-wasip2   # in your guest's crate
deploy/qemu-nitro/dev-enclave.sh --guest target/wasm32-wasip2/release/cosigner.wasm
```

It builds the enclave image, starts a block store and an ACME CA, boots the
enclave under QEMU's `nitro-enclave` machine, waits for it to fetch and measure
your component and obtain a certificate, then prints the three values a client
pins and stays up. Ctrl-C stops everything it started.

There is nothing to configure. The guest is fetched from the store at boot and
measured into PCR16 before it can obtain a key, so a new build is a new PCR16
and a restart — see [dev-enclave](DEV_ENCLAVE.md) for the details, the options
and what is and is not real about it.

## The protocol

Only `/auth/*` answers without an assertion. Everything else reaches the guest,
and nothing reaches the guest without a fresh approval.

### Registering

Registration is **open**: any passkey may enrol, and each one gets its own
tenant with its own isolated filesystem. There is no invitation, no enrolment
token and no operator step.

```
POST /auth/register/options   {"display_name": "optional"}
  → 200 {"registration_id": "...", "options": <PublicKeyCredentialCreationOptions>}

POST /auth/register/verify    {"registration_id": "...", "credential": <RegisterPublicKeyCredential>}
  → 200 {"tenant_id": "...", "credential_id": "..."}
```

`options` is what you hand to `navigator.credentials.create()` — or to your
platform authenticator. Keep `credential_id`; every later request names it.

### One request

Four steps, because the approval is bound to the request rather than to a
session.

```
1.  POST /auth/request/options
    {"credential_id": "...", "method": "POST", "path": "/sign", "query": null}
      → 200 {"challenge_id": "...", "options": <PublicKeyCredentialRequestOptions>}
      + header x-enclave-attestation: <base64 COSE_Sign1>

2.  verify that document (next section) before doing anything with it

3.  sign the challenge → POST /auth/request/verify
    {"challenge_id": "...", "assertion": "<base64url of the PublicKeyCredential JSON>"}
      → 200 {"token": "...", "expires_in_secs": 60}

4.  the real request, with  Authorization: Bearer <token>
```

Notes that matter:

- The challenge is issued **for that method, path and query**. A token moved to
  another route is refused — this is enforced, not advisory.
- A token is **single use** and expires in 60 seconds. That bounds the time to
  *start* an interaction, not how long one may run: a long stream approved once
  keeps going.
- `deny_unknown_fields` is set on both request bodies. An extra field is a 400,
  deliberately — this route used to take a `body_sha256` and a client still
  sending one must be told it means nothing now rather than have it ignored.
- The assertion is one header holding the credential JSON verbatim, not five
  holding its parts.
- Auth headers are stripped before the guest sees the request. A guest can
  neither read a client's token nor forge one.

### Step 2, in full

This is the part worth implementing carefully; it is what the whole design rests
on. Given the document bytes from `x-enclave-attestation`:

1. **Signature and chain.** COSE_Sign1, ES384. `cabundle` is ordered root
   first; the chain to check is `cabundle` in order, then `certificate`. Every
   certificate except the leaf must be a CA, each must be validly issued by the
   one before it, and each must be inside its validity window.
2. **Root.** The presented root must equal the one you pinned. Do not accept
   "some root" — see [Dev and production](#dev-and-production).
3. **PCR0**, against the value the image build published.
4. **PCR16**, against the value your component measures to. `nitro-attest
   --measure <component>.wasm` prints it, and the runtime computes it the same
   way.
5. **`user_data` binds this connection.** 68 bytes, two sha2-256 multihashes:

   ```
   0x12 0x20 ‖ sha256(tls_certificate_der) ‖ 0x12 0x20 ‖ sha256(guest_component)
   ```

   The first must equal sha256 of the DER of the certificate **this TLS
   connection was served**. That is what ties the document to the channel you
   are on; without it, a verified document proves an enclave exists somewhere,
   not that you are talking to it.
6. **Nonce** — the one you sent, echoed back. It is not optional: every request
   must carry `x-enclave-nonce` (unpadded base64url, 8–64 bytes), and one
   without it is refused with a 400 before routing, with no document.
7. **Age.** The document carries the enclave's own timestamp. Reject an old one.

Why both registers, since it is the usual question: PCR0 is measured by the
hypervisor from the image, so nothing inside the enclave can choose it — but the
image does not contain the guest. PCR16 is the guest, measured and locked by the
runtime before it could obtain a key — but because the *runtime* writes it, an
enclave running somebody else's runtime could claim your guest's value. PCR0
says the runtime that wrote PCR16 is yours; PCR16 says which application it
loaded. Neither substitutes for the other.

Guest responses deliberately carry no document. By then you have pinned the
certificate, and TLS proves the peer still holds its key — so **refuse any
connection that serves a different certificate**, and attest again before using
it. A certificate renewal looks exactly like that, and so does an interception;
a fresh document is what tells them apart.

### Attesting without a request

Every response under `/auth/` carries a document, whatever its status. To
attest the enclave without asking it for anything — at startup, or after the
certificate changed — send `GET /auth/` with a nonce: the answer is a 405, and
the document on it is the point. `nitro-attest --url https://<host>` does exactly
this.

### What the guest sees

Your component receives an ordinary `wasi:http` request with
`x-enclave-tenant` set to the caller's tenant, and a filesystem rooted at that
tenant's own directory. Path traversal out of it is refused by the runtime, not
by the guest. You do not have to implement tenant separation; you have to not
work around it.

## What changes in an existing verifier

A crate shaped like a pure-verification library — bytes in, no HTTP, no async —
is exactly the right shape. The changes are:

1. **Source of the document**: the `x-enclave-attestation` response header on
   `/auth/*`, not a GET endpoint.
2. **Add a trust-root parameter.** Default to the AWS Nitro root; allow an
   override. This is the only thing that differs between dev and production.
3. **Add PCR16** to what is pinned, alongside PCR0.
4. **Replace the `user_data` parser** with the multihash layout above, and
   actually compare against the served certificate — which means the HTTP layer
   has to hand the peer certificate down to the verifier.
5. **App side**: the options → assertion → verify → token sequence, and storing
   `credential_id` from registration.

### One decision to make

This repo's [`nitro-attestation`](../crates/nitro-attestation) crate already
does all of step 2–6 above, has no dependency on any enclave-side code by
design, and is what the runtime and every end-to-end leg are tested against.
Depending on it directly means one verifier instead of two implementations that
have to agree.

The catch is real, though: it verifies with `aws-lc-rs`, which needs a C
toolchain and CMake to cross-compile. A pure-Rust `p384`/`x509` stack is
friendlier for iOS and Android builds. So this is a trade-off — one maintained
verifier against an easier mobile build — and not an obvious win either way.

If you keep your own, the two things most worth copying are the chain order
(`cabundle` root-first, then the leaf) and the rule that a non-pinned root is
reported distinctly rather than accepted quietly.

## Dev and production

The difference is one value.

|  | dev enclave | production |
|---|---|---|
| trust root | the file `dev-enclave.sh` prints | omit — the AWS Nitro root |
| PCR0 | printed at startup | from the release image build |
| PCR16 | printed at startup | from your component's release build |
| CA | Pebble's root, also printed | a public root |

Everything else — the endpoints, the verification steps, the failure modes — is
identical. That is the point: you are not developing against a relaxed path and
meeting the real one in production.

**Do not set an "allow untrusted root" flag to make dev work.** A verifier that
accepts whatever root a document arrived with is checking nothing, and it will
pass in production too. Pin the dev root as a root; the code path is then the
same one production uses.

## What the local enclave does not prove

Worth being plain about, because it is easy to assume otherwise.

QEMU's emulated NSM does not sign anything — its source says *"we don't actually
sign the data, so we use -1 as the 'alg' value"*, and -1 is not a COSE algorithm
identifier. So the emulator image mints a certificate chain at boot and re-signs
the documents the device produced, contents untouched. Your client then runs its
whole verification path against something it can accept.

But the key is inside an image whoever runs it controls. A verified document
locally means *"this image said so"*, where on hardware it means *"a Nitro
enclave with this measurement said so"*. The root changes at every boot for
exactly that reason: there is deliberately nothing to hardcode into an app.

KMS is not exercised either — it will not release a key against a document it
cannot trace to a Nitro root, so the local image uses a static master key. On
hardware, a key policy pinning PCR0 and PCR16 is what stops a substituted guest
from reading anything; locally, a substituted guest boots and serves, and only
the client's PCR16 check refuses it.

Neither limitation affects the client code you write. Both are reasons to run
against real hardware before you ship.

## Settings the local enclave uses

| | |
|---|---|
| URL | `https://127.0.0.1:8443` (override with `--port`) |
| certificate name | `enclave.test`, issued by Pebble over real ACME |
| WebAuthn RP id | `enclave.test` |
| WebAuthn origin | `https://enclave.test` — claimed in the assertion, even though you connect to `127.0.0.1` |
| challenge TTL | 60s |
| token TTL | 60s, single use |

The origin is the one that trips people up: it is compared exactly, not by
suffix, so an assertion claiming `https://127.0.0.1:8443` is refused. Production
needs the RP id to be a domain your app is actually associated with.

## Reference client

[`runtime/src/bin/passkey-client.rs`](../runtime/src/bin/passkey-client.rs)
implements all of the above, including a software authenticator, and is the
executable answer when something here disagrees with it — it is what the end-to-end
harness drives, so it is known to work against a running enclave.

```bash
passkey-client --url https://127.0.0.1:8443 --state alice.json \
    --trust-root <printed> --pcr0 <printed> --pcr16 <printed> \
    get --path /whatever-your-guest-serves
```

`--dump-proof <dir>` writes the three things a verifier cannot recover
afterwards — the document, the certificate that connection was served, and the
nonce — which is the fastest way to test a verifier offline.
