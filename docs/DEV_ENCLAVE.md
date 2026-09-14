# The development enclave

A real enclave on your own machine, to develop a client against.

```bash
sudo modprobe vsock_loopback                       # once per boot
docker build -t s3fs-qemu-nitro:latest deploy/qemu-nitro
cargo install vhost-device-vsock --root target/qemu-nitro/tools

deploy/qemu-nitro/dev-enclave.sh --guest path/to/your-component.wasm
```

It prints the URL and the three values a client must pin, then stays up until
you stop it.

This is the same stack [`run-e2e.sh`](../deploy/qemu-nitro/run-e2e.sh) asserts
against — both scripts share
[`deploy/qemu-nitro/lib.sh`](../deploy/qemu-nitro/lib.sh), so the thing you
develop against is the thing CI checks. The difference is only what happens
after the enclave starts serving: the e2e asserts and exits, this waits.

## What is real

The enclave boots as an EIF under QEMU's `nitro-enclave` machine — the same
image format and the same boot path as production, measured into PCR0 by the
hypervisor. It takes its address by DHCP over emulated vsock, mounts the
encrypted block store over that link, fetches your component from the store and
measures it into PCR16 before it can obtain a key, orders a certificate from a
CA over RFC 8555 TLS-ALPN-01, and gates every request on a WebAuthn assertion
bound to that exact request.

Your client verifies the attestation document by signature, certificate chain,
validity window, pinned root and both measurements — the same code path, with
the same flags, that it will run against hardware.

## What is not real

**The key that signs attestation documents.** QEMU's NSM implements the protocol
but not the signing; its source says *"we don't actually sign the data, so we use
-1 as the 'alg' value"*, and -1 is not a COSE algorithm identifier. So the
emulator image mints a certificate chain at boot and re-signs what the device
produced, contents untouched
([`runtime/src/testing/cosign.rs`](../runtime/src/testing/cosign.rs)).

The key lives inside an image its operator controls, so a verified document here
means *"this image said so"*, where on hardware it means *"a Nitro enclave with
this measurement said so"*. That gap needs hardware and nothing local can close
it. The root changes at every boot for exactly that reason: there is deliberately
nothing here to hardcode into an app.

Before this, every client against the emulator had to pass `--unsigned-emulator`,
which skips the signature, the chain and the validity windows — most of what a
client does, and the part most worth exercising before it meets hardware.

**KMS.** It will not release a key against a document it cannot trace to a Nitro
root, so the emulator image uses a static master key. On hardware, a key policy
pinning PCR0 and PCR16 is what stops a substituted guest from reading anything;
locally, a substituted guest boots and serves. The e2e's leg 8 shows the half
that *is* testable: the enclave measures whatever it fetched, and a client
pinning the approved guest refuses it.

**The CA.** Certificates come from [Pebble](https://github.com/letsencrypt/pebble),
Let's Encrypt's test server. The protocol is real RFC 8555 — directory, account,
order, TLS-ALPN-01 challenge, finalize, and a certificate sealed into the store —
but no public root signs it, so a client needs Pebble's root as well, printed as
`--ca` on startup. A real client should pin the certificate out of the
attestation document instead, which is what the document binds it for.

## Must PCR0 always be zero?

No, and it is not. Under QEMU, PCR0 is a genuine measurement of the image, and
the e2e checks that the value the enclave attests is byte-for-byte the value
`nix build` printed:

```
PCR0  build:    8f2026d5a6c50479e27152c06ca86852ce0ec9528efd5f…
      attested: 8f2026d5a6c50479e27152c06ca86852ce0ec9528efd5f…
```

Change anything in the image — code, or a setting in `eif-qemu`'s environment —
and PCR0 changes, because an enclave image is its configuration as much as its
code. The emulator's PCR0 differs from production's for that reason, which is
the honest outcome: a client can tell which it is talking to.

PCR0 is all zeroes only in the debug mode `nitro-cli run-enclave --debug-mode`
produces, which this image does not use. The one constant measurement in this
repo is in the in-process test harness
([`runtime/src/testing/mod.rs`](../runtime/src/testing/mod.rs)), which has no
image to measure.

## What a client pins

Three values, and none stands in for another:

| | what it says | why it alone is not enough |
|---|---|---|
| `--pcr0` | the runtime image, measured by the hypervisor | the image no longer contains the guest |
| `--pcr16` | your component, measured by the runtime before it could get a key | the runtime writes it, so a substituted *runtime* could claim your value |
| `--trust-root` | what the document chains to | says nothing about which enclave |

Pass `--pcr0` and `--pcr16` together: PCR0 says the runtime that wrote PCR16 is
yours, PCR16 says which application it loaded.

Do **not** pass `--allow-untrusted-root`. With it, verification accepts whatever
root the document arrived with and reports it as self-signed, so a "pinned" root
pins nothing. Without it the presented root must equal yours — the same
comparison a client makes against AWS's.

## Trying it

The repo's own client signs a WebAuthn assertion per request, which is the only
way anything reaches the guest:

```bash
target/release/passkey-client \
    --url https://127.0.0.1:8443 --state target/qemu-nitro/dev/alice.json \
    --trust-root target/qemu-nitro/dev/trust-root.der \
    --pcr0 <printed> --pcr16 <printed> \
    get --path /counter
```

Registration is open: any passkey may enrol and gets its own tenant. A second
`--state` file is a second tenant, which is how to check that one cannot see the
other's data.

To verify the attestation without touching the guest, `nitro-attest --url
https://127.0.0.1:8443/auth/` with the same three flags. The document rides on
the `/auth/` exchange, which needs no credential — that is where a client
identifies the enclave before it approves anything.

## Options

| flag | |
|---|---|
| `--guest COMPONENT.wasm` | the component to serve. Without one, the example in `examples/guest-http` is built |
| `--port PORT` | host port forwarded to the enclave's `:443`. Default 8443 |
| `--name NAME` | names this run's containers and its directory under `target/qemu-nitro`. It keeps runs apart on disk; only one can be up at a time, because MinIO's port and the enclave's vsock CID are fixed |

Everything the run produced lives under `target/qemu-nitro/<name>/`: the console
log, the trust root, the passkey state files, and `fcm-messages.jsonl` — every
notification the guest raised, since Firebase is stubbed locally.

## Restarting

Stop it and start it again with the new component. That is a fresh start, not a
reload: the store is rebuilt, so the enclave boots into genesis rather than
resuming, and PCR16 changes. A client still pinning the old measurement will
refuse the new enclave, which is the behaviour you want to see.

## If it does not start

| | |
|---|---|
| `no /dev/vsock` | `sudo modprobe vsock_loopback` |
| `no /dev/kvm` | the `nitro-enclave` machine needs KVM; it will not run in a VM without nested virtualisation |
| `missing QEMU image` | `docker build -t s3fs-qemu-nitro:latest deploy/qemu-nitro` |
| `... is not tracked by git` | Nix flakes copy only tracked files; `git add deploy/qemu-nitro/` |
| the enclave never reported a trust root | `S3FS_COSIGN_ATTESTATIONS` is unset in the image — check `eif-qemu`'s environment in `flake.nix` |
| a port is in use | `--port`, and `--name` if you want two at once |
