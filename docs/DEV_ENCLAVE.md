# The development enclave

A real enclave on your own machine, to develop a client against.

```bash
sudo modprobe vsock_loopback                       # once per boot
docker build -t s3fs-qemu-nitro:latest deploy/qemu-nitro   # QEMU with the nitro-enclave machine; ~680 MB
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
| `--rp-id DOMAIN` | the WebAuthn relying party the image is built with. Default `enclave.test`; a phone app needs a domain whose `assetlinks.json` names it |
| `--allowed-origin ORIGIN` | an origin assertions may claim besides `https://<rp id>`, repeatable — `android:apk-key-hash:<hash>` for an Android app |
| `--keep-store` | keep the store in `target/qemu-nitro/<name>-store` and resume it on the next start with that name — see [Restarting](#restarting) |
| `--fresh` | with `--keep-store`, discard the kept store first |
| `--guest-egress ORIGIN` | an origin the guest may send requests to, `http(s)://host[:port]`, repeatable. None by default. The machine running the script is `192.168.127.254` from inside the enclave |
| `--background-timeout SECS` | how long one background task may run; the runtime's default is 30 |
| `--guest-env NAME=VALUE` | a variable for the guest, repeatable — e.g. the address of the origin it may reach |

Everything the run produced lives under `target/qemu-nitro/<name>/`: the console
log, the trust root, the passkey state files, and `fcm-messages.jsonl` — every
notification the guest raised, since Firebase is stubbed locally.

## On a public host

The same stack runs on a machine the internet can reach, which is how a client is tested against
something other than a laptop — a phone on a mobile network, a staging deployment. **It is test
infrastructure, not a trust boundary.** Everything in [What is not real](#what-is-not-real) still
holds and matters more once the host is not yours alone: whoever controls the host can read every
tenant's data (the master key is static and public in `flake.nix`) and sign any attestation document
(the chain is minted inside the image). Put test money behind it, never real money.

What changes:

| flag | |
|---|---|
| `--domain NAME` | serve `NAME` with a certificate from Let's Encrypt, validated over TLS-ALPN-01. `NAME` must resolve to the host and `--port` must be 443, reachable from the internet. Pebble is not started |
| `--acme-staging` | Let's Encrypt's staging CA. Prove issuance with it first: production allows five duplicate certificates a week, and nothing trusts a staging one |
| `--acme-contact EMAIL` | the contact registered with the CA |
| `--fcm-project ID --fcm-service-account FILE` | real Firebase notifications instead of the stub. The key is baked into the image, so it lands in the builder's Nix store and the EIF |
| `--memory SIZE` | the enclave's memory (QEMU `-m`). Default `3G`; the runtime with a small guest runs in `1536M` |
| `--store-bind ADDR` | publish MinIO on one address, e.g. `127.0.0.1`. Its credentials are the defaults; the enclave still reaches it through gvproxy |
| `--publish-hook CMD` | run `CMD <run dir>` once the enclave is up. The trust root is new every boot, so whatever clients read their pins from needs the new one |
| `--pack DIR` / `--prebuilt DIR` | build here, run there — below |

The host needs KVM (bare metal, or an instance with nested virtualisation — on EC2 the c8i, m8i and
r8i families), `vsock_loopback`, Docker, `python3`, `jq`, `curl`, `openssl`, and for an unprivileged
user on :443, `sysctl net.ipv4.ip_unprivileged_port_start=443`.

### Build here, run there

Building needs Nix, cargo and this checkout; running needs none of them. `--pack DIR` builds the
image with the image options given and puts into `DIR` everything a run needs:

```
DIR/
├── image.env          every image option, the runtime revision, and the image tags below
├── eif/               s3fs-qemu.eif, pcr.json
├── bin/               gvproxy (static); nitro-attest, passkey-client, vhost-device-vsock (libc only)
├── images/            qemu.tar.gz, minio.tar.gz — the container images, loaded on first run
├── deploy/qemu-nitro/ this harness, as it was when the image was built
├── scripts/           lib.sh, minio-up.sh, minio-image.sh, wasi-sdk.sh
└── wit/               what guests are built against, for a consumer's drift check
```

A bundle runs from its own copy of the harness, so nothing from this repository has to be beside
it — not a checkout, not the QEMU image, not Nix, cargo or git:

```
DIR/deploy/qemu-nitro/dev-enclave.sh --prebuilt DIR --guest component.wasm --port 443 --keep-store ...
```

The host needs KVM the user can open, `vsock_loopback` (`sudo modprobe vsock_loopback`), Docker,
`python3`, `jq`, `curl` and `openssl`; on a GitHub-hosted runner `/dev/kvm` is root-owned and needs
the udev rule `scripts/lib.sh`'s `prepare_enclave_host` applies. Image options are refused with
`--prebuilt`: the image is what was packed, and `image.env` says what that was. `QEMU_IMAGE` and
`MINIO_IMAGE` in the environment override the tags the bundle recorded. Extract a bundle at a
short path: its sockets live under `DIR/target/qemu-nitro/<name>/`, and a Unix socket path is at
most 107 bytes — past that `vhost-device-vsock` fails with "path must be shorter than SUN_LEN".

`scripts/ci-pack.sh OUT PROFILE [image options...]` is the whole release step: it packs, tars the
bundle as `dev-enclave-PROFILE-<rev>.tar.gz` with a `.sha256`, and then runs `run-e2e.sh` — all
eight legs — from an extracted copy with nothing pointing at the checkout. The "Publish a dev
enclave" workflow runs it on a hosted runner and attaches the result to a release named after the
profile and the revision. One bundle is one configuration: image options are measured into PCR0,
so a consumer publishes the options its harness expects, pins the bundle built from them, and
checks `image.env` against them before booting.

The attestation chain the emulator mints is valid for 30 days, so a long-running host has to be
restarted within that — with `--keep-store`, a restart costs nothing but new pins.

## Restarting

Stop it and start it again with the new component. By default that is a fresh
start, not a reload: the store is rebuilt, so the enclave boots into genesis
rather than resuming, and PCR16 changes. A client still pinning the old
measurement will refuse the new enclave, which is the behaviour you want to see.

With `--keep-store` the store survives. MinIO's data lives in
`target/qemu-nitro/<name>-store/minio` instead of inside its container, so the
next start with the same name finds the receipt and the store together and
**resumes**: every tenant, passkey and file a guest wrote is still there. A new
component is an **upgrade** of that store — the boot machine records the new
pair — not a new one. Two things still change every boot, and clients have to
re-read them: the trust root, minted fresh by design, and PCR16 whenever the
component did.

Pebble also starts a new CA every time, while a kept store holds the certificate
an earlier Pebble issued and serves it until renewal. So with `--keep-store`
every root and intermediate seen is kept in the store directory, and
`pebble-root.pem` holds all of them — trust that whole file. The store directory
also carries an `id`, stable across restarts, for clients that keep state per
store. `--fresh` (with `--keep-store`) deletes the directory and starts over;
so does deleting it by hand while the enclave is down.

## If it does not start

| | |
|---|---|
| `no /dev/vsock` | `sudo modprobe vsock_loopback` |
| `no /dev/kvm` | the `nitro-enclave` machine needs KVM; it will not run in a VM without nested virtualisation |
| `missing QEMU image` | `docker build -t s3fs-qemu-nitro:latest deploy/qemu-nitro` |
| `... is not tracked by git` | Nix flakes copy only tracked files; `git add deploy/qemu-nitro/` |
| the enclave never reported a trust root | `S3FS_COSIGN_ATTESTATIONS` is unset in the image — check `eif-qemu`'s environment in `flake.nix` |
| a port is in use | `--port`, and `--name` if you want two at once |
