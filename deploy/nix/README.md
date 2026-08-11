# Building the enclave image

```console
$ nix build .#eif          # → result/s3fs.eif, result/pcr.json
$ jq -r .PCR0 result/pcr.json
42dfa2f7f828fd1dbb955a8d8c00537c4545d56467e850254f72bd80627c35fa…
```

## Why Nix, only here

PCR0 is a digest of the enclave image. A KMS key policy pins it and a client
checks it, and the whole value of that number is that somebody else can rebuild
the image and get the same one. The Dockerfile this replaced ran `apt-get
update` over `debian:bookworm-slim`, so it produced a different PCR0 every week
and attested to nothing anyone could reproduce.

The parent instance is built with Packer instead, and that is not
inconsistency. The parent is the party the enclave *excludes*: PCR0 covers what
runs inside the enclave and says nothing about its host, so reproducing the
host buys no security property at all.

## Outputs

| | |
|---|---|
| `.#eif` | the production image, with `pcr.json` |
| `.#eif-qemu` | the same code configured for the emulator — different config, therefore a different PCR0 |
| `.#eif-selftest` | the tiny NSM entropy check |
| `.#enclave-runtime`, `.#guest-http`, `.#nitro-attest` | the binaries |
| `.#gvproxy` | both ends of the vsock, built static |

## Reproducibility, and what it cost

`nix build .#eif --rebuild` rebuilds and compares. Getting that to pass took
four things, none of which was obvious from a failure message:

- **`cpio --reproducible`.** The `newc` header records each file's inode and
  device numbers, which are whatever the filesystem handed out. Without this
  even the *bootstrap* ramdisk — two files that never change — came out
  different on every build, and PCR1 with it.
- **`--owner=0:0` and a fixed mtime.** Store paths already carry epoch+1; the
  directories created during assembly do not.
- **Sorted members.** cpio records the order it is given, and `find` does not
  promise one. `LC_ALL=C sort` also keeps parents ahead of their children.
- **`faketime`.** `eif_build` stamps wall-clock `BuildTime` into the image's
  metadata. No PCR covers metadata, so the *measurements* were reproducible
  without this — but the file differed by 15 bytes, which is enough to make
  anyone comparing artifacts by hash think something was wrong.

A pinned lock file for `eif_build` is in this directory for a related reason:
upstream gitignores theirs, and letting the dependency set of the tool that
*computes PCR0* float would mean the measurement came from something slightly
different each time.

## What is still taken on trust

The kernel, `init` and `nsm.ko` are AWS's prebuilt blobs, pinned by hash. Every
build therefore uses identical bytes, but their provenance is not verifiable
from here — they are the one opaque input to PCR0. AWS publishes
[`aws-nitro-enclaves-sdk-bootstrap`](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap),
which builds them from source *with nixpkgs*; adopting it would close the gap
at the cost of a kernel compile.

## Running Nix without root

The flake is ordinary and works with any Nix. On a machine where you cannot
install the daemon, [`nix-portable`](https://github.com/DavHau/nix-portable)
gives a working `nix` in userspace:

```console
$ curl -L -o ~/.local/bin/nix-portable \
    https://github.com/DavHau/nix-portable/releases/latest/download/nix-portable-x86_64
$ chmod +x ~/.local/bin/nix-portable && ln -s ~/.local/bin/{nix-portable,nix}
```

Two consequences worth knowing. `nix run` and `nix shell` need a mount
namespace it cannot always get, so use `nix build` and run the result. And the
store lives at `~/.nix-portable/nix/store`, so `result/` is a symlink that only
resolves inside its namespace — the harness scripts translate the path, and
that branch is dead on a normal install.
