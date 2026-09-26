#!/usr/bin/env bash
# A dev enclave, built here and runnable anywhere: the bundle a release carries.
#
#   scripts/ci-pack.sh OUT PROFILE [image options...]
#
# Packs the image with the image options given (`dev-enclave.sh --pack`), tars
# it as dev-enclave-PROFILE-<rev>.tar.gz beside a .sha256, and then proves the
# tarball is what it claims by running the whole stack from an extracted copy —
# deploy/qemu-nitro/run-e2e.sh, all eight legs, with BUNDLE pointing at the copy
# and nothing pointing at this checkout. A bundle that needs something outside
# itself fails here, not on a host that has nothing else.
#
# Needs what building an enclave needs: Nix, cargo, Docker, and a clean
# checkout; and what running one needs, which prepare_enclave_host supplies.
# The example guest is what the smoke boots; a bundle carries no guest, and
# whoever runs it names their own.
#
# Image options fix PCR0, so one bundle is one configuration. A consumer
# repository publishes the options its harness expects and pins the bundle
# built from them — see docs/DEV_ENCLAVE.md.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

out="${1:-}"; profile="${2:-}"
[[ -n "$out" && -n "$profile" ]] || fail "usage: ${0##*/} OUT PROFILE [image options...]"
[[ "$profile" =~ ^[A-Za-z0-9._-]+$ ]] || fail "a profile is a name, not a path: $profile"
shift 2
out="$(mkdir -p "$out" && cd "$out" && pwd)"

prepare_enclave_host

rev="$(git rev-parse --short HEAD)"
# A release is built from a commit, so its name means something. Iterating on the pack itself is
# the one time a dirty tree is the point; ALLOW_DIRTY says so, and the name says so too.
if ! git diff --quiet HEAD; then
    [[ -n "${ALLOW_DIRTY:-}" ]] || fail "the checkout is dirty; a bundle is built from a commit (ALLOW_DIRTY=1 to pack anyway)"
    rev="$rev-dirty"
fi
name="dev-enclave-$profile-$rev"

say "packing $name"
# --name keeps this run's directory apart from any enclave already up on this machine.
deploy/qemu-nitro/dev-enclave.sh --name pack --pack "$out/$profile" "$@"

say "the tarball"
tar -C "$out" --transform "s,^$profile,$name," -czf "$out/$name.tar.gz" "$profile"
(cd "$out" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
ls -la "$out/$name.tar.gz" | awk '{print $5, $9}'

say "the smoke: the whole stack, from the tarball alone"
nix build "$REPO#guest-release" --out-link "$out/guest" --print-build-logs >/dev/null
rm -rf "$out/smoke"; mkdir -p "$out/smoke"
tar xzf "$out/$name.tar.gz" -C "$out/smoke" --strip-components=1
# The guest out of the store — through nix-portable's chroot when that is what `nix` is here,
# as deploy/qemu-nitro/lib.sh's resolve_out_link does.
guest="$(readlink -f "$out/guest" 2>/dev/null || true)"
[[ -d "$guest" ]] || guest="$HOME/.nix-portable$(readlink "$out/guest")"
[[ -f "$guest/guest.wasm" ]] || fail "no guest behind $out/guest"
# From the copy, not the checkout: its own lib.sh, its own scripts, its own images.
BUNDLE="$out/smoke" GUEST_WASM="$guest/guest.wasm" "$out/smoke/deploy/qemu-nitro/run-e2e.sh"

say "bundle ready"
echo "$out/$name.tar.gz"
cat "$out/$name.tar.gz.sha256"
