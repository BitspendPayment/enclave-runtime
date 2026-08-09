#!/usr/bin/env bash
# Assemble an EIF containing the NSM self-test, for booting under QEMU's
# nitro-enclave machine.
#
# An EIF is a kernel, a cmdline and a stack of ramdisks. `nitro-cli` normally
# builds one from a Docker image, but it is not needed: the format is open and
# `eif_build` from aws-nitro-enclaves-image-format assembles one anywhere.
#
# The ramdisk layout is what the enclave `init` expects, which the strings in
# that binary spell out: it inserts nsm.ko itself, sends a vsock heartbeat to
# the parent, then reads /cmd and /env and executes inside /rootfs.
#
#   ramdisk 1   init, nsm.ko              (bootstrap)
#   ramdisk 2   rootfs/…, cmd, env        (the application)
#
# The payload is `nsm-selftest` from the nitro-nsm crate: statically linked
# against musl and pure Rust, so the ramdisk needs no shared libraries and no
# cross-compiling C toolchain.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${WORK:-$REPO/target/qemu-nitro}"
BLOBS="$WORK/blobs"
OUT="$WORK/selftest.eif"

mkdir -p "$WORK"

# --- the payload ------------------------------------------------------------
echo "== building nsm-selftest (static musl) =="
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
cargo build --release -p nitro-nsm --bin nsm-selftest --target x86_64-unknown-linux-musl
BIN="$REPO/target/x86_64-unknown-linux-musl/release/nsm-selftest"
file "$BIN" | grep -q "statically linked\|static-pie" \
    || { echo "FATAL: nsm-selftest is not static; it will not run in the ramdisk" >&2; exit 1; }

# --- kernel and init blobs --------------------------------------------------
# These come from aws-nitro-enclaves-cli. They are the same kernel and init a
# real enclave boots, which is the point: the harness should differ from
# production in the hypervisor, not in the guest.
if [[ ! -f "$BLOBS/bzImage" ]]; then
    echo "== fetching enclave kernel blobs =="
    rm -rf "$WORK/cli"
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/aws/aws-nitro-enclaves-cli "$WORK/cli"
    (cd "$WORK/cli" && git sparse-checkout set blobs)
    mkdir -p "$BLOBS"
    cp "$WORK/cli/blobs/x86_64/"{bzImage,bzImage.config,cmdline,init,nsm.ko} "$BLOBS/"
fi

# --- ramdisks ---------------------------------------------------------------
echo "== assembling ramdisks =="
rm -rf "$WORK/rd1" "$WORK/rd2"
# init mounts devtmpfs, procfs and sysfs and does not create the mountpoints
# first — a ramdisk without them dies with `mount: /dev: No such file or
# directory` before it reaches the application. cpio stores empty directories
# fine, they just have to be here.
# The mountpoints go in the *application* ramdisk, under rootfs/: init binds
# /rootfs onto itself and mounts the pseudo-filesystems inside it, so an empty
# rootfs/ dies with `mount: /dev: No such file or directory` — a message that
# reads as a bootstrap problem but is not. The list comes from the paths `init`
# itself references (strings(1) on the blob).
mkdir -p "$WORK/rd1"/{dev,proc,sys,rootfs} \
         "$WORK/rd2/rootfs"/{dev/pts,dev/shm,proc,sys/fs/cgroup,run,tmp}

cp "$BLOBS/init" "$WORK/rd1/init"
cp "$BLOBS/nsm.ko" "$WORK/rd1/nsm.ko"
chmod +x "$WORK/rd1/init"

cp "$BIN" "$WORK/rd2/rootfs/nsm-selftest"
chmod +x "$WORK/rd2/rootfs/nsm-selftest"
# `cmd` is the entrypoint, one argument per line; `env` is the environment.
printf '/nsm-selftest\n' > "$WORK/rd2/cmd"
printf 'PATH=/\n' > "$WORK/rd2/env"

# newc is what the kernel's initramfs loader expects.
(cd "$WORK/rd1" && find . -mindepth 1 -printf '%P\n' | cpio -o -H newc --quiet > "$WORK/ramdisk1.cpio")
(cd "$WORK/rd2" && find . -mindepth 1 -printf '%P\n' | cpio -o -H newc --quiet > "$WORK/ramdisk2.cpio")

# --- eif_build --------------------------------------------------------------
if ! command -v eif_build >/dev/null; then
    echo "== building eif_build =="
    cargo install --quiet --root "$WORK/tools" \
        --git https://github.com/aws/aws-nitro-enclaves-image-format eif_build
    export PATH="$WORK/tools/bin:$PATH"
fi

echo "== assembling EIF =="
eif_build \
    --kernel "$BLOBS/bzImage" \
    --kernel_config "$BLOBS/bzImage.config" \
    --cmdline "$(cat "$BLOBS/cmdline")" \
    --ramdisk "$WORK/ramdisk1.cpio" \
    --ramdisk "$WORK/ramdisk2.cpio" \
    --output "$OUT"

echo
echo "EIF: $OUT"
ls -la "$OUT"
