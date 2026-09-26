#!/usr/bin/env bash
# Build one example guest to a wasm32-wasip2 component.
#
#   build-guest.sh http | grpc | sqlite
#
# Each example is its own cargo workspace, so these do not share the root
# target/ directory and have to be built by name rather than swept up by
# `--workspace`.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

guest="${1:?which guest: http, grpc or sqlite}"
dir="$REPO/examples/guest-$guest"
[[ -d "$dir" ]] || fail "no such guest: examples/guest-$guest"

cd "$dir"

# Only the SQLite guest compiles C. Its sysroot comes from wasi-sdk, which
# scripts/wasi-sdk.sh puts in place; the rest of the guests need no C toolchain
# at all, which is why this is a special case rather than the default.
if [[ "$guest" == "sqlite" ]]; then
    sdk="${WASI_SDK:-$HOME/wasi-sdk}"
    [[ -x "$sdk/bin/clang" ]] || fail "no wasi-sdk at $sdk — run scripts/wasi-sdk.sh first"
    export CC_wasm32_wasip2="$sdk/bin/clang"
    export AR_wasm32_wasip2="$sdk/bin/ar"
    export CFLAGS_wasm32_wasip2="--sysroot=$sdk/share/wasi-sysroot -DSQLITE_THREADSAFE=0 -DHAVE_USLEEP=1"
fi

say "building guest-$guest"
cargo build --release --target wasm32-wasip2

echo "built $dir/target/wasm32-wasip2/release/guest-$guest.wasm"
