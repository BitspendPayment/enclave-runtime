#!/usr/bin/env bash
# Formatting, lints, and every test that needs nothing built beside it.
#
# The fast gate. Nothing here needs a wasm guest, Docker, or a network, so it is
# the job that should fail first when something is simply wrong.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

say "rustfmt"
cargo fmt --all -- --check

# `--all-targets` so the lints cover tests and benches too, and `-D warnings`
# because a lint nobody has to fix is a lint that accumulates.
say "clippy"
cargo clippy --workspace --all-targets -- -D warnings

say "unit tests"
cargo test --workspace --lib

# Integration suites run only where they are named, and this one ran nowhere
# before. It is the boot machine — genesis, resume, upgrades and the refusals —
# over the in-memory backend, so it needs no guest built.
say "boot machine"
cargo test -p enclave-runtime --test boot_origin
