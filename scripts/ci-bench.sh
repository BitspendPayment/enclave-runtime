#!/usr/bin/env bash
# The two criterion benches, in the form the tracker can read.
#
# `instance_cost` measures what a warm instance saves over a fresh one, and it
# runs the real component — so the guest has to be built before cargo is asked
# for a number, or the bench panics with a build hint instead of producing one.
# `fs_hot_paths` runs over the in-memory backend and needs nothing.
#
# `--output-format bencher` is criterion's libtest-compatible output, which is
# what github-action-benchmark reads as `tool: cargo`. Criterion's own format is
# richer and completely opaque to it.
#
# Worth saying plainly: numbers from a shared runner carry its neighbours in
# them. The tracked history is for spotting a change of shape over many runs,
# not for trusting any single figure — which is why the alert threshold in the
# workflow is deliberately loose and never fails the build.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

"$REPO/scripts/build-guest.sh" http

say "benchmarks"
# Each bench target is named rather than swept up with `--workspace`. Everything
# after `--` is handed to *every* target cargo runs, and in bench profile that
# includes each crate's libtest harness — which does not know `--output-format`,
# rejects it, and fails the whole run before a single benchmark executes. Naming
# the two `harness = false` criterion targets keeps the flag with the only
# harnesses that understand it.
#
# lib.sh sets `pipefail`, so a failing cargo still fails the script despite tee.
: > "$REPO/bench.txt"
cargo bench -p enclave-runtime --bench instance_cost -- --output-format bencher \
    | tee -a "$REPO/bench.txt"
cargo bench -p s3fs-core --bench fs_hot_paths -- --output-format bencher \
    | tee -a "$REPO/bench.txt"

echo "wrote $REPO/bench.txt"
