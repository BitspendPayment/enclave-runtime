#!/usr/bin/env bash
# Common to every script here.
#
# These recipes used to live inline in .github/workflows/ci.yml, which meant the
# only way to run a CI job was to push and wait. Everything in this directory
# runs the same way on a laptop as it does on a runner — that is the whole point
# of the directory existing.
#
# Sourced, not executed: `. "$(dirname "$0")/lib.sh"`.

set -euo pipefail

# Not `dirname $0/..`: a script invoked through a symlink or from another
# directory would resolve somewhere else, and every path below is repo-relative.
REPO="$(git rev-parse --show-toplevel)"
export REPO

# The same shape deploy/qemu-nitro/run-e2e.sh prints, so a run that spans both
# reads as one log rather than two conventions meeting in the middle.
say() { printf '\n== %s ==\n' "$*"; }

fail() {
    printf '\nFAIL: %s\n' "$*" >&2
    exit 1
}
