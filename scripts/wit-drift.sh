#!/usr/bin/env bash
# Every vendored WIT copy must equal the canonical one under wit/.
#
# A guest vendors its own copy because wit-bindgen reads a path inside the
# guest's crate. Two copies of an interface that must be byte-identical is
# exactly the thing that drifts unnoticed: both sides still compile, and the
# mismatch surfaces much later as a runtime trap in a component that looked fine.
#
# A loop rather than the single hard-coded `cmp` this replaces. Today only
# guest-http vendors anything, so the old check was complete — but the next
# guest to vendor a copy would have been silently uncovered, and nothing would
# have said so.

set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
cd "$REPO"

status=0
found=0

while IFS= read -r copy; do
    found=$((found + 1))
    base="$(basename "$copy")"

    # Matched by basename across wit/, not by a constructed path: the canonical
    # file is wit/tasks/tasks.wit, not wit/tasks.wit, and hard-coding either
    # shape breaks on whichever one comes next.
    mapfile -t canonical < <(find wit -type f -name "$base" | sort)
    case "${#canonical[@]}" in
        1) ;;
        0)
            echo "no canonical WIT for $copy (looked for $base under wit/)" >&2
            status=1
            continue
            ;;
        *)
            echo "ambiguous: $base exists at ${canonical[*]}" >&2
            status=1
            continue
            ;;
    esac

    if cmp -s "$copy" "${canonical[0]}"; then
        echo "ok     $copy == ${canonical[0]}"
    else
        echo "DRIFT  $copy differs from ${canonical[0]}" >&2
        diff -u "${canonical[0]}" "$copy" >&2 || true
        status=1
    fi
done < <(find examples -type f -path '*/wit/*.wit' -not -path '*/target/*' | sort)

# A check that silently covers nothing is worse than no check, because it still
# reports green. If the vendored copies move, this says so instead.
if (( found == 0 )); then
    echo "no vendored WIT found under examples/*/wit/ — this check has stopped checking anything" >&2
    exit 1
fi

exit "$status"
