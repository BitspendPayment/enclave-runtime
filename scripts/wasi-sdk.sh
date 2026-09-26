#!/usr/bin/env bash
# Put wasi-sdk where the SQLite guest's C toolchain can find it.
#
# Idempotent: with the SDK already unpacked this exits immediately, which is
# what makes the CI cache worth having and what lets a developer run
# ci-sqlite.sh repeatedly without re-downloading 110 MB.
#
# The download used to be `curl -sSL` with no `-f`. Without it a non-2xx
# response is written to the tarball as HTML and the failure surfaces two steps
# later inside `tar`, complaining about the archive format and naming nothing
# that would lead you to the real cause.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

WASI_SDK_VERSION="${WASI_SDK_VERSION:-25}"
WASI_SDK_RELEASE="${WASI_SDK_RELEASE:-25.0}"
WASI_SDK="${WASI_SDK:-$HOME/wasi-sdk}"

# wasi-sdk publishes no checksum file with its releases — the assets are the
# tarballs and nothing else — so this is the hash of the artifact this repo was
# tested against, recorded here rather than taken on trust from the network
# every run. Recompute with:
#   sha256sum wasi-sdk-25.0-x86_64-linux.tar.gz
WASI_SDK_SHA256="${WASI_SDK_SHA256:-52640dde13599bf127a95499e61d6d640256119456d1af8897ab6725bcf3d89c}"

if [[ -x "$WASI_SDK/bin/clang" ]]; then
    echo "wasi-sdk already at $WASI_SDK"
    exit 0
fi

say "installing wasi-sdk $WASI_SDK_RELEASE"

tarball="$(mktemp -d)/wasi-sdk.tar.gz"
url="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/wasi-sdk-${WASI_SDK_RELEASE}-x86_64-linux.tar.gz"

# --retry-all-errors so a transient 5xx from the release CDN is a pause rather
# than a failed run; -f so an error page is an error, not a tarball.
curl -fL --retry 3 --retry-all-errors --max-time 600 -o "$tarball" "$url" \
    || fail "could not download $url"

echo "$WASI_SDK_SHA256  $tarball" | sha256sum -c - \
    || fail "wasi-sdk checksum mismatch — the release was changed, or the download was truncated"

mkdir -p "$WASI_SDK"
tar xf "$tarball" -C "$WASI_SDK" --strip-components=1
rm -rf "$(dirname "$tarball")"

[[ -x "$WASI_SDK/bin/clang" ]] || fail "unpacked wasi-sdk has no bin/clang at $WASI_SDK"
echo "wasi-sdk $WASI_SDK_RELEASE installed at $WASI_SDK"
