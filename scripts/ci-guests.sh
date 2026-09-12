#!/usr/bin/env bash
# Serving a real guest: dispatch, transport, the gate, and background work.
#
# Everything here runs the real component through the real linker over the
# in-memory backend, so the whole dispatch path is covered without Docker or a
# network. The suites are `#[ignore]`d because they need a guest built first,
# which is why every one of them is run with `--include-ignored`.
#
# Every suite is named explicitly. There is no glob, so a suite nobody lists
# runs nowhere — which is how `serve_auth`, the suite for the entire
# authorization model, went uncovered for as long as it did.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

say "WIT drift"
"$REPO/scripts/wit-drift.sh"

"$REPO/scripts/build-guest.sh" http
"$REPO/scripts/build-guest.sh" grpc

# Built before the suites rather than between them: one of serve_auth's tests
# drives this real binary as a subprocess instead of a stand-in, and skips
# silently when it is missing. A skipped test that reports green is the failure
# mode worth spending a build on avoiding.
say "building the passkey client"
cargo build --release -p enclave-runtime --features testing --bin passkey-client

# A binary's own unit tests are not part of `--lib`, so they need naming. These
# are the measurements the client insists on before it approves anything.
# `--release` so this shares the compile with the binary just built.
say "passkey client"
cargo test --release -p enclave-runtime --features testing --bin passkey-client

say "background tasks"
cargo test -p enclave-runtime --lib tasks::tests -- --include-ignored

say "serving a guest"
cargo test -p enclave-runtime --test serve_guest -- --include-ignored

# The central claim: a client opens a real TLS connection and checks that the
# attestation document binds the certificate it just saw.
say "TLS termination and the attestation binding"
cargo test -p enclave-runtime --test serve_tls -- --include-ignored

# h2 is negotiated for the clients that ask, and every client that does not is
# untouched.
say "HTTP/2 negotiation, and HTTP/1.1 beside it"
cargo test -p enclave-runtime --test serve_h2 -- --include-ignored

# Both directions open at once: the guest answering while the client is still
# sending, backpressure, trailers, and what an open stream costs the tenant
# holding it.
say "bidirectional gRPC streaming"
cargo test -p enclave-runtime --test serve_grpc -- --include-ignored

# The same guest driven by tonic over TLS, so the guest's hand-written framing
# is checked against an implementation from outside this repo.
say "gRPC on the wire, with a real client"
cargo test -p enclave-runtime --test serve_grpc_wire -- --include-ignored

# The whole authorization model — challenge, assertion, token, scope, tenant
# isolation — and the only suite that checks an attestation document against the
# connection it arrived on.
say "interaction tokens, end to end"
cargo test -p enclave-runtime --test serve_auth -- --include-ignored

say "guest logging"
cargo test -p enclave-runtime --test guest_logs -- --include-ignored

# The verifier's own tests build the binary, so there is no separate build step
# here — nothing in CI executes the artifact itself.
say "verifier measurement requirements"
cargo test -p nitro-attestation --features cli --bin nitro-attest
