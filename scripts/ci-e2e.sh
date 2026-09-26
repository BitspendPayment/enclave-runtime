#!/usr/bin/env bash
# The whole stack, in an emulated enclave.
#
# deploy/qemu-nitro/run-e2e.sh is the harness and asserts its own preconditions;
# this script is what puts them in place on a machine that has none of them. On
# a workstation that already boots enclaves, everything below is a no-op and the
# harness runs directly.
#
# Nested virtualisation on GitHub-hosted runners works but is not supported by
# GitHub, so this is the one job here that can fail for reasons outside this
# repository. Everything it needs is installed explicitly rather than assumed,
# so that when it does fail the log says which part was missing.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

# The in-process suites first, against the same guest, before anything is
# booted. They are minutes where the emulated enclave is the better part of an
# hour, and they fail on the layer at fault — a TLS or gRPC framing bug found
# here names itself, where the same bug found through QEMU is a timeout with a
# console log to read. Folded into this job rather than kept as their own so
# there is one integration signal, not two.
"$REPO/scripts/ci-guests.sh"

# The block store against a real S3 implementation, folded in for the same
# reason. It starts its own MinIO through testcontainers, so it needs nothing
# from the harness below and nothing from the store the enclave will mount.
"$REPO/scripts/ci-storage.sh"

# KVM, vsock, the QEMU image and vhost-device-vsock — see scripts/lib.sh.
prepare_enclave_host

exec deploy/qemu-nitro/run-e2e.sh
