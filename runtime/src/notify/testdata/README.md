A throwaway RSA key, generated for the `notify::oauth` tests and used nowhere
else. It signs assertions to a token endpoint that only exists in those tests.

It is committed for the same reason `deploy/qemu-nitro/pebble/key.pem` is: a
test that generates a 2048-bit key on every run pays for it on every run, and a
fixture makes the tests deterministic. Nothing outside `#[cfg(test)]` reads it.
