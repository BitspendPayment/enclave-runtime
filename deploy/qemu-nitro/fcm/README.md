A test service account for the end-to-end harness, and the stub it talks to.

`service-account.json` is a throwaway RSA key with a `token_uri` pointing at
`fcm-stub.py` on the host rather than at Google. It is committed for the same
reason `../pebble/key.pem` is: the emulator image has to carry *something*, and
a fixture keeps the run deterministic. Nothing outside this directory reads it,
and the production image sets these values empty.

It is minified on purpose. `nix/eif.nix` writes the image environment as
`KEY=value` lines joined by newlines, so a raw newline in the value would split
one setting into two.
