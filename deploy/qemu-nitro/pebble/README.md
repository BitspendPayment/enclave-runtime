# Pebble's own TLS material, for the QEMU e2e

Pebble is the ACME test CA the end-to-end runs against. Two different
certificates are involved and they are easy to confuse:

- **The certificates Pebble *issues*** — the enclave's serving certificate.
  Pebble generates a fresh root and intermediate at every startup and publishes
  them on its management port, so nothing about those is checked in.
- **The certificate Pebble *serves its own API under*** — that is what is here.
  The enclave has to validate it before it will send an ACME order, and it is
  reached at `https://192.168.127.254:14000/dir`, gvproxy's host address.

Pebble's built-in certificate is `CN=localhost` with no SAN for that address,
so the harness supplies its own.

| | |
|---|---|
| `ca.pem` | The root. Baked into `eif-qemu` at `/pebble-ca.pem` and named by `S3FS_ACME_CA`, so it is covered by PCR0 like any other configuration. |
| `cert.pem`, `key.pem` | Pebble's API certificate, SANs `192.168.127.254`, `127.0.0.1`, `localhost`, `pebble`. Mounted into the container. |

The CA's private key is **deliberately not here**: it was destroyed after
signing, so this root can never issue anything else. Both certificates are
valid for 100 years, which keeps `eif-qemu` reproducible — regenerating them on
each build would change PCR0 every time and make the measurement meaningless.

None of this is a secret and none of it is trusted by anything but the QEMU
harness. The production image ships no such file, and a production binary has
no `--acme-ca` flag to read one with.

To regenerate (only if a SAN must change):

```console
$ cd deploy/qemu-nitro/pebble
$ openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca-key.pem -out ca.pem -days 36500 \
    -subj "/CN=s3fs e2e Pebble test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
$ openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout key.pem -out csr.pem -subj "/CN=pebble.e2e"
$ cat > san.cnf <<'CNF'
[ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt
[alt]
IP.1 = 192.168.127.254
IP.2 = 127.0.0.1
DNS.1 = localhost
DNS.2 = pebble
CNF
$ openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -days 36500 -extfile san.cnf -extensions ext -out cert.pem
$ rm -f ca-key.pem ca.srl csr.pem san.cnf   # the CA key does not survive
```

PCR0 changes when `ca.pem` does, so `run-e2e.sh` will report the new
measurement and leg 4 keeps checking it against what `nix build` printed.
