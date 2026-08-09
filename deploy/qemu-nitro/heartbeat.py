#!/usr/bin/env python3
"""Answer the enclave init's boot heartbeat.

A real enclave's `init` proves it is alive to the parent instance: it connects
to the parent over vsock on port 9000, writes one byte (0xB7) and waits to read
the same byte back. Only then does it run the application. There is no timeout
and no fallback — with nobody listening, the enclave boots the kernel, prints
nothing further, and sits there. That silence looks exactly like a broken image,
which is why this tiny thing exists as its own file rather than an inline
one-liner: it is the first thing to check when a boot appears to hang.

On real hardware the parent side is `nitro-cli`. Here the parent is this
script, listening on the host's own AF_VSOCK. It cannot be a Unix socket:
`vhost-device-vsock`'s `uds-path` backend only accepts packets addressed to the
host CID (2), and the enclave dials **CID 3**, the Nitro parent convention. It
drops the rest with `dropping packet for unknown cid: 3`. So the backend runs
with `forward-cid=1` instead, which turns the guest's connection into a real
host vsock connection to the loopback CID — and that needs `vsock_loopback`
loaded on the host.

Usage: heartbeat.py <port>
"""
import socket
import sys

port = int(sys.argv[1])

srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
srv.bind((socket.VMADDR_CID_ANY, port))
srv.listen(8)
print(f"heartbeat: listening on vsock port {port}", flush=True)

while True:
    conn, _ = srv.accept()
    with conn:
        data = conn.recv(1)
        if not data:
            continue
        print(f"heartbeat: received 0x{data[0]:02x}, echoing", flush=True)
        conn.sendall(data)
