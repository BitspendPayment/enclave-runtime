#!/usr/bin/env python3
"""Serve a disk image to the enclave over vsock, as the parent's EBS volume.

The ZFS storage spike (runtime/src/zfs.rs) keeps tenant data on a block device
the parent serves with NBD. On Nitro that is `nbdkit --vsock` over an attached
EBS volume. Here it is this script over a sparse file, for the same reason the
heartbeat is a script: nbdkit is not on a developer's machine, and the store's
own nbdkit from Nix cannot run outside nix-portable's namespace.

Only what the enclave's client sends is implemented: the fixed-newstyle
handshake with NBD_OPT_EXPORT_NAME, then READ, WRITE (with FUA), FLUSH and
DISC. Requests are answered in order, one connection at a time. Slow next to
nbdkit, which makes the spike's latency figures pessimistic, not optimistic.

The parent sees only dm-crypt ciphertext, so nothing here is trusted: tests
replay or roll back this file to play the hostile host.

Usage: nbd-stub.py <port> <image>
"""
import os
import socket
import struct
import sys

NBDMAGIC = 0x4E42444D41474943
IHAVEOPT = 0x49484156454F5054
REQUEST_MAGIC, REPLY_MAGIC = 0x25609513, 0x67446698
FIXED_NEWSTYLE, NO_ZEROES = 1, 2
HAS_FLAGS, SEND_FLUSH, SEND_FUA = 1, 4, 8
READ, WRITE, DISC, FLUSH = 0, 1, 2, 3
CMD_FLAG_FUA = 1
EINVAL = 22

port, image = int(sys.argv[1]), sys.argv[2]


def read_exact(conn, n):
    b = bytearray()
    while len(b) < n:
        chunk = conn.recv(n - len(b))
        if not chunk:
            raise EOFError
        b += chunk
    return bytes(b)


def serve(conn, fd):
    size = os.fstat(fd).st_size
    conn.sendall(struct.pack(">QQH", NBDMAGIC, IHAVEOPT, FIXED_NEWSTYLE | NO_ZEROES))
    (client_flags,) = struct.unpack(">I", read_exact(conn, 4))
    magic, option, length = struct.unpack(">QII", read_exact(conn, 16))
    read_exact(conn, length)  # the export name; there is only one
    if magic != IHAVEOPT or option != 1:
        print(f"nbd: unsupported option {option}, closing", flush=True)
        return
    conn.sendall(struct.pack(">QH", size, HAS_FLAGS | SEND_FLUSH | SEND_FUA))
    if not client_flags & NO_ZEROES:
        conn.sendall(bytes(124))
    print(f"nbd: serving {image} ({size} bytes)", flush=True)

    while True:
        magic, flags, kind, handle, offset, length = struct.unpack(">IHHQQI", read_exact(conn, 28))
        if magic != REQUEST_MAGIC:
            print("nbd: bad request magic, closing", flush=True)
            return
        if kind == DISC:
            return
        error, data = 0, b""
        if kind == READ:
            data = os.pread(fd, length, offset)
        elif kind == WRITE:
            os.pwrite(fd, read_exact(conn, length), offset)
            if flags & CMD_FLAG_FUA:
                os.fdatasync(fd)
        elif kind == FLUSH:
            os.fdatasync(fd)
        else:
            error = EINVAL
        conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, error, handle) + data)


srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
srv.bind((socket.VMADDR_CID_ANY, port))
srv.listen(1)
print(f"nbd: listening on vsock port {port}", flush=True)

while True:
    conn, _ = srv.accept()
    # Reopened per connection, so a test can swap the image between boots.
    fd = os.open(image, os.O_RDWR)
    try:
        with conn:
            serve(conn, fd)
    except (EOFError, ConnectionError) as e:
        print(f"nbd: connection ended: {e!r}", flush=True)
    finally:
        os.close(fd)
