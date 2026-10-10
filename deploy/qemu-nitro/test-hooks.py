#!/usr/bin/env python3
"""Stop the enclave at a named point in an anchor, for tests that play the host.

The runtime's testing build dials this port at a few points in an anchor
(`hook` in runtime/src/zfs.rs), sends `<point> <detail>`, and waits for one line
back: `continue` or `abort`. Rules come from files in <dir>, so a test can copy
the disk at an exact moment, or kill the enclave between two steps:

  <dir>/hooks.rules    `<point> hold|abort`, one per line; each fires once
  <dir>/hooks.release  a held point goes on once its name is a line here, once
                       per hold
  stdout               `<point> <detail> -> <action>` as each arrives

Anything without a rule continues. Listening on the host's AF_VSOCK, as
heartbeat.py does and for the same reason.

Usage: test-hooks.py <port> <dir>
"""
import os
import socket
import sys
import threading
import time

port, rundir = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()
fired = set()  # indexes of rule lines already used
held = {}  # point -> holds so far


def lines(name):
    try:
        with open(os.path.join(rundir, name)) as f:
            return [line.split() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def answer(conn):
    with conn:
        line = conn.makefile("r").readline().strip()
        point = line.split(" ", 1)[0]
        with lock:
            action = "continue"
            for i, rule in enumerate(lines("hooks.rules")):
                if i not in fired and rule[:1] == [point]:
                    fired.add(i)
                    action = rule[1]
                    break
            if action == "hold":
                held[point] = held.get(point, 0) + 1
                ordinal = held[point]
        print(f"{line} -> {action}", flush=True)
        if action == "hold":
            while sum(r[:1] == [point] for r in lines("hooks.release")) < ordinal:
                time.sleep(0.1)
            print(f"{point} released", flush=True)
            action = "continue"
        conn.sendall(f"{action}\n".encode())


srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
srv.bind((socket.VMADDR_CID_ANY, port))
srv.listen(8)
print(f"test-hooks: listening on vsock port {port}", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=answer, args=(conn,), daemon=True).start()
