#!/usr/bin/env python3
"""Write a guest's settings into its file, where the runtime reads them.

    guest-env.py GUEST.wasm NAME=VALUE...

The settings go into a custom section, `enclave-guest-env`, appended to the component in place.
The runtime reads it from the guest file it has just hashed into PCR16, so a guest's settings are
measured with its code: change one and PCR16 changes, exactly as changing the code does. That is
how a deployment configures the guest it uploads; the image carries no guest settings at all.

A file that already carries settings is refused: configure the guest as it was built.
"""

import re
import sys

SECTION = b"enclave-guest-env"
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def leb128(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def read_leb128(data, at):
    value = shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, at
        shift += 7


def has_settings(data):
    """Whether the component's own sections already include the settings section."""
    at = 8
    while at < len(data):
        section_id = data[at]
        size, at = read_leb128(data, at + 1)
        end = at + size
        if section_id == 0:
            name_len, name_at = read_leb128(data, at)
            if data[name_at:name_at + name_len] == SECTION:
                return True
        at = end
    return False


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    path, settings = argv[1], argv[2:]
    names = set()
    for setting in settings:
        name, sep, value = setting.partition("=")
        if not sep or not NAME.match(name) or "\n" in value:
            sys.exit(f"{setting!r}: expected NAME=VALUE on one line")
        if name in names:
            sys.exit(f"{name} is set twice")
        names.add(name)

    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"\0asm"):
        sys.exit(f"{path} is not a wasm file")
    if has_settings(data):
        sys.exit(f"{path} already carries settings: configure the guest as it was built")

    body = leb128(len(SECTION)) + SECTION + "".join(f"{s}\n" for s in settings).encode()
    with open(path, "ab") as f:
        f.write(b"\0" + leb128(len(body)) + body)


if __name__ == "__main__":
    main(sys.argv)
