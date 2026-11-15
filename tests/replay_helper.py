#!/usr/bin/env python3
"""Unprivileged WLPC replay source used by faults.py; stdout is binary IPC only."""

import os
from pathlib import Path
import signal
import struct
import sys
import time


MAGIC = 0x574C5043
MODES = {"partial", "idle", "exit-zero", "exit-seven", "bad-wire", "oversize",
         "incomplete-tcp", "flows"}


def write(data):
    while data:
        n = os.write(1, data)
        if n <= 0:
            raise RuntimeError("short IPC write")
        data = data[n:]


def message(kind, payload):
    write(struct.pack("!III", MAGIC, kind, len(payload)) + payload)


def ethernet_tcp(sequence=100, flags=0x10, reverse=False, fragment=0):
    """Deterministic Ethernet / IPv4 / TCP with valid IPv4 checksum."""
    a, b = b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x02"
    sport, dport = 12345, 8081
    if reverse:
        a, b, sport, dport = b, a, dport, sport
    tcp = struct.pack("!HHIIBBHHH", sport, dport, sequence, 50, 0x50, flags, 4096, 0, 0)
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, fragment, 64, 6, 0, a, b))
    checksum = sum(struct.unpack("!10H", ip))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    struct.pack_into("!H", ip, 10, checksum ^ 65535)
    return bytes.fromhex("00112233445566778899aabb0800") + ip + tcp


def packet(data, index, wire_length=None):
    payload = struct.pack("!QII", 1700000000000000 + index * 1000,
                          len(data) if wire_length is None else wire_length, len(data)) + data
    message(2, payload)


def main():
    if len(sys.argv) != 4 or sys.argv[1] != "--capture" or sys.argv[2] not in MODES:
        return 2
    mode = sys.argv[2]  # The production BPF argument is deliberately ignored.
    root = Path(os.environ["WIRELENS_REPLAY_DIR"])
    # Atomic publication lets the runner target exactly the worker for this scenario.
    temporary = root / (mode + ".pid.tmp")
    temporary.write_text(str(os.getpid()), encoding="ascii")
    temporary.replace(root / (mode + ".pid"))
    if mode == "partial":
        write(b"W")
    else:
        message(1, struct.pack("!I", 1))  # DLT_EN10MB
        if mode == "bad-wire":
            packet(ethernet_tcp(), 0, wire_length=53)
        elif mode == "oversize":
            packet(bytes(65536), 0)
        elif mode == "incomplete-tcp":
            packet(ethernet_tcp(fragment=0x2000), 0)
            packet(ethernet_tcp(fragment=1), 1)
            packet(ethernet_tcp()[:44], 2, wire_length=54)
        elif mode == "flows":
            frames = [ethernet_tcp(sequence=90),
                      ethernet_tcp(sequence=100, flags=2),
                      ethernet_tcp(sequence=100, flags=2),
                      ethernet_tcp(sequence=900, flags=2, reverse=True),
                      ethernet_tcp(sequence=900, flags=2, reverse=True),
                      ethernet_tcp(sequence=200, flags=2)]
            for index, frame in enumerate(frames):
                packet(frame, index)
    while True:
        if mode in {"exit-zero", "exit-seven"} and (root / (mode + ".go")).exists():
            return 0 if mode == "exit-zero" else 7
        time.sleep(0.02)


if __name__ == "__main__":
    # Preserve normal external SIGTERM semantics, rather than simulating an IPC error.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(1)
