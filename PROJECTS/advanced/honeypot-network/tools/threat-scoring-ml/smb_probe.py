#!/usr/bin/env python3
"""
©AngelaMos | 2026
smb_probe.py

Sends a minimal SMB1 or SMB2 negotiate request, framed with a
4-byte NetBIOS session header, to exercise smbd's negotiate-only
handler. mode: "none" (raw connect, no frame — no scan event),
"smb2" (modern negotiate), or "smb1" (legacy — the dialect
EternalBlue-style scanners probe for).
"""

import socket
import sys
import time

SMB2_MAGIC = bytes([0xFE, ord("S"), ord("M"), ord("B")])
SMB1_MAGIC = bytes([0xFF, ord("S"), ord("M"), ord("B")])


def nbss_frame(payload):
    length = len(payload)
    header = bytes([0x00, (length >> 16) & 0xFF,
                     (length >> 8) & 0xFF, length & 0xFF])
    return header + payload


def main():
    host, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    s = socket.create_connection((host, port), timeout=5)
    try:
        if mode == "smb2":
            s.sendall(nbss_frame(SMB2_MAGIC + b"\x00" * 4))
        elif mode == "smb1":
            s.sendall(nbss_frame(SMB1_MAGIC + b"\x00" * 4))
        # mode == "none": send nothing, just connect and close
        time.sleep(0.2)
    finally:
        s.close()


if __name__ == "__main__":
    main()