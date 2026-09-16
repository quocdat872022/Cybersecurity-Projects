#!/usr/bin/env python3
"""
©AngelaMos | 2026
mysql_client.py

Minimal MySQL wire-protocol client for exercising the mysqld
honeypot without depending on a real mysql CLI being installed.
Sends the auth packet (username only, per parseAuthUsername) then
fires each query as COM_QUERY. Does not attempt to parse result
sets — fire-and-forget, since the honeypot logs on receipt.
"""

import socket
import sys


def send_packet(sock, seq, payload):
    length = len(payload)
    header = bytes([
        length & 0xFF, (length >> 8) & 0xFF,
        (length >> 16) & 0xFF, seq & 0xFF,
    ])
    sock.sendall(header + payload)


def read_packet(sock):
    header = sock.recv(4)
    if len(header) < 4:
        raise ConnectionError("short read on packet header")
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            break
        payload += chunk
    return payload


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    queries = sys.argv[3:]

    s = socket.create_connection((host, port), timeout=5)
    try:
        read_packet(s)  # greeting; contents unused

        auth_payload = b"\x00" * 32 + b"root" + b"\x00"
        send_packet(s, 1, auth_payload)
        read_packet(s)  # OK packet

        for q in queries:
            send_packet(s, 0, b"\x03" + q.encode())
    finally:
        s.close()


if __name__ == "__main__":
    main()