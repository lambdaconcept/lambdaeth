#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Minimal DHCP server to exercise the board's DHCP client (stdlib only).

Serves a single fixed address to a single MAC. Binds UDP port 67 (run with
sudo) on one interface and answers DISCOVER with OFFER and REQUEST with ACK,
broadcasting replies (the board sets the BOOTP broadcast flag). Prints every
transaction; exits after --count ACKs (renewals included) or --timeout.

    sudo pdm run python scripts/dhcp_test_server.py \\
        --interface enp130s0 --server-ip 192.168.10.120 \\
        --lease-ip 192.168.10.199 --lease 30 --count 2
"""

import argparse
import socket
import struct
import sys
import time

COOKIE = bytes([0x63, 0x82, 0x53, 0x63])


def ip_bytes(s):
    return bytes(int(p) for p in s.split("."))


def parse(payload):
    if len(payload) < 244 or payload[236:240] != COOKIE:
        return None
    msg = {
        "op":     payload[0],
        "xid":    payload[4:8],
        "flags":  struct.unpack(">H", payload[10:12])[0],
        "ciaddr": payload[12:16],
        "chaddr": payload[28:34],
        "options": {},
    }
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        length = payload[i + 1]
        msg["options"][code] = payload[i + 2:i + 2 + length]
        i += 2 + length
    return msg


def reply(msg_type, req, server_ip, lease_ip, lease, netmask, router):
    def option(code, data):
        return bytes([code, len(data)]) + data
    head = struct.pack(">BBBBIHH", 2, 1, 6, 0,
                       struct.unpack(">I", req["xid"])[0], 0, req["flags"])
    head += b"\x00" * 4 + ip_bytes(lease_ip) + ip_bytes(server_ip) + b"\x00" * 4
    head += req["chaddr"] + b"\x00" * 10 + b"\x00" * 192 + COOKIE
    opts = (option(53, bytes([msg_type])) +
            option(54, ip_bytes(server_ip)) +
            option(51, struct.pack(">I", lease)) +
            option(1, ip_bytes(netmask)) +
            option(3, ip_bytes(router)) +
            b"\xff")
    packet = head + opts
    return packet + b"\x00" * max(0, 300 - len(packet))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="enp130s0")
    parser.add_argument("--mac", default="02:4c:45:54:48:00",
                        help="Only answer this client (avoid disturbing "
                             "other devices; empty = answer anyone)")
    parser.add_argument("--server-ip", default="192.168.10.120")
    parser.add_argument("--lease-ip", default="192.168.10.199")
    parser.add_argument("--netmask", default="255.255.255.0")
    parser.add_argument("--lease", type=int, default=30)
    parser.add_argument("--count", type=int, default=2,
                        help="Exit after this many ACKs (renewals count)")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                    (args.interface + "\0").encode())
    sock.bind(("", 67))
    sock.settimeout(1.0)
    print(f"DHCP test server on {args.interface}: offering {args.lease_ip} "
          f"(lease {args.lease}s), server id {args.server_ip}")

    acks = 0
    deadline = time.monotonic() + args.timeout
    while acks < args.count and time.monotonic() < deadline:
        try:
            payload, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        msg = parse(payload)
        if msg is None or msg["op"] != 1 or 53 not in msg["options"]:
            continue
        mac = ":".join(f"{b:02x}" for b in msg["chaddr"])
        if args.mac and mac.lower() != args.mac.lower().replace("-", ":"):
            continue
        kind = msg["options"][53][0]
        xid = msg["xid"].hex()
        if kind == 1:
            print(f"DISCOVER from {mac} (xid {xid}) -> OFFER {args.lease_ip}")
            sock.sendto(reply(2, msg, args.server_ip, args.lease_ip,
                              args.lease, args.netmask, args.server_ip),
                        ("255.255.255.255", 68))
        elif kind == 3:
            renew = msg["ciaddr"] != b"\x00" * 4
            print(f"REQUEST{' (renewal)' if renew else ''} from {mac} "
                  f"(xid {xid}) -> ACK {args.lease_ip}")
            sock.sendto(reply(5, msg, args.server_ip, args.lease_ip,
                              args.lease, args.netmask, args.server_ip),
                        ("255.255.255.255", 68))
            acks += 1

    sock.close()
    ok = acks >= args.count
    print(f"{acks} ACK(s) served: {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
