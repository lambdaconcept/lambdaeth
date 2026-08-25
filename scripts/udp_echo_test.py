#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Send UDP datagrams to the board and check the echoes, per bound port.

Each tested port must echo every datagram back from itself; a port given
with --expect-drop-port must stay silent (bound-port builds drop it).
"""

import argparse
import random
import socket
import sys
import time


def test_echo_port(ip, port, count, size, timeout, prng):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.bind(("", 0))
    ok = lost = mismatched = 0
    rtts = []
    for i in range(count):
        payload = bytes(prng.randrange(256) for _ in range(size))
        start = time.monotonic()
        sock.sendto(payload, (ip, port))
        try:
            data, addr = sock.recvfrom(65536)
            rtt = (time.monotonic() - start) * 1e6
            if data == payload and addr == (ip, port):
                ok += 1
                rtts.append(rtt)
                print(f"[{port}:{i}] echo OK from {addr[0]}:{addr[1]}, "
                      f"{len(data)} bytes, rtt={rtt:.0f} us")
            else:
                mismatched += 1
                print(f"[{port}:{i}] MISMATCH: sent {len(payload)}B, "
                      f"got {len(data)}B from {addr}")
        except socket.timeout:
            lost += 1
            print(f"[{port}:{i}] timeout")
    sock.close()

    line = f"port {port}: {ok}/{count} echoed, {lost} lost, {mismatched} mismatched"
    if rtts:
        line += (f", rtt min/avg/max = {min(rtts):.0f}/"
                 f"{sum(rtts)/len(rtts):.0f}/{max(rtts):.0f} us")
    print(line + "\n")
    return ok == count


def test_drop_port(ip, port, count, size, timeout, prng):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.bind(("", 0))
    silent = True
    for i in range(count):
        payload = bytes(prng.randrange(256) for _ in range(size))
        sock.sendto(payload, (ip, port))
        try:
            data, addr = sock.recvfrom(65536)
            silent = False
            print(f"[{port}:{i}] UNEXPECTED reply from {addr[0]}:{addr[1]}, "
                  f"{len(data)} bytes")
        except socket.timeout:
            print(f"[{port}:{i}] silent (dropped as expected)")
    sock.close()
    print(f"port {port}: {'silent' if silent else 'REPLIED'} "
          f"(expected drops)\n")
    return silent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default="192.168.10.50")
    parser.add_argument("--port", type=int, action="append", dest="ports",
                        metavar="PORT",
                        help="UDP port(s) to test (repeatable; "
                             "default: 8000 8001 8002)")
    parser.add_argument("--expect-drop-port", type=int, default=None,
                        metavar="PORT",
                        help="Also check that PORT does not echo (unbound)")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--size", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    ports = args.ports or [8000, 8001, 8002]
    prng = random.Random(1234)

    passed = True
    for port in ports:
        passed &= test_echo_port(args.ip, port, args.count, args.size,
                                 args.timeout, prng)
    if args.expect_drop_port is not None:
        passed &= test_drop_port(args.ip, args.expect_drop_port, 3, args.size,
                                 min(args.timeout, 1.0), prng)

    print("PASS" if passed else "FAIL")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
