#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Exercise the board's TCP echo servers with the Linux kernel stack.

Per listen port: connect, echo several payload sizes, half-close and expect
the board's FIN (clean shutdown), then reconnect to prove the port listens
again. Also checks that a busy port refuses a second client and that an
unbound port refuses outright (RST).
"""

import argparse
import random
import socket
import sys
import time


def echo_session(ip, port, sizes, timeout, prng, tag):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        print(f"[{tag}] connect failed: {exc}")
        return False
    ok = True
    try:
        total = 0
        start = time.monotonic()
        for size in sizes:
            payload = bytes(prng.randrange(256) for _ in range(size))
            s.sendall(payload)
            data = b""
            while len(data) < size:
                chunk = s.recv(65536)
                if not chunk:
                    raise ConnectionError("EOF during echo")
                data += chunk
            if data != payload:
                print(f"[{tag}] MISMATCH at size {size}")
                ok = False
            total += size
        elapsed = time.monotonic() - start
        # Clean shutdown: our FIN, then the board's FIN (EOF).
        s.shutdown(socket.SHUT_WR)
        tail = s.recv(65536)
        if tail != b"":
            print(f"[{tag}] unexpected data after shutdown: {len(tail)}B")
            ok = False
        print(f"[{tag}] echoed {total}B in {elapsed*1e3:.0f} ms "
              f"({total/max(elapsed,1e-9)/1e3:.0f} kB/s), clean close")
    except OSError as exc:
        print(f"[{tag}] FAILED: {exc}")
        ok = False
    finally:
        s.close()
    return ok


def expect_refused(ip, port, timeout, tag):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        print(f"[{tag}] refused (RST) as expected")
        return True
    except OSError as exc:
        print(f"[{tag}] expected refusal, got {exc!r}")
        return False
    else:
        s.close()
        print(f"[{tag}] UNEXPECTEDLY accepted")
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default="192.168.10.50")
    parser.add_argument("--port", type=int, action="append", dest="ports",
                        metavar="PORT",
                        help="TCP port(s) to test (repeatable; "
                             "default: 2000 2001)")
    parser.add_argument("--refused-port", type=int, default=9999,
                        help="Unbound port that must refuse (RST)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--sizes", default="1,64,536,1400,4000",
                        help="Comma-separated echo payload sizes")
    args = parser.parse_args()

    ports = args.ports or [2000, 2001]
    sizes = [int(s) for s in args.sizes.split(",")]
    prng = random.Random(4321)

    passed = True

    # Echo + clean close + reconnect on every port.
    for port in ports:
        for rnd in range(2):
            passed &= echo_session(args.ip, port, sizes, args.timeout, prng,
                                   f"{port}#{rnd}")

    # Simultaneous connections on all ports.
    if len(ports) > 1:
        socks = []
        try:
            for port in ports:
                socks.append((port, socket.create_connection(
                    (args.ip, port), timeout=args.timeout)))
            for port, s in socks:
                payload = bytes(prng.randrange(256) for _ in range(200))
                s.sendall(payload)
                data = b""
                while len(data) < len(payload):
                    chunk = s.recv(65536)
                    if not chunk:
                        raise ConnectionError("EOF")
                    data += chunk
                if data != payload:
                    print(f"[simul:{port}] MISMATCH")
                    passed = False
            print(f"[simul] {len(socks)} concurrent connections echoed")
        except OSError as exc:
            print(f"[simul] FAILED: {exc}")
            passed = False
        finally:
            for _port, s in socks:
                s.close()
        time.sleep(0.5)     # Let the close handshakes finish.

    # A busy port refuses a second client.
    try:
        holder = socket.create_connection((args.ip, ports[0]),
                                          timeout=args.timeout)
        holder.sendall(b"hold")
        _ = holder.recv(16)
        passed &= expect_refused(args.ip, ports[0], args.timeout, "busy")
        holder.close()
        time.sleep(0.5)
    except OSError as exc:
        print(f"[busy] FAILED to establish holder: {exc}")
        passed = False

    # Unbound port refuses outright.
    passed &= expect_refused(args.ip, args.refused_port, args.timeout,
                             f"unbound:{args.refused_port}")

    print("PASS" if passed else "FAIL")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()


