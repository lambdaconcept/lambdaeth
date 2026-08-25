#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Exercise the board's TCP *client* endpoint.

Run a listening server on the host; the board (built with e.g.
``--tcp-client 192.168.10.120:5001``) connects to it by itself, retrying
every reconnect period until this server exists. Per round: accept, send
several payloads, verify the echoes, close — then check the board
reconnects on its own for the next round.
"""

import argparse
import random
import socket
import sys
import time


def serve_round(listener, sizes, timeout, prng, tag):
    listener.settimeout(timeout)
    try:
        conn, addr = listener.accept()
    except socket.timeout:
        print(f"[{tag}] board never connected")
        return False
    ok = True
    try:
        conn.settimeout(timeout)
        print(f"[{tag}] board connected from {addr[0]}:{addr[1]}")
        total = 0
        start = time.monotonic()
        for size in sizes:
            payload = bytes(prng.randrange(256) for _ in range(size))
            conn.sendall(payload)
            data = b""
            while len(data) < size:
                chunk = conn.recv(65536)
                if not chunk:
                    raise ConnectionError("EOF during echo")
                data += chunk
            if data != payload:
                print(f"[{tag}] MISMATCH at size {size}")
                ok = False
            total += size
        elapsed = time.monotonic() - start
        # We close first; the board ACKs, FINs back and goes reconnecting.
        conn.shutdown(socket.SHUT_WR)
        tail = conn.recv(65536)
        if tail != b"":
            print(f"[{tag}] unexpected data after shutdown: {len(tail)}B")
            ok = False
        print(f"[{tag}] echoed {total}B in {elapsed*1e3:.0f} ms "
              f"({total/max(elapsed,1e-9)/1e3:.0f} kB/s), clean close")
    except OSError as exc:
        print(f"[{tag}] FAILED: {exc}")
        ok = False
    finally:
        conn.close()
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001,
                        help="Port the board's client targets")
    parser.add_argument("--rounds", type=int, default=3,
                        help="Accept/echo/close cycles (proves reconnection)")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="Accept timeout (board retries every ~1 s)")
    parser.add_argument("--sizes", default="1,64,536,1400,4000")
    args = parser.parse_args()

    sizes = [int(s) for s in args.sizes.split(",")]
    prng = random.Random(8765)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen, args.port))
    listener.listen(1)
    print(f"listening on {args.listen}:{args.port}, "
          f"waiting for the board to connect...")

    passed = True
    for rnd in range(args.rounds):
        passed &= serve_round(listener, sizes, args.timeout, prng, f"#{rnd}")
    listener.close()

    print("PASS" if passed else "FAIL")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
