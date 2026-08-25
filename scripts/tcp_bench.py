#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""TCP throughput benchmark against a --tcp-bench build.

Upload (PC -> FPGA, first TCP port): the board is a pure byte sink, so
nothing is echoed; we time sendall() plus the FIN handshake (the board's FIN
only comes back after every byte was ACKed), and the received byte count can
be cross-checked in the bench_rx_bytes CSR.

Download (FPGA -> PC, second TCP port): the board streams an incrementing
byte pattern; we time receiving N bytes and verify the pattern. The board's
TX is stop-and-wait (one segment in flight), so this direction measures
MSS/RTT — with Linux delayed ACKs it collapses, so TCP_QUICKACK is measured
too.
"""

import argparse
import socket
import struct
import sys
import time


def connect_retry(ip, port, timeout, attempts=12):
    """The board refuses (RST) while a previous shutdown is finishing."""
    for _ in range(attempts):
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except ConnectionRefusedError:
            time.sleep(0.5)
    return socket.create_connection((ip, port), timeout=timeout)


def report(tag, nbytes, seconds):
    mbps = nbytes * 8 / seconds / 1e6
    print(f"[{tag}] {nbytes/1e6:.1f} MB in {seconds:.2f} s "
          f"= {nbytes/seconds/1e6:.2f} MB/s ({mbps:.0f} Mbit/s)")


def upload(ip, port, nbytes, timeout):
    buf = bytes(i & 0xff for i in range(65536))
    s = socket.create_connection((ip, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    start = time.monotonic()
    left = nbytes
    while left:
        chunk = min(left, len(buf))
        s.sendall(buf[:chunk])
        left -= chunk
    # The board's FIN arrives only once everything was ACKed: a clean gate.
    s.shutdown(socket.SHUT_WR)
    while s.recv(65536):
        pass
    elapsed = time.monotonic() - start
    s.close()
    report(f"upload:{port}", nbytes, elapsed)
    return nbytes / elapsed


def download(ip, port, nbytes, timeout, quickack):
    s = connect_retry(ip, port, timeout)
    # The stream is endless; end the run with an immediate RST (linger 0) so
    # the board aborts straight back to LISTEN.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                 struct.pack("ii", 1, 0))
    start = time.monotonic()
    got = 0
    expect = 0
    ok = True
    while got < nbytes:
        if quickack:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        chunk = s.recv(65536)
        if not chunk:
            raise ConnectionError("EOF from board")
        for b in chunk:
            if b != expect:
                ok = False
            expect = (expect + 1) & 0xff
        got += len(chunk)
    elapsed = time.monotonic() - start
    s.close()
    tag = f"download:{port}" + (" quickack" if quickack else " delayed-ack")
    report(tag, got, elapsed)
    if not ok:
        print(f"[{tag}] PATTERN MISMATCH")
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default="192.168.10.50")
    parser.add_argument("--upload-port", type=int, default=2000)
    parser.add_argument("--download-port", type=int, default=2001)
    parser.add_argument("--upload-mb", type=float, default=16)
    parser.add_argument("--download-mb", type=float, default=4)
    parser.add_argument("--delayed-ack-kb", type=float, default=192,
                        help="Size of the extra no-quickack download run "
                             "(slow; 0 skips it)")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    ok = True
    upload(args.ip, args.upload_port, int(args.upload_mb * 1e6),
           args.timeout)
    ok &= download(args.ip, args.download_port, int(args.download_mb * 1e6),
                   args.timeout, quickack=True)
    if args.delayed_ack_kb > 0:
        time.sleep(1)       # Let the previous close settle (re-listen).
        ok &= download(args.ip, args.download_port,
                       int(args.delayed_ack_kb * 1e3), 60.0, quickack=False)
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
