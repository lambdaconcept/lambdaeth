#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Host-side CSR access over the UART-to-Wishbone bridge (stdlib only).

Protocol: 'W' addr32be data32be -> 'w' ; 'R' addr32be -> 'r' data32be.

Usage:
    csrctl.py [--port /dev/ttyUSB2] [--csr-map build/.../csr.json] COMMAND

Commands:
    read ADDR|NAME            Read a 32-bit word (or a whole named register).
    write ADDR|NAME VALUE     Write a 32-bit word (or a whole named register).
    dump                      Read every register in the CSR map.
    set-mac AA:BB:CC:DD:EE:FF Set the MAC address register.
    set-ip A.B.C.D            Set the IP address register.
"""

import argparse
import json
import os
import sys
import termios


def open_serial(path, baudrate=115200):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
    attrs = termios.tcgetattr(fd)
    baud = getattr(termios, f"B{baudrate}")
    attrs[0] = 0                      # iflag
    attrs[1] = 0                      # oflag
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL  # cflag
    attrs[3] = 0                      # lflag
    attrs[4] = baud                   # ispeed
    attrs[5] = baud                   # ospeed
    attrs[6][termios.VMIN]  = 0
    attrs[6][termios.VTIME] = 5       # 0.5 s read timeout
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


def drain(fd):
    """Discard any stale bytes (e.g. left over from a previous bitstream)."""
    while os.read(fd, 4096):
        pass


def read_exact(fd, n, what="response"):
    data = b""
    while len(data) < n:
        chunk = os.read(fd, n - len(data))
        if not chunk:
            raise TimeoutError(f"timeout waiting for {what} "
                               f"(got {data.hex() or 'nothing'})")
        data += chunk
    return data


def wait_for(fd, marker, what, limit=64):
    """Scan for a response marker byte, skipping stale bytes."""
    skipped = b""
    for _ in range(limit):
        byte = read_exact(fd, 1, what)
        if byte == marker:
            return
        skipped += byte
    raise IOError(f"no {what} marker (skipped {skipped.hex()})")


def bridge_read32(fd, addr):
    os.write(fd, b"R" + addr.to_bytes(4, "big"))
    wait_for(fd, b"r", "read response")
    return int.from_bytes(read_exact(fd, 4, "read data"), "big")


def bridge_write32(fd, addr, value):
    os.write(fd, b"W" + addr.to_bytes(4, "big") + value.to_bytes(4, "big"))
    wait_for(fd, b"w", "write ack")


def reg_read(fd, addr, size):
    """Read `size` bytes of a little-endian CSR register (any alignment).

    The bridge only does word-aligned 32-bit accesses (address LSBs are
    dropped), so sub-word/unaligned registers are extracted from the
    covering words.
    """
    base  = addr & ~3
    value = 0
    for off in range(0, addr + size - base, 4):
        word = bridge_read32(fd, base + off)
        value |= word << (8 * off)
    value >>= 8 * (addr - base)
    mask = (1 << (8 * size)) - 1
    return value & mask


def reg_write(fd, addr, size, value):
    """Write `size` bytes of a little-endian CSR register (any alignment).

    Sub-word/unaligned registers are updated read-modify-write, preserving
    neighbours packed into the same words (the bridge always writes full
    words).
    """
    if addr % 4 == 0 and size % 4 == 0:
        for off in range(0, size, 4):
            bridge_write32(fd, addr + off, (value >> (8 * off)) & 0xffffffff)
        return
    base   = addr & ~3
    nwords = (addr + size - base + 3) // 4
    current = 0
    for i in range(nwords):
        current |= bridge_read32(fd, base + 4*i) << (32 * i)
    shift = 8 * (addr - base)
    mask  = ((1 << (8 * size)) - 1) << shift
    current = (current & ~mask) | ((value << shift) & mask)
    for i in range(nwords):
        bridge_write32(fd, base + 4*i, (current >> (32 * i)) & 0xffffffff)


def load_map(path):
    with open(path) as f:
        return json.load(f)


def resolve(csr_map, token):
    """Return (addr, size) for a register name or a raw address."""
    if csr_map:
        for name, info in csr_map.items():
            if token == name or name.endswith(token):
                return info["addr"], info["size"]
    return int(token, 0), 4


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", default="/dev/ttyUSB2")
    parser.add_argument("--baudrate", type=int, default=115200)
    parser.add_argument("--csr-map", default="build/tang_mega_138k_udp_echo/csr.json")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("read");    p.add_argument("target")
    p = sub.add_parser("write");   p.add_argument("target"); p.add_argument("value")
    sub.add_parser("dump")
    p = sub.add_parser("set-mac"); p.add_argument("mac")
    p = sub.add_parser("set-ip");  p.add_argument("ip")
    args = parser.parse_args()

    csr_map = {}
    if os.path.exists(args.csr_map):
        csr_map = load_map(args.csr_map)

    fd = open_serial(args.port, args.baudrate)
    try:
        drain(fd)
        if args.cmd == "read":
            addr, size = resolve(csr_map, args.target)
            value = reg_read(fd, addr, size)
            print(f"{args.target} @ {addr:#06x} = {value:#0{2 + 2*size}x}")
        elif args.cmd == "write":
            addr, size = resolve(csr_map, args.target)
            reg_write(fd, addr, size, int(args.value, 0))
            print(f"{args.target} @ {addr:#06x} <- {args.value}")
        elif args.cmd == "dump":
            for name, info in csr_map.items():
                value = reg_read(fd, info["addr"], info["size"])
                print(f"{info['addr']:#06x} {name:24s} = {value:#0{2 + 2*info['size']}x}")
        elif args.cmd == "set-mac":
            mac = int(args.mac.replace(":", "").replace("-", ""), 16)
            addr, size = resolve(csr_map, "mac_address")
            reg_write(fd, addr, size, mac)
            print(f"mac_address <- {args.mac} ({mac:#014x})")
        elif args.cmd == "set-ip":
            ip = 0
            for part in args.ip.split("."):
                ip = (ip << 8) | int(part)
            addr, size = resolve(csr_map, "ip_address")
            reg_write(fd, addr, size, ip)
            print(f"ip_address <- {args.ip} ({ip:#010x})")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
