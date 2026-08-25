#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Minimal Ethernet "life" test for the Sipeed Tang Mega 138K Pro dock.

The design brings up the RTL8211F RGMII PHY (25 MHz reference clock generated
by the FPGA, 2 ns TX/RX clock skews, >=20 ms hardware reset) and the LambdaEth
MAC core with a 32-bit sys-side datapath (so the 50 MHz sys clock sustains
gigabit line rate through the CDC FIFOs).

Life signs:

* TX: an ARP probe (sender IP 0.0.0.0) for --target-ip is broadcast once per
  second. Watch it on the host with:  sudo tcpdump -e -i <iface> arp
  If --target-ip is the host itself, the host unicasts ARP replies back, which
  exercises the full RX path.
* RX: every received frame is counted (good CRC / errored separately).
* UART (115200 8N1, FT2232 channel B): one status line per second:
      rx=XXXXXXXX ok=XXXXXXXX er=XXXXXXXX tx=XXXXXXXX
* LEDs:
      0: sys clock heartbeat        3: toggles on RX good frame
      1: eth_rx clock heartbeat     4: toggles on RX errored frame
      2: RX activity (stretched)    5: toggles on TX frame sent

Usage:
    python examples/tang_mega_138k_eth_life.py --target-ip 192.168.10.120
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))  # serial.py

from amaranth.hdl import (Module, Signal, Elaboratable, ClockDomain, ClockSignal,
                          Instance, Cat, Mux, C, Const, IOBufferInstance)
from amaranth.lib import io
from amaranth.lib.wiring import connect

from lambdaeth.common import eth_phy_stream_signature, convert_ip, convert_mac
from lambdaeth.mac import MACCore
from lambdaeth.phy import GW5RGMIIPHY

from serial import AsyncSerialTX


# Frame construction -------------------------------------------------------------------------------

def build_arp_probe(src_mac, target_ip):
    """ARP probe (RFC 5227): who-has target_ip, sender IP 0.0.0.0."""
    src = convert_mac(src_mac).to_bytes(6, "big")
    tpa = convert_ip(target_ip).to_bytes(4, "big")
    frame = b""
    frame += b"\xff\xff\xff\xff\xff\xff"      # dst: broadcast
    frame += src                              # src
    frame += b"\x08\x06"                      # ethertype: ARP
    frame += b"\x00\x01"                      # htype: ethernet
    frame += b"\x08\x00"                      # ptype: IPv4
    frame += b"\x06\x04"                      # hlen, plen
    frame += b"\x00\x01"                      # oper: request
    frame += src                              # sha
    frame += b"\x00\x00\x00\x00"              # spa: 0.0.0.0 (probe)
    frame += b"\x00\x00\x00\x00\x00\x00"      # tha
    frame += tpa                              # tpa
    return frame


# TX frame generator -------------------------------------------------------------------------------

class FrameSender(Elaboratable):
    """Streams a fixed frame into a 32-bit eth_phy stream once per period."""

    def __init__(self, frame, period):
        assert len(frame) > 0
        self.frame  = frame
        self.period = period
        self.source = eth_phy_stream_signature(32).create()
        self.sent   = Signal(32)

    def elaborate(self, platform):
        m = Module()

        frame = self.frame
        words = [int.from_bytes(frame[i:i+4].ljust(4, b"\x00"), "little")
                 for i in range(0, len(frame), 4)]
        nbeats  = len(words)
        last_be = 1 << ((len(frame) - 1) % 4)

        timer = Signal(range(self.period))
        idx   = Signal(range(nbeats))

        with m.FSM():
            with m.State("WAIT"):
                m.d.sync += timer.eq(timer + 1)
                with m.If(timer == self.period - 1):
                    m.d.sync += [timer.eq(0), idx.eq(0)]
                    m.next = "SEND"

            with m.State("SEND"):
                m.d.comb += [
                    self.source.valid.eq(1),
                    self.source.first.eq(idx == 0),
                    self.source.last.eq(idx == nbeats - 1),
                ]
                with m.Switch(idx):
                    for i, word in enumerate(words):
                        with m.Case(i):
                            m.d.comb += self.source.p.data.eq(word)
                with m.If(idx == nbeats - 1):
                    m.d.comb += self.source.p.last_be.eq(last_be)
                with m.If(self.source.ready):
                    m.d.sync += idx.eq(idx + 1)
                    with m.If(idx == nbeats - 1):
                        m.d.sync += self.sent.eq(self.sent + 1)
                        m.next = "WAIT"

        return m


# UART status printer ------------------------------------------------------------------------------

class StatusPrinter(Elaboratable):
    """Prints 'name=XXXXXXXX ...' for each 32-bit field, once per period."""

    def __init__(self, fields, period, divisor):
        self.fields  = fields   # dict: name -> Signal(32)
        self.period  = period
        self.divisor = divisor
        self.tx_o    = Signal(init=1)

    def elaborate(self, platform):
        m = Module()

        m.submodules.uart = uart = AsyncSerialTX(divisor=self.divisor)
        m.d.comb += self.tx_o.eq(uart.o)

        # Latch the fields, then emit the message byte by byte.
        latched = {name: Signal(32, name=f"latch_{name}") for name in self.fields}

        # Token list: ("lit", byte) or ("hex", name, nibble_index_from_msb).
        tokens = []
        for name in self.fields:
            for char in f"{name}=":
                tokens.append(("lit", ord(char)))
            for nibble in range(8):
                tokens.append(("hex", name, nibble))
            tokens.append(("lit", ord(" ")))
        tokens = tokens[:-1] + [("lit", 0x0d), ("lit", 0x0a)]

        timer = Signal(range(self.period))
        pos   = Signal(range(len(tokens) + 1))

        byte = Signal(8)
        with m.Switch(pos):
            for i, token in enumerate(tokens):
                with m.Case(i):
                    if token[0] == "lit":
                        m.d.comb += byte.eq(token[1])
                    else:
                        _, name, nibble = token
                        nib = latched[name][28 - 4*nibble:32 - 4*nibble]
                        m.d.comb += byte.eq(Mux(nib < 10,
                                                ord("0") + nib,
                                                ord("a") - 10 + nib))

        with m.FSM():
            with m.State("WAIT"):
                m.d.sync += timer.eq(timer + 1)
                with m.If(timer == self.period - 1):
                    m.d.sync += [timer.eq(0), pos.eq(0)]
                    m.d.sync += [latched[name].eq(sig)
                                 for name, sig in self.fields.items()]
                    m.next = "PRINT"

            with m.State("PRINT"):
                m.d.comb += [
                    uart.data.eq(byte),
                    uart.ack.eq(uart.rdy),
                ]
                with m.If(uart.rdy):
                    m.d.sync += pos.eq(pos + 1)
                    with m.If(pos == len(tokens) - 1):
                        m.next = "WAIT"

        return m


# Top ------------------------------------------------------------------------------------------

class EthLife(Elaboratable):
    def __init__(self, mac_addr="02:4c:45:54:48:00", target_ip="192.168.10.120",
                 sys_clk_freq=50e6, baudrate=115200):
        self.mac_addr     = mac_addr
        self.target_ip    = target_ip
        self.sys_clk_freq = sys_clk_freq
        self.baudrate     = baudrate

    def elaborate(self, platform):
        m = Module()

        # Clock domains (defined here: common ancestor of PHY and MAC).
        m.domains += ClockDomain("eth_tx")
        m.domains += ClockDomain("eth_rx")

        # PHY + MAC ------------------------------------------------------------------------
        phy = GW5RGMIIPHY(
            create_domains  = False,
            hw_reset_cycles = int(20e-3 * self.sys_clk_freq),  # RTL8211F: >=10 ms.
        )
        mac = MACCore(phy, data_width=32, with_csr=False)
        m.submodules.phy = phy
        m.submodules.mac = mac
        connect(m, mac.phy_tx, phy.tx)
        connect(m, phy.rx, mac.phy_rx)

        # Pads -----------------------------------------------------------------------------
        # Raw IOBufferInstance (plain `assign`) is used instead of the
        # platform-lowered io.Buffer: GowinSynthesis refuses ODDR/IODELAY
        # driving the TBUF primitives the vendor lowering emits, and expects
        # to infer/pack the IOB itself (same netlist shape as LiteX).
        eth_clocks = platform.request("eth_clocks", 0, dir="-")
        eth        = platform.request("eth", 0, dir="-")
        ephy_clk   = platform.request("ephy_clk", 0, dir="-")

        rx_clk = Signal()
        m.submodules.rx_clk_buf = IOBufferInstance(eth_clocks.rx.io, i=rx_clk)
        m.submodules.tx_clk_buf = IOBufferInstance(eth_clocks.tx.io, o=phy.clk_tx)
        rx_ctl  = Signal()
        rx_data = Signal(4)
        m.submodules.rx_ctl_buf = IOBufferInstance(eth.rx_ctl.io, i=rx_ctl)
        m.submodules.rx_dat_buf = IOBufferInstance(eth.rx_data.io, i=rx_data)
        m.submodules.tx_ctl_buf = IOBufferInstance(eth.tx_ctl.io, o=phy.tx_ctl)
        m.submodules.tx_dat_buf = IOBufferInstance(eth.tx_data.io, o=phy.tx_data)
        m.submodules.rst_n_buf  = IOBufferInstance(eth.rst_n.io, o=phy.rst_n)
        mdc = Signal()  # MDIO unused: keep MDC quiet (straps default the PHY).
        m.submodules.mdc_buf    = IOBufferInstance(eth.mdc.io, o=mdc)

        m.d.comb += [
            phy.clk_rx.eq(rx_clk),
            phy.rx_ctl.eq(rx_ctl),
            phy.rx_data.eq(rx_data),
        ]

        # 25 MHz reference clock for the RTL8211F (no crystal on this dock).
        clk25  = Signal()
        ephy_o = Signal()
        m.submodules.ephy_clkdiv = Instance("CLKDIV",
            p_DIV_MODE = "2",
            i_HCLKIN   = ClockSignal("sync"),
            i_RESETN   = C(1),
            i_CALIB    = C(0),
            o_CLKOUT   = clk25,
        )
        m.submodules.ephy_oddr = Instance("ODDR",
            i_CLK = clk25,
            i_D0  = C(1),
            i_D1  = C(0),
            i_TX  = C(0),
            o_Q0  = ephy_o,
        )
        m.submodules.ephy_buf = IOBufferInstance(ephy_clk.io, o=ephy_o)

        # TX: periodic ARP probe -------------------------------------------------------------
        frame = build_arp_probe(self.mac_addr, self.target_ip)
        m.submodules.sender = sender = FrameSender(
            frame, period=int(self.sys_clk_freq))
        connect(m, sender.source, mac.sink)

        # RX: counters -----------------------------------------------------------------------
        rx_frames = Signal(32)
        rx_ok     = Signal(32)
        rx_err    = Signal(32)
        m.d.comb += mac.source.ready.eq(1)
        with m.If(mac.source.valid & mac.source.last):
            m.d.sync += rx_frames.eq(rx_frames + 1)
            with m.If(mac.source.p.error == 0):
                m.d.sync += rx_ok.eq(rx_ok + 1)
            with m.Else():
                m.d.sync += rx_err.eq(rx_err + 1)

        # UART status ------------------------------------------------------------------------
        uart_pins = platform.request("uart", 0)
        m.submodules.printer = printer = StatusPrinter(
            fields  = {"rx": rx_frames, "ok": rx_ok, "er": rx_err, "tx": sender.sent},
            period  = int(self.sys_clk_freq),
            divisor = round(self.sys_clk_freq / self.baudrate),
        )
        m.d.comb += uart_pins.tx.o.eq(printer.tx_o)

        # LEDs ---------------------------------------------------------------------------
        sys_beat = Signal(26)
        m.d.sync += sys_beat.eq(sys_beat + 1)

        eth_beat = Signal(27)
        m.d.eth_rx += eth_beat.eq(eth_beat + 1)

        rx_act = Signal(23)
        with m.If(phy.rx.valid):
            m.d.eth_rx += rx_act.eq(-1)
        with m.Elif(rx_act != 0):
            m.d.eth_rx += rx_act.eq(rx_act - 1)

        m.d.comb += [
            platform.request("led", 0).o.eq(sys_beat[-1]),
            platform.request("led", 1).o.eq(eth_beat[-1]),
            platform.request("led", 2).o.eq(rx_act != 0),
            platform.request("led", 3).o.eq(rx_ok[0]),
            platform.request("led", 4).o.eq(rx_err[0]),
            platform.request("led", 5).o.eq(sender.sent[0]),
        ]

        return m


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ip", default="192.168.10.120",
                        help="IP to ARP-probe once per second")
    parser.add_argument("--mac", default="02:4c:45:54:48:00",
                        help="Source MAC address")
    parser.add_argument("--build-dir", default="build/tang_mega_138k_eth_life")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()

    from amaranth_boards.tang_mega_138k_pro_dock import TangMega138kProDockPlatform

    platform = TangMega138kProDockPlatform(toolchain="Gowin")
    result = platform.build(
        EthLife(mac_addr=args.mac, target_ip=args.target_ip),
        name        = "eth_life",
        build_dir   = args.build_dir,
        do_build    = not args.no_build,
        do_program  = False,
        add_options = (
            "set_option -use_mspi_as_gpio 1\n"
            "set_option -use_sspi_as_gpio 1\n"
            "set_option -use_ready_as_gpio 1\n"
            "set_option -use_done_as_gpio 1\n"
            "set_option -use_cpu_as_gpio 1\n"
        ),
        add_constraints = (
            "create_clock -name eth_rx_clk -period 8.0 "
            "[get_ports {eth_clocks_0__rx__io}]\n"
        ),
    )
    if args.no_build:
        result.execute_local(args.build_dir, run_script=False)
    print(f"Build artifacts in {args.build_dir}")


if __name__ == "__main__":
    main()
