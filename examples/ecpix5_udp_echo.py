#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""UDP + TCP echo demo for the LambdaConcept ECPIX-5 (Lattice ECP5-5G, KSZ9031
RGMII PHY), built with the open-source Yosys + nextpnr-ecp5 + ecppack flow.

This is the ECP5 counterpart of ``tang_mega_138k_udp_echo.py`` (same network
fabric, CSR map and host tooling); only the clocking, PHY and pad wiring are
board-specific:

* ``clk100`` -> EHXPLLL -> ``sync`` (default 50 MHz, --sys-clk-freq) with the
  PLL lock as reset.
* :class:`lambdaeth.phy.ECP5RGMIIPHY`: ODDRX1F/IDDRX1F DDR pads with static
  DELAYG skews (defaults: TX clock +2 ns, RX 0 ns — LiteX's ECPIX-5 values;
  tune with --tx-delay/--rx-delay in ns). The KSZ9031 has its own 25 MHz
  crystal and is held in reset for 20 ms at power-up; autonegotiation takes
  ~3 s after every (re)flash.
* PHY CSRs are mapped as a ``phy`` window next to the ``core`` window
  (``phy__inband_status``: bit 0 link up, bits 2:1 speed (2 = 1000 Mbps),
  bit 3 full duplex; ``phy__mdio_w``/``phy__mdio_r``: bit-banged MDIO).
* UART: the board's FT4232H channel C (``usb-FTDI_Quad_RS232-HS-if02-port0``,
  typically ``/dev/ttyUSB3``; channel A is the JTAG) at 115200 — pass it to
  ``scripts/csrctl.py --port`` together with ``--csr-map
  build/ecpix5_udp_echo/csr.json``. The ``ftdi_sio`` kernel module must be
  loaded for the serial channels to appear.
* RGB LEDs: 0 green = sys heartbeat, 1 green = eth_rx heartbeat (link clock
  present), 2 blue = RX activity, 3 red/green/blue = ARP / UDP RX / UDP TX.

Architecture::

  RGMII PHY <-> MACCore(32) <-> width/packet adapters <-> UDPIPCore(8) <-> echo FIFO x N
                                                            ^ mac/ip/ports from CSR
  UART (115200) -> UARTWishboneBridge -> Wishbone -> WishboneCSRBridge -> CSRs

Behaviour (identical to the Tang Mega demo): ARP/ICMP for the board IP, one
UDP echo stream per bound port (--udp-port, default 8000 8001 8002; unbound
ports dropped and counted), one TCP echo server per listen port (--tcp-port,
default 2000 2001), optional TCP clients (--tcp-client IP:PORT[:LOCAL]),
--dhcp, --no-icmp, --no-tcp, --tcp-mss/--tcp-rx-depth/--rx-cdc-depth and
--tcp-bench. See the Tang Mega example docstring for details.

Toolchain: native ``yosys``/``nextpnr-ecp5``/``ecppack`` from PATH if
present, otherwise the pip-installed YoWASP builds (``pdm install -G ecp5``
provides ``yowasp-yosys``/``yowasp-nextpnr-ecp5``/``yowasp-ecppack``). The
``YOSYS``/``NEXTPNR_ECP5``/``ECPPACK`` environment variables override.

Usage:
    pdm run python examples/ecpix5_udp_echo.py [--ip 192.168.10.50 | --dhcp]
        [--udp-port 8000 ...] [--tcp-port 2000 ...] [--no-build]
    sudo openFPGALoader -b ecpix5_r03 build/ecpix5_udp_echo/udp_echo.bit
    pdm run python scripts/csrctl.py --port /dev/ttyUSB3 \
        --csr-map build/ecpix5_udp_echo/csr.json dump

Measured (ECPIX-5 85F, r03, sys 50 MHz, LFE5UM5G-85F-8): nextpnr Fmax
eth_rx 137.7 MHz / sys 73.9 MHz, 17 % LUTs, 38 DP16KD; ICMP RTT ~0.16 ms,
UDP echo RTT ~75 us (64 B) / ~205 us (1400 B), TCP echo ~71 kB/s per
connection (stop-and-wait), 0 RX errors under ping flood.
"""

import argparse
import json
import os
import shutil

from amaranth.hdl import (Module, Signal, Elaboratable, ClockDomain, ClockSignal,
                          Instance, C, IOBufferInstance)
from amaranth.lib.cdc import ResetSynchronizer
from amaranth.lib.wiring import connect

from amaranth_soc import csr
from amaranth_soc.csr.wishbone import WishboneCSRBridge
from amaranth_stream import PacketFIFO

from lambdaeth.common import convert_ip, convert_mac
from lambdaeth.mac import MACCore
from lambdaeth.phy import ECP5RGMIIPHY
from lambdaeth.core import (UDPIPCore, TCPServer, TCPClient,
                            udp_user_signature, eth_stream_signature)
from lambdaeth.core import _normalize_tcp_ports
from lambdaeth.core.boundary import MACByteBoundary
from lambdaeth.soc import UARTWishboneBridge


DEFAULT_MAC       = "02:4c:45:54:48:01"
DEFAULT_IP        = "192.168.10.50"
DEFAULT_UDP_PORTS = (8000, 8001, 8002)
DEFAULT_TCP_PORTS = (2000, 2001)
CLK100_FREQ       = 100e6


# CSR registers --------------------------------------------------------------------------------

class Scratch(csr.Register, access="rw"):
    value: csr.Field(csr.action.RW, 32, init=0x1a3bdae7)


class MacAddress(csr.Register, access="rw"):
    def __init__(self, init):
        super().__init__({"value": csr.Field(csr.action.RW, 48, init=init)})


class IpAddress(csr.Register, access="rw"):
    def __init__(self, init):
        super().__init__({"value": csr.Field(csr.action.RW, 32, init=init)})


class UdpPort(csr.Register, access="rw"):
    def __init__(self, init):
        super().__init__({"value": csr.Field(csr.action.RW, 16, init=init)})


class Counter32(csr.Register, access="r"):
    value: csr.Field(csr.action.R, 32)


# Clocking -------------------------------------------------------------------------------------

def pll_params(f_in, f_out, vco_min=400e6, vco_max=800e6, pfd_min=3.125e6, pfd_max=400e6):
    """EHXPLLL dividers for an exact ``f_in -> f_out`` (the ``ecppll`` search:
    prefer a VCO near 600 MHz)."""
    best = None
    for clki_div in range(1, 129):
        f_pfd = f_in / clki_div
        if not pfd_min <= f_pfd <= pfd_max:
            continue
        for clkfb_div in range(1, 81):
            for clkop_div in range(1, 129):
                f_vco = f_pfd * clkfb_div * clkop_div
                if not vco_min <= f_vco <= vco_max:
                    continue
                if abs(f_vco / clkop_div - f_out) > 1e-3:
                    continue
                score = abs(f_vco - 600e6)
                if best is None or score < best[0]:
                    best = (score, clki_div, clkfb_div, clkop_div)
    if best is None:
        raise ValueError(f"no EHXPLLL configuration for {f_in/1e6} MHz -> {f_out/1e6} MHz")
    _, clki_div, clkfb_div, clkop_div = best
    return {"clki_div": clki_div, "clkfb_div": clkfb_div, "clkop_div": clkop_div}


class SysPLL(Elaboratable):
    """``clk_in`` -> EHXPLLL -> ``clk_out`` (CLKOP, internal feedback), plus
    the asynchronous ``locked`` output."""
    def __init__(self, f_in, f_out):
        self.f_in   = f_in
        self.f_out  = f_out
        self.params = pll_params(f_in, f_out)
        self.clk_in  = Signal()
        self.clk_out = Signal()
        self.locked  = Signal()

    def elaborate(self, platform):
        m = Module()
        p = self.params
        m.submodules.pll = Instance("EHXPLLL",
            a_FREQUENCY_PIN_CLKI    = str(int(self.f_in / 1e6)),
            a_FREQUENCY_PIN_CLKOP   = str(int(self.f_out / 1e6)),
            a_ICP_CURRENT           = "12",
            a_LPF_RESISTOR          = "8",
            a_MFG_ENABLE_FILTEROPAMP= "1",
            a_MFG_GMCREF_SEL        = "2",
            p_PLLRST_ENA     = "DISABLED",
            p_INTFB_WAKE     = "DISABLED",
            p_STDBY_ENABLE   = "DISABLED",
            p_DPHASE_SOURCE  = "DISABLED",
            p_OUTDIVIDER_MUXA= "DIVA",
            p_OUTDIVIDER_MUXB= "DIVB",
            p_OUTDIVIDER_MUXC= "DIVC",
            p_OUTDIVIDER_MUXD= "DIVD",
            p_CLKI_DIV       = p["clki_div"],
            p_CLKOP_ENABLE   = "ENABLED",
            p_CLKOP_DIV      = p["clkop_div"],
            p_CLKOP_CPHASE   = max(p["clkop_div"] // 2 - 1, 0),
            p_CLKOP_FPHASE   = 0,
            p_FEEDBK_PATH    = "CLKOP",
            p_CLKFB_DIV      = p["clkfb_div"],
            i_RST          = C(0),
            i_STDBY        = C(0),
            i_CLKI         = self.clk_in,
            o_CLKOP        = self.clk_out,
            i_CLKFB        = self.clk_out,
            i_PHASESEL0    = C(0),
            i_PHASESEL1    = C(0),
            i_PHASEDIR     = C(1),
            i_PHASESTEP    = C(1),
            i_PHASELOADREG = C(1),
            i_PLLWAKESYNC  = C(0),
            i_ENCLKOP      = C(0),
            o_LOCK         = self.locked,
        )
        return m


# Top ------------------------------------------------------------------------------------------

class UDPEcho(Elaboratable):
    def __init__(self, mac_addr=DEFAULT_MAC, ip_addr=DEFAULT_IP,
                 sys_clk_freq=50e6, baudrate=115200, with_icmp=True,
                 udp_ports=DEFAULT_UDP_PORTS, tcp_ports=DEFAULT_TCP_PORTS,
                 with_dhcp=False, tcp_mss=536, tcp_rx_depth=2048,
                 rx_cdc_depth=512, tcp_bench=False,
                 tx_delay=2e-9, rx_delay=0e-9):
        self.mac_init     = convert_mac(mac_addr)
        self.ip_init      = convert_ip(ip_addr)
        self.sys_clk_freq = sys_clk_freq
        self.baudrate     = baudrate
        self.with_icmp    = with_icmp
        self.with_dhcp    = with_dhcp
        self.udp_ports    = [int(port) for port in udp_ports]
        self.tcp_ports    = _normalize_tcp_ports(
            list(tcp_ports) if tcp_ports else None)
        self.tcp_mss      = tcp_mss
        self.tcp_rx_depth = tcp_rx_depth
        self.rx_cdc_depth = rx_cdc_depth
        self.tcp_bench    = tcp_bench
        assert len(self.udp_ports) >= 1
        if tcp_bench:
            assert self.tcp_ports and len(self.tcp_ports) >= 2, \
                "--tcp-bench needs two TCP ports (sink + source)"

        # PHY (built here: its CSR window is part of the memory map).
        self.phy = ECP5RGMIIPHY(
            create_domains  = False,
            hw_reset_cycles = int(20e-3 * sys_clk_freq),
            tx_delay        = tx_delay,
            rx_delay        = rx_delay,
            with_mdio       = True,
        )

        # CSRs (built here so the memory map is available before elaboration).
        # The map itself is shaped by the enabled features.
        tcp_specs = list((self.tcp_ports or {}).values())
        n_clients = sum(spec.mode == "client" for spec in tcp_specs)
        est = (0x50 + 2 * len(self.udp_ports) + 2 * len(tcp_specs) +
               6 * n_clients + (24 if tcp_specs else 0) +
               (8 if with_dhcp else 0) + (8 if tcp_bench else 0))
        addr_width = max(6, (est - 1).bit_length())
        regs = csr.Builder(addr_width=addr_width, data_width=8)
        self.scratch     = regs.add("scratch",     Scratch())
        self.mac_reg     = regs.add("mac_address", MacAddress(init=self.mac_init))
        if with_dhcp:
            # The network assigns the IP; expose the lease (0 = unbound).
            self.dhcp_ip_reg = regs.add("dhcp_ip", Counter32())
        else:
            self.ip_reg = regs.add("ip_address", IpAddress(init=self.ip_init))
        # One runtime port binding per requested UDP/TCP endpoint (p0, p1,
        # ... match the auto-named UDPIPCore user ports); TCP clients also
        # get their remote target.
        self.udp_port_regs = [
            regs.add(f"udp_port_p{i}", UdpPort(init=port))
            for i, port in enumerate(self.udp_ports)
        ]
        self.tcp_port_regs = []
        self.tcp_remote_regs = {}
        for i, (name, spec) in enumerate((self.tcp_ports or {}).items()):
            self.tcp_port_regs.append(
                regs.add(f"tcp_port_{name}", UdpPort(init=spec.local_port)))
            if spec.mode == "client":
                self.tcp_remote_regs[name] = (
                    regs.add(f"tcp_remote_ip_{name}",
                             IpAddress(init=spec.remote_ip)),
                    regs.add(f"tcp_remote_port_{name}",
                             UdpPort(init=spec.remote_port)),
                )
        self.rx_frames   = regs.add("rx_frames",   Counter32())
        self.rx_errors   = regs.add("rx_errors",   Counter32())
        self.arp_events  = regs.add("arp_events",  Counter32())
        self.udp_rx_cnt  = regs.add("udp_rx",      Counter32())
        self.udp_tx_cnt  = regs.add("udp_tx",      Counter32())
        self.udp_drop_cnt = regs.add("udp_drop",   Counter32())
        self.unreachable = regs.add("unreachable", Counter32())
        if with_icmp:
            self.icmp_cnt = regs.add("icmp_echo",  Counter32())
        if self.tcp_ports:
            self.tcp_rx_cnt   = regs.add("tcp_rx_seg", Counter32())
            self.tcp_tx_cnt   = regs.add("tcp_tx_seg", Counter32())
            self.tcp_drop_cnt = regs.add("tcp_drop",   Counter32())
            self.tcp_rst_cnt  = regs.add("tcp_rst",    Counter32())
            self.tcp_status   = regs.add("tcp_status", Counter32())
        if with_dhcp:
            self.dhcp_events = regs.add("dhcp_events", Counter32())
        if tcp_bench:
            # Benchmark byte counters: PC->FPGA bytes swallowed by the sink
            # endpoint, FPGA->PC bytes emitted by the source endpoint.
            self.bench_rx = regs.add("bench_rx_bytes", Counter32())
            self.bench_tx = regs.add("bench_tx_bytes", Counter32())
        self.csr_bridge  = csr.Bridge(regs.as_memory_map())

        # Combine the stack CSRs with the PHY CSR window.
        self.csr_decoder = csr.Decoder(addr_width=addr_width + 1, data_width=8)
        self.csr_decoder.add(self.csr_bridge.bus, name="core")
        self.csr_decoder.add(self.phy.bus, name="phy")
        self.memory_map  = self.csr_decoder.bus.memory_map

    def elaborate(self, platform):
        m = Module()

        # Clocking: clk100 -> PLL -> sync; reset while the PLL is unlocked ----------------
        clk100 = platform.request("clk100", 0)
        m.submodules.sys_pll = sys_pll = SysPLL(CLK100_FREQ, self.sys_clk_freq)
        sys_clk = Signal()
        m.domains += ClockDomain("sync")
        m.d.comb += [
            sys_pll.clk_in.eq(clk100.i),
            sys_clk.eq(sys_pll.clk_out),
            ClockSignal("sync").eq(sys_clk),
        ]
        m.submodules.sys_rst_sync = ResetSynchronizer(~sys_pll.locked, domain="sync")
        platform.add_clock_constraint(sys_clk, self.sys_clk_freq)

        # Clock domains (common ancestor of PHY and MAC).
        m.domains += ClockDomain("eth_tx")
        m.domains += ClockDomain("eth_rx")

        # PHY + MAC ------------------------------------------------------------------------
        phy = self.phy
        mac = MACCore(phy, data_width=32, with_csr=False,
                      rx_cdc_depth=self.rx_cdc_depth)
        m.submodules.phy = phy
        m.submodules.mac = mac
        connect(m, mac.phy_tx, phy.tx)
        connect(m, phy.rx, mac.phy_rx)

        # Pads: DDR/clock pads are raw (the PHY owns the ODDRX1F/IDDRX1F/DELAYG
        # chain, which nextpnr packs into the IOLOGIC of the pad), the slow
        # pads use regular platform buffers (the rst pin is active-low) ------------------
        eth = platform.request("eth_rgmii", 0, dir={
            "rst": "o", "mdc": "o", "mdio": "io",
            "tx_clk": "-", "tx_ctrl": "-", "tx_data": "-",
            "rx_clk": "-", "rx_ctrl": "-", "rx_data": "-",
        })
        platform.add_clock_constraint(eth.rx_clk.io, phy.rx_clk_freq)

        rx_clk  = Signal()
        rx_ctl  = Signal()
        rx_data = Signal(4)
        m.submodules.rx_clk_buf = IOBufferInstance(eth.rx_clk.io,  i=rx_clk)
        m.submodules.rx_ctl_buf = IOBufferInstance(eth.rx_ctrl.io, i=rx_ctl)
        m.submodules.rx_dat_buf = IOBufferInstance(eth.rx_data.io, i=rx_data)
        m.submodules.tx_clk_buf = IOBufferInstance(eth.tx_clk.io,  o=phy.clk_tx)
        m.submodules.tx_ctl_buf = IOBufferInstance(eth.tx_ctrl.io, o=phy.tx_ctl)
        m.submodules.tx_dat_buf = IOBufferInstance(eth.tx_data.io, o=phy.tx_data)
        m.d.comb += [
            phy.clk_rx.eq(rx_clk),
            phy.rx_ctl.eq(rx_ctl),
            phy.rx_data.eq(rx_data),
            eth.rst.o.eq(~phy.rst_n),       # logical reset (pad is active-low)
            eth.mdc.o.eq(phy.mdc),
            eth.mdio.o.eq(phy.mdio.o),
            eth.mdio.oe.eq(phy.mdio.oe),
            phy.mdio.i.eq(eth.mdio.i),
        ]

        # UDP/IP core (8-bit, sys domain) ----------------------------------------------------
        m.submodules.core = core = UDPIPCore(clk_freq=self.sys_clk_freq,
                                             with_icmp=self.with_icmp,
                                             udp_ports=self.udp_ports,
                                             tcp_ports=self.tcp_ports,
                                             with_dhcp=self.with_dhcp,
                                             tcp_mss=self.tcp_mss,
                                             tcp_rx_depth=self.tcp_rx_depth)
        m.d.comb += core.mac_address.eq(self.mac_reg.f.value.data)
        if self.with_dhcp:
            m.d.comb += self.dhcp_ip_reg.f.value.r_data.eq(core.dhcp_ip)
        else:
            m.d.comb += core.ip_address.eq(self.ip_reg.f.value.data)

        # Width/framing boundary between the byte-wide core and the 32-bit
        # MAC user interface (store-and-forward TX for line-rate bursts).
        m.submodules.boundary = boundary = MACByteBoundary(mac_dw=32)
        connect(m, boundary.mac_tx, mac.sink)
        connect(m, mac.source, boundary.mac_rx)
        connect(m, core.mac_tx, boundary.eth_tx)
        connect(m, boundary.eth_rx, core.mac_rx)

        # One UDP echo loop per bound port, each through its own store-and-
        # forward FIFO (decouples RX from TX so ARP replies are never blocked
        # by an in-flight echo). The core forces each TX src_port to the
        # binding, so only the destination is set here: back to the sender.
        for i, name in enumerate(core.udp_ports):
            echo = PacketFIFO(udp_user_signature(),
                              payload_depth=2048, packet_depth=8)
            m.submodules[f"echo_fifo_{name}"] = echo
            tx = getattr(core, f"udp_tx_{name}")
            connect(m, getattr(core, f"udp_rx_{name}"), echo.i_stream)
            m.d.comb += [
                tx.valid.eq(echo.o_stream.valid),
                tx.payload.eq(echo.o_stream.payload),
                tx.first.eq(echo.o_stream.first),
                tx.last.eq(echo.o_stream.last),
                echo.o_stream.ready.eq(tx.ready),
                tx.param.ip.eq(echo.o_stream.param.ip),
                tx.param.dst_port.eq(echo.o_stream.param.src_port),
                tx.param.length.eq(echo.o_stream.param.length),
                # Runtime rebinding from CSR (init = the requested port).
                getattr(core, f"udp_port_{name}")
                    .eq(self.udp_port_regs[i].f.value.data),
            ]

        # TCP endpoint fabrics. Default: echo loops (rx -> FIFO -> tx,
        # closing once the peer closed and every byte went back). With
        # --tcp-bench, the first endpoint becomes a byte *sink* (PC->FPGA
        # benchmark, counted in bench_rx_bytes) and the second a pattern
        # *source* (FPGA->PC benchmark, counted in bench_tx_bytes) — no
        # echoing, so neither direction waits on the other.
        for i, (name, spec) in enumerate((core.tcp_ports or {}).items()):
            rx = getattr(core, f"tcp_rx_{name}")
            tx = getattr(core, f"tcp_tx_{name}")
            connected   = getattr(core, f"tcp_connected_{name}")
            peer_closed = getattr(core, f"tcp_peer_closed_{name}")

            if self.tcp_bench and i == 0:
                # Upload sink: swallow everything at one byte per cycle.
                count = Signal(32)
                m.d.comb += [
                    rx.ready.eq(1),
                    self.bench_rx.f.value.r_data.eq(count),
                    getattr(core, f"tcp_close_{name}").eq(peer_closed),
                ]
                with m.If(rx.valid):
                    m.d.sync += count.eq(count + 1)
            elif self.tcp_bench and i == 1:
                # Download source: stream an incrementing byte pattern while
                # connected; the engine cuts segments at the effective MSS.
                count = Signal(32)
                pattern = Signal(8)
                m.d.comb += [
                    tx.valid.eq(connected & ~peer_closed),
                    tx.payload.eq(pattern),
                    rx.ready.eq(1),
                    self.bench_tx.f.value.r_data.eq(count),
                    getattr(core, f"tcp_close_{name}").eq(peer_closed),
                ]
                with m.If(tx.valid & tx.ready):
                    m.d.sync += [pattern.eq(pattern + 1),
                                 count.eq(count + 1)]
                with m.If(~connected):
                    m.d.sync += pattern.eq(0)
            else:
                echo = PacketFIFO(eth_stream_signature(),
                                  payload_depth=2048, packet_depth=8)
                m.submodules[f"tcp_echo_{name}"] = echo
                connect(m, rx, echo.i_stream)
                connect(m, echo.o_stream, tx)

                rx_bytes = Signal(32)
                tx_bytes = Signal(32)
                with m.If(rx.valid & rx.ready):
                    m.d.sync += rx_bytes.eq(rx_bytes + 1)
                with m.If(tx.valid & tx.ready):
                    m.d.sync += tx_bytes.eq(tx_bytes + 1)
                m.d.comb += getattr(core, f"tcp_close_{name}").eq(
                    peer_closed & (rx_bytes == tx_bytes))

            m.d.comb += [
                getattr(core, f"tcp_port_{name}")
                    .eq(self.tcp_port_regs[i].f.value.data),
                self.tcp_status.f.value.r_data[2*i].eq(connected),
                self.tcp_status.f.value.r_data[2*i + 1].eq(peer_closed),
            ]
            if spec.mode == "client":
                ip_reg, port_reg = self.tcp_remote_regs[name]
                m.d.comb += [
                    getattr(core, f"tcp_remote_ip_{name}")
                        .eq(ip_reg.f.value.data),
                    getattr(core, f"tcp_remote_port_{name}")
                        .eq(port_reg.f.value.data),
                ]

        # CSR plumbing: UART -> Wishbone -> CSR decoder (core + phy windows) -----------------
        m.submodules.csr_bridge  = self.csr_bridge
        m.submodules.csr_decoder = self.csr_decoder
        m.submodules.wb_bridge   = wb_bridge = WishboneCSRBridge(
            self.csr_decoder.bus, data_width=32)
        m.submodules.uart_bridge = uart_bridge = UARTWishboneBridge(
            addr_width = wb_bridge.wb_bus.addr_width,
            divisor    = round(self.sys_clk_freq / self.baudrate))
        connect(m, uart_bridge.wb, wb_bridge.wb_bus)

        uart_pins = platform.request("uart", 0)
        m.d.comb += [
            uart_bridge.rx_i.eq(uart_pins.rx.i),
            uart_pins.tx.o.eq(uart_bridge.tx_o),
        ]

        # Counters ---------------------------------------------------------------------------
        def counter(reg, pulse):
            count = Signal(32)
            with m.If(pulse):
                m.d.sync += count.eq(count + 1)
            m.d.comb += reg.f.value.r_data.eq(count)
            return count

        rx_last = Signal()
        rx_err  = Signal()
        m.d.comb += [
            rx_last.eq(mac.source.valid & mac.source.ready & mac.source.last),
            rx_err.eq(rx_last & (mac.source.p.error != 0)),
        ]
        counter(self.rx_frames, rx_last)
        counter(self.rx_errors, rx_err)
        arp_cnt = counter(self.arp_events, core.arp_event)
        rx_cnt  = counter(self.udp_rx_cnt, core.udp_rx_pkt)
        tx_cnt  = counter(self.udp_tx_cnt, core.udp_tx_pkt)
        counter(self.udp_drop_cnt, core.udp_drop)
        counter(self.unreachable, core.unreachable)
        if self.with_icmp:
            counter(self.icmp_cnt, core.icmp_pkt)
        if self.tcp_ports:
            counter(self.tcp_rx_cnt,   core.tcp_rx_seg)
            counter(self.tcp_tx_cnt,   core.tcp_tx_seg)
            counter(self.tcp_drop_cnt, core.tcp_drop)
            counter(self.tcp_rst_cnt,  core.tcp_rst)
        if self.with_dhcp:
            counter(self.dhcp_events, core.dhcp_event)

        # LEDs (RGB, active-high after the platform inversion) ------------------------------
        sys_beat = Signal(26)
        m.d.sync += sys_beat.eq(sys_beat + 1)
        eth_beat = Signal(27)
        m.d.eth_rx += eth_beat.eq(eth_beat + 1)
        rx_act = Signal(23)
        with m.If(phy.rx.valid):
            m.d.eth_rx += rx_act.eq(-1)
        with m.Elif(rx_act != 0):
            m.d.eth_rx += rx_act.eq(rx_act - 1)

        leds = [platform.request("rgb_led", i) for i in range(4)]
        m.d.comb += [
            leds[0].g.o.eq(sys_beat[-1]),
            leds[1].g.o.eq(eth_beat[-1]),
            leds[2].b.o.eq(rx_act != 0),
            leds[3].r.o.eq(arp_cnt[0]),
            leds[3].g.o.eq(rx_cnt[0]),
            leds[3].b.o.eq(tx_cnt[0]),
        ]

        return m


def dump_csr_map(top, path):
    resources = {}

    def walk(memory_map, prefix, base):
        for _reg, reg_name, (start, end) in memory_map.resources():
            name = "__".join(str(part) for part in (*prefix, *reg_name))
            resources[name] = {"addr": base + start, "size": end - start}
        for window, win_name, (start, _end, _ratio) in memory_map.windows():
            walk(window, (*prefix, *(win_name or ())), base + start)

    walk(top.memory_map, (), 0)
    resources = dict(sorted(resources.items(), key=lambda kv: kv[1]["addr"]))
    with open(path, "w") as f:
        json.dump(resources, f, indent=2)
    return resources


def select_toolchain():
    """Point Amaranth at the YoWASP tools when the native ones are absent."""
    chosen = {}
    for tool in ("yosys", "nextpnr-ecp5", "ecppack"):
        env_var = tool.upper().replace("-", "_")
        if env_var in os.environ:
            chosen[tool] = os.environ[env_var]
        elif shutil.which(tool):
            chosen[tool] = tool
        elif shutil.which(f"yowasp-{tool}"):
            os.environ[env_var] = chosen[tool] = f"yowasp-{tool}"
        else:
            chosen[tool] = f"{tool} (NOT FOUND: install it or `pdm install -G ecp5`)"
    return chosen


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mac", default=DEFAULT_MAC)
    parser.add_argument("--ip", default=DEFAULT_IP)
    parser.add_argument("--udp-port", type=int, action="append", dest="udp_ports",
                        metavar="PORT",
                        help="Bind a UDP echo stream to PORT (repeatable; "
                             f"default: {' '.join(map(str, DEFAULT_UDP_PORTS))})")
    parser.add_argument("--tcp-port", type=int, action="append", dest="tcp_ports",
                        metavar="PORT",
                        help="Listen with a TCP echo server on PORT "
                             "(repeatable; default: "
                             f"{' '.join(map(str, DEFAULT_TCP_PORTS))})")
    parser.add_argument("--tcp-client", action="append", dest="tcp_clients",
                        metavar="IP:PORT[:LOCAL]",
                        help="Actively connect a TCP echo endpoint out to "
                             "IP:PORT (repeatable; retries/reconnects "
                             "forever; LOCAL = fixed source port)")
    parser.add_argument("--no-tcp", action="store_true",
                        help="Build without any TCP logic")
    parser.add_argument("--tcp-mss", type=int, default=536,
                        help="TCP segment size limit / advertised MSS "
                             "(default 536; 1460 fills ethernet frames)")
    parser.add_argument("--tcp-rx-depth", type=int, default=2048,
                        help="TCP RX buffer per endpoint = advertised "
                             "window (BRAM bytes)")
    parser.add_argument("--rx-cdc-depth", type=int, default=512,
                        help="MAC RX CDC FIFO depth in 32-bit words (raise "
                             "to absorb window-sized bursts when benching)")
    parser.add_argument("--tcp-bench", action="store_true",
                        help="Replace the first two TCP echo servers with a "
                             "byte sink (port A, PC->FPGA) and a pattern "
                             "source (port B, FPGA->PC); see "
                             "scripts/tcp_bench.py and the bench_*_bytes "
                             "CSRs")
    parser.add_argument("--no-icmp", action="store_true",
                        help="Build without the ICMP echo responder")
    parser.add_argument("--dhcp", action="store_true",
                        help="Acquire the IP address via DHCP (--ip is "
                             "ignored; read the lease from the dhcp_ip CSR)")
    parser.add_argument("--sys-clk-freq", type=float, default=50e6,
                        help="System clock (PLL from clk100), Hz (default 50e6)")
    parser.add_argument("--tx-delay", type=float, default=2.0,
                        help="RGMII TX clock skew in ns (default 2.0)")
    parser.add_argument("--rx-delay", type=float, default=0.0,
                        help="RGMII RX input skew in ns (default 0.0)")
    parser.add_argument("--variant", choices=("85", "45"), default="85",
                        help="ECPIX-5 FPGA variant (default 85)")
    parser.add_argument("--nextpnr-opts", default="",
                        help="Extra nextpnr-ecp5 options (e.g. "
                             "'--timing-allow-fail --seed 3')")
    parser.add_argument("--build-dir", default="build/ecpix5_udp_echo")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()

    from amaranth_boards.ecpix5 import ECPIX585Platform, ECPIX545Platform

    udp_ports = args.udp_ports or list(DEFAULT_UDP_PORTS)
    if args.no_tcp:
        tcp_ports = None
    else:
        tcp_ports = [TCPServer(p)
                     for p in (args.tcp_ports or DEFAULT_TCP_PORTS)]
        for spec in (args.tcp_clients or ()):
            parts = spec.split(":")
            tcp_ports.append(TCPClient(
                parts[0], int(parts[1]),
                local_port=int(parts[2]) if len(parts) > 2 else None))
    top = UDPEcho(mac_addr=args.mac, ip_addr=args.ip, with_icmp=not args.no_icmp,
                  udp_ports=udp_ports, tcp_ports=tcp_ports,
                  with_dhcp=args.dhcp, tcp_mss=args.tcp_mss,
                  tcp_rx_depth=args.tcp_rx_depth,
                  rx_cdc_depth=args.rx_cdc_depth, tcp_bench=args.tcp_bench,
                  sys_clk_freq=args.sys_clk_freq,
                  tx_delay=args.tx_delay * 1e-9, rx_delay=args.rx_delay * 1e-9)
    if args.dhcp:
        print("IP address: DHCP (read the lease from the dhcp_ip CSR)")
    print(f"UDP echo streams: "
          f"{', '.join(f'p{i}={p}' for i, p in enumerate(udp_ports))}")
    if tcp_ports:
        print("TCP endpoints: " + ", ".join(
            f"p{i}={spec!r}" for i, spec in
            enumerate(top.tcp_ports.values())))
    print(f"sys clock: {args.sys_clk_freq/1e6:g} MHz "
          f"(PLL {pll_params(CLK100_FREQ, args.sys_clk_freq)}); "
          f"RGMII tx_delay {args.tx_delay} ns, rx_delay {args.rx_delay} ns")

    os.makedirs(args.build_dir, exist_ok=True)
    csr_map = dump_csr_map(top, os.path.join(args.build_dir, "csr.json"))
    print("CSR map (byte addresses over the UART bridge):")
    for name, info in csr_map.items():
        print(f"  {info['addr']:#06x} {name} ({info['size']} bytes)")

    tools = select_toolchain()
    print("Toolchain: " + ", ".join(f"{k}={v}" for k, v in tools.items()))

    platform_cls = ECPIX585Platform if args.variant == "85" else ECPIX545Platform
    platform = platform_cls()
    result = platform.build(
        top,
        name        = "udp_echo",
        build_dir   = args.build_dir,
        do_build    = not args.no_build,
        do_program  = False,
        nextpnr_opts = args.nextpnr_opts,
        # KSZ9031 MODE[3:0] straps are RXD[3:0]: pull-ups select RGMII with
        # all capabilities advertised (as LiteX does for this board).
        add_preferences = "\n".join(
            f'IOBUF PORT "eth_rgmii_0__rx_data__io[{i}]" PULLMODE=UP;'
            for i in range(4)) + "\n",
    )
    if args.no_build:
        result.execute_local(args.build_dir, run_script=False)
    print(f"Build artifacts in {args.build_dir}")


if __name__ == "__main__":
    main()
