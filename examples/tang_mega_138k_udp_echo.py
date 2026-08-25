#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""UDP + TCP echo demo for the Sipeed Tang Mega 138K Pro dock.

Architecture::

  RGMII PHY <-> MACCore(32) <-> width/packet adapters <-> UDPIPCore(8) <-> echo FIFO x N
                                                            ^ mac/ip/ports from CSR
  UART (115200) -> UARTWishboneBridge -> Wishbone -> WishboneCSRBridge -> CSRs

* The board answers ARP for its IP and replies to ICMP echo (ping).
* One UDP user stream pair is built per requested port (--udp-port, repeat
  for more; default 8000 8001 8002). Each is looped back through its own
  FIFO: a datagram sent to a bound port is echoed back to the sender from
  that port. Datagrams to unbound ports are dropped (see the udp_drop
  counter). With a single --udp-port, no TX arbitration logic is generated.
* One TCP echo server is built per requested listen port (--tcp-port, repeat
  for more; default 2000 2001; --no-tcp removes all TCP logic). Each port
  carries one connection at a time (`nc 192.168.10.50 2000`): bytes are
  echoed back, further connection attempts and unbound ports are refused
  (RST), and the connection closes cleanly after the client's FIN.
* TCP *client* endpoints are added with --tcp-client IP:PORT[:LOCAL]
  (repeatable): the board actively connects out to IP:PORT (retrying every
  second until the server appears, reconnecting after closes) and echoes
  whatever that server sends. Remote IP/port are CSR-retargetable
  (tcp_remote_ip_p<i>/tcp_remote_port_p<i>, next attempt).
* ICMP support is optional at build time (--no-icmp): when disabled, none of
  the ICMP logic (responder, protocol dispatch, TX arbiter, CSR counter) is
  generated.
* With --dhcp the board gets its IP from the network instead: the DHCP
  client binds a lease as soon as the link comes up (renewing it at half
  the lease), nothing is answered until then, and the leased address is
  readable in the ``dhcp_ip`` CSR (0 while unbound). The ``ip_address``
  CSR does not exist in this configuration (--ip is ignored) and TCP
  client endpoints hold their connection attempts until bound.
* MAC/IP addresses and the port bindings are runtime-configurable via CSR
  over the UART bridge (defaults let it work out of the box):
  ``csrctl.py write udp_port_p0 9000`` rebinds the first UDP stream,
  ``csrctl.py write tcp_port_p0 2323`` the first TCP listener (effective
  for the next connection). See ``scripts/csrctl.py``.
* CSR also exposes a scratch register, RX/ARP/UDP/ICMP/TCP/DHCP counters
  and a TCP status register (bit 2i = connected, bit 2i+1 = peer closed).
* LEDs: 0 sys heartbeat, 1 eth_rx heartbeat, 2 RX activity, 3 ARP event,
  4 UDP RX datagram, 5 UDP TX datagram.

Usage:
    python examples/tang_mega_138k_udp_echo.py [--ip 192.168.10.50 | --dhcp]
        [--udp-port 8000 ...] [--tcp-port 2000 ...]
        [--tcp-client 192.168.10.120:5001 ...] [--no-icmp] [--no-tcp]
"""

import argparse
import json
import os
import sys

from amaranth.hdl import (Module, Signal, Elaboratable, ClockDomain, ClockSignal,
                          Instance, C, IOBufferInstance)
from amaranth.lib.wiring import connect

from amaranth_soc import csr
from amaranth_soc.csr.wishbone import WishboneCSRBridge
from amaranth_stream import PacketFIFO

from lambdaeth.common import convert_ip, convert_mac
from lambdaeth.mac import MACCore
from lambdaeth.phy import GW5RGMIIPHY
from lambdaeth.core import (UDPIPCore, TCPServer, TCPClient,
                            udp_user_signature, eth_stream_signature)
from lambdaeth.core import _normalize_tcp_ports
from lambdaeth.core.boundary import MACByteBoundary
from lambdaeth.soc import UARTWishboneBridge


DEFAULT_MAC       = "02:4c:45:54:48:00"
DEFAULT_IP        = "192.168.10.50"
DEFAULT_UDP_PORTS = (8000, 8001, 8002)
DEFAULT_TCP_PORTS = (2000, 2001)


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


# Top ------------------------------------------------------------------------------------------

class UDPEcho(Elaboratable):
    def __init__(self, mac_addr=DEFAULT_MAC, ip_addr=DEFAULT_IP,
                 sys_clk_freq=50e6, baudrate=115200, with_icmp=True,
                 udp_ports=DEFAULT_UDP_PORTS, tcp_ports=DEFAULT_TCP_PORTS,
                 with_dhcp=False, tcp_mss=536, tcp_rx_depth=2048,
                 rx_cdc_depth=512, tcp_bench=False):
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
        self.memory_map  = self.csr_bridge.bus.memory_map

    def elaborate(self, platform):
        m = Module()

        # Clock domains (common ancestor of PHY and MAC).
        m.domains += ClockDomain("eth_tx")
        m.domains += ClockDomain("eth_rx")

        # PHY + MAC ------------------------------------------------------------------------
        phy = GW5RGMIIPHY(
            create_domains  = False,
            hw_reset_cycles = int(20e-3 * self.sys_clk_freq),
        )
        mac = MACCore(phy, data_width=32, with_csr=False,
                      rx_cdc_depth=self.rx_cdc_depth)
        m.submodules.phy = phy
        m.submodules.mac = mac
        connect(m, mac.phy_tx, phy.tx)
        connect(m, phy.rx, mac.phy_rx)

        # Pads (direct `assign`; Gowin packs the IOBs itself) ---------------------------------
        eth_clocks = platform.request("eth_clocks", 0, dir="-")
        eth        = platform.request("eth", 0, dir="-")
        ephy_clk   = platform.request("ephy_clk", 0, dir="-")

        rx_clk  = Signal()
        rx_ctl  = Signal()
        rx_data = Signal(4)
        m.submodules.rx_clk_buf = IOBufferInstance(eth_clocks.rx.io, i=rx_clk)
        m.submodules.tx_clk_buf = IOBufferInstance(eth_clocks.tx.io, o=phy.clk_tx)
        m.submodules.rx_ctl_buf = IOBufferInstance(eth.rx_ctl.io, i=rx_ctl)
        m.submodules.rx_dat_buf = IOBufferInstance(eth.rx_data.io, i=rx_data)
        m.submodules.tx_ctl_buf = IOBufferInstance(eth.tx_ctl.io, o=phy.tx_ctl)
        m.submodules.tx_dat_buf = IOBufferInstance(eth.tx_data.io, o=phy.tx_data)
        m.submodules.rst_n_buf  = IOBufferInstance(eth.rst_n.io, o=phy.rst_n)
        mdc = Signal()
        m.submodules.mdc_buf    = IOBufferInstance(eth.mdc.io, o=mdc)
        m.d.comb += [
            phy.clk_rx.eq(rx_clk),
            phy.rx_ctl.eq(rx_ctl),
            phy.rx_data.eq(rx_data),
        ]

        # 25 MHz reference clock for the RTL8211F.
        clk25  = Signal()
        ephy_o = Signal()
        m.submodules.ephy_clkdiv = Instance("CLKDIV",
            p_DIV_MODE="2", i_HCLKIN=ClockSignal("sync"), i_RESETN=C(1),
            i_CALIB=C(0), o_CLKOUT=clk25)
        m.submodules.ephy_oddr = Instance("ODDR",
            i_CLK=clk25, i_D0=C(1), i_D1=C(0), i_TX=C(0), o_Q0=ephy_o)
        m.submodules.ephy_buf = IOBufferInstance(ephy_clk.io, o=ephy_o)

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

        # CSR plumbing: UART -> Wishbone -> CSR ------------------------------------------------
        m.submodules.csr_bridge = self.csr_bridge
        m.submodules.wb_bridge  = wb_bridge = WishboneCSRBridge(
            self.csr_bridge.bus, data_width=32)
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

        # LEDs ----------------------------------------------------------------------------
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
            platform.request("led", 3).o.eq(arp_cnt[0]),
            platform.request("led", 4).o.eq(rx_cnt[0]),
            platform.request("led", 5).o.eq(tx_cnt[0]),
        ]

        return m


def dump_csr_map(top, path):
    resources = {}
    for _reg, reg_name, (start, end) in top.memory_map.resources():
        resources["__".join(str(part) for part in reg_name)] = {
            "addr": start, "size": end - start,
        }
    with open(path, "w") as f:
        json.dump(resources, f, indent=2)
    return resources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
    parser.add_argument("--build-dir", default="build/tang_mega_138k_udp_echo")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()

    from amaranth_boards.tang_mega_138k_pro_dock import TangMega138kProDockPlatform

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
                  rx_cdc_depth=args.rx_cdc_depth, tcp_bench=args.tcp_bench)
    if args.dhcp:
        print("IP address: DHCP (read the lease from the dhcp_ip CSR)")
    print(f"UDP echo streams: "
          f"{', '.join(f'p{i}={p}' for i, p in enumerate(udp_ports))}")
    if tcp_ports:
        print("TCP endpoints: " + ", ".join(
            f"p{i}={spec!r}" for i, spec in
            enumerate(top.tcp_ports.values())))

    os.makedirs(args.build_dir, exist_ok=True)
    csr_map = dump_csr_map(top, os.path.join(args.build_dir, "csr.json"))
    print("CSR map (byte addresses over the UART bridge):")
    for name, info in csr_map.items():
        print(f"  {info['addr']:#06x} {name} ({info['size']} bytes)")

    platform = TangMega138kProDockPlatform(toolchain="Gowin")
    result = platform.build(
        top,
        name        = "udp_echo",
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
