#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""1000BASE-X (SFP) UDP + TCP echo demo for the Sipeed Tang Mega 138K Pro dock.

The dock routes GTR12 quad 1 lanes 0 and 1 to the two SFP cages; the 125 MHz
SERDES reference clock is on Q1 REFPAD0. The GTR12 hard PCS is configured
(via ``gowin-serdes``) for 1.25 Gb/s, CPLL, 10-bit fabric width, 8b10b and
K28.5 word alignment — the fabric-side PCS (Clause 36/37 ordered sets and
autonegotiation) is :class:`lambdaeth.phy.GW51000BASEXPHY`.

Architecture::

  SFP0 <-> GTR12 Q1 lane0 <-> GW51000BASEXPHY <-> MACCore(32) <-> UDPIPCore(8) <-> echo x N
  SFP1 <-> GTR12 Q1 lane1 <-> GW51000BASEXPHY (autoneg partner, no MAC)
  UART (115200) -> UARTWishboneBridge -> Wishbone -> WishboneCSRBridge -> CSRs

* Lane 0 carries the full UDP/TCP/ICMP echo stack (same behavior as the
  RGMII ``tang_mega_138k_udp_echo.py`` example).
* Lane 1 (unless --no-partner) is an autonegotiation-only link partner: with
  a fiber/DAC between the two SFP cages, both PHYs complete Clause 37
  autoneg and report link up — a full serdes+PCS hardware self-test.
* --loopback nes|enc|fes configures a lane-0 serdes-internal loopback
  instead (no SFP module needed): with ``nes`` (near-end serial) the PHY
  negotiates against itself, and adding ``--tcp-client <own-ip>:2000``
  makes the TCP stack connect to itself over the looped-back lane — a
  complete serdes+PCS+MAC+TCP hardware self-test.
* CSR map: ``core__*`` (stack registers/counters), ``phy__*`` (lane-0 PCS:
  reset/status/lp_abi), ``phy1__*`` (lane-1 partner). ``phy__status`` bits:
  0 link_up, 1 is_sgmii, 2 pll_ok (CMU), 3 align_link.
* LEDs: 0 sys heartbeat, 1 eth_rx heartbeat, 2 lane0 link_up, 3 lane0
  align_link, 4 lane1 link_up, 5 RX activity.

Usage:
    GW_SH=$PWD/scripts/gw_sh_wrapper pdm run python \
        examples/tang_mega_138k_1000basex.py [--ip 192.168.10.60]
        [--loopback nes] [--no-partner] [--udp-port 8000 ...] [...]

Hardware bring-up (verified):
    # Self-test without SFP modules (link + TCP-to-self over the loop):
    ... tang_mega_138k_1000basex.py --loopback nes --tcp-client 192.168.10.60:2000
    sudo openFPGALoader -b tangmega138k --ftdi-serial 2023102515 \
        build/tang_mega_138k_1000basex/basex_echo.fs
    pdm run python scripts/csrctl.py --port /dev/ttyUSB9 \
        --csr-map build/tang_mega_138k_1000basex/csr.json read phy__status
    # -> 0x0d = link_up | pll_ok | align_link; core__tcp_status -> 0x11
    # With SFP modules and a fiber/DAC between the two cages, build without
    # --loopback: lane0 and lane1 (phy1__status) negotiate with each other.
"""

import argparse
import json
import os
import pathlib

from amaranth.build import Resource, Subsignal, Pins, Attrs
from amaranth.hdl import Module, Signal, Cat, Elaboratable, ClockDomain
from amaranth.lib.cdc import FFSynchronizer, PulseSynchronizer
from amaranth.lib.wiring import connect

from amaranth_soc import csr
from amaranth_soc.csr.wishbone import WishboneCSRBridge
from amaranth_stream import PacketFIFO

from lambdaeth.common import convert_ip, convert_mac
from lambdaeth.mac import MACCore
from lambdaeth.phy import GW51000BASEXPHY
from lambdaeth.core import (UDPIPCore, TCPServer, TCPClient,
                            udp_user_signature, eth_stream_signature)
from lambdaeth.core import _normalize_tcp_ports
from lambdaeth.core.boundary import MACByteBoundary
from lambdaeth.soc import UARTWishboneBridge

from gowin_serdes import (EncodingMode, GearRate, GowinDevice, GowinSerDes,
                          GowinSerDesGroup, LaneConfig, OperationMode,
                          PLLSelection, RefClkSource)


DEFAULT_MAC       = "02:4c:45:54:48:10"
DEFAULT_IP        = "192.168.10.60"
DEFAULT_UDP_PORTS = (8000, 8001, 8002)
DEFAULT_TCP_PORTS = (2000, 2001)


# SerDes configuration ---------------------------------------------------------------------------

def make_serdes(loopback="off", partner=True):
    """GTR12 Q1 lanes 0(+1): 1.25G CPLL, 10-bit, 8b10b, K28.5 align, CTC off.

    Matches the vendor 1GSERETH ``serdes/`` example configuration for the
    Tang Mega 138K Pro (125 MHz on Q1 REFPAD0, SFP0/SFP1 on Q1 lanes 0/1).
    """
    # Match the Gowin IDE 1GSERETH reference output (byte-identical CSR
    # blob): CTC/chbond don't-care fields, and the vendor reset-ownership
    # scheme — CPLL/CMU resets and POR are controlled by the fabric, with
    # the constant lane CTRL word bit 0 set (see ge_pcs serdes_control).
    vendor = {
        "ctc_skipa_pattern":         28,
        "ctc_skipb_pattern":         28,
        "ctc_rd_start_depth":        "8",
        "chbond_cfg_rd_start_depth": 8,
        "cpll_reset_by_fabric":      True,
    }
    vendor_quad = {
        "cmu0_reset_by_fabric": True,
        "cmu1_reset_by_fabric": True,
        "por_toggle_by_fabric": True,
    }
    # Valid IDE loopBack values: OFF, LB_NES (near-end serial), LB_FES
    # (far-end serial), LB_ENC, RX_ONLY, TX_ONLY (case-sensitive; unknown
    # values are silently ignored by the toml->csr converter).
    overrides = dict(vendor)
    if loopback != "off":
        overrides["loopBack"] = {
            "nes": "LB_NES", "fes": "LB_FES", "enc": "LB_ENC",
        }[loopback]

    def lane_cfg(lane_overrides):
        return LaneConfig(
            operation_mode = OperationMode.TX_RX,
            tx_data_rate   = "1.25G",
            rx_data_rate   = "1.25G",
            tx_gear_rate   = GearRate.G1_1,
            rx_gear_rate   = GearRate.G1_1,
            pll            = PLLSelection.CPLL,
            ref_clk_source = RefClkSource.Q1_REFCLK0,
            ref_clk_freq   = "125M",
            width_mode     = 10,
            tx_encoding    = EncodingMode.B8B10B,
            rx_encoding    = EncodingMode.B8B10B,
            word_align     = True,
            ctc_enable     = False,
            fabric_ctrl    = 0x1,
            toml_lane_overrides = lane_overrides,
        )

    lane_configs = [lane_cfg(overrides)]
    if partner:
        lane_configs.append(lane_cfg(dict(vendor)))
    group  = GowinSerDesGroup(quad=1, first_lane=0, lane_configs=lane_configs,
                              toml_quad_overrides=dict(vendor_quad))
    serdes = GowinSerDes(device=GowinDevice.GW5AST_138, groups=[group])
    return serdes, group


def wire_lane(m, lane, phy):
    """Connect a GW51000BASEXPHY to a gowin-serdes lane."""
    m.d.comb += [
        # Clocks: loop the PCS fabric clocks back (vendor style) and feed
        # them to the PHY CRG which drives the eth clock domains.
        lane.tx.clk.eq(lane.tx.pcs_clkout),
        lane.rx.clk.eq(lane.rx.pcs_clkout),
        phy.clk_tx.eq(lane.tx.pcs_clkout),
        phy.clk_rx.eq(lane.rx.pcs_clkout),
        # TX: {disparity, k, d} + FIFO write qualifier.
        lane.tx.data.eq(phy.tx_data),
        lane.tx.fifo_wren.eq(phy.tx_wren),
        phy.tx_afull.eq(lane.tx.fifo_afull),
        # RX: {coding_err, disparity_err, k, d}.
        phy.rx_data.eq(Cat(lane.rx.data[0:10], lane.rx.data[80])),
        phy.rx_aempty.eq(lane.rx.fifo_aempty),
        lane.rx.fifo_rden.eq(phy.rx_rden),
        # Status / resets.
        phy.pll_ok.eq(lane.status.pll_lock),
        phy.align_link.eq(lane.status.word_align_link),
        lane.reset.pma_rstn.eq(phy.pma_rstn),
        lane.reset.pcs_tx_rst.eq(phy.pcs_tx_rst),
        lane.reset.pcs_rx_rst.eq(phy.pcs_rx_rst),
    ]


# Frame sniffer --------------------------------------------------------------------------------

SNIFF_BYTES = 64


class FrameSniffer(Elaboratable):
    """Capture the first 64 bytes of one frame from an eth_phy RX stream.

    ``arm`` (sync-domain pulse) starts a capture of the next frame seen on
    ``stream`` (in ``domain``); ``done`` (sync-domain level) reports
    completion and freezes ``data``. ``frame`` pulses once per received
    frame (sync domain) for counting.
    """
    def __init__(self, stream, domain):
        self._stream = stream
        self._domain = domain
        self.arm     = Signal()
        self.done    = Signal()
        self.data    = Signal(SNIFF_BYTES * 8)
        self.frame   = Signal()

    def elaborate(self, platform):
        m = Module()
        cd = self._domain
        st = self._stream

        m.submodules.arm_ps = arm_ps = PulseSynchronizer("sync", cd)
        m.d.comb += arm_ps.i.eq(self.arm)

        cap     = Signal.like(self.data)
        idx     = Signal(range(SNIFF_BYTES + 1))
        done_cd = Signal()

        with m.FSM(domain=cd):
            with m.State("IDLE"):
                with m.If(arm_ps.o):
                    m.d[cd] += [idx.eq(0), done_cd.eq(0)]
                    m.next = "WAIT"
            with m.State("WAIT"):
                with m.If(st.valid & st.first):
                    m.d[cd] += [
                        cap.word_select(idx[:6], 8).eq(st.p.data),
                        idx.eq(1),
                    ]
                    with m.If(st.last):
                        m.d[cd] += done_cd.eq(1)
                        m.next = "IDLE"
                    with m.Else():
                        m.next = "CAP"
            with m.State("CAP"):
                with m.If(st.valid):
                    with m.If(idx < SNIFF_BYTES):
                        m.d[cd] += [
                            cap.word_select(idx[:6], 8).eq(st.p.data),
                            idx.eq(idx + 1),
                        ]
                    with m.If(st.last | (idx == SNIFF_BYTES)):
                        m.d[cd] += done_cd.eq(1)
                        m.next = "IDLE"

        # done is synchronized; data is frozen (only written while armed)
        # by the time done is observed in the sync domain.
        m.submodules.done_cdc = FFSynchronizer(done_cd, self.done)
        m.d.comb += self.data.eq(cap)

        # Frame pulses towards the sync domain.
        m.submodules.frame_ps = frame_ps = PulseSynchronizer(cd, "sync")
        m.d.comb += [
            frame_ps.i.eq(st.valid & st.last),
            self.frame.eq(frame_ps.o),
        ]

        return m


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

class BaseXEcho(Elaboratable):
    def __init__(self, serdes, group, mac_addr=DEFAULT_MAC, ip_addr=DEFAULT_IP,
                 sys_clk_freq=50e6, baudrate=115200, with_icmp=True,
                 udp_ports=DEFAULT_UDP_PORTS, tcp_ports=DEFAULT_TCP_PORTS,
                 tcp_mss=536, tcp_rx_depth=2048, rx_cdc_depth=512,
                 with_partner=True, uart_index=1, uart_swap=False,
                 with_beacons=True):
        self.serdes       = serdes
        self.group        = group
        self.uart_index   = uart_index
        self.uart_swap    = uart_swap
        self.with_beacons = with_beacons
        self.mac_init     = convert_mac(mac_addr)
        self.ip_init      = convert_ip(ip_addr)
        self.sys_clk_freq = sys_clk_freq
        self.baudrate     = baudrate
        self.with_icmp    = with_icmp
        self.udp_ports    = [int(port) for port in udp_ports]
        self.tcp_ports    = _normalize_tcp_ports(
            list(tcp_ports) if tcp_ports else None)
        self.tcp_mss      = tcp_mss
        self.tcp_rx_depth = tcp_rx_depth
        self.rx_cdc_depth = rx_cdc_depth
        self.with_partner = with_partner
        assert len(self.udp_ports) >= 1
        assert (len(group.lanes) >= 2) == with_partner or not with_partner

        # PHYs (constructed here so their CSR maps are available).
        self.phy = GW51000BASEXPHY(create_domains=False)
        if with_partner:
            self.phy1 = GW51000BASEXPHY(create_domains=False,
                                        tx_domain="eth1_tx",
                                        rx_domain="eth1_rx")

        # Stack CSRs.
        tcp_specs = list((self.tcp_ports or {}).values())
        n_clients = sum(spec.mode == "client" for spec in tcp_specs)
        n_sniff   = 2 if with_partner else 1
        est = (0x60 + 2 * len(self.udp_ports) + 2 * len(tcp_specs) +
               6 * n_clients + (24 if tcp_specs else 0) +
               (8 + SNIFF_BYTES + 8) * n_sniff)
        addr_width = max(6, (est - 1).bit_length())
        regs = csr.Builder(addr_width=addr_width, data_width=8)
        self.scratch = regs.add("scratch",     Scratch())
        self.mac_reg = regs.add("mac_address", MacAddress(init=self.mac_init))
        self.ip_reg  = regs.add("ip_address",  IpAddress(init=self.ip_init))
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
        self.phy_dbg      = regs.add("phy_dbg",     Counter32())
        self.rx_frames    = regs.add("rx_frames",   Counter32())
        self.rx_errors    = regs.add("rx_errors",   Counter32())
        self.arp_events   = regs.add("arp_events",  Counter32())
        self.udp_rx_cnt   = regs.add("udp_rx",      Counter32())
        self.udp_tx_cnt   = regs.add("udp_tx",      Counter32())
        self.udp_drop_cnt = regs.add("udp_drop",    Counter32())
        self.unreachable  = regs.add("unreachable", Counter32())
        if with_icmp:
            self.icmp_cnt = regs.add("icmp_echo",   Counter32())
        if self.tcp_ports:
            self.tcp_rx_cnt   = regs.add("tcp_rx_seg", Counter32())
            self.tcp_tx_cnt   = regs.add("tcp_tx_seg", Counter32())
            self.tcp_drop_cnt = regs.add("tcp_drop",   Counter32())
            self.tcp_rst_cnt  = regs.add("tcp_rst",    Counter32())
            self.tcp_status   = regs.add("tcp_status", Counter32())
        # SFP module status: bit0/1 = SFP0/SFP1 RX_LOS (loss of signal).
        self.sfp_status = regs.add("sfp_status", Counter32())
        # Frame sniffers: PHY-level RX frame counters and 64-byte frame
        # snapshots per lane (snap_ctrl bit0/1 = arm lane0/1, snap_status
        # bit0/1 = done; snap<lane>_w<i> = captured bytes 4i..4i+3).
        self.snap_ctrl   = regs.add("snap_ctrl",   IpAddress(init=0))
        self.snap_status = regs.add("snap_status", Counter32())
        self.snap_regs   = []
        self.phy_frame_regs = []
        for lane in range(2 if with_partner else 1):
            self.phy_frame_regs.append(
                regs.add(f"phy{lane}_rx_frames", Counter32()))
            self.snap_regs.append([
                regs.add(f"snap{lane}_w{i}", Counter32())
                for i in range(SNIFF_BYTES // 4)
            ])
        self.csr_bridge = csr.Bridge(regs.as_memory_map())

        # Combine the stack CSRs with the per-PHY CSR windows.
        self.csr_decoder = csr.Decoder(addr_width=addr_width + 1, data_width=8)
        self.csr_decoder.add(self.csr_bridge.bus, name="core")
        self.csr_decoder.add(self.phy.bus, name="phy")
        if with_partner:
            self.csr_decoder.add(self.phy1.bus, name="phy1")
        self.memory_map = self.csr_decoder.bus.memory_map

    def elaborate(self, platform):
        m = Module()

        # Clock domains (common ancestor of PHY and MAC; clocked/reset by the
        # PHY CRGs from the lane PCS fabric clocks).
        m.domains += ClockDomain("eth_tx")
        m.domains += ClockDomain("eth_rx")
        if self.with_partner:
            m.domains += ClockDomain("eth1_tx")
            m.domains += ClockDomain("eth1_rx")

        # SerDes ---------------------------------------------------------------------------
        m.submodules.serdes = self.serdes
        por_count = Signal(16)
        with m.If(~por_count.all()):
            m.d.sync += por_count.eq(por_count + 1)
        m.d.comb += self.serdes.por_n.eq(por_count.all())

        lanes = self.group.lanes

        # Lane 0: PHY + MAC + stack ----------------------------------------------------------
        phy = self.phy
        m.submodules.phy = phy
        wire_lane(m, lanes[0], phy)

        mac = MACCore(phy, data_width=32, with_csr=False,
                      rx_cdc_depth=self.rx_cdc_depth)
        m.submodules.mac = mac
        connect(m, mac.phy_tx, phy.tx)
        connect(m, phy.rx, mac.phy_rx)

        # Lane 1: autonegotiation-only link partner ------------------------------------------
        if self.with_partner:
            phy1 = self.phy1
            m.submodules.phy1 = phy1
            wire_lane(m, lanes[1], phy1)
            # No MAC: never sends frames, discards received ones.
            m.d.comb += phy1.tx.valid.eq(0)

        # UDP/IP core (8-bit, sys domain) ----------------------------------------------------
        m.submodules.core = core = UDPIPCore(clk_freq=self.sys_clk_freq,
                                             with_icmp=self.with_icmp,
                                             udp_ports=self.udp_ports,
                                             tcp_ports=self.tcp_ports,
                                             tcp_mss=self.tcp_mss,
                                             tcp_rx_depth=self.tcp_rx_depth)
        m.d.comb += [
            core.mac_address.eq(self.mac_reg.f.value.data),
            core.ip_address.eq(self.ip_reg.f.value.data),
        ]

        m.submodules.boundary = boundary = MACByteBoundary(mac_dw=32)
        connect(m, boundary.mac_tx, mac.sink)
        connect(m, mac.source, boundary.mac_rx)
        connect(m, core.mac_tx, boundary.eth_tx)
        connect(m, boundary.eth_rx, core.mac_rx)

        # UDP echo loops.
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
                getattr(core, f"udp_port_{name}")
                    .eq(self.udp_port_regs[i].f.value.data),
            ]

        # TCP echo servers/clients.
        for i, (name, spec) in enumerate((core.tcp_ports or {}).items()):
            rx = getattr(core, f"tcp_rx_{name}")
            tx = getattr(core, f"tcp_tx_{name}")
            connected   = getattr(core, f"tcp_connected_{name}")
            peer_closed = getattr(core, f"tcp_peer_closed_{name}")

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
            m.d.comb += [
                getattr(core, f"tcp_close_{name}").eq(
                    peer_closed & (rx_bytes == tx_bytes)),
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
        m.submodules.csr_bridge  = self.csr_bridge
        m.submodules.csr_decoder = self.csr_decoder
        m.submodules.wb_bridge   = wb_bridge = WishboneCSRBridge(
            self.csr_decoder.bus, data_width=32)
        m.submodules.uart_bridge = uart_bridge = UARTWishboneBridge(
            addr_width = wb_bridge.wb_bus.addr_width,
            divisor    = round(self.sys_clk_freq / self.baudrate))
        connect(m, uart_bridge.wb, wb_bridge.wb_bus)

        uart_pins = platform.request("uart", self.uart_index)
        if self.uart_index == 0:
            # Board debugger UART (P15/N16, fixed directions).
            assert not self.uart_swap
            m.d.comb += [
                uart_bridge.rx_i.eq(uart_pins.rx.i),
                uart_pins.tx.o.eq(uart_bridge.tx_o),
            ]
        else:
            # Pmod UARTs are declared dir="io" so that --uart-swap can flip
            # the assumed TX/RX assignment without touching the wiring.
            tx_pin = uart_pins.rx if self.uart_swap else uart_pins.tx
            rx_pin = uart_pins.tx if self.uart_swap else uart_pins.rx
            m.d.comb += [
                uart_bridge.rx_i.eq(rx_pin.i),
                tx_pin.o.eq(uart_bridge.tx_o),
                tx_pin.oe.eq(1),
            ]

        # 115200-baud 0x55/0xAA beacons on the TX pins of the unused pmod
        # UARTs: whichever host tty shows a continuous byte stream is wired
        # to that pin (identifies the FT4232 channel/pin mapping).
        if self.with_beacons:
            beacon = Signal()
            beacon_div = Signal(range(434))
            with m.If(beacon_div == 433):
                m.d.sync += [beacon_div.eq(0), beacon.eq(~beacon)]
            with m.Else():
                m.d.sync += beacon_div.eq(beacon_div + 1)
            for idx in (2, 3):  # Only the pmod pairs with verified direction.
                if idx == self.uart_index:
                    continue
                pins = platform.request("uart", idx)
                pin  = pins.rx if self.uart_swap else pins.tx
                m.d.comb += [pin.o.eq(beacon), pin.oe.eq(1)]

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
        counter(self.arp_events, core.arp_event)
        counter(self.udp_rx_cnt, core.udp_rx_pkt)
        counter(self.udp_tx_cnt, core.udp_tx_pkt)
        counter(self.udp_drop_cnt, core.udp_drop)
        counter(self.unreachable, core.unreachable)
        if self.with_icmp:
            counter(self.icmp_cnt, core.icmp_pkt)
        if self.tcp_ports:
            counter(self.tcp_rx_cnt,   core.tcp_rx_seg)
            counter(self.tcp_tx_cnt,   core.tcp_tx_seg)
            counter(self.tcp_drop_cnt, core.tcp_drop)
            counter(self.tcp_rst_cnt,  core.tcp_rst)

        # SFP module control/status --------------------------------------------------------
        # Enable the module transmitters (TX_DISABLE is pulled up inside the
        # module: floating = laser off) and read RX_LOS.
        sfp0 = platform.request("sfp_ctl", 0)
        sfp1 = platform.request("sfp_ctl", 1)
        los0_sync = Signal()
        los1_sync = Signal()
        m.submodules.los0_cdc = FFSynchronizer(sfp0.los.i, los0_sync)
        m.submodules.los1_cdc = FFSynchronizer(sfp1.los.i, los1_sync)
        m.d.comb += [
            sfp0.tx_off.o.eq(0),
            sfp1.tx_off.o.eq(0),
            self.sfp_status.f.value.r_data[0].eq(los0_sync),
            self.sfp_status.f.value.r_data[1].eq(los1_sync),
        ]

        # Frame sniffers + PHY-level frame counters ---------------------------------------
        sniffers = [FrameSniffer(phy.rx, "eth_rx")]
        if self.with_partner:
            sniffers.append(FrameSniffer(self.phy1.rx, "eth1_rx"))
        snap_ctrl_prev = Signal(len(sniffers))
        m.d.sync += snap_ctrl_prev.eq(self.snap_ctrl.f.value.data[:len(sniffers)])
        for lane, sniff in enumerate(sniffers):
            m.submodules[f"sniffer{lane}"] = sniff
            m.d.comb += [
                sniff.arm.eq(self.snap_ctrl.f.value.data[lane]
                             & ~snap_ctrl_prev[lane]),
                self.snap_status.f.value.r_data[lane].eq(sniff.done),
            ]
            for i, reg in enumerate(self.snap_regs[lane]):
                m.d.comb += reg.f.value.r_data.eq(sniff.data[32*i:32*(i+1)])
            counter(self.phy_frame_regs[lane], sniff.frame)

        # PHY debug register -------------------------------------------------------------
        # [7:0]  eth_tx heartbeat (increments while the TX PCS clock runs)
        # [15:8] eth_rx heartbeat (increments while the recovered clock runs)
        # [23:16] count of K28.5 code groups seen on lane0 RX
        # [24] rx_cdr_lock  [25] k_lock  [26] lane ready  [27] signal_detect
        # [28] tx_afull     [29] rx_aempty
        # [30] lane1 signal_detect  [31] lane1 rx_cdr_lock
        lane0 = lanes[0]
        tx_hb = Signal(22)
        rx_hb = Signal(22)
        m.d.eth_tx += tx_hb.eq(tx_hb + 1)
        m.d.eth_rx += rx_hb.eq(rx_hb + 1)
        k_cnt = Signal(14)
        with m.If(phy.rx_data[0:9] == 0x1bc):  # K28.5
            m.d.eth_rx += k_cnt.eq(k_cnt + 1)
        m.d.comb += [
            self.phy_dbg.f.value.r_data[0:8].eq(tx_hb[-8:]),
            self.phy_dbg.f.value.r_data[8:16].eq(rx_hb[-8:]),
            self.phy_dbg.f.value.r_data[16:24].eq(k_cnt[-8:]),
            self.phy_dbg.f.value.r_data[24].eq(lane0.status.rx_cdr_lock),
            self.phy_dbg.f.value.r_data[25].eq(lane0.status.k_lock),
            self.phy_dbg.f.value.r_data[26].eq(lane0.status.ready),
            self.phy_dbg.f.value.r_data[27].eq(lane0.status.signal_detect),
            self.phy_dbg.f.value.r_data[28].eq(phy.tx_afull),
            self.phy_dbg.f.value.r_data[29].eq(phy.rx_aempty),
        ]
        if self.with_partner:
            m.d.comb += [
                self.phy_dbg.f.value.r_data[30].eq(lanes[1].status.signal_detect),
                self.phy_dbg.f.value.r_data[31].eq(lanes[1].status.rx_cdr_lock),
            ]

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
            platform.request("led", 2).o.eq(phy.link_up),
            platform.request("led", 3).o.eq(phy.align_link),
            platform.request("led", 4).o.eq(
                self.phy1.link_up if self.with_partner else 0),
            platform.request("led", 5).o.eq(rx_act != 0),
        ]

        return m


# Build ----------------------------------------------------------------------------------------

def make_platform():
    """Board platform with the serdes-aware Gowin toolchain additions."""
    from amaranth_boards.tang_mega_138k_pro_dock import TangMega138kProDockPlatform

    class SerdesDockPlatform(TangMega138kProDockPlatform):
        @property
        def file_templates(self):
            templates = dict(super().file_templates)
            # Also feed .csr files (SerDes configuration blobs) to the PnR:
            # they are baked into the bitstream and replayed by the hard
            # configuration engine at load.
            templates["{{name}}.tcl"] = r"""
                # {{autogenerated}}
                {% for file in platform.iter_files(".v",".sv",".vhd",".vhdl") -%}
                    add_file {{file}}
                {% endfor %}
                add_file -type verilog {{name}}.v
                add_file -type cst {{name}}.cst
                add_file -type sdc {{name}}.sdc
                {% for file in platform.iter_files(".csr") -%}
                    set_csr {{file}}
                {% endfor %}
                set_device -name {{platform.family}} {{platform.part}}
                set_option -verilog_std v2001 -print_all_synthesis_warning 1 -show_all_warn 1
                {{get_override("add_options")|default("# (add_options placeholder)")}}
                run all
                file delete -force {{name}}.fs
                file copy -force impl/pnr/project.fs {{name}}.fs
            """
            templates["impl/project_process_config.json"] = r"""
                {
                    "SerDes_retiming" : false,
                    "Process_Configuration_Verion" : "1.0"
                }
            """
            return templates

    return SerdesDockPlatform(toolchain="Gowin")


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mac", default=DEFAULT_MAC)
    parser.add_argument("--ip", default=DEFAULT_IP)
    parser.add_argument("--udp-port", type=int, action="append", dest="udp_ports",
                        metavar="PORT")
    parser.add_argument("--tcp-port", type=int, action="append", dest="tcp_ports",
                        metavar="PORT")
    parser.add_argument("--tcp-client", action="append", dest="tcp_clients",
                        metavar="IP:PORT[:LOCAL]")
    parser.add_argument("--no-tcp", action="store_true")
    parser.add_argument("--no-icmp", action="store_true")
    parser.add_argument("--tcp-mss", type=int, default=536)
    parser.add_argument("--tcp-rx-depth", type=int, default=2048)
    parser.add_argument("--rx-cdc-depth", type=int, default=512)
    parser.add_argument("--loopback", choices=("off", "nes", "enc", "fes"),
                        default="off",
                        help="Lane-0 serdes-internal loopback (link test "
                             "without an SFP module): nes = near-end "
                             "serial, enc = near-end encoded, fes = "
                             "far-end serial")
    parser.add_argument("--no-partner", action="store_true",
                        help="Build without the lane-1 autoneg partner PHY")
    parser.add_argument("--uart", choices=("debug", "j3", "pmod-a", "pmod-b"),
                        default="pmod-a",
                        help="CSR UART: pmod-a = FPGA tx=B19/rx=A17 "
                             "(ttyUSB9, default), pmod-b = tx=C21/rx=B20 "
                             "(ttyUSB10), j3 = tx=A19/rx=A18 (unverified), "
                             "debug = on-board debugger P15/N16 (flaky "
                             "BL616 forwarding)")
    parser.add_argument("--uart-swap", action="store_true",
                        help="Swap the assumed TX/RX pins of the pmod UART")
    parser.add_argument("--no-beacons", action="store_true",
                        help="No 0x55 beacon streams on the unused pmod "
                             "UART TX pins")
    parser.add_argument("--build-dir", default="build/tang_mega_138k_1000basex")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()

    build_dir = pathlib.Path(args.build_dir)
    os.makedirs(build_dir, exist_ok=True)

    # SerDes configuration -> TOML -> CSR blob.
    serdes, group = make_serdes(loopback=args.loopback,
                                partner=not args.no_partner)
    csr_path  = build_dir / "serdes.csr"
    toml_path = build_dir / "serdes.toml"
    serdes.generate_csr(output_path=str(csr_path), toml_path=str(toml_path))
    print(f"SerDes config: {toml_path} -> {csr_path}")

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

    uart_index = {"debug": 0, "j3": 1, "pmod-a": 2, "pmod-b": 3}[args.uart]
    top = BaseXEcho(serdes, group, mac_addr=args.mac, ip_addr=args.ip,
                    with_icmp=not args.no_icmp, udp_ports=udp_ports,
                    tcp_ports=tcp_ports, tcp_mss=args.tcp_mss,
                    tcp_rx_depth=args.tcp_rx_depth,
                    rx_cdc_depth=args.rx_cdc_depth,
                    with_partner=not args.no_partner,
                    uart_index=uart_index, uart_swap=args.uart_swap,
                    with_beacons=not args.no_beacons)

    csr_map = dump_csr_map(top, build_dir / "csr.json")
    print("CSR map (byte addresses over the UART bridge):")
    for name, info in csr_map.items():
        print(f"  {info['addr']:#06x} {name} ({info['size']} bytes)")

    platform = make_platform()
    platform.add_file("serdes.csr", csr_path.read_bytes())

    # Pmod-2 UARTs towards the external FT4232 (hardware-verified mapping:
    # pmod-a = ttyUSB9 with FPGA TX=B19/RX=A17, pmod-b = ttyUSB10 with FPGA
    # TX=C21/RX=B20). Both pins dir="io" so --uart-swap can flip TX/RX at
    # build time. The J3 pair (A19/A18, ttyUSB8) is kept for reference but
    # did not respond in either orientation.
    # SFP cage control pins (dock schematic / user-verified): RX_LOS inputs
    # V18 (SFP0) / W18 (SFP1); TX_DISABLE outputs R18 (SFP0) / M20 (SFP1).
    platform.add_resources([
        Resource("sfp_ctl", 0,
                 Subsignal("los",    Pins("V18", dir="i")),
                 Subsignal("tx_off", Pins("R18", dir="o")),
                 Attrs(IO_TYPE="LVCMOS33", PULL_MODE="UP")),
        Resource("sfp_ctl", 1,
                 Subsignal("los",    Pins("W18", dir="i")),
                 Subsignal("tx_off", Pins("M20", dir="o")),
                 Attrs(IO_TYPE="LVCMOS33", PULL_MODE="UP")),
    ])

    pmod_uart_attrs = Attrs(IO_TYPE="LVCMOS33", PULL_MODE="UP")
    platform.add_resources([
        Resource("uart", 1,
                 Subsignal("tx", Pins("A19", dir="io")),
                 Subsignal("rx", Pins("A18", dir="io")),
                 pmod_uart_attrs),
        Resource("uart", 2,
                 Subsignal("tx", Pins("B19", dir="io")),
                 Subsignal("rx", Pins("A17", dir="io")),
                 pmod_uart_attrs),
        Resource("uart", 3,
                 Subsignal("tx", Pins("C21", dir="io")),
                 Subsignal("rx", Pins("B20", dir="io")),
                 pmod_uart_attrs),
    ])

    # The eth clock domains are driven straight from the GTR12 PCS fabric
    # clock outputs; constrain them at the hard macro pins (the fabric alias
    # nets do not survive synthesis). Hierarchy: serdes/quad<q>/quad.
    quad = f"serdes/quad{group.quad}/quad"
    sdc = [
        f"create_clock -name eth_tx -period 8.0 [get_pins {{{quad}/LANE0_PCS_TX_O_FABRIC_CLK}}]",
        f"create_clock -name eth_rx -period 8.0 [get_pins {{{quad}/LANE0_PCS_RX_O_FABRIC_CLK}}]",
    ]
    if not args.no_partner:
        sdc += [
            f"create_clock -name eth1_tx -period 8.0 [get_pins {{{quad}/LANE1_PCS_TX_O_FABRIC_CLK}}]",
            f"create_clock -name eth1_rx -period 8.0 [get_pins {{{quad}/LANE1_PCS_RX_O_FABRIC_CLK}}]",
        ]
    # All crossings between these domains go through 2-FF synchronizers,
    # AsyncFIFO gray pointers or stable-by-protocol capture registers.
    clocks = ["clk50_0__io", "eth_tx", "eth_rx"]
    if not args.no_partner:
        clocks += ["eth1_tx", "eth1_rx"]
    for a in clocks:
        for b in clocks:
            if a != b:
                sdc.append(f"set_false_path -from [get_clocks {{{a}}}] "
                           f"-to [get_clocks {{{b}}}]")

    result = platform.build(
        top,
        name        = "basex_echo",
        build_dir   = args.build_dir,
        do_build    = not args.no_build,
        do_program  = False,
        add_options = (
            "set_option -use_mspi_as_gpio 1\n"
            "set_option -use_sspi_as_gpio 1\n"
            "set_option -use_ready_as_gpio 1\n"
            "set_option -use_done_as_gpio 1\n"
            "set_option -use_cpu_as_gpio 1\n"
            "set_option -bit_security 0\n"
            "set_option -bit_encrypt 0\n"
            "set_option -bit_compress 0\n"
            "set_option -serdesRetiming 0\n"
        ),
        add_constraints = "\n".join(sdc) + "\n",
    )
    if args.no_build:
        result.execute_local(args.build_dir, run_script=False)
    print(f"Build artifacts in {args.build_dir}")


if __name__ == "__main__":
    main()
