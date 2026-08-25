#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Wire-level system test: MACCore + boundary + UDP/IP core + echo FIFO.

Frames are driven into ``phy_rx`` and read from ``phy_tx`` complete with
preamble and FCS, across the three clock domains — everything except the
RGMII primitives themselves.
"""

import random

from amaranth.hdl import Module, Signal, ClockDomain, Elaboratable
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from amaranth_stream import PacketFIFO

from lambdaeth.mac import MACCore
from lambdaeth.core import UDPIPCore, udp_user_signature, eth_stream_signature
from lambdaeth.core.boundary import MACByteBoundary

from .helpers import crc32_bytes
from .net_helpers import (build_eth, build_arp, build_udp_frame,
                          build_ping_frame, build_tcp_frame, ParsedFrame,
                          mac_bytes, TCP_FIN, TCP_SYN, TCP_PSH, TCP_ACK)

BOARD_MAC = 0x024c45544800
BOARD_IP  = 0xc0a80a32
HOST_MAC  = 0x60cf847491a3
HOST_IP   = 0xc0a80a78

PREAMBLE = bytes([0x55]*7 + [0xd5])


class PHYMeta:
    data_width = 8
    tx_domain  = "eth_tx"
    rx_domain  = "eth_rx"


class SystemDUT(Elaboratable):
    def __init__(self, udp_ports=None, tcp_ports=None):
        self.mac  = MACCore(PHYMeta(), data_width=32, with_csr=False,
                            rx_cdc_depth=512)
        self.core = UDPIPCore(clk_freq=1e6, udp_ports=udp_ports,
                              tcp_ports=tcp_ports)

    def elaborate(self, platform):
        m = Module()
        m.domains.eth_tx = ClockDomain()
        m.domains.eth_rx = ClockDomain()

        m.submodules.mac      = mac      = self.mac
        m.submodules.core     = core     = self.core
        m.submodules.boundary = boundary = MACByteBoundary(mac_dw=32)

        connect(m, boundary.mac_tx, mac.sink)
        connect(m, mac.source, boundary.mac_rx)
        connect(m, core.mac_tx, boundary.eth_tx)
        connect(m, boundary.eth_rx, core.mac_rx)

        if core.udp_ports is None:
            # Unbound catch-all port: echo everything, ports swapped.
            m.submodules.echo = echo = PacketFIFO(
                udp_user_signature(), payload_depth=2048, packet_depth=8)
            connect(m, core.udp_rx, echo.i_stream)
            m.d.comb += [
                core.udp_tx.valid.eq(echo.o_stream.valid),
                core.udp_tx.payload.eq(echo.o_stream.payload),
                core.udp_tx.first.eq(echo.o_stream.first),
                core.udp_tx.last.eq(echo.o_stream.last),
                echo.o_stream.ready.eq(core.udp_tx.ready),
                core.udp_tx.param.ip.eq(echo.o_stream.param.ip),
                core.udp_tx.param.src_port.eq(echo.o_stream.param.dst_port),
                core.udp_tx.param.dst_port.eq(echo.o_stream.param.src_port),
                core.udp_tx.param.length.eq(echo.o_stream.param.length),
            ]
        else:
            # One echo loop per bound port (src_port forced by the core).
            for name in core.udp_ports:
                echo = PacketFIFO(udp_user_signature(),
                                  payload_depth=2048, packet_depth=8)
                m.submodules[f"echo_{name}"] = echo
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
                ]

        if core.tcp_ports is not None:
            # TCP echo servers, as in the hardware example.
            for name in core.tcp_ports:
                echo = PacketFIFO(eth_stream_signature(),
                                  payload_depth=2048, packet_depth=8)
                m.submodules[f"tcp_echo_{name}"] = echo
                rx = getattr(core, f"tcp_rx_{name}")
                tx = getattr(core, f"tcp_tx_{name}")
                connect(m, rx, echo.i_stream)
                connect(m, echo.o_stream, tx)
                rx_bytes = Signal(32)
                tx_bytes = Signal(32)
                with m.If(rx.valid & rx.ready):
                    m.d.sync += rx_bytes.eq(rx_bytes + 1)
                with m.If(tx.valid & tx.ready):
                    m.d.sync += tx_bytes.eq(tx_bytes + 1)
                m.d.comb += getattr(core, f"tcp_close_{name}").eq(
                    getattr(core, f"tcp_peer_closed_{name}") &
                    (rx_bytes == tx_bytes))

        m.d.comb += [
            core.mac_address.eq(BOARD_MAC),
            core.ip_address.eq(BOARD_IP),
        ]
        return m


async def phy_send(ctx, ep, frame):
    """Drive a wire-level frame (with preamble/FCS) into phy_rx, PHY-style:
    continuous bytes, no backpressure, last on the final byte."""
    wire = PREAMBLE + bytes(frame) + bytes(crc32_bytes(frame))
    for i, byte in enumerate(wire):
        ctx.set(ep.valid, 1)
        ctx.set(ep.p.data, byte)
        ctx.set(ep.first, i == 0)
        ctx.set(ep.last, i == len(wire) - 1)
        await ctx.tick(domain="eth_rx")
    ctx.set(ep.valid, 0)
    ctx.set(ep.last, 0)
    # Inter-frame gap.
    for _ in range(14):
        await ctx.tick(domain="eth_rx")


async def phy_recv(ctx, ep, timeout=200_000):
    """Capture one wire-level frame from phy_tx; strips preamble and FCS."""
    ctx.set(ep.ready, 1)
    wire = []
    for _ in range(timeout):
        _clk, _rst, valid, data, last = await ctx.tick(domain="eth_tx").sample(
            ep.valid, ep.p.data, ep.last)
        if valid:
            wire.append(data)
            if last:
                break
    else:
        raise TimeoutError("no frame from phy_tx")
    assert bytes(wire[:8]) == PREAMBLE, f"bad preamble: {bytes(wire[:8]).hex()}"
    frame, fcs = bytes(wire[8:-4]), bytes(wire[-4:])
    assert fcs == bytes(crc32_bytes(frame)), "bad FCS on TX frame"
    return frame


def test_system_udp_echo():
    dut = SystemDUT()
    sim = Simulator(dut)
    sim.add_clock(10e-9, domain="sync")
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    prng = random.Random(7)
    payload = bytes(prng.randrange(256) for _ in range(32))

    arp_req = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))
    udp_in  = build_udp_frame(HOST_MAC, HOST_IP, 43210,
                              BOARD_MAC, BOARD_IP, 8000, payload)

    async def tb(ctx):
        # ARP handshake.
        await phy_send(ctx, dut.mac.phy_rx, arp_req)
        reply = ParsedFrame(await phy_recv(ctx, dut.mac.phy_tx))
        assert reply.ethertype == 0x0806
        assert reply.arp_opcode == 2
        assert reply.dst_mac == mac_bytes(HOST_MAC)
        assert len(reply.raw) == 60          # Padded by the MAC.

        # UDP echo.
        await phy_send(ctx, dut.mac.phy_rx, udp_in)
        echo = ParsedFrame(await phy_recv(ctx, dut.mac.phy_tx))
        assert echo.ethertype == 0x0800
        assert echo.dst_mac == mac_bytes(HOST_MAC)
        assert echo.ip_csum_ok
        assert echo.udp_src_port == 8000
        assert echo.udp_dst_port == 43210
        assert echo.udp_payload == payload
        assert len(echo.raw) >= 60

        # ICMP ping (standard 56-byte data), wire-level.
        ping_payload = bytes(prng.randrange(256) for _ in range(56))
        ping = build_ping_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                                ident=0xbeef, seq=1, payload=ping_payload)
        await phy_send(ctx, dut.mac.phy_rx, ping)
        pong = ParsedFrame(await phy_recv(ctx, dut.mac.phy_tx))
        assert pong.ip_protocol == 1
        assert pong.icmp_type == 0
        assert pong.icmp_csum_ok
        assert pong.icmp_ident == 0xbeef
        assert pong.icmp_payload == ping_payload

    sim.add_testbench(tb)
    sim.run()


def test_system_multi_port_echo():
    """Wire-level exchange with per-port bound streams: both bound ports
    echo (source port = binding), an unbound port stays silent."""
    dut = SystemDUT(udp_ports=[8000, 8001])
    sim = Simulator(dut)
    sim.add_clock(10e-9, domain="sync")
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    prng = random.Random(21)

    async def tb(ctx):
        await phy_send(ctx, dut.mac.phy_rx, build_eth(
            0xffffffffffff, HOST_MAC, 0x0806,
            build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP)))
        await phy_recv(ctx, dut.mac.phy_tx)          # ARP reply.

        for i, port in enumerate([8000, 8001]):
            payload = bytes(prng.randrange(256) for _ in range(48 + i))
            frame = build_udp_frame(HOST_MAC, HOST_IP, 47000 + i,
                                    BOARD_MAC, BOARD_IP, port, payload)
            await phy_send(ctx, dut.mac.phy_rx, frame)
            echo = ParsedFrame(await phy_recv(ctx, dut.mac.phy_tx))
            assert echo.ip_csum_ok
            assert echo.udp_src_port == port
            assert echo.udp_dst_port == 47000 + i
            assert echo.udp_payload == payload

        # Unbound port: no reply must come.
        stray = build_udp_frame(HOST_MAC, HOST_IP, 47999,
                                BOARD_MAC, BOARD_IP, 9999, b"drop me")
        await phy_send(ctx, dut.mac.phy_rx, stray)
        try:
            frame = await phy_recv(ctx, dut.mac.phy_tx, timeout=30_000)
        except TimeoutError:
            pass
        else:
            raise AssertionError(f"unexpected reply: {bytes(frame).hex()}")

    sim.add_testbench(tb)
    sim.run()


def test_system_tcp_echo():
    """Wire-level TCP session: handshake, echo, close — through the MAC
    across all three clock domains."""
    dut = SystemDUT(tcp_ports=[2000])
    sim = Simulator(dut)
    sim.add_clock(10e-9, domain="sync")
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    payload = b"wire-level tcp echo!"
    HSEQ = 0x00c0ffee

    async def tb(ctx):
        await phy_send(ctx, dut.mac.phy_rx, build_eth(
            0xffffffffffff, HOST_MAC, 0x0806,
            build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP)))
        await phy_recv(ctx, dut.mac.phy_tx)              # ARP reply.

        def tcp(flags, seq, ack, data=b""):
            return build_tcp_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                                   47123, 2000, seq, ack, flags, data)

        async def recv_seg():
            seg = ParsedFrame(await phy_recv(ctx, dut.mac.phy_tx))
            assert seg.ip_protocol == 6 and seg.tcp_csum_ok and seg.ip_csum_ok
            assert len(seg.raw) >= 60                    # MAC padding.
            return seg

        # Handshake.
        await phy_send(ctx, dut.mac.phy_rx, tcp(TCP_SYN, HSEQ, 0))
        synack = await recv_seg()
        assert synack.tcp_flag_syn and synack.tcp_flag_ack
        assert synack.tcp_ack == HSEQ + 1
        siss = synack.tcp_seq
        await phy_send(ctx, dut.mac.phy_rx,
                       tcp(TCP_ACK, HSEQ + 1, siss + 1))

        # Echo.
        await phy_send(ctx, dut.mac.phy_rx,
                       tcp(TCP_PSH | TCP_ACK, HSEQ + 1, siss + 1, payload))
        data = b""
        acked = False
        while not (acked and data == payload):
            seg = await recv_seg()
            if seg.tcp_ack == HSEQ + 1 + len(payload):
                acked = True
            if seg.tcp_payload:
                assert seg.tcp_seq == siss + 1 + len(data)
                data += seg.tcp_payload
        await phy_send(ctx, dut.mac.phy_rx,
                       tcp(TCP_ACK, HSEQ + 1 + len(payload),
                           siss + 1 + len(payload)))

        # Close.
        await phy_send(ctx, dut.mac.phy_rx,
                       tcp(TCP_FIN | TCP_ACK, HSEQ + 1 + len(payload),
                           siss + 1 + len(payload)))
        got_fin = False
        while not got_fin:
            seg = await recv_seg()
            assert seg.tcp_ack == HSEQ + 2 + len(payload)
            got_fin = seg.tcp_flag_fin
        await phy_send(ctx, dut.mac.phy_rx,
                       tcp(TCP_ACK, HSEQ + 2 + len(payload),
                           siss + 2 + len(payload)))

    sim.add_testbench(tb)
    sim.run()


def test_system_small_and_large():
    dut = SystemDUT()
    sim = Simulator(dut)
    sim.add_clock(10e-9, domain="sync")
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    prng = random.Random(8)
    payloads = [b"x", bytes(prng.randrange(256) for _ in range(700))]

    arp_req = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))

    async def tb(ctx):
        await phy_send(ctx, dut.mac.phy_rx, arp_req)
        await phy_recv(ctx, dut.mac.phy_tx)
        for i, payload in enumerate(payloads):
            frame = build_udp_frame(HOST_MAC, HOST_IP, 50000 + i,
                                    BOARD_MAC, BOARD_IP, 9000, payload)
            await phy_send(ctx, dut.mac.phy_rx, frame)
            echo = ParsedFrame(await phy_recv(ctx, dut.mac.phy_tx))
            assert echo.udp_dst_port == 50000 + i
            assert echo.udp_payload == payload

    sim.add_testbench(tb)
    sim.run()
