#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Tests of the DHCP client (``with_dhcp``).

The testbench plays the DHCP server over plain MAC frames. The DUT owns its
IP: nothing is answered before a lease is bound, then ARP/ICMP/UDP work on
the leased address, which is also exposed on ``dhcp_ip``.
"""

import pytest

from amaranth.hdl import Module, Elaboratable
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from amaranth_stream import PacketFIFO

from lambdaeth.core import UDPIPCore, udp_user_signature

from .net_helpers import (build_eth, build_arp, build_udp_frame,
                          build_ping_frame, build_dhcp_reply_frame,
                          parse_dhcp, ParsedFrame, mac_bytes, ip_bytes)
from .test_udpip_core import send_frame, recv_frame, make_sim

BOARD_MAC  = 0x024c45544800
HOST_MAC   = 0x60cf847491a3
HOST_IP    = 0xc0a80a78          # 192.168.10.120
SERVER_MAC = 0x0242ac110002
SERVER_IP  = 0xc0a80a01          # 192.168.10.1 (the DHCP server)
LEASED_IP  = 0xc0a80ac7          # 192.168.10.199

RETRY = 0.005                    # 5000 cycles at the 1 MHz test clock.
TICKS = 500                      # Cycles per lease "second" in simulation.


class DHCPDut(Elaboratable):
    """Core with DHCP enabled and a UDP echo on port 8000."""
    def __init__(self, udp_ports=(8000,)):
        self.core = UDPIPCore(clk_freq=1e6, with_dhcp=True, dhcp_retry=RETRY,
                              dhcp_ticks_per_sec=TICKS,
                              udp_ports=list(udp_ports) or None)

    def elaborate(self, platform):
        m = Module()
        m.submodules.core = core = self.core
        if core.udp_ports is not None:
            m.submodules.echo = echo = PacketFIFO(
                udp_user_signature(), payload_depth=1024, packet_depth=4)
            connect(m, core.udp_rx_p0, echo.i_stream)
            m.d.comb += [
                core.udp_tx_p0.valid.eq(echo.o_stream.valid),
                core.udp_tx_p0.payload.eq(echo.o_stream.payload),
                core.udp_tx_p0.first.eq(echo.o_stream.first),
                core.udp_tx_p0.last.eq(echo.o_stream.last),
                echo.o_stream.ready.eq(core.udp_tx_p0.ready),
                core.udp_tx_p0.param.ip.eq(echo.o_stream.param.ip),
                core.udp_tx_p0.param.dst_port
                    .eq(echo.o_stream.param.src_port),
                core.udp_tx_p0.param.length.eq(echo.o_stream.param.length),
            ]
        else:
            # Legacy unfiltered pair: echo everything, ports swapped
            # (src_port passes through the arbiter untouched).
            m.submodules.echo = echo = PacketFIFO(
                udp_user_signature(), payload_depth=1024, packet_depth=4)
            connect(m, core.udp_rx, echo.i_stream)
            m.d.comb += [
                core.udp_tx.valid.eq(echo.o_stream.valid),
                core.udp_tx.payload.eq(echo.o_stream.payload),
                core.udp_tx.first.eq(echo.o_stream.first),
                core.udp_tx.last.eq(echo.o_stream.last),
                echo.o_stream.ready.eq(core.udp_tx.ready),
                core.udp_tx.param.ip.eq(echo.o_stream.param.ip),
                core.udp_tx.param.src_port
                    .eq(echo.o_stream.param.dst_port),
                core.udp_tx.param.dst_port
                    .eq(echo.o_stream.param.src_port),
                core.udp_tx.param.length.eq(echo.o_stream.param.length),
            ]
        m.d.comb += core.mac_address.eq(BOARD_MAC)
        return m


async def recv_dhcp(ctx, core, timeout=20000):
    """Receive one DHCP message from the board (validated envelope)."""
    frame = ParsedFrame(await recv_frame(ctx, core.mac_tx, timeout=timeout))
    assert frame.ethertype == 0x0800 and frame.ip_protocol == 17
    assert frame.dst_mac == b"\xff" * 6
    assert frame.ip_dst == ip_bytes(0xffffffff)
    assert frame.udp_src_port == 68 and frame.udp_dst_port == 67
    msg = parse_dhcp(frame.udp_payload)
    assert msg["op"] == 1 and msg["cookie_ok"]
    assert msg["chaddr"] == mac_bytes(BOARD_MAC)
    assert msg["flags"] & 0x8000            # Broadcast flag requested.
    return msg, frame


async def do_bind(ctx, core, lease=100, leased_ip=LEASED_IP):
    """Play the server through a full DORA exchange."""
    disc, frame = await recv_dhcp(ctx, core)
    assert disc["options"][53] == b"\x01"   # DISCOVER
    assert frame.ip_src == ip_bytes(0)      # From 0.0.0.0 while unbound.
    await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
        SERVER_MAC, SERVER_IP, BOARD_MAC, disc["xid"], 2, leased_ip,
        lease=lease))
    req, _ = await recv_dhcp(ctx, core)
    assert req["options"][53] == b"\x03"    # REQUEST
    assert req["options"][50] == ip_bytes(leased_ip)
    assert req["options"][54] == ip_bytes(SERVER_IP)
    assert req["xid"] == disc["xid"]
    await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
        SERVER_MAC, SERVER_IP, BOARD_MAC, req["xid"], 5, leased_ip,
        lease=lease))
    for _ in range(20):
        await ctx.tick()
    assert ctx.get(core.dhcp_bound) == 1
    assert ctx.get(core.dhcp_ip) == leased_ip


async def arp_handshake(ctx, core, board_ip):
    request = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, board_ip))
    await send_frame(ctx, core.mac_rx, request)
    reply = ParsedFrame(await recv_frame(ctx, core.mac_tx))
    assert reply.ethertype == 0x0806 and reply.arp_opcode == 2
    assert reply.arp_sender_ip == ip_bytes(board_ip)


async def expect_no_frame(ctx, core, cycles=3000):
    ctx.set(core.mac_tx.ready, 1)
    for _ in range(cycles):
        _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
        assert not valid, "unexpected TX frame"
    ctx.set(core.mac_tx.ready, 0)


def test_dhcp_bind_and_serve():
    """DORA binds; the leased IP answers ARP, ICMP and UDP echo, and is
    readable on dhcp_ip."""
    dut = DHCPDut()
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await do_bind(ctx, core, lease=1000)
        # The leased address is fully live: ARP...
        await arp_handshake(ctx, core, LEASED_IP)
        # ...ICMP echo...
        ping = build_ping_frame(HOST_MAC, HOST_IP, BOARD_MAC, LEASED_IP,
                                ident=7, seq=1, payload=b"dhcp ping!")
        await send_frame(ctx, core.mac_rx, ping)
        pong = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert pong.ip_protocol == 1 and pong.icmp_type == 0
        assert pong.ip_src == ip_bytes(LEASED_IP)
        # ...and the bound UDP echo.
        frame = build_udp_frame(HOST_MAC, HOST_IP, 40000,
                                BOARD_MAC, LEASED_IP, 8000, b"on a lease")
        await send_frame(ctx, core.mac_rx, frame)
        echo = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert echo.ip_src == ip_bytes(LEASED_IP)
        assert echo.udp_src_port == 8000
        assert echo.udp_payload == b"on a lease"

    sim.add_testbench(tb)
    sim.run()


def test_dhcp_discover_retries():
    """An unanswered DISCOVER is retried after the retry period."""
    dut = DHCPDut()
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        d1, _ = await recv_dhcp(ctx, core)
        assert d1["options"][53] == b"\x01"
        d2, _ = await recv_dhcp(ctx, core)      # Ignore the first one.
        assert d2["options"][53] == b"\x01"
        # Answer the retry normally.
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, d2["xid"], 2, LEASED_IP))
        req, _ = await recv_dhcp(ctx, core)
        assert req["options"][53] == b"\x03"
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, req["xid"], 5, LEASED_IP))
        for _ in range(20):
            await ctx.tick()
        assert ctx.get(core.dhcp_bound) == 1

    sim.add_testbench(tb)
    sim.run()


def test_dhcp_nak_restarts():
    """A NAK to the REQUEST restarts discovery; the next round binds."""
    dut = DHCPDut()
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        disc, _ = await recv_dhcp(ctx, core)
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, disc["xid"], 2, LEASED_IP))
        req, _ = await recv_dhcp(ctx, core)
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, req["xid"], 6, 0))   # NAK
        disc2, _ = await recv_dhcp(ctx, core)
        assert disc2["options"][53] == b"\x01"
        assert ctx.get(core.dhcp_bound) == 0
        # Complete the second round.
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, disc2["xid"], 2, LEASED_IP))
        req2, _ = await recv_dhcp(ctx, core)
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, req2["xid"], 5, LEASED_IP))
        for _ in range(20):
            await ctx.tick()
        assert ctx.get(core.dhcp_bound) == 1

    sim.add_testbench(tb)
    sim.run()


def test_dhcp_renews_at_half_lease():
    """A broadcast renewal REQUEST (ciaddr set) goes out at lease/2 and the
    ACK refreshes the lease."""
    dut = DHCPDut()
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await do_bind(ctx, core, lease=8)       # T1 after 4 ticks (2000 cyc).
        renew, _ = await recv_dhcp(ctx, core)
        assert renew["options"][53] == b"\x03"
        assert renew["ciaddr"] == ip_bytes(LEASED_IP)
        assert 50 not in renew["options"]       # Rebinding-style REQUEST.
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, renew["xid"], 5, LEASED_IP,
            lease=8))
        for _ in range(50):
            await ctx.tick()
        assert ctx.get(core.dhcp_bound) == 1
        assert ctx.get(core.dhcp_ip) == LEASED_IP

    sim.add_testbench(tb)
    sim.run()


def test_dhcp_lease_expiry_restarts():
    """Unanswered renewals: at lease end the address is dropped and
    discovery restarts."""
    dut = DHCPDut()
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await do_bind(ctx, core, lease=4)
        renew, _ = await recv_dhcp(ctx, core)   # Ignore the renewal.
        assert renew["ciaddr"] == ip_bytes(LEASED_IP)
        # Next message must be a fresh DISCOVER after expiry.
        msg, frame = await recv_dhcp(ctx, core)
        while msg["options"][53] == b"\x03":    # Possible renew retries.
            msg, frame = await recv_dhcp(ctx, core)
        assert msg["options"][53] == b"\x01"
        assert frame.ip_src == ip_bytes(0)      # Address dropped.
        assert ctx.get(core.dhcp_bound) == 0
        assert ctx.get(core.dhcp_ip) == 0

    sim.add_testbench(tb)
    sim.run()


def test_dhcp_foreign_offer_ignored():
    """OFFERs for another client (chaddr mismatch) are ignored."""
    dut = DHCPDut()
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        disc, _ = await recv_dhcp(ctx, core)
        # Offer addressed to some other MAC: must be ignored.
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, disc["xid"], 2, 0xc0a80abb,
            chaddr=0x020000000042))
        await expect_no_frame(ctx, core, cycles=2000)
        # The correct offer proceeds.
        await send_frame(ctx, core.mac_rx, build_dhcp_reply_frame(
            SERVER_MAC, SERVER_IP, BOARD_MAC, disc["xid"], 2, LEASED_IP))
        req, _ = await recv_dhcp(ctx, core)
        assert req["options"][50] == ip_bytes(LEASED_IP)

    sim.add_testbench(tb)
    sim.run()


def test_dhcp_legacy_stream_passthrough():
    """with_dhcp + the unfiltered single UDP stream: DHCP replies are
    filtered out of the user stream, everything else passes (and the user's
    src_port survives the passthrough arbiter)."""
    dut = DHCPDut(udp_ports=())
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await do_bind(ctx, core, lease=1000)
        await arp_handshake(ctx, core, LEASED_IP)
        frame = build_udp_frame(HOST_MAC, HOST_IP, 41000,
                                BOARD_MAC, LEASED_IP, 4242, b"any port")
        await send_frame(ctx, core.mac_rx, frame)
        echo = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert echo.udp_src_port == 4242        # User-chosen, passed through.
        assert echo.udp_dst_port == 41000
        assert echo.udp_payload == b"any port"
        assert echo.ip_src == ip_bytes(LEASED_IP)

    sim.add_testbench(tb)
    sim.run()


def test_dhcp_member_shapes_and_optionality():
    from amaranth.back import rtlil

    plain = UDPIPCore(clk_freq=1e6)
    assert hasattr(plain, "ip_address") and not hasattr(plain, "dhcp_ip")
    dhcp = UDPIPCore(clk_freq=1e6, with_dhcp=True)
    for name in ("dhcp_ip", "dhcp_bound", "dhcp_event"):
        assert hasattr(dhcp, name)
    assert not hasattr(dhcp, "ip_address")

    with pytest.raises(AssertionError):
        UDPIPCore(clk_freq=1e6, with_dhcp=True, udp_ports=[68])
    with pytest.raises(AssertionError):
        UDPIPCore(clk_freq=1e6, with_dhcp=True, udp_ports={"dhcp": 9000})

    plain_rtlil = rtlil.convert(UDPIPCore(clk_freq=1e6), name="c_plain")
    assert "dhcp" not in plain_rtlil
