#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""ICMP echo responder tests, including build-time optionality."""

import random

import pytest

from amaranth.hdl import Module, Elaboratable
from amaranth.sim import Simulator

from lambdaeth.core import UDPIPCore

from .net_helpers import (build_eth, build_arp, build_udp_frame,
                          build_ping_frame, ParsedFrame, mac_bytes, ip_bytes)
from .test_udpip_core import (BOARD_MAC, BOARD_IP, HOST_MAC, HOST_IP,
                              EchoDUT, send_frame, recv_frame, make_sim)


class NoIcmpDUT(Elaboratable):
    def __init__(self):
        self.core = UDPIPCore(clk_freq=1e6, with_icmp=False)

    def elaborate(self, platform):
        m = Module()
        m.submodules.core = core = self.core
        m.d.comb += [
            core.mac_address.eq(BOARD_MAC),
            core.ip_address.eq(BOARD_IP),
            # Tie off the UDP user port (no echo loop needed here).
            core.udp_rx.ready.eq(1),
        ]
        return m


@pytest.mark.parametrize("payload_len", [1, 10, 56, 400])
@pytest.mark.parametrize("stall", [0.0, 0.25])
def test_ping_reply(payload_len, stall):
    dut = EchoDUT()          # UDPIPCore defaults to with_icmp=True.
    sim = make_sim(dut)
    core = dut.core
    prng = random.Random(payload_len)

    payload = bytes(prng.randrange(256) for _ in range(payload_len))
    arp_req = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))
    ping = build_ping_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                            ident=0x1234, seq=payload_len, payload=payload)

    async def tb(ctx):
        # The host ARPs the board first (also primes the board's ARP cache).
        await send_frame(ctx, core.mac_rx, arp_req)
        await recv_frame(ctx, core.mac_tx)               # ARP reply.
        await send_frame(ctx, core.mac_rx, ping, stall_rate=stall, rng=prng)
        reply = ParsedFrame(await recv_frame(ctx, core.mac_tx,
                                             stall_rate=stall, rng=prng))
        assert reply.ethertype == 0x0800
        assert reply.dst_mac == mac_bytes(HOST_MAC)
        assert reply.src_mac == mac_bytes(BOARD_MAC)
        assert reply.ip_csum_ok
        assert reply.ip_src == ip_bytes(BOARD_IP)
        assert reply.ip_dst == ip_bytes(HOST_IP)
        assert reply.ip_protocol == 1
        assert reply.icmp_type == 0          # Echo reply.
        assert reply.icmp_code == 0
        assert reply.icmp_csum_ok            # Incremental checksum update.
        assert reply.icmp_ident == 0x1234
        assert reply.icmp_seq == payload_len
        assert reply.icmp_payload == payload

    sim.add_testbench(tb)
    sim.run()


def test_ping_and_udp_interleave():
    """Pings and UDP echoes share the IP TX arbiter without interference."""
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core
    prng = random.Random(5)

    udp_payload  = bytes(prng.randrange(256) for _ in range(50))
    ping_payload = bytes(prng.randrange(256) for _ in range(56))
    arp_req = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))
    ping = build_ping_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                            ident=7, seq=1, payload=ping_payload)
    udp  = build_udp_frame(HOST_MAC, HOST_IP, 40000,
                           BOARD_MAC, BOARD_IP, 8000, udp_payload)

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, arp_req)
        await recv_frame(ctx, core.mac_tx)                  # ARP reply.
        for _ in range(3):
            await send_frame(ctx, core.mac_rx, ping)
            await send_frame(ctx, core.mac_rx, udp)
            replies = [ParsedFrame(await recv_frame(ctx, core.mac_tx)),
                       ParsedFrame(await recv_frame(ctx, core.mac_tx))]
            protos = sorted(r.ip_protocol for r in replies)
            assert protos == [1, 17]
            for r in replies:
                if r.ip_protocol == 1:
                    assert r.icmp_type == 0
                    assert r.icmp_payload == ping_payload
                    assert r.icmp_csum_ok
                else:
                    assert r.udp_payload == udp_payload

    sim.add_testbench(tb)
    sim.run()


def test_non_echo_icmp_dropped():
    """Other ICMP types (e.g. timestamp request, type 13) are ignored."""
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core

    frame = build_ping_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                             ident=1, seq=1, payload=b"\x00"*12, msgtype=13)

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, frame)
        ctx.set(core.mac_tx.ready, 1)
        for _ in range(1500):
            _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
            assert not valid, "unexpected TX frame"

    sim.add_testbench(tb)
    sim.run()


def test_without_icmp_ping_ignored_udp_works():
    """with_icmp=False: no ICMP logic is built; pings are dropped while the
    rest of the stack still works (ARP shown here)."""
    dut = NoIcmpDUT()
    assert not hasattr(dut.core, "icmp_pkt")
    sim = make_sim(dut)
    core = dut.core

    ping = build_ping_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                            ident=1, seq=1, payload=b"hello ldeth!")
    arp_req = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, ping)
        ctx.set(core.mac_tx.ready, 1)
        for _ in range(1500):
            _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
            assert not valid, "unexpected TX frame (ping must be ignored)"
        ctx.set(core.mac_tx.ready, 0)
        # ARP still answered.
        await send_frame(ctx, core.mac_rx, arp_req)
        reply = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert reply.ethertype == 0x0806
        assert reply.arp_opcode == 2

    sim.add_testbench(tb)
    sim.run()


def test_icmp_netlist_optionality():
    """The ICMP logic exists in the netlist only when requested."""
    from amaranth.back import rtlil

    with_icmp    = rtlil.convert(UDPIPCore(clk_freq=1e6, with_icmp=True),
                                 name="core_full")
    without_icmp = rtlil.convert(UDPIPCore(clk_freq=1e6, with_icmp=False),
                                 name="core_udp_only")
    assert "icmp" in with_icmp
    assert "icmp" not in without_icmp
    assert len(without_icmp) < len(with_icmp)