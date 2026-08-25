#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Tests of the build-time UDP user port binding (``udp_ports``).

Each requested UDP port yields its own bound user stream pair; here every
pair is looped back through a PacketFIFO, mirroring the hardware example.
"""

import random

import pytest

from amaranth.hdl import Module, Signal, Elaboratable
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from amaranth_stream import PacketFIFO

from lambdaeth.core import UDPIPCore, udp_user_signature
from lambdaeth.core.udp import UDPPortDispatch, UDPPortArbiter

from .net_helpers import (build_eth, build_arp, build_udp_frame, ParsedFrame,
                          mac_bytes, ip_bytes)
from .test_udpip_core import send_frame, recv_frame, make_sim

BOARD_MAC = 0x024c45544800
BOARD_IP  = 0xc0a80a32          # 192.168.10.50
HOST_MAC  = 0x60cf847491a3
HOST_IP   = 0xc0a80a78          # 192.168.10.120


class MultiEchoDUT(Elaboratable):
    """UDP/IP core with bound user ports, each looped back through a FIFO."""
    def __init__(self, udp_ports):
        self.core       = UDPIPCore(clk_freq=1e6, udp_ports=udp_ports)
        self.drop_count = Signal(16)

    def elaborate(self, platform):
        m = Module()
        m.submodules.core = core = self.core
        with m.If(core.udp_drop):
            m.d.sync += self.drop_count.eq(self.drop_count + 1)
        for name in core.udp_ports:
            fifo = PacketFIFO(udp_user_signature(),
                              payload_depth=1024, packet_depth=4)
            m.submodules[f"echo_{name}"] = fifo
            rx = getattr(core, f"udp_rx_{name}")
            tx = getattr(core, f"udp_tx_{name}")
            connect(m, rx, fifo.i_stream)
            m.d.comb += [
                tx.valid.eq(fifo.o_stream.valid),
                tx.payload.eq(fifo.o_stream.payload),
                tx.first.eq(fifo.o_stream.first),
                tx.last.eq(fifo.o_stream.last),
                fifo.o_stream.ready.eq(tx.ready),
                # Reply to the sender, at its source port. src_port is not
                # driven: the core forces it to the port binding.
                tx.param.ip.eq(fifo.o_stream.param.ip),
                tx.param.dst_port.eq(fifo.o_stream.param.src_port),
                tx.param.length.eq(fifo.o_stream.param.length),
            ]
        m.d.comb += [
            core.mac_address.eq(BOARD_MAC),
            core.ip_address.eq(BOARD_IP),
        ]
        return m


async def arp_handshake(ctx, core):
    request = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))
    await send_frame(ctx, core.mac_rx, request)
    await recv_frame(ctx, core.mac_tx)      # ARP reply, checked elsewhere.


async def expect_no_frame(ctx, core, cycles=1500):
    ctx.set(core.mac_tx.ready, 1)
    for _ in range(cycles):
        _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
        assert not valid, "unexpected TX frame"
    ctx.set(core.mac_tx.ready, 0)


@pytest.mark.parametrize("udp_ports", [[8000], [8000, 8001, 9500]])
def test_echo_on_every_bound_port(udp_ports):
    """Each requested port echoes independently, sending from its binding."""
    dut = MultiEchoDUT(udp_ports)
    sim = make_sim(dut)
    core = dut.core
    prng = random.Random(42)

    async def tb(ctx):
        await arp_handshake(ctx, core)
        for i, port in enumerate(udp_ports):
            payload = bytes(prng.randrange(256) for _ in range(20 + 13*i))
            frame = build_udp_frame(HOST_MAC, HOST_IP, 40000 + i,
                                    BOARD_MAC, BOARD_IP, port, payload)
            await send_frame(ctx, core.mac_rx, frame)
            echo = ParsedFrame(await recv_frame(ctx, core.mac_tx))
            assert echo.ethertype == 0x0800
            assert echo.dst_mac == mac_bytes(HOST_MAC)
            assert echo.ip_csum_ok
            assert echo.ip_src == ip_bytes(BOARD_IP)
            assert echo.ip_protocol == 17
            assert echo.udp_src_port == port        # Forced to the binding.
            assert echo.udp_dst_port == 40000 + i   # Back to the sender.
            assert echo.udp_payload == payload

    sim.add_testbench(tb)
    sim.run()


def test_unbound_port_dropped():
    """Datagrams to a port nobody requested are dropped (and counted),
    without disturbing the bound ports."""
    dut = MultiEchoDUT([8000, 8001])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        stray = build_udp_frame(HOST_MAC, HOST_IP, 50000,
                                BOARD_MAC, BOARD_IP, 9999, b"nobody home")
        await send_frame(ctx, core.mac_rx, stray)
        await expect_no_frame(ctx, core)
        drops = ctx.get(dut.drop_count)
        assert drops == 1, f"expected exactly one udp_drop pulse, got {drops}"

        # The stack is still alive on a bound port.
        frame = build_udp_frame(HOST_MAC, HOST_IP, 50001,
                                BOARD_MAC, BOARD_IP, 8001, b"still here")
        await send_frame(ctx, core.mac_rx, frame)
        echo = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert echo.udp_src_port == 8001
        assert echo.udp_payload == b"still here"

    sim.add_testbench(tb)
    sim.run()


def test_interleaved_ports_share_the_wire():
    """Back-to-back datagrams across ports all echo; per-port order holds."""
    ports = [8000, 8001, 8002]
    dut = MultiEchoDUT(ports)
    sim = make_sim(dut)
    core = dut.core
    prng = random.Random(7)

    # Two rounds over all ports, distinct payloads.
    sends = []
    for rnd in range(2):
        for i, port in enumerate(ports):
            payload = bytes(prng.randrange(256) for _ in range(prng.randrange(4, 80)))
            sends.append((port, 41000 + len(sends), payload))

    async def tb(ctx):
        await arp_handshake(ctx, core)
        for port, sport, payload in sends:
            frame = build_udp_frame(HOST_MAC, HOST_IP, sport,
                                    BOARD_MAC, BOARD_IP, port, payload)
            await send_frame(ctx, core.mac_rx, frame)
        expected = {}       # bound port -> ordered replies
        for port, sport, payload in sends:
            expected.setdefault(port, []).append((sport, payload))
        for _ in sends:
            echo = ParsedFrame(await recv_frame(ctx, core.mac_tx))
            sport, payload = expected[echo.udp_src_port].pop(0)
            assert echo.udp_dst_port == sport
            assert echo.udp_payload == payload
        assert all(not v for v in expected.values())

    sim.add_testbench(tb)
    sim.run()


def test_runtime_rebind():
    """udp_port_<name> inputs rebind a stream at runtime: the new port
    echoes (RX match and TX src_port follow), the old one drops."""
    dut = MultiEchoDUT([8000, 8001])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        ctx.set(core.udp_port_p0, 7000)

        frame = build_udp_frame(HOST_MAC, HOST_IP, 51000,
                                BOARD_MAC, BOARD_IP, 7000, b"rebound")
        await send_frame(ctx, core.mac_rx, frame)
        echo = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert echo.udp_src_port == 7000
        assert echo.udp_dst_port == 51000
        assert echo.udp_payload == b"rebound"

        # The build-time default no longer matches.
        stale = build_udp_frame(HOST_MAC, HOST_IP, 51001,
                                BOARD_MAC, BOARD_IP, 8000, b"stale")
        await send_frame(ctx, core.mac_rx, stale)
        await expect_no_frame(ctx, core)
        assert ctx.get(dut.drop_count) == 1

    sim.add_testbench(tb)
    sim.run()


def test_member_shapes():
    """The interface is shaped by the request (conditional members)."""
    legacy = UDPIPCore(clk_freq=1e6)
    assert hasattr(legacy, "udp_rx") and hasattr(legacy, "udp_tx")
    assert not hasattr(legacy, "udp_drop")

    multi = UDPIPCore(clk_freq=1e6, udp_ports=[8000, 8001])
    for name in ("udp_rx_p0", "udp_tx_p0", "udp_port_p0",
                 "udp_rx_p1", "udp_tx_p1", "udp_port_p1", "udp_drop"):
        assert hasattr(multi, name)
    assert not hasattr(multi, "udp_rx") and not hasattr(multi, "udp_tx")

    named = UDPIPCore(clk_freq=1e6, udp_ports={"ctrl": 5000, "data": 5001})
    assert hasattr(named, "udp_rx_ctrl") and hasattr(named, "udp_tx_data")


def test_netlist_optionality():
    """Port logic exists only when requested, and shrinks to fit:
    no dispatch/arbiter at all without ``udp_ports``, and no TX arbitration
    FSM for a single bound port (nothing to arbitrate)."""
    from amaranth.back import rtlil

    legacy = rtlil.convert(UDPIPCore(clk_freq=1e6), name="core_legacy")
    single = rtlil.convert(UDPIPCore(clk_freq=1e6, udp_ports=[8000]),
                           name="core_single")
    multi  = rtlil.convert(UDPIPCore(clk_freq=1e6, udp_ports=[8000, 8001]),
                           name="core_multi")
    assert "port_dispatch" not in legacy and "port_arbiter" not in legacy
    assert "port_dispatch" in single and "port_dispatch" in multi
    assert len(single) < len(multi)

    # The single-user arbiter is pure wiring; two users need the FSM.
    arb1 = rtlil.convert(UDPPortArbiter({"a": 8000}), name="arb1")
    arb2 = rtlil.convert(UDPPortArbiter({"a": 8000, "b": 8001}), name="arb2")
    assert "fsm_state" not in arb1
    assert "fsm_state" in arb2


def test_port_map_validation():
    with pytest.raises(AssertionError):
        UDPPortDispatch({})                          # Empty.
    with pytest.raises(AssertionError):
        UDPPortDispatch({"a": 8000, "b": 8000})      # Duplicate numbers.
    with pytest.raises(AssertionError):
        UDPPortDispatch({"a": 0x10000})              # Out of range.
    with pytest.raises(AssertionError):
        UDPPortDispatch({"not id": 8000})            # Invalid name.
    with pytest.raises(AssertionError):
        UDPPortArbiter({"drop": 8000})               # FSM state collision.
