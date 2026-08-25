#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""End-to-end tests of the UDP/IP core over plain MAC frame streams."""

import random

import pytest

from amaranth.hdl import Module, Elaboratable
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from amaranth_stream import PacketFIFO

from lambdaeth.core import UDPIPCore, udp_user_signature

from .net_helpers import (build_eth, build_arp, build_udp_frame, ParsedFrame,
                          mac_bytes, ip_bytes)


BOARD_MAC = 0x024c45544800
BOARD_IP  = 0xc0a80a32          # 192.168.10.50
HOST_MAC  = 0x60cf847491a3
HOST_IP   = 0xc0a80a78          # 192.168.10.120


class EchoDUT(Elaboratable):
    """UDP/IP core with the user port looped back through a PacketFIFO."""
    def __init__(self):
        self.core = UDPIPCore(clk_freq=1e6)

    def elaborate(self, platform):
        m = Module()
        m.submodules.core = core = self.core
        m.submodules.fifo = fifo = PacketFIFO(udp_user_signature(),
                                              payload_depth=2048, packet_depth=8)
        connect(m, core.udp_rx, fifo.i_stream)

        # Swap the parameters: reply to the sender, from the port it targeted.
        m.d.comb += [
            core.udp_tx.valid.eq(fifo.o_stream.valid),
            core.udp_tx.payload.eq(fifo.o_stream.payload),
            core.udp_tx.first.eq(fifo.o_stream.first),
            core.udp_tx.last.eq(fifo.o_stream.last),
            fifo.o_stream.ready.eq(core.udp_tx.ready),
            core.udp_tx.param.ip.eq(fifo.o_stream.param.ip),
            core.udp_tx.param.src_port.eq(fifo.o_stream.param.dst_port),
            core.udp_tx.param.dst_port.eq(fifo.o_stream.param.src_port),
            core.udp_tx.param.length.eq(fifo.o_stream.param.length),
        ]
        m.d.comb += [
            core.mac_address.eq(BOARD_MAC),
            core.ip_address.eq(BOARD_IP),
        ]
        return m


async def send_frame(ctx, ep, frame, *, stall_rate=0.0, rng=None):
    rng = rng or random.Random(0)
    for i, byte in enumerate(frame):
        while stall_rate and rng.random() < stall_rate:
            ctx.set(ep.valid, 0)
            await ctx.tick()
        ctx.set(ep.valid, 1)
        ctx.set(ep.payload, byte)
        ctx.set(ep.first, i == 0)
        ctx.set(ep.last, i == len(frame) - 1)
        await ctx.tick().until(ep.ready)
        ctx.set(ep.valid, 0)
    ctx.set(ep.first, 0)
    ctx.set(ep.last, 0)


async def recv_frame(ctx, ep, *, timeout=20000, stall_rate=0.0, rng=None):
    rng = rng or random.Random(1)
    data = []
    for _ in range(timeout):
        ready = 0 if (stall_rate and rng.random() < stall_rate) else 1
        ctx.set(ep.ready, ready)
        _clk, _rst, valid, payload, last = await ctx.tick().sample(
            ep.valid, ep.payload, ep.last)
        if ready and valid:
            data.append(payload)
            if last:
                ctx.set(ep.ready, 0)
                return data
    raise TimeoutError("no complete frame received")


def make_sim(dut):
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    return sim


def test_arp_reply():
    """The core answers an ARP request for its IP and learns the sender."""
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core

    request = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, request)
        reply = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert reply.ethertype == 0x0806
        assert reply.dst_mac == mac_bytes(HOST_MAC)
        assert reply.src_mac == mac_bytes(BOARD_MAC)
        assert reply.arp_opcode == 2
        assert reply.arp_sender_mac == mac_bytes(BOARD_MAC)
        assert reply.arp_sender_ip == ip_bytes(BOARD_IP)
        assert reply.arp_target_mac == mac_bytes(HOST_MAC)
        assert reply.arp_target_ip == ip_bytes(HOST_IP)
        assert len(reply.raw) == 60

    sim.add_testbench(tb)
    sim.run()


def test_arp_ignores_other_ip():
    """Requests for other IPs are ignored."""
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core

    request = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP ^ 1))

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, request)
        ctx.set(core.mac_tx.ready, 1)
        for _ in range(600):
            _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
            assert not valid, "unexpected TX frame"

    sim.add_testbench(tb)
    sim.run()


@pytest.mark.parametrize("payload_len", [1, 18, 26, 100, 400])
@pytest.mark.parametrize("stall", [0.0, 0.25])
def test_udp_echo(payload_len, stall):
    """A UDP datagram from a learned host is echoed back correctly."""
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core
    prng = random.Random(payload_len)

    payload = bytes(prng.randrange(256) for _ in range(payload_len))
    arp_req = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))
    udp_in  = build_udp_frame(HOST_MAC, HOST_IP, 54321,
                              BOARD_MAC, BOARD_IP, 8000, payload)

    async def tb(ctx):
        # ARP first (the host would do the same); also fills the ARP cache.
        await send_frame(ctx, core.mac_rx, arp_req)
        await recv_frame(ctx, core.mac_tx)  # ARP reply, checked elsewhere.

        await send_frame(ctx, core.mac_rx, udp_in, stall_rate=stall, rng=prng)
        echo = ParsedFrame(await recv_frame(ctx, core.mac_tx,
                                            stall_rate=stall, rng=prng))
        assert echo.ethertype == 0x0800
        assert echo.dst_mac == mac_bytes(HOST_MAC)
        assert echo.src_mac == mac_bytes(BOARD_MAC)
        assert echo.ip_csum_ok
        assert echo.ip_src == ip_bytes(BOARD_IP)
        assert echo.ip_dst == ip_bytes(HOST_IP)
        assert echo.ip_protocol == 17
        assert echo.udp_src_port == 8000
        assert echo.udp_dst_port == 54321
        assert echo.udp_length == 8 + payload_len
        assert echo.udp_payload == payload
        # (Padding to the 60-byte minimum is done downstream, in the MAC.)

    sim.add_testbench(tb)
    sim.run()


def test_udp_echo_back_to_back():
    """Several datagrams echo in order."""
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core
    prng = random.Random(99)

    payloads = [bytes(prng.randrange(256) for _ in range(prng.randrange(1, 60)))
                for _ in range(4)]
    arp_req = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, arp_req)
        await recv_frame(ctx, core.mac_tx)
        for i, payload in enumerate(payloads):
            frame = build_udp_frame(HOST_MAC, HOST_IP, 40000 + i,
                                    BOARD_MAC, BOARD_IP, 8000, payload)
            await send_frame(ctx, core.mac_rx, frame)
        for i, payload in enumerate(payloads):
            echo = ParsedFrame(await recv_frame(ctx, core.mac_tx))
            assert echo.udp_dst_port == 40000 + i
            assert echo.udp_payload == payload

    sim.add_testbench(tb)
    sim.run()


def test_udp_wrong_ip_dropped():
    """Datagrams to another IP are not echoed."""
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core

    frame = build_udp_frame(HOST_MAC, HOST_IP, 1, BOARD_MAC, BOARD_IP ^ 0x100,
                            2, b"hello")

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, frame)
        ctx.set(core.mac_tx.ready, 1)
        for _ in range(1000):
            _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
            assert not valid, "unexpected TX frame"

    sim.add_testbench(tb)
    sim.run()


def test_udp_bad_ip_checksum_dropped():
    dut = EchoDUT()
    sim = make_sim(dut)
    core = dut.core

    frame = bytearray(build_udp_frame(HOST_MAC, HOST_IP, 1, BOARD_MAC, BOARD_IP,
                                      2, b"hello"))
    frame[24] ^= 0x01  # Corrupt the IP checksum.

    async def tb(ctx):
        await send_frame(ctx, core.mac_rx, bytes(frame))
        ctx.set(core.mac_tx.ready, 1)
        for _ in range(1000):
            _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
            assert not valid, "unexpected TX frame"

    sim.add_testbench(tb)
    sim.run()


class BareDUT(Elaboratable):
    """UDP/IP core with the user port exposed to the testbench."""
    def __init__(self):
        self.core = UDPIPCore(clk_freq=1e6)

    def elaborate(self, platform):
        m = Module()
        m.submodules.core = core = self.core
        m.d.comb += [
            core.mac_address.eq(BOARD_MAC),
            core.ip_address.eq(BOARD_IP),
        ]
        return m


def test_udp_tx_resolves_via_arp_request():
    """Board-initiated datagram to an unknown IP triggers an ARP request;
    after the reply the datagram goes out."""
    dut = BareDUT()
    sim = make_sim(dut)
    core = dut.core
    payload = b"ping!"

    async def tb_user(ctx):
        ctx.set(core.udp_tx.param.ip, HOST_IP)
        ctx.set(core.udp_tx.param.src_port, 8000)
        ctx.set(core.udp_tx.param.dst_port, 5555)
        ctx.set(core.udp_tx.param.length, len(payload))
        for i, byte in enumerate(payload):
            ctx.set(core.udp_tx.valid, 1)
            ctx.set(core.udp_tx.payload, byte)
            ctx.set(core.udp_tx.first, i == 0)
            ctx.set(core.udp_tx.last, i == len(payload) - 1)
            await ctx.tick().until(core.udp_tx.ready)
            ctx.set(core.udp_tx.valid, 0)

    async def tb_net(ctx):
        # First TX frame must be the ARP request for HOST_IP.
        arp_req = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert arp_req.ethertype == 0x0806
        assert arp_req.dst_mac == b"\xff"*6
        assert arp_req.arp_opcode == 1
        assert arp_req.arp_target_ip == ip_bytes(HOST_IP)
        # Answer it.
        reply = build_eth(BOARD_MAC, HOST_MAC, 0x0806,
                          build_arp(2, HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP))
        await send_frame(ctx, core.mac_rx, reply)
        # Then the datagram.
        frame = ParsedFrame(await recv_frame(ctx, core.mac_tx))
        assert frame.ethertype == 0x0800
        assert frame.dst_mac == mac_bytes(HOST_MAC)
        assert frame.udp_src_port == 8000
        assert frame.udp_dst_port == 5555
        assert frame.udp_payload == payload

    sim.add_testbench(tb_user)
    sim.add_testbench(tb_net)
    sim.run()
