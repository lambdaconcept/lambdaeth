#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

import random

import pytest

from amaranth.hdl import Module
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from lambdaeth.mac.converter import EthStreamConverter
from lambdaeth.mac.last_be import TXLastBE, RXLastBE

from .helpers import send_packet, recv_packet


@pytest.mark.parametrize("length", [1, 3, 4, 7, 8, 61])
def test_up_convert_8_to_32(length):
    """8-bit PHY stream (last only) packed into 32-bit beats."""
    m = Module()
    m.submodules.lb   = lb   = RXLastBE(8)
    m.submodules.conv = conv = EthStreamConverter(8, 32)
    connect(m, lb.source, conv.sink)

    sim = Simulator(m)
    sim.add_clock(1e-6)
    prng = random.Random(length)
    payload = [prng.randrange(256) for _ in range(length)]

    async def tb(ctx):
        await send_packet(ctx, lb.sink, payload, with_last_be=False,
                          stall_rate=0.2, rng=prng)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, conv.source, data_width=32,
                                        stall_rate=0.2, rng=prng)
        assert data == payload
        assert beats[0]["first"] == 1
        assert beats[-1]["last"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


@pytest.mark.parametrize("length", [1, 3, 4, 7, 8, 61])
def test_down_convert_32_to_8(length):
    """32-bit beats split into an 8-bit stream, terminated by TXLastBE."""
    m = Module()
    m.submodules.conv = conv = EthStreamConverter(32, 8)
    m.submodules.lb   = lb   = TXLastBE(8)
    connect(m, conv.source, lb.sink)

    sim = Simulator(m)
    sim.add_clock(1e-6)
    prng = random.Random(length)
    payload = [prng.randrange(256) for _ in range(length)]

    async def tb(ctx):
        await send_packet(ctx, conv.sink, payload, data_width=32,
                          stall_rate=0.2, rng=prng)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, lb.source, stall_rate=0.2, rng=prng)
        assert data == payload
        assert beats[0]["first"] == 1
        assert beats[-1]["last"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


def test_roundtrip_32_8_32():
    m = Module()
    m.submodules.down = down = EthStreamConverter(32, 8)
    m.submodules.lb   = lb   = TXLastBE(8)
    m.submodules.up   = up   = EthStreamConverter(8, 32)
    connect(m, down.source, lb.sink)
    connect(m, lb.source, up.sink)

    sim = Simulator(m)
    sim.add_clock(1e-6)
    prng = random.Random(12)
    packets = [[prng.randrange(256) for _ in range(prng.randrange(1, 40))]
               for _ in range(6)]

    async def tb(ctx):
        for p in packets:
            await send_packet(ctx, down.sink, p, data_width=32,
                              stall_rate=0.2, rng=prng)

    async def tb_out(ctx):
        for p in packets:
            data, _ = await recv_packet(ctx, up.source, data_width=32,
                                        stall_rate=0.2, rng=prng)
            assert data == p

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()
