#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

import random

from amaranth.hdl import Module
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from lambdaeth.mac.preamble import PreambleInserter, PreambleChecker

from .helpers import send_packet, recv_packet


PREAMBLE_BYTES = [0x55]*7 + [0xd5]


def test_preamble_inserter_8bit():
    dut = PreambleInserter(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    payload = list(range(1, 61))

    async def tb(ctx):
        await send_packet(ctx, dut.sink, payload)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, dut.source)
        assert data == PREAMBLE_BYTES + payload
        assert beats[0]["first"] == 1
        assert beats[-1]["last"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


def test_preamble_checker_8bit():
    dut = PreambleChecker(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    payload = list(range(1, 61))

    async def tb(ctx):
        await send_packet(ctx, dut.sink, PREAMBLE_BYTES + payload,
                          with_last_be=False)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, dut.source)
        assert data == payload
        assert beats[0]["first"] == 1
        assert beats[-1]["last"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


def test_preamble_checker_error():
    dut = PreambleChecker(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    payload = list(range(1, 31))

    errors = 0

    async def count_errors(ctx):
        nonlocal errors
        while True:
            _clk, _rst, err = await ctx.tick().sample(dut.error)
            errors += err

    async def tb(ctx):
        # Garbage packet without SFD: consumed while hunting, error pulses.
        await send_packet(ctx, dut.sink, [0x55]*10, with_last_be=False)
        # Then a good packet still goes through.
        await send_packet(ctx, dut.sink, PREAMBLE_BYTES + payload,
                          with_last_be=False)

    async def tb_out(ctx):
        data, _ = await recv_packet(ctx, dut.source)
        assert data == payload

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.add_testbench(count_errors, background=True)
    sim.run()
    assert errors == 1


def test_preamble_roundtrip():
    m = Module()
    m.submodules.inserter = inserter = PreambleInserter(8)
    m.submodules.checker  = checker  = PreambleChecker(8)
    connect(m, inserter.source, checker.sink)

    sim = Simulator(m)
    sim.add_clock(1e-6)
    prng = random.Random(11)
    packets = [[prng.randrange(256) for _ in range(prng.randrange(1, 70))]
               for _ in range(4)]

    async def tb(ctx):
        for p in packets:
            await send_packet(ctx, inserter.sink, p, stall_rate=0.2, rng=prng)

    async def tb_out(ctx):
        for p in packets:
            data, _ = await recv_packet(ctx, checker.source,
                                        stall_rate=0.2, rng=prng)
            assert data == p

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()
