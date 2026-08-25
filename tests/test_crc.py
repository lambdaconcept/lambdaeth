#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

import random
import zlib

import pytest

from amaranth.sim import Simulator

from lambdaeth.mac.crc import (CRCEngine, crc32_calc, CRC32, CRC32Check,
                               CRC32Inserter, CRC32Checker,
                               CRC32_WIDTH, CRC32_POLYNOM, CRC32_INIT)

from .helpers import (crc32_bytes, send_packet, recv_packet, send_beats,
                      packet_to_beats)


@pytest.mark.parametrize("data_width", [8, 32])
def test_crc_engine_matches_model(data_width):
    dut = CRCEngine(data_width, CRC32_WIDTH, CRC32_POLYNOM)
    sim = Simulator(dut)
    prng = random.Random(42)

    async def tb(ctx):
        for _ in range(64):
            crc_prev = prng.randrange(2**CRC32_WIDTH)
            data     = prng.randrange(2**data_width)
            ctx.set(dut.crc_prev, crc_prev)
            ctx.set(dut.data, data)
            await ctx.delay(1e-9)
            expected = crc32_calc(data_width, CRC32_WIDTH, CRC32_POLYNOM,
                                  crc_prev, data)
            assert ctx.get(dut.crc_next) == expected

    sim.add_testbench(tb)
    sim.run()


def test_crc32_value_matches_zlib():
    dut = CRC32(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    prng = random.Random(7)
    data = [prng.randrange(256) for _ in range(60)]

    async def tb(ctx):
        ctx.set(dut.be, 1)
        ctx.set(dut.en, 1)
        for n, byte in enumerate(data):
            ctx.set(dut.data, byte)
            # value is combinational on the current byte.
            assert ctx.get(dut.value) == zlib.crc32(bytes(data[:n + 1]))
            await ctx.tick()

    sim.add_testbench(tb)
    sim.run()


def test_crc32_check_residue():
    dut = CRC32Check(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    prng = random.Random(8)
    payload = [prng.randrange(256) for _ in range(59)]
    frame = payload + crc32_bytes(payload)

    async def tb(ctx):
        ctx.set(dut.be, 1)
        ctx.set(dut.en, 1)
        for n, byte in enumerate(frame):
            ctx.set(dut.data, byte)
            if n == len(frame) - 1:
                assert ctx.get(dut.error) == 0
            elif n > 4:
                assert ctx.get(dut.error) == 1
            await ctx.tick()
        # Corrupted last byte -> error.
        ctx.set(dut.clear, 1)
        await ctx.tick()
        ctx.set(dut.clear, 0)
        bad = frame[:-1] + [frame[-1] ^ 0x01]
        for n, byte in enumerate(bad):
            ctx.set(dut.data, byte)
            if n == len(bad) - 1:
                assert ctx.get(dut.error) == 1
            await ctx.tick()

    sim.add_testbench(tb)
    sim.run()


@pytest.mark.parametrize("with_last_be", [True, False])
@pytest.mark.parametrize("length", [1, 4, 59, 60])
def test_crc32_inserter_8bit(length, with_last_be):
    dut = CRC32Inserter(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    prng = random.Random(length)
    payload = [prng.randrange(256) for _ in range(length)]

    async def tb(ctx):
        await send_packet(ctx, dut.sink, payload, with_last_be=with_last_be)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, dut.source)
        assert data == payload + crc32_bytes(payload)
        assert beats[-1]["last"] == 1
        assert beats[0]["first"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


@pytest.mark.parametrize("length", [1, 3, 4, 7, 8, 60])
def test_crc32_inserter_32bit(length):
    dut = CRC32Inserter(32)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    prng = random.Random(length)
    payload = [prng.randrange(256) for _ in range(length)]

    async def tb(ctx):
        await send_packet(ctx, dut.sink, payload, data_width=32)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, dut.source, data_width=32)
        assert data == payload + crc32_bytes(payload)

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


@pytest.mark.parametrize("corrupt", [False, True])
def test_crc32_checker_8bit(corrupt):
    dut = CRC32Checker(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    prng = random.Random(9)
    payload = [prng.randrange(256) for _ in range(60)]
    frame = payload + crc32_bytes(payload)
    if corrupt:
        frame[10] ^= 0x40

    errors = 0

    async def count_errors(ctx):
        nonlocal errors
        while True:
            _clk, _rst, err = await ctx.tick().sample(dut.error)
            errors += err

    async def tb(ctx):
        # 8-bit RX path: PHYs drive only `last` (no last_be).
        await send_packet(ctx, dut.sink, frame, with_last_be=False)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, dut.source)
        assert data == frame[:-4]
        if corrupt:
            assert beats[-1]["error"] != 0
        else:
            assert all(b["error"] == 0 for b in beats)

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.add_testbench(count_errors, background=True)
    sim.run()
    assert errors == (1 if corrupt else 0)


@pytest.mark.parametrize("data_width", [8, 32])
def test_crc32_roundtrip_backpressure(data_width):
    from amaranth.hdl import Module
    from amaranth.lib.wiring import connect

    m = Module()
    m.submodules.inserter = inserter = CRC32Inserter(data_width)
    m.submodules.checker  = checker  = CRC32Checker(data_width)
    connect(m, inserter.source, checker.sink)

    sim = Simulator(m)
    sim.add_clock(1e-6)
    prng = random.Random(10)
    packets = [[prng.randrange(256) for _ in range(prng.randrange(1, 80))]
               for _ in range(8)]

    async def tb(ctx):
        for p in packets:
            await send_packet(ctx, inserter.sink, p, data_width=data_width,
                              stall_rate=0.3, rng=prng)

    async def tb_out(ctx):
        for p in packets:
            data, beats = await recv_packet(ctx, checker.source,
                                            data_width=data_width,
                                            stall_rate=0.3, rng=prng)
            assert data == p
            assert all(b["error"] == 0 for b in beats)

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()
