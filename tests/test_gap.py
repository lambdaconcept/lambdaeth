#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

from amaranth.sim import Simulator

from lambdaeth.mac.gap import Gap

from .helpers import send_packet


def test_gap_8bit():
    dut = Gap(8)
    assert dut.cycles == 12
    sim = Simulator(dut)
    sim.add_clock(1e-6)

    packets = [list(range(1, 9)), list(range(10, 18))]
    received = []
    idle_between = 0

    async def tb(ctx):
        for p in packets:
            await send_packet(ctx, dut.sink, p, with_last_be=False)

    async def tb_out(ctx):
        nonlocal idle_between
        ctx.set(dut.source.ready, 1)
        # Receive first packet.
        got = []
        while True:
            _clk, _rst, valid, data, last = await ctx.tick().sample(
                dut.source.valid, dut.source.p.data, dut.source.last)
            if valid:
                got.append(data)
                if last:
                    break
        received.append(got)
        # Count idle cycles until the next packet shows up.
        idle = 0
        while True:
            _clk, _rst, valid, data, last = await ctx.tick().sample(
                dut.source.valid, dut.source.p.data, dut.source.last)
            if valid:
                break
            idle += 1
        idle_between = idle
        got = [data]
        while not last:
            _clk, _rst, valid, data, last = await ctx.tick().sample(
                dut.source.valid, dut.source.p.data, dut.source.last)
            if valid:
                got.append(data)
        received.append(got)

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()

    assert received == packets
    assert idle_between >= 12
