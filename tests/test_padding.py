#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

import pytest

from amaranth.sim import Simulator

from lambdaeth.mac.padding import PaddingInserter, PaddingChecker

from .helpers import send_packet, recv_packet


@pytest.mark.parametrize("with_last_be", [True, False])
@pytest.mark.parametrize("length", [1, 59, 60, 61])
def test_padding_inserter_8bit(length, with_last_be):
    dut = PaddingInserter(8, 60)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    payload = [(i + 1) & 0xff for i in range(length)]
    expected = payload + [0]*max(0, 60 - length)

    async def tb(ctx):
        # Send the packet twice: padding state must fully reset in between
        # (regression test for the LiteEth counter carry-over on exactly
        # padded packets).
        await send_packet(ctx, dut.sink, payload, with_last_be=with_last_be)
        await send_packet(ctx, dut.sink, payload, with_last_be=with_last_be)

    async def tb_out(ctx):
        for _ in range(2):
            data, beats = await recv_packet(ctx, dut.source)
            assert data == expected
            assert beats[-1]["last"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


@pytest.mark.parametrize("length,expect_error", [(59, True), (60, False), (61, False)])
def test_padding_checker_8bit(length, expect_error):
    dut = PaddingChecker(8, 60)
    sim = Simulator(dut)
    sim.add_clock(1e-6)
    payload = [(i + 1) & 0xff for i in range(length)]

    async def tb(ctx):
        await send_packet(ctx, dut.sink, payload, with_last_be=False)

    async def tb_out(ctx):
        data, beats = await recv_packet(ctx, dut.source)
        assert data == payload
        if expect_error:
            assert beats[-1]["error"] != 0
        else:
            assert all(b["error"] == 0 for b in beats)

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()
