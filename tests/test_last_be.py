#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

from amaranth.hdl import Module, ClockDomain
from amaranth.sim import Simulator

from lambdaeth.mac.last_be import TXLastBE, RXLastBE

from .helpers import send_beats, recv_beats, beats_to_packet


def test_tx_last_be_truncates():
    """A down-converter tail (beats after the one with last_be) is dropped."""
    dut = TXLastBE(8)
    sim = Simulator(dut)
    sim.add_clock(1e-6)

    # 6 data bytes followed by 2 dummy sub-beats; last_be on beat 5.
    beats = []
    for i in range(8):
        beats.append({
            "data":    i + 1,
            "first":   i == 0,
            "last":    i == 7,
            "last_be": 1 if i == 5 else 0,
        })

    async def tb(ctx):
        await send_beats(ctx, dut.sink, beats)

    async def tb_out(ctx):
        got = await recv_beats(ctx, dut.source)
        assert beats_to_packet(got) == [1, 2, 3, 4, 5, 6]
        assert got[-1]["last"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


def test_rx_last_be_8bit():
    dut = RXLastBE(8)
    m = Module()
    m.domains.sync = ClockDomain()  # DUT is purely combinational.
    m.submodules.dut = dut
    sim = Simulator(m)
    sim.add_clock(1e-6)

    beats = [{"data": i, "first": i == 0, "last": i == 3, "last_be": 0}
             for i in range(4)]

    async def tb(ctx):
        await send_beats(ctx, dut.sink, beats)

    async def tb_out(ctx):
        got = await recv_beats(ctx, dut.source)
        assert [b["last_be"] for b in got] == [0, 0, 0, 1]

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()
