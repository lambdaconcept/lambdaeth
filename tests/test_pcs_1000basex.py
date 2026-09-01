#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""1000BASE-X PCS tests.

The PCS TX and RX halves are exercised back-to-back through their TBI-style
code-group interfaces (two PCS instances cross-connected, as in a lane0/lane1
fiber loopback): Clause 37 autonegotiation must complete on both sides,
frames must round-trip with correct first/last/error flags, invalid code
groups must terminate frames with an error beat, and a broken link must
restart autonegotiation on both sides.

The GTR12 hard PCS (8b/10b + comma alignment) is not modeled: the TX
``{disparity, k, d}`` code groups are fed directly into the peer's RX
``{coding_err, disparity_err, k, d}`` input with the error bits forced to 0
(or injected by the harness).
"""

from amaranth.hdl import Module, Signal, Cat, C, ClockDomain, Elaboratable
from amaranth.back import verilog
from amaranth.sim import Simulator

from lambdaeth.phy import GW51000BASEXPHY
from lambdaeth.phy.pcs_1000basex import PCS, PCSTX, RunningDisparity, K, D

from .helpers import packet_to_beats, send_beats, recv_beats, beats_to_packet


# Shrunk Clause 37 timers: breaklink/ack 125 cycles, checker 500 cycles.
FAST_TIMERS = dict(
    clk_freq       = 125e6,
    check_period   = 4e-6,
    breaklink_time = 1e-6,
    more_ack_time  = 1e-6,
    sgmii_ack_time = 1e-6,
)


class _PCSLoopback(Elaboratable):
    """Two PCS instances cross-connected at the code-group level."""
    def __init__(self):
        self.a = PCS(**FAST_TIMERS)
        self.b = PCS(**FAST_TIMERS)
        self.break_ab = Signal()  # Corrupt the a->b symbol stream.
        self.err_ab   = Signal()  # Inject a coding error on a->b.

    def elaborate(self, platform):
        m = Module()

        m.domains += ClockDomain("eth_tx")
        m.domains += ClockDomain("eth_rx")

        m.submodules.a = self.a
        m.submodules.b = self.b

        ab_kd = Signal(9)  # {k, d} towards b.
        with m.If(self.break_ab):
            m.d.comb += ab_kd.eq(0)  # /D0.0/ forever: no commas, no data.
        with m.Else():
            m.d.comb += ab_kd.eq(self.a.tbi_tx[0:9])
        m.d.comb += [
            self.b.tbi_rx.eq(Cat(ab_kd, C(0, 1), self.err_ab)),
            self.b.tbi_rx_ce.eq(1),
            self.a.tbi_rx.eq(Cat(self.b.tbi_tx[0:9], C(0, 2))),
            self.a.tbi_rx_ce.eq(1),
        ]

        return m


async def _wait_link_up(ctx, dut, timeout=20_000):
    for _ in range(timeout):
        if ctx.get(dut.a.link_up) and ctx.get(dut.b.link_up):
            return
        await ctx.tick(domain="eth_tx")
    raise TimeoutError("autonegotiation did not complete")


# Running disparity ---------------------------------------------------------------------------------

def test_running_disparity():
    dut = RunningDisparity()
    sim = Simulator(dut)
    sim.add_clock(8e-9)

    async def tb(ctx):
        ctx.set(dut.ce, 1)

        async def step(k, d):
            ctx.set(dut.k, k)
            ctx.set(dut.d, d)
            before = ctx.get(dut.disparity)
            await ctx.tick()
            return before, ctx.get(dut.disparity)

        # Initial running disparity is negative (0).
        assert ctx.get(dut.disparity) == 0
        # K28.5 flips the disparity.
        before, after = await step(1, K(28, 5))
        assert (before, after) == (0, 1)
        before, after = await step(1, K(28, 5))
        assert (before, after) == (1, 0)
        # /I1/ second byte D5.6 is balanced: preserves.
        before, after = await step(0, D(5, 6))
        assert (before, after) == (0, 0)
        # /I2/ second byte D16.2 flips.
        before, after = await step(0, D(16, 2))
        assert (before, after) == (0, 1)
        before, after = await step(0, D(16, 2))
        assert (before, after) == (1, 0)

    sim.add_testbench(tb)
    sim.run()


# PCS TX idle pattern -------------------------------------------------------------------------------

def test_pcstx_idle():
    dut = PCSTX()
    sim = Simulator(dut)
    sim.add_clock(8e-9)

    async def tb(ctx):
        # No config, no data: pure idle.
        ctx.set(dut.config_valid, 0)
        ctx.set(dut.sink.valid, 0)
        # Let the FSM settle into the /I/ loop.
        for _ in range(8):
            await ctx.tick()
        # Steady state: K28.5 with negative starting RD (bit9=0), then
        # /I2/ D16.2 with positive starting RD (bit9=1) restoring negative.
        seen = [ctx.get(dut.tx_data)]
        for _ in range(7):
            await ctx.tick()
            seen.append(ctx.get(dut.tx_data))
        k285  = (0 << 9) | (1 << 8) | K(28, 5)   # 0x1bc
        d16_2 = (1 << 9) | (0 << 8) | D(16, 2)   # 0x250
        if seen[0] == k285:
            expected = [k285, d16_2] * 4
        else:
            expected = [d16_2, k285] * 4
        assert seen == expected, [hex(v) for v in seen]

    sim.add_testbench(tb)
    sim.run()


# Autoneg + frame round-trip ------------------------------------------------------------------------

def test_autoneg_and_frame_roundtrip():
    dut = _PCSLoopback()
    sim = Simulator(dut)
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    frame = [0x55]*7 + [0xd5] + list(range(60)) + [0xde, 0xad, 0xbe, 0xef]
    done  = []

    async def tb_send(ctx):
        await _wait_link_up(ctx, dut)
        # a -> b.
        await send_beats(ctx, dut.a.tx,
                         packet_to_beats(frame, 8, with_last_be=False),
                         domain="eth_tx")
        # b -> a.
        await send_beats(ctx, dut.b.tx,
                         packet_to_beats(frame, 8, with_last_be=False),
                         domain="eth_tx")

    async def tb_recv(ctx):
        await _wait_link_up(ctx, dut)
        # 1000BASE-X (not SGMII), FD + ACK ability from the peer.
        assert ctx.get(dut.a.lp_abi) == 0x4020
        assert ctx.get(dut.b.lp_abi) == 0x4020
        assert ctx.get(dut.a.is_sgmii) == 0
        assert ctx.get(dut.b.is_sgmii) == 0

        beats = await recv_beats(ctx, dut.b.rx, domain="eth_rx", timeout=20_000)
        assert beats_to_packet(beats, 8) == frame
        assert beats[0]["first"] == 1
        assert all(b["error"] == 0 for b in beats)
        assert all(b["last"] == 0 for b in beats[:-1])

        beats = await recv_beats(ctx, dut.a.rx, domain="eth_rx", timeout=20_000)
        assert beats_to_packet(beats, 8) == frame
        assert beats[0]["first"] == 1
        assert all(b["error"] == 0 for b in beats)
        done.append(True)

    sim.add_testbench(tb_send)
    sim.add_testbench(tb_recv)
    sim.run()
    assert done


def test_back_to_back_frames():
    """Frames queued without a valid gap are still delimited (via ``last``)."""
    dut = _PCSLoopback()
    sim = Simulator(dut)
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    frame1 = [0x55]*7 + [0xd5] + list(range(20))
    frame2 = [0x55]*7 + [0xd5] + list(range(100, 140))
    done   = []

    async def tb_send(ctx):
        await _wait_link_up(ctx, dut)
        beats = (packet_to_beats(frame1, 8, with_last_be=False) +
                 packet_to_beats(frame2, 8, with_last_be=False))
        await send_beats(ctx, dut.a.tx, beats, domain="eth_tx")

    async def tb_recv(ctx):
        await _wait_link_up(ctx, dut)
        beats = await recv_beats(ctx, dut.b.rx, domain="eth_rx", timeout=20_000)
        assert beats_to_packet(beats, 8) == frame1
        beats = await recv_beats(ctx, dut.b.rx, domain="eth_rx", timeout=20_000)
        assert beats_to_packet(beats, 8) == frame2
        done.append(True)

    sim.add_testbench(tb_send)
    sim.add_testbench(tb_recv)
    sim.run()
    assert done


def test_rx_error_terminates_frame():
    """An invalid code group mid-frame yields an error + last beat."""
    dut = _PCSLoopback()
    sim = Simulator(dut)
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    frame = [0x55]*7 + [0xd5] + list(range(32))
    done  = []

    async def tb_send(ctx):
        await _wait_link_up(ctx, dut)
        await send_beats(ctx, dut.a.tx,
                         packet_to_beats(frame, 8, with_last_be=False),
                         domain="eth_tx")

    async def tb_inject(ctx):
        # Wait for the frame to start streaming out of b, then corrupt one
        # code group.
        for _ in range(20_000):
            if ctx.get(dut.b.rx.valid):
                break
            await ctx.tick(domain="eth_rx")
        ctx.set(dut.err_ab, 1)
        await ctx.tick(domain="eth_rx")
        ctx.set(dut.err_ab, 0)

    async def tb_recv(ctx):
        await _wait_link_up(ctx, dut)
        beats = await recv_beats(ctx, dut.b.rx, domain="eth_rx", timeout=20_000)
        # Frame is cut short by an error beat.
        assert beats[-1]["error"] == 1
        assert beats[-1]["last"] == 1
        assert len(beats) < len(frame)
        done.append(True)

    sim.add_testbench(tb_send)
    sim.add_testbench(tb_inject)
    sim.add_testbench(tb_recv)
    sim.run()
    assert done


def test_link_break_restarts_autoneg():
    dut = _PCSLoopback()
    sim = Simulator(dut)
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    async def tb(ctx):
        await _wait_link_up(ctx, dut)

        # Break a->b: b loses /C//I/ ordered sets, restarts, and its
        # breaklink (empty /C/) also takes a down.
        ctx.set(dut.break_ab, 1)
        for _ in range(20_000):
            if not ctx.get(dut.b.link_up) and not ctx.get(dut.a.link_up):
                break
            await ctx.tick(domain="eth_tx")
        assert not ctx.get(dut.b.link_up)
        assert not ctx.get(dut.a.link_up)

        # Repair: both sides renegotiate.
        ctx.set(dut.break_ab, 0)
        await _wait_link_up(ctx, dut)

    sim.add_testbench(tb)
    sim.run()


# PHY component -------------------------------------------------------------------------------------

def _mark_used(elaboratable):
    elaboratable._MustUse__used = True
    return elaboratable


def test_phy_convention():
    phy = _mark_used(GW51000BASEXPHY())
    assert phy.data_width == 8
    assert phy.tx_clk_freq == 125e6
    assert phy.rx_clk_freq == 125e6
    assert phy.tx_domain == "eth_tx"
    assert phy.rx_domain == "eth_rx"
    assert phy.tx.ready is not None and phy.rx.valid is not None


def test_phy_memory_map():
    phy = _mark_used(GW51000BASEXPHY())
    names = [reg_name[-1] for _reg, reg_name, _rng in phy.bus.memory_map.resources()]
    assert names == ["reset", "ctrl", "status", "lp_abi"]


def test_an_bypass_frame_roundtrip():
    """With autonegotiation bypassed, frames flow without any /C/ exchange."""
    dut = _PCSLoopback()
    sim = Simulator(dut)
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")

    frame = [0x55]*7 + [0xd5] + list(range(16))
    done  = []

    async def tb_send(ctx):
        ctx.set(dut.a.an_bypass, 1)
        ctx.set(dut.b.an_bypass, 1)
        for _ in range(20):
            await ctx.tick(domain="eth_tx")
        assert ctx.get(dut.a.link_up) and ctx.get(dut.b.link_up)
        await send_beats(ctx, dut.a.tx,
                         packet_to_beats(frame, 8, with_last_be=False),
                         domain="eth_tx")

    async def tb_recv(ctx):
        beats = await recv_beats(ctx, dut.b.rx, domain="eth_rx", timeout=20_000)
        assert beats_to_packet(beats, 8) == frame
        done.append(True)

    sim.add_testbench(tb_send)
    sim.add_testbench(tb_recv)
    sim.run()
    assert done


def test_phy_verilog():
    phy = GW51000BASEXPHY()
    vlog = verilog.convert(phy, name="gw5_1000basex_phy")
    # Lane-facing pads present.
    for port in ["clk_tx", "clk_rx", "tx_data", "tx_wren", "tx_afull",
                 "rx_data", "rx_aempty", "rx_rden", "pll_ok", "align_link",
                 "pma_rstn", "pcs_tx_rst", "pcs_rx_rst", "link_up"]:
        assert f" {port}" in vlog or f"\\{port}" in vlog, f"missing pad {port}"
