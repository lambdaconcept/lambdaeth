#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

import random

import pytest

from amaranth.hdl import Module, ClockDomain, Elaboratable
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from lambdaeth.mac import MACCore

from .helpers import crc32_bytes, send_packet, recv_packet, send_beats, packet_to_beats


PREAMBLE = [0x55]*7 + [0xd5]


class PHYMeta:
    """Duck-typed PHY metadata for MACCore."""
    def __init__(self, data_width=8):
        self.data_width = data_width
        self.tx_domain  = "eth_tx"
        self.rx_domain  = "eth_rx"


class MACLoopback(Elaboratable):
    """MACCore with its PHY streams looped back."""
    def __init__(self, core_dw=8, phy_dw=8, **kwargs):
        self.mac = MACCore(PHYMeta(phy_dw), data_width=core_dw,
                           with_csr=False, **kwargs)

    def elaborate(self, platform):
        m = Module()
        m.domains.eth_tx = ClockDomain()
        m.domains.eth_rx = ClockDomain()
        m.submodules.mac = self.mac
        connect(m, self.mac.phy_tx, self.mac.phy_rx)
        return m


class MACRxHarness(Elaboratable):
    """MACCore with phy_rx driven by the testbench (with_csr=True)."""
    def __init__(self, core_dw=8, phy_dw=8, **kwargs):
        self.mac = MACCore(PHYMeta(phy_dw), data_width=core_dw, **kwargs)

    def elaborate(self, platform):
        m = Module()
        m.domains.eth_tx = ClockDomain()
        m.domains.eth_rx = ClockDomain()
        m.submodules.mac = self.mac
        return m


def make_sim(dut):
    sim = Simulator(dut)
    sim.add_clock(10e-9, domain="sync")
    sim.add_clock(8e-9, domain="eth_tx")
    sim.add_clock(8e-9, domain="eth_rx")
    return sim


@pytest.mark.parametrize("core_dw", [8, 32])
def test_mac_loopback(core_dw):
    dut = MACLoopback(core_dw=core_dw, phy_dw=8)
    sim = make_sim(dut)
    prng = random.Random(20)

    packets = [
        [prng.randrange(256) for _ in range(64)],   # No padding needed.
        [prng.randrange(256) for _ in range(9)],    # Padded to 60.
        [prng.randrange(256) for _ in range(61)],   # Unaligned for dw=32.
    ]
    expected = [p + [0]*max(0, 60 - len(p)) for p in packets]

    async def tb(ctx):
        for p in packets:
            await send_packet(ctx, dut.mac.sink, p, data_width=core_dw,
                              stall_rate=0.1, rng=prng)

    async def tb_out(ctx):
        for e in expected:
            data, beats = await recv_packet(ctx, dut.mac.source,
                                            data_width=core_dw,
                                            stall_rate=0.1, rng=prng)
            assert data == e
            assert all(b["error"] == 0 for b in beats)
            assert beats[-1]["last"] == 1

    sim.add_testbench(tb)
    sim.add_testbench(tb_out)
    sim.run()


async def csr_read(ctx, bus, addr, size):
    """Read a size-byte little-endian value over an 8-bit CSR bus."""
    value = 0
    for i in range(size):
        ctx.set(bus.addr, addr + i)
        ctx.set(bus.r_stb, 1)
        await ctx.tick()
        ctx.set(bus.r_stb, 0)
        value |= ctx.get(bus.r_data) << (8*i)
    return value


def reg_addr(memory_map, name):
    for _reg, reg_name, (start, _end) in memory_map.resources():
        if reg_name[-1] == name or name in reg_name:
            return start
    raise KeyError(name)


def test_mac_csr_and_rx_errors():
    dut = MACRxHarness()
    sim = make_sim(dut)
    prng = random.Random(21)
    mac  = dut.mac

    payload   = [prng.randrange(256) for _ in range(60)]
    good      = PREAMBLE + payload + crc32_bytes(payload)
    bad_fcs   = list(good)
    bad_fcs[20] ^= 0x10                       # Corrupt a payload byte.
    truncated = [0x55]*10                     # Ends while hunting for SFD.

    memory_map = mac.bus.memory_map
    status_addr   = reg_addr(memory_map, "status")
    preamble_addr = reg_addr(memory_map, "preamble_errors")
    crc_addr      = reg_addr(memory_map, "crc_errors")

    async def tb_rx(ctx):
        for frame in [good, bad_fcs, truncated]:
            await send_beats(ctx, mac.phy_rx,
                             packet_to_beats(frame, 8, with_last_be=False),
                             domain="eth_rx")
            # Inter-frame gap.
            for _ in range(16):
                await ctx.tick(domain="eth_rx")

    async def tb_out(ctx):
        # Good frame: no errors.
        data, beats = await recv_packet(ctx, mac.source)
        assert data == payload
        assert all(b["error"] == 0 for b in beats)
        # Bad FCS frame: passed through with error marked on last beat.
        expected_bad = list(payload)
        expected_bad[20 - len(PREAMBLE)] ^= 0x10
        data, beats = await recv_packet(ctx, mac.source)
        assert data == expected_bad
        assert beats[-1]["error"] != 0
        # Let the error pulses reach the sys-domain counters.
        for _ in range(16):
            await ctx.tick()
        assert await csr_read(ctx, mac.bus, status_addr, 1) == 0b11
        assert await csr_read(ctx, mac.bus, crc_addr, 4) == 1
        assert await csr_read(ctx, mac.bus, preamble_addr, 4) == 1

    sim.add_testbench(tb_rx)
    sim.add_testbench(tb_out)
    sim.run()
