#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""UART -> Wishbone -> CSR bridge chain test."""

from amaranth.hdl import Module, Elaboratable
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from amaranth_soc import csr
from amaranth_soc.csr.wishbone import WishboneCSRBridge

from lambdaeth.soc import UARTWishboneBridge


DIVISOR = 8


class Regs(csr.Register, access="rw"):
    value: csr.Field(csr.action.RW, 32)


class MacReg(csr.Register, access="rw"):
    value: csr.Field(csr.action.RW, 48)


class DUT(Elaboratable):
    def __init__(self):
        regs = csr.Builder(addr_width=5, data_width=8)
        self.scratch = regs.add("scratch", Regs())
        self.mac     = regs.add("mac", MacReg())
        self.csr_bridge  = csr.Bridge(regs.as_memory_map())
        self.wb_bridge   = WishboneCSRBridge(self.csr_bridge.bus, data_width=32)
        self.uart_bridge = UARTWishboneBridge(
            addr_width=self.wb_bridge.wb_bus.addr_width, divisor=DIVISOR)
        self.memory_map  = self.csr_bridge.bus.memory_map

    def elaborate(self, platform):
        m = Module()
        m.submodules.csr_bridge  = self.csr_bridge
        m.submodules.wb_bridge   = self.wb_bridge
        m.submodules.uart_bridge = self.uart_bridge
        connect(m, self.uart_bridge.wb, self.wb_bridge.wb_bus)
        return m


async def uart_send(ctx, pin, byte):
    ctx.set(pin, 0)                       # Start bit.
    for _ in range(DIVISOR):
        await ctx.tick()
    for i in range(8):
        ctx.set(pin, (byte >> i) & 1)
        for _ in range(DIVISOR):
            await ctx.tick()
    ctx.set(pin, 1)                       # Stop bit.
    for _ in range(DIVISOR):
        await ctx.tick()


async def uart_recv(ctx, pin, timeout=200000):
    for _ in range(timeout):
        _clk, _rst, level = await ctx.tick().sample(pin)
        if not level:
            break
    else:
        raise TimeoutError("no start bit")
    # Sample mid-bit.
    for _ in range(DIVISOR // 2):
        await ctx.tick()
    byte = 0
    for i in range(8):
        for _ in range(DIVISOR):
            await ctx.tick()
        byte |= ctx.get(pin) << i
    for _ in range(DIVISOR):              # Stop bit.
        await ctx.tick()
    return byte


async def bridge_write32(ctx, dut, addr, value):
    for byte in b"W" + addr.to_bytes(4, "big") + value.to_bytes(4, "big"):
        await uart_send(ctx, dut.uart_bridge.rx_i, byte)
    assert await uart_recv(ctx, dut.uart_bridge.tx_o) == ord("w")


async def bridge_read32(ctx, dut, addr):
    for byte in b"R" + addr.to_bytes(4, "big"):
        await uart_send(ctx, dut.uart_bridge.rx_i, byte)
    assert await uart_recv(ctx, dut.uart_bridge.tx_o) == ord("r")
    value = 0
    for _ in range(4):
        value = (value << 8) | await uart_recv(ctx, dut.uart_bridge.tx_o)
    return value


def reg_addr(memory_map, name):
    for _reg, reg_name, (start, _end) in memory_map.resources():
        if name in reg_name:
            return start
    raise KeyError(name)


def test_uart_csr_bridge():
    dut = DUT()
    sim = Simulator(dut)
    sim.add_clock(1e-6)

    scratch_addr = reg_addr(dut.memory_map, "scratch")
    mac_addr     = reg_addr(dut.memory_map, "mac")

    async def tb(ctx):
        ctx.set(dut.uart_bridge.rx_i, 1)
        for _ in range(20):
            await ctx.tick()

        # Scratch write/read roundtrip over the full chain.
        await bridge_write32(ctx, dut, scratch_addr, 0xdeadbeef)
        assert await bridge_read32(ctx, dut, scratch_addr) == 0xdeadbeef
        assert ctx.get(dut.scratch.f.value.data) == 0xdeadbeef

        # 48-bit MAC register: two word accesses (little-endian CSR layout).
        mac = 0x024c45544800
        await bridge_write32(ctx, dut, mac_addr, mac & 0xffffffff)
        await bridge_write32(ctx, dut, mac_addr + 4, mac >> 32)
        assert ctx.get(dut.mac.f.value.data) == mac
        assert await bridge_read32(ctx, dut, mac_addr) == mac & 0xffffffff
        assert await bridge_read32(ctx, dut, mac_addr + 4) == mac >> 32

        # Garbage bytes are ignored; the protocol resynchronizes.
        for byte in b"\x00\xffXYZ":
            await uart_send(ctx, dut.uart_bridge.rx_i, byte)
        assert await bridge_read32(ctx, dut, scratch_addr) == 0xdeadbeef

    sim.add_testbench(tb)
    sim.run()
