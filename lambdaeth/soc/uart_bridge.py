#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""UART-to-Wishbone bridge.

Drives a 32-bit Wishbone initiator from a simple byte protocol on a UART,
allowing a host to access CSRs (through e.g.
:class:`amaranth_soc.csr.wishbone.WishboneCSRBridge`).

Protocol (all multi-byte values big-endian, addresses in bytes):

* Write: ``'W' A3 A2 A1 A0 D3 D2 D1 D0``  ->  response ``'w'``
* Read:  ``'R' A3 A2 A1 A0``              ->  response ``'r' D3 D2 D1 D0``

Unknown command bytes are ignored, so the host can resynchronize by pausing
and retrying. Addresses are word-aligned (the two LSBs are dropped); writes
use full word selects.

See ``scripts/csrctl.py`` for the host side.
"""

from amaranth.hdl import Module, Signal, Cat
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out

from amaranth_soc import wishbone

from .serial import AsyncSerialRX, AsyncSerialTX


__all__ = ["UARTWishboneBridge"]


CMD_WRITE  = ord("W")
CMD_READ   = ord("R")
RESP_WRITE = ord("w")
RESP_READ  = ord("r")


class UARTWishboneBridge(wiring.Component):
    """UART-driven Wishbone initiator.

    Parameters
    ----------
    addr_width : int
        Wishbone address width (word addresses).
    divisor : int
        UART clock divisor (``round(clk_freq / baudrate)``).

    Ports
    -----
    rx_i : In(1), tx_o : Out(1)
        UART pins.
    wb : Out(wishbone.Signature)
        32-bit Wishbone initiator (granularity 8).
    """
    def __init__(self, *, addr_width, divisor):
        self.divisor = divisor
        super().__init__({
            "rx_i": In(1, init=1),
            "tx_o": Out(1, init=1),
            "wb":   Out(wishbone.Signature(addr_width=addr_width, data_width=32,
                                           granularity=8)),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.uart_rx = uart_rx = AsyncSerialRX(divisor=self.divisor)
        m.submodules.uart_tx = uart_tx = AsyncSerialTX(divisor=self.divisor)
        m.d.comb += [
            uart_rx.i.eq(self.rx_i),
            self.tx_o.eq(uart_tx.o),
            uart_rx.ack.eq(1),  # Always accept received bytes.
        ]

        wb = self.wb

        is_write = Signal()
        addr     = Signal(32)
        data     = Signal(32)
        count    = Signal(range(5))

        rx_stb  = Signal()
        rx_data = Signal(8)
        m.d.comb += [
            rx_stb.eq(uart_rx.rdy),
            rx_data.eq(uart_rx.data),
        ]

        m.d.comb += [
            wb.adr.eq(addr[2:]),
            wb.dat_w.eq(data),
            wb.sel.eq(0b1111),
            wb.we.eq(is_write),
        ]

        with m.FSM():
            with m.State("CMD"):
                with m.If(rx_stb):
                    m.d.sync += count.eq(0)
                    with m.If(rx_data == CMD_WRITE):
                        m.d.sync += is_write.eq(1)
                        m.next = "ADDR"
                    with m.Elif(rx_data == CMD_READ):
                        m.d.sync += is_write.eq(0)
                        m.next = "ADDR"

            with m.State("ADDR"):
                with m.If(rx_stb):
                    m.d.sync += [
                        addr.eq(Cat(rx_data, addr[:24])),
                        count.eq(count + 1),
                    ]
                    with m.If(count == 3):
                        m.d.sync += count.eq(0)
                        with m.If(is_write):
                            m.next = "DATA"
                        with m.Else():
                            m.next = "BUS"

            with m.State("DATA"):
                with m.If(rx_stb):
                    m.d.sync += [
                        data.eq(Cat(rx_data, data[:24])),
                        count.eq(count + 1),
                    ]
                    with m.If(count == 3):
                        m.d.sync += count.eq(0)
                        m.next = "BUS"

            with m.State("BUS"):
                m.d.comb += [
                    wb.cyc.eq(1),
                    wb.stb.eq(1),
                ]
                with m.If(wb.ack):
                    m.d.sync += data.eq(wb.dat_r)
                    m.next = "RESP"

            with m.State("RESP"):
                with m.If(is_write):
                    m.d.comb += uart_tx.data.eq(RESP_WRITE)
                with m.Else():
                    m.d.comb += uart_tx.data.eq(RESP_READ)
                m.d.comb += uart_tx.ack.eq(uart_tx.rdy)
                with m.If(uart_tx.rdy):
                    m.d.sync += count.eq(0)
                    with m.If(is_write):
                        m.next = "CMD"
                    with m.Else():
                        m.next = "RDATA"

            with m.State("RDATA"):
                # Send read data, big-endian.
                byte = Signal(8)
                with m.Switch(count):
                    for i in range(4):
                        with m.Case(i):
                            m.d.comb += byte.eq(data[8*(3 - i):8*(4 - i)])
                m.d.comb += [
                    uart_tx.data.eq(byte),
                    uart_tx.ack.eq(uart_tx.rdy),
                ]
                with m.If(uart_tx.rdy):
                    m.d.sync += count.eq(count + 1)
                    with m.If(count == 3):
                        m.next = "CMD"

        return m
