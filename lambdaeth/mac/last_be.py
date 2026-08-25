#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2024 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2015 Sebastien Bourdeauducq <sb@m-labs.hk>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""``last``/``last_be`` adaptation around width converters."""

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out

from ..common import eth_phy_stream_signature


__all__ = ["TXLastBE", "RXLastBE"]


class TXLastBE(wiring.Component):
    """Terminate a down-converted packet at the beat carrying ``last_be``.

    A down-converter emits all sub-beats of the final word and asserts ``last``
    only on the final one; the beat holding the true end of packet is the one
    with a non-zero ``last_be``. This component re-asserts ``last`` on that
    beat and discards the remaining sub-beats.

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
    source : Out(eth_phy_stream_signature(data_width))
    """
    def __init__(self, data_width):
        self.data_width = data_width
        sig = eth_phy_stream_signature(data_width)
        super().__init__({
            "sink":   In(sig),
            "source": Out(sig),
        })

    def elaborate(self, platform):
        m = Module()

        sink   = self.sink
        source = self.source

        with m.FSM():
            with m.State("COPY"):
                m.d.comb += [
                    source.valid.eq(sink.valid),
                    sink.ready.eq(source.ready),
                    source.first.eq(sink.first),
                    source.p.eq(sink.p),
                    source.last.eq(sink.p.last_be != 0),
                ]
                with m.If(sink.valid & sink.ready):
                    # Last byte seen but the packet token is still to come:
                    # discard the remaining sub-beats.
                    with m.If(source.last & ~sink.last):
                        m.next = "WAIT-LAST"

            with m.State("WAIT-LAST"):
                m.d.comb += sink.ready.eq(1)
                with m.If(sink.valid & sink.last):
                    m.next = "COPY"

        return m


class RXLastBE(wiring.Component):
    """Qualify ``last_be`` for 8-bit PHYs which only drive ``last``.

    For wider data widths this is a pass-through (the PHY must drive
    ``last_be`` itself).

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
    source : Out(eth_phy_stream_signature(data_width))
    """
    def __init__(self, data_width):
        self.data_width = data_width
        sig = eth_phy_stream_signature(data_width)
        super().__init__({
            "sink":   In(sig),
            "source": Out(sig),
        })

    def elaborate(self, platform):
        m = Module()

        sink   = self.sink
        source = self.source

        m.d.comb += [
            source.valid.eq(sink.valid),
            sink.ready.eq(source.ready),
            source.first.eq(sink.first),
            source.last.eq(sink.last),
            source.p.eq(sink.p),
        ]
        if self.data_width == 8:
            m.d.comb += source.p.last_be.eq(sink.last)

        return m
