#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2021 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2015-2017 Sebastien Bourdeauducq <sb@m-labs.hk>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Inter-packet gap insertion."""

import math

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out

from ..common import eth_phy_stream_signature, eth_interpacket_gap


__all__ = ["Gap"]


class Gap(wiring.Component):
    """Enforce the inter-packet gap by stalling the stream after each packet.

    Must run in the PHY TX clock domain so the gap is expressed in wire time.

    Parameters
    ----------
    data_width : int
        Stream data width.
    cycles : int or None
        Gap duration in cycles. Defaults to the standard 96 bit-times
        (``ceil(12 / (data_width // 8))`` cycles).

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
    source : Out(eth_phy_stream_signature(data_width))
    """
    def __init__(self, data_width, cycles=None):
        self.data_width = data_width
        if cycles is None:
            cycles = math.ceil(eth_interpacket_gap / (data_width // 8))
        assert cycles >= 1
        self.cycles = cycles
        sig = eth_phy_stream_signature(data_width)
        super().__init__({
            "sink":   In(sig),
            "source": Out(sig),
        })

    def elaborate(self, platform):
        m = Module()

        sink   = self.sink
        source = self.source

        counter = Signal(range(self.cycles + 1))

        with m.FSM():
            with m.State("COPY"):
                m.d.comb += [
                    source.valid.eq(sink.valid),
                    sink.ready.eq(source.ready),
                    source.first.eq(sink.first),
                    source.last.eq(sink.last),
                    source.p.eq(sink.p),
                ]
                with m.If(sink.valid & sink.last & sink.ready):
                    m.d.sync += counter.eq(self.cycles)
                    m.next = "GAP"

            with m.State("GAP"):
                m.d.sync += counter.eq(counter - 1)
                with m.If(counter == 1):
                    m.next = "COPY"

        return m
