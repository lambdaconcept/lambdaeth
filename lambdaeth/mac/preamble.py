#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2021 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2021 David Sawatzke <d-git@sawatzke.dev>
# Copyright (c) 2015-2017 Sebastien Bourdeauducq <sb@m-labs.hk>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Ethernet preamble insertion/checking."""

from amaranth.hdl import Module, Signal, Const
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out

from ..common import eth_phy_stream_signature, eth_preamble


__all__ = ["PreambleInserter", "PreambleChecker"]


class PreambleInserter(wiring.Component):
    """Insert the preamble and SFD at the beginning of each packet.

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
        Packet octets.
    source : Out(eth_phy_stream_signature(data_width))
        Preamble, SFD and packet octets.
    """
    def __init__(self, data_width):
        assert data_width in (8, 16, 32, 64)
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

        dw    = self.data_width
        beats = 64 // dw

        preamble = Const(eth_preamble, 64)
        count    = Signal(range(max(beats, 2)))

        with m.FSM():
            with m.State("IDLE"):
                m.d.sync += count.eq(0)
                with m.If(sink.valid):
                    m.next = "PREAMBLE"

            with m.State("PREAMBLE"):
                m.d.comb += [
                    source.valid.eq(1),
                    source.first.eq(count == 0),
                    source.p.data.eq(preamble.word_select(count, dw)),
                ]
                with m.If(source.ready):
                    with m.If(count == beats - 1):
                        m.next = "COPY"
                    with m.Else():
                        m.d.sync += count.eq(count + 1)

            with m.State("COPY"):
                m.d.comb += [
                    source.valid.eq(sink.valid),
                    sink.ready.eq(source.ready),
                    source.p.eq(sink.p),
                    source.last.eq(sink.last),
                ]
                with m.If(sink.valid & sink.last & source.ready):
                    m.next = "IDLE"

        return m


class PreambleChecker(wiring.Component):
    """Detect and strip the preamble at the beginning of each packet.

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
        Raw octets from the PHY.
    source : Out(eth_phy_stream_signature(data_width))
        Packet octets starting immediately after the SFD.
    error : Out(1)
        Pulses each time a preamble error is detected (packet ended while
        hunting for the SFD).
    """
    def __init__(self, data_width):
        assert data_width in (8, 16, 32, 64)
        self.data_width = data_width
        sig = eth_phy_stream_signature(data_width)
        super().__init__({
            "sink":   In(sig),
            "source": Out(sig),
            "error":  Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        sink   = self.sink
        source = self.source

        dw = self.data_width

        preamble = Const(eth_preamble, 64)
        is_first = Signal()

        with m.FSM():
            with m.State("PREAMBLE"):
                m.d.comb += sink.ready.eq(1)
                m.d.sync += is_first.eq(1)
                # Match the end of the preamble (SFD).
                with m.If(sink.valid & ~sink.last & (sink.p.data == preamble[-dw:])):
                    m.next = "COPY"
                with m.If(sink.valid & sink.last):
                    m.d.comb += self.error.eq(1)

            with m.State("COPY"):
                m.d.comb += [
                    source.valid.eq(sink.valid),
                    sink.ready.eq(source.ready),
                    source.p.eq(sink.p),
                    source.first.eq(is_first),
                    source.last.eq(sink.last),
                ]
                with m.If(source.valid & source.ready):
                    m.d.sync += is_first.eq(0)
                    with m.If(source.last):
                        m.next = "PREAMBLE"

        return m
