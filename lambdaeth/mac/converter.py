#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Field-aware width conversion for ``eth_phy`` streams.

The generic ``amaranth_stream`` converters pack the raw payload bits of a
whole beat, which would interleave the ``data``/``last_be``/``error`` fields.
Ethernet datapaths need each field converted separately (data bytes packed
together, per-byte masks packed together), which is what
:class:`EthStreamConverter` implements.
"""

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect, flipped

from ..common import eth_phy_stream_signature, eff_last_be


__all__ = ["EthStreamConverter"]


class EthStreamConverter(wiring.Component):
    """Integer-ratio width converter for ``eth_phy`` streams.

    Up-conversion packs ``ratio`` narrow beats into one wide beat; an early
    ``last`` flushes immediately (missing bytes are zeroed, ``last_be`` marks
    the true end). Down-conversion emits all sub-beats of each wide beat with
    ``last`` on the final sub-beat and ``last_be``/``error`` bits distributed;
    chain a :class:`~lambdaeth.mac.last_be.TXLastBE` downstream to terminate
    the packet at the beat carrying ``last_be``.

    Ports
    -----
    sink : In(eth_phy_stream_signature(i_width))
    source : Out(eth_phy_stream_signature(o_width))
    """
    def __init__(self, i_width, o_width):
        assert i_width % 8 == 0 and o_width % 8 == 0
        if max(i_width, o_width) % min(i_width, o_width) != 0:
            raise ValueError(f"Width ratio must be an integer ({i_width} <-> {o_width})")
        self.i_width = i_width
        self.o_width = o_width
        super().__init__({
            "sink":   In(eth_phy_stream_signature(i_width)),
            "source": Out(eth_phy_stream_signature(o_width)),
        })

    def elaborate(self, platform):
        m = Module()

        if self.i_width == self.o_width:
            connect(m, flipped(self.sink), flipped(self.source))
            return m
        if self.o_width > self.i_width:
            return self._elaborate_up(m)
        return self._elaborate_down(m)

    # -- Up-conversion (narrow -> wide) ----------------------------------------------------------

    def _elaborate_up(self, m):
        sink   = self.sink
        source = self.source

        ratio    = self.o_width // self.i_width
        i_nbytes = self.i_width // 8

        last_be = eff_last_be(m, sink)

        sel       = Signal(range(ratio))
        buf_data  = Signal(self.o_width)
        buf_lbe   = Signal(self.o_width // 8)
        buf_error = Signal(self.o_width // 8)
        buf_first = Signal()
        buf_last  = Signal()
        out_valid = Signal()

        m.d.comb += [
            sink.ready.eq(~out_valid | source.ready),
            source.valid.eq(out_valid),
            source.p.data.eq(buf_data),
            source.p.last_be.eq(buf_lbe),
            source.p.error.eq(buf_error),
            source.first.eq(buf_first),
            source.last.eq(buf_last),
        ]

        # Output beat consumed.
        with m.If(source.valid & source.ready):
            m.d.sync += out_valid.eq(0)

        # Input beat accepted (overrides the clear above when both happen).
        with m.If(sink.valid & sink.ready):
            with m.If(sel == 0):
                # Start of a new output word: clear stale segments.
                m.d.sync += [
                    buf_data.eq(0),
                    buf_lbe.eq(0),
                    buf_error.eq(0),
                    buf_first.eq(sink.first),
                ]
            for i in range(ratio):
                with m.If(sel == i):
                    m.d.sync += [
                        buf_data.word_select(i, self.i_width).eq(sink.p.data),
                        buf_error.word_select(i, i_nbytes).eq(sink.p.error),
                    ]
                    with m.If(sink.last):
                        m.d.sync += buf_lbe.word_select(i, i_nbytes).eq(last_be)
            with m.If(sink.last | (sel == ratio - 1)):
                m.d.sync += [
                    out_valid.eq(1),
                    buf_last.eq(sink.last),
                    sel.eq(0),
                ]
            with m.Else():
                m.d.sync += sel.eq(sel + 1)

        return m

    # -- Down-conversion (wide -> narrow) --------------------------------------------------------

    def _elaborate_down(self, m):
        sink   = self.sink
        source = self.source

        ratio    = self.i_width // self.o_width
        o_nbytes = self.o_width // 8

        last_be = eff_last_be(m, sink)

        sel       = Signal(range(ratio))
        buf_data  = Signal(self.i_width)
        buf_lbe   = Signal(self.i_width // 8)
        buf_error = Signal(self.i_width // 8)
        buf_first = Signal()
        buf_last  = Signal()
        have      = Signal()

        last_sub = sel == ratio - 1

        m.d.comb += [
            sink.ready.eq(~have | (source.ready & last_sub)),
            source.valid.eq(have),
            source.p.data.eq(buf_data.word_select(sel, self.o_width)),
            source.p.last_be.eq(buf_lbe.word_select(sel, o_nbytes)),
            source.p.error.eq(buf_error.word_select(sel, o_nbytes)),
            source.first.eq(buf_first & (sel == 0)),
            source.last.eq(buf_last & last_sub),
        ]

        with m.If(source.valid & source.ready):
            m.d.sync += sel.eq(sel + 1)
            with m.If(last_sub):
                m.d.sync += [
                    have.eq(0),
                    sel.eq(0),
                ]

        # Latch a new wide beat (overrides the clear above when both happen).
        with m.If(sink.valid & sink.ready):
            m.d.sync += [
                buf_data.eq(sink.p.data),
                buf_lbe.eq(last_be),
                buf_error.eq(sink.p.error),
                buf_first.eq(sink.first),
                buf_last.eq(sink.last),
                have.eq(1),
                sel.eq(0),
            ]

        return m
