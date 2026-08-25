#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2021 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2021 David Sawatzke <d-git@sawatzke.dev>
# Copyright (c) 2015 Sebastien Bourdeauducq <sb@m-labs.hk>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Minimum-frame padding insertion/checking."""

import math

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out

from ..common import eth_phy_stream_signature, eth_mtu_default, eff_last_be


__all__ = ["PaddingInserter", "PaddingChecker"]


class PaddingInserter(wiring.Component):
    """Pad packets to a minimum length of ``padding`` bytes.

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
    source : Out(eth_phy_stream_signature(data_width))
    """
    def __init__(self, data_width, padding):
        assert data_width in (8, 16, 32, 64)
        self.data_width = data_width
        self.padding    = padding
        sig = eth_phy_stream_signature(data_width)
        super().__init__({
            "sink":   In(sig),
            "source": Out(sig),
        })

    def elaborate(self, platform):
        m = Module()

        sink   = self.sink
        source = self.source

        dw     = self.data_width
        nbytes = dw // 8

        # Beat index of the last beat required to reach `padding` bytes, and
        # the byte-enable of the final valid byte within it.
        padding_limit = math.ceil(self.padding / nbytes) - 1
        pad_last_be   = 1 << ((self.padding - 1) % nbytes)

        last_be = eff_last_be(m, sink)

        counter      = Signal(16)
        counter_done = Signal()
        m.d.comb += counter_done.eq(counter >= padding_limit)

        with m.FSM():
            with m.State("COPY"):
                m.d.comb += [
                    source.valid.eq(sink.valid),
                    sink.ready.eq(source.ready),
                    source.first.eq(sink.first),
                    source.last.eq(sink.last),
                    source.p.eq(sink.p),
                ]
                with m.If(source.valid & source.ready):
                    m.d.sync += counter.eq(counter + 1)
                    with m.If(sink.last):
                        with m.If(~counter_done):
                            # Packet too short: suppress last and start padding.
                            m.d.comb += [
                                source.last.eq(0),
                                source.p.last_be.eq(0),
                            ]
                            m.next = "PADDING"
                        with m.Elif((counter == padding_limit) &
                                    (pad_last_be > last_be)):
                            # Right amount of beats but too few bytes in the
                            # last one: extend it with the (zero) pad bytes.
                            m.d.comb += source.p.last_be.eq(pad_last_be)
                            m.d.sync += counter.eq(0)
                        with m.Else():
                            m.d.sync += counter.eq(0)

            with m.State("PADDING"):
                m.d.comb += [
                    source.valid.eq(1),
                    source.p.data.eq(0),
                ]
                with m.If(counter_done):
                    m.d.comb += [
                        source.p.last_be.eq(pad_last_be),
                        source.last.eq(1),
                    ]
                with m.If(source.valid & source.ready):
                    m.d.sync += counter.eq(counter + 1)
                    with m.If(counter_done):
                        m.d.sync += counter.eq(0)
                        m.next = "COPY"

        return m


class PaddingChecker(wiring.Component):
    """Flag packets shorter than ``packet_min_length`` bytes.

    The packet is not dropped here; its last beat is marked with an all-ones
    ``error`` mask so that downstream logic can discard it.

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
    source : Out(eth_phy_stream_signature(data_width))
    """
    def __init__(self, data_width, packet_min_length, eth_mtu=eth_mtu_default):
        assert data_width in (8, 16, 32, 64)
        self.data_width        = data_width
        self.packet_min_length = packet_min_length
        self.eth_mtu           = eth_mtu
        sig = eth_phy_stream_signature(data_width)
        super().__init__({
            "sink":   In(sig),
            "source": Out(sig),
        })

    def elaborate(self, platform):
        m = Module()

        sink   = self.sink
        source = self.source

        dw     = self.data_width
        nbytes = dw // 8

        length     = Signal(range(self.eth_mtu))
        length_inc = Signal(range(nbytes + 1))

        # Decode the length increment from last_be (full word by default,
        # which also covers non-last beats and 8-bit producers driving only
        # `last`).
        m.d.comb += length_inc.eq(nbytes)
        for i in range(nbytes):
            with m.If(sink.p.last_be == (1 << i)):
                m.d.comb += length_inc.eq(i + 1)

        with m.If(sink.valid & sink.ready):
            with m.If(sink.last):
                m.d.sync += length.eq(0)
            with m.Else():
                m.d.sync += length.eq(length + length_inc)

        m.d.comb += [
            source.valid.eq(sink.valid),
            sink.ready.eq(source.ready),
            source.first.eq(sink.first),
            source.last.eq(sink.last),
            source.p.data.eq(sink.p.data),
            source.p.last_be.eq(sink.p.last_be),
            source.p.error.eq(sink.p.error),
        ]
        with m.If(sink.valid & sink.last &
                  ((length + length_inc) < self.packet_min_length)):
            m.d.comb += source.p.error.eq(-1)

        return m
