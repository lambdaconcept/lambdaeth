#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2024 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2015 Sebastien Bourdeauducq <sb@m-labs.hk>
# Copyright (c) 2021 David Sawatzke <d-git@sawatzke.dev>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""IEEE 802.3 CRC32 engines, inserter and checker."""

import functools
import operator
from collections import Counter

from amaranth.hdl import Elaboratable, Module, Signal, Cat, ResetInserter
from amaranth.lib import wiring, fifo
from amaranth.lib.wiring import In, Out

from ..common import eth_phy_stream_signature, eff_last_be


__all__ = ["CRCEngine", "crc32_calc", "CRC32", "CRC32Check", "CRC32Inserter", "CRC32Checker"]


# CRC Engine ---------------------------------------------------------------------------------------

class CRCEngine(Elaboratable):
    """Cyclic Redundancy Check (CRC) engine using an asynchronous LFSR.

    Computes the next CRC value from the previous CRC value and ``data_width``
    bits of input data (LSB first), unrolled into pure combinational logic.

    Parameters
    ----------
    data_width : int
        Bit width of the data input.
    width : int
        Bit width of the CRC value.
    polynom : int
        CRC polynomial (e.g. 0x04C11DB7 for IEEE 802.3).

    Attributes
    ----------
    data : Signal(data_width), in
    crc_prev : Signal(width), in
    crc_next : Signal(width), out
    """
    def __init__(self, data_width, width, polynom):
        self.data_width = data_width
        self.width      = width
        self.polynom    = polynom

        self.data     = Signal(data_width)
        self.crc_prev = Signal(width)
        self.crc_next = Signal(width)

    @staticmethod
    def _optimize_xors(bits):
        """Keep only terms with an odd occurrence count (x ^ x == 0)."""
        return [bit for bit, count in Counter(bits).items() if count % 2 == 1]

    def elaborate(self, platform):
        m = Module()

        # Determine bits affected by the polynom.
        polynom_taps = [bit for bit in range(self.width) if (1 << bit) & self.polynom]

        # Derive the XOR terms of each output bit by symbolically shifting the LFSR.
        crc_bits = [[("state", i)] for i in range(self.width)]
        for n in range(self.data_width):
            feedback = crc_bits.pop(-1) + [("din", n)]
            for pos in range(self.width - 1):
                if (pos + 1) in polynom_taps:
                    crc_bits[pos] += feedback
                crc_bits[pos] = self._optimize_xors(crc_bits[pos])
            crc_bits.insert(0, feedback)

        for i in range(self.width):
            sources = []
            for t, n in crc_bits[i]:
                if t == "state":
                    sources.append(self.crc_prev[n])
                else:
                    sources.append(self.data[n])
            if sources:
                m.d.comb += self.crc_next[i].eq(functools.reduce(operator.xor, sources))
            else:
                m.d.comb += self.crc_next[i].eq(0)

        return m


def crc32_calc(data_width, width, polynom, crc_prev, data):
    """Software model of :class:`CRCEngine` (LSB-first LFSR step over one word)."""
    state = [(crc_prev >> i) & 1 for i in range(width)]

    for n in range(data_width):
        d = (data >> n) & 1
        feedback = state[-1] ^ d
        state.pop()
        for pos in range(width - 1):
            if (polynom >> (pos + 1)) & 1:
                state[pos] ^= feedback
        state.insert(0, feedback)

    crc_next = 0
    for i, bit in enumerate(state):
        if bit:
            crc_next |= (1 << i)
    return crc_next


# CRC32 Parameters ---------------------------------------------------------------------------------

CRC32_WIDTH   = 32
CRC32_POLYNOM = 0x04c11db7
CRC32_INIT    = 2**CRC32_WIDTH - 1
CRC32_CHECK   = 0xc704dd7b


# CRC32 Generator ----------------------------------------------------------------------------------

class CRC32(Elaboratable):
    """IEEE 802.3 CRC generator.

    One engine per byte lane allows the CRC value to be read for any number of
    valid bytes in the current word (selected by the one-hot ``be`` mask).

    Attributes
    ----------
    data : Signal(data_width), in
        Data input.
    be : Signal(data_width // 8), in
        One-hot mask selecting the last valid byte of ``data``. Must be
        non-zero for ``value``/``error`` to be meaningful.
    en : Signal, in
        Clock enable: accumulate ``data`` into the CRC register.
    clear : Signal, in
        Synchronous re-initialization of the CRC register (takes precedence
        over ``en``).
    value : Signal(32), out
        CRC value to append to the packet (bit-reversed, complemented).
    error : Signal, out
        CRC residue check result (for checker use).
    """
    def __init__(self, data_width):
        assert data_width % 8 == 0
        self.data_width = data_width

        self.data  = Signal(data_width)
        self.be    = Signal(data_width // 8)
        self.en    = Signal()
        self.clear = Signal()
        self.value = Signal(CRC32_WIDTH)
        self.error = Signal()

    def elaborate(self, platform):
        m = Module()

        # One engine per byte prefix: 8, 16, ... data_width bits.
        engines = []
        for n in range(self.data_width // 8):
            engine = CRCEngine(
                data_width = (n + 1)*8,
                width      = CRC32_WIDTH,
                polynom    = CRC32_POLYNOM,
            )
            m.submodules[f"engine{n}"] = engine
            engines.append(engine)

        reg = Signal(CRC32_WIDTH, init=CRC32_INIT)
        with m.If(self.clear):
            m.d.sync += reg.eq(CRC32_INIT)
        with m.Elif(self.en):
            m.d.sync += reg.eq(engines[-1].crc_next)

        for n, engine in enumerate(engines):
            m.d.comb += [
                engine.data.eq(self.data),
                engine.crc_prev.eq(reg),
            ]
            with m.If(self.be[n]):
                m.d.comb += [
                    self.value.eq(engine.crc_next[::-1] ^ CRC32_INIT),
                    self.error.eq(engine.crc_next != CRC32_CHECK),
                ]

        return m


# CRC32 Checker Engine -------------------------------------------------------------------------------

class CRC32Check(Elaboratable):
    """IEEE 802.3 CRC checker.

    Uses a single full-width engine; partial last words are handled by masking
    the invalid bytes to zero and comparing against the residue expected after
    the corresponding number of zero bytes.

    Attributes are the same as :class:`CRC32`, without ``value``.
    """
    def __init__(self, data_width):
        assert data_width % 8 == 0
        self.data_width = data_width

        self.data  = Signal(data_width)
        self.be    = Signal(data_width // 8)
        self.en    = Signal()
        self.clear = Signal()
        self.error = Signal()

    def elaborate(self, platform):
        m = Module()

        # Expected residues: check_be[k] is the residue after feeding k zero
        # bytes into an engine holding a valid residue.
        check_be = [CRC32_CHECK]
        for _ in range(1, self.data_width // 8):
            check_be.append(crc32_calc(8, CRC32_WIDTH, CRC32_POLYNOM, check_be[-1], 0))

        m.submodules.engine = engine = CRCEngine(
            data_width = self.data_width,
            width      = CRC32_WIDTH,
            polynom    = CRC32_POLYNOM,
        )

        reg = Signal(CRC32_WIDTH, init=CRC32_INIT)
        with m.If(self.clear):
            m.d.sync += reg.eq(CRC32_INIT)
        with m.Elif(self.en):
            m.d.sync += reg.eq(engine.crc_next)

        m.d.comb += [
            engine.data.eq(self.data),
            engine.crc_prev.eq(reg),
        ]
        for n in range(self.data_width // 8):
            with m.If(self.be[n]):
                m.d.comb += [
                    engine.data.eq(self.data & (2**((n + 1)*8) - 1)),
                    self.error.eq(engine.crc_next != check_be[-(n + 1)]),
                ]

        return m


# CRC32 Inserter -----------------------------------------------------------------------------------

class CRC32Inserter(wiring.Component):
    """Append the FCS at the end of each packet.

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
        Packet data without CRC.
    source : Out(eth_phy_stream_signature(data_width))
        Packet data with CRC.
    """
    def __init__(self, data_width):
        assert data_width in (8, 32)
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

        dw     = self.data_width
        nbytes = dw // 8
        ratio  = 32 // dw

        m.submodules.crc = crc = CRC32(dw)

        # Normalized last byte-enable (handles 8-bit producers driving only `last`).
        last_be = eff_last_be(m, sink)

        m.d.comb += [
            crc.data.eq(sink.p.data),
            crc.be.eq(last_be),
        ]

        crc_packet = Signal(CRC32_WIDTH)
        last_be_r  = Signal(nbytes)
        count      = Signal(range(max(ratio, 2)))

        with m.FSM():
            with m.State("IDLE"):
                m.d.comb += crc.clear.eq(1)
                m.d.sync += count.eq(0)
                with m.If(sink.valid):
                    m.next = "COPY"

            with m.State("COPY"):
                m.d.comb += [
                    crc.en.eq(sink.valid & source.ready),
                    source.valid.eq(sink.valid),
                    sink.ready.eq(source.ready),
                    source.first.eq(sink.first),
                    source.p.data.eq(sink.p.data),
                    source.p.error.eq(sink.p.error),
                    # last/last_be are suppressed: the packet now extends with the FCS.
                    source.last.eq(0),
                    source.p.last_be.eq(0),
                ]
                with m.If(sink.last):
                    # Fill the free space of the last data word with the
                    # beginning of the CRC value (only relevant for dw > 8).
                    for e in range(nbytes):
                        with m.If(last_be[e]):
                            m.d.comb += source.p.data.eq(
                                Cat(sink.p.data[:(e + 1)*8], crc.value)[:dw])
                with m.If(sink.valid & sink.last & source.ready):
                    m.d.sync += [
                        crc_packet.eq(crc.value),
                        last_be_r.eq(last_be),
                    ]
                    m.next = "CRC"

            with m.State("CRC"):
                if ratio > 1:
                    # Send the remaining CRC words one by one.
                    m.d.comb += [
                        source.valid.eq(1),
                        source.p.data.eq(crc_packet.word_select(count, dw)),
                    ]
                    with m.If(count == ratio - 1):
                        m.d.comb += [
                            source.last.eq(1),
                            source.p.last_be.eq(1 << (nbytes - 1)),
                        ]
                    with m.If(source.ready):
                        m.d.sync += count.eq(count + 1)
                        with m.If(count == ratio - 1):
                            m.d.sync += count.eq(0)
                            m.next = "IDLE"
                else:
                    # dw == 32: send the CRC bytes that did not fit in the last
                    # data word.
                    m.d.comb += [
                        source.valid.eq(1),
                        source.last.eq(1),
                        source.p.data.eq(crc_packet),
                        source.p.last_be.eq(last_be_r),
                    ]
                    for e in range(nbytes):
                        with m.If(last_be_r[e]):
                            m.d.comb += source.p.data.eq(crc_packet[-(e + 1)*8:])
                    with m.If(source.ready):
                        m.next = "IDLE"

        return m


# CRC32 Checker ------------------------------------------------------------------------------------

class CRC32Checker(wiring.Component):
    """Check and strip the FCS at the end of each packet.

    The last ``32 / data_width`` beats of a packet are held back in a small
    FIFO; when the packet ends they are discarded (they carry the FCS) and the
    check result is merged into the ``error`` mask of the last emitted beat.

    Packets shorter than the FCS are swallowed entirely (and flagged on
    ``error``).

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
        Packet data with CRC.
    source : Out(eth_phy_stream_signature(data_width))
        Packet data without CRC. On the last beat, ``error`` is all-ones when
        the CRC check failed.
    error : Out(1)
        Pulses once per packet with a wrong CRC.
    """
    def __init__(self, data_width):
        assert data_width in (8, 32)
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

        dw     = self.data_width
        nbytes = dw // 8
        ratio  = 32 // dw

        m.submodules.crc = crc = CRC32Check(dw)

        last_be = eff_last_be(m, sink)
        m.d.comb += [
            crc.data.eq(sink.p.data),
            crc.be.eq(last_be),
        ]

        # Delay FIFO: data + error + first, per beat. last/last_be are applied
        # from the live sink (i.e. `ratio` beats in advance).
        entry_width = dw + nbytes + 1
        fifo_reset  = Signal()
        m.submodules.fifo = delay_fifo = ResetInserter(fifo_reset)(
            fifo.SyncFIFO(width=entry_width, depth=ratio + 1))

        fifo_full = Signal()
        fifo_out  = Signal()
        fifo_in   = Signal()
        in_reset  = Signal()

        m.d.comb += [
            fifo_full.eq(delay_fifo.level == ratio),
            fifo_out.eq(source.valid & source.ready),
            fifo_in.eq(sink.valid & ~in_reset & (~fifo_full | fifo_out)),

            delay_fifo.w_data.eq(Cat(sink.p.data, sink.p.error, sink.first)),
            delay_fifo.w_en.eq(fifo_in),
            sink.ready.eq(fifo_in),
        ]

        fifo_data  = delay_fifo.r_data[:dw]
        fifo_error = delay_fifo.r_data[dw:dw + nbytes]
        fifo_first = delay_fifo.r_data[dw + nbytes]

        with m.FSM():
            with m.State("RESET"):
                m.d.comb += [
                    in_reset.eq(1),
                    crc.clear.eq(1),
                    fifo_reset.eq(1),
                ]
                m.next = "COPY"

            with m.State("COPY"):
                m.d.comb += [
                    delay_fifo.r_en.eq(fifo_out),
                    source.valid.eq(sink.valid & fifo_full),
                    source.p.data.eq(fifo_data),
                    source.first.eq(fifo_first),
                    source.last.eq(sink.last),
                    source.p.last_be.eq(sink.p.last_be),
                    # The CRC error applies to the whole packet; mark all bytes
                    # of the last emitted beat.
                    source.p.error.eq(fifo_error |
                                      (crc.error & sink.last).replicate(nbytes)),
                    self.error.eq(sink.valid & sink.ready & sink.last & crc.error),
                ]
                with m.If(sink.valid & sink.ready):
                    m.d.comb += crc.en.eq(1)
                    with m.If(sink.last):
                        m.next = "RESET"

        return m
