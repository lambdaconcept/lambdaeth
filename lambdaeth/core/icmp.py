#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""ICMP echo (ping) responder.

Echo requests are answered by replaying the buffered payload with
``msgtype`` rewritten to echo-reply and the ICMP checksum incrementally
updated (RFC 1624: only the type byte changes, so ``csum' = csum + 0x0800``
with end-around carry).

Limitations: only echo requests are handled (other ICMP types are dropped),
zero-length echo data is not answered (a stream packet needs at least one
beat), and requests larger than the buffer are dropped.
"""

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect

from amaranth_stream import Packetizer, Depacketizer, PacketFIFO

from .layouts import (eth_stream_signature, icmp_header_layout, bswap,
                      ICMP_HEADER_LEN, IPV4_PROTOCOL_ICMP,
                      ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_REPLY)


__all__ = ["ICMPEcho"]


class ICMPEcho(wiring.Component):
    """Buffered ICMP echo responder (one request in flight).

    Sits on an IP protocol port: ``sink`` carries the IP payload of received
    ICMP packets (with ``src_ip``/``ip_length`` metadata from the IP RX
    layer), ``source`` carries the reply with metadata for the IP TX layer.
    """
    def __init__(self, fifo_depth=2048):
        self.fifo_depth = fifo_depth
        super().__init__({
            "sink":      In(eth_stream_signature()),
            "src_ip":    In(32),
            "ip_length": In(16),
            "protocol":  In(8),
            "source":    Out(eth_stream_signature()),
            "dst_ip":    Out(32),
            "length":    Out(16),
            "out_protocol": Out(8),
            "echo_pkt":  Out(1),   # Pulse: echo reply completed.
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.depacketizer = depack = Depacketizer(
            icmp_header_layout, eth_stream_signature())
        m.submodules.packetizer = pack = Packetizer(
            icmp_header_layout, eth_stream_signature())
        m.submodules.fifo = fifo = PacketFIFO(
            eth_stream_signature(), payload_depth=self.fifo_depth, packet_depth=2)

        hdr = depack.header

        # Latched request state (single request in flight).
        pending  = Signal()
        peer_ip  = Signal(32)
        quench   = Signal(32)
        checksum = Signal(16)    # Natural byte order.
        data_len = Signal(16)    # Echo data length (after the ICMP header).
        count    = Signal(16)

        # RFC 1624 incremental checksum update for msgtype 8 -> 0.
        csum_adj = Signal(17)
        csum_new = Signal(16)
        m.d.comb += [
            csum_adj.eq(checksum + 0x0800),
            csum_new.eq(csum_adj[:16] + csum_adj[16]),
        ]

        # Reply header and metadata.
        m.d.comb += [
            pack.header.msgtype.eq(ICMP_TYPE_ECHO_REPLY),
            pack.header.code.eq(0),
            pack.header.checksum.eq(bswap(csum_new)),
            pack.header.quench.eq(quench),          # Opaque passthrough.
            self.dst_ip.eq(peer_ip),
            self.length.eq(data_len + ICMP_HEADER_LEN),
            self.out_protocol.eq(IPV4_PROTOCOL_ICMP),
        ]

        rx_data_len = Signal(16)
        m.d.comb += rx_data_len.eq(self.ip_length - ICMP_HEADER_LEN)

        # RX: header -> validate -> trim into the FIFO ------------------------------------------
        with m.FSM(name="rx_fsm"):
            with m.State("IDLE"):
                with m.If(self.sink.valid):
                    with m.If(self.protocol == IPV4_PROTOCOL_ICMP):
                        m.next = "HEADER"
                    with m.Else():
                        m.next = "DROP_SINK"

            with m.State("HEADER"):
                m.d.comb += [
                    depack.i_stream.valid.eq(self.sink.valid),
                    depack.i_stream.payload.eq(self.sink.payload),
                    depack.i_stream.first.eq(self.sink.first),
                    depack.i_stream.last.eq(self.sink.last),
                    self.sink.ready.eq(depack.i_stream.ready),
                ]
                with m.If(depack.o_stream.valid):
                    m.d.sync += [
                        peer_ip.eq(self.src_ip),
                        quench.eq(hdr.quench),
                        checksum.eq(bswap(hdr.checksum)),
                        data_len.eq(rx_data_len),
                        count.eq(0),
                    ]
                    with m.If((hdr.msgtype == ICMP_TYPE_ECHO_REQUEST) &
                              (hdr.code == 0) &
                              ~pending &
                              (rx_data_len != 0) &
                              (rx_data_len <= self.fifo_depth)):
                        m.next = "RECEIVE"
                    with m.Else():
                        m.next = "DROP"
                with m.Elif(self.sink.valid & self.sink.ready & self.sink.last):
                    # Runt: the depacketizer resynchronized; so do we.
                    m.next = "IDLE"

            with m.State("RECEIVE"):
                m.d.comb += [
                    depack.i_stream.valid.eq(self.sink.valid),
                    depack.i_stream.payload.eq(self.sink.payload),
                    depack.i_stream.first.eq(self.sink.first),
                    depack.i_stream.last.eq(self.sink.last),
                    self.sink.ready.eq(depack.i_stream.ready),

                    fifo.i_stream.valid.eq(depack.o_stream.valid),
                    fifo.i_stream.payload.eq(depack.o_stream.payload),
                    fifo.i_stream.first.eq(count == 0),
                    fifo.i_stream.last.eq(depack.o_stream.last |
                                          (count == data_len - 1)),
                    depack.o_stream.ready.eq(fifo.i_stream.ready),
                ]
                with m.If(fifo.i_stream.valid & fifo.i_stream.ready):
                    m.d.sync += count.eq(count + 1)
                    with m.If(depack.o_stream.last):
                        # Frame ended (possibly truncated): reply anyway with
                        # what was buffered.
                        m.d.sync += [pending.eq(1), data_len.eq(count + 1)]
                        m.next = "IDLE"
                    with m.Elif(fifo.i_stream.last):
                        # Echo data complete; discard the frame padding.
                        m.d.sync += pending.eq(1)
                        m.next = "DROP"

            with m.State("DROP"):
                m.d.comb += [
                    depack.i_stream.valid.eq(self.sink.valid),
                    depack.i_stream.payload.eq(self.sink.payload),
                    depack.i_stream.first.eq(self.sink.first),
                    depack.i_stream.last.eq(self.sink.last),
                    self.sink.ready.eq(depack.i_stream.ready),
                    depack.o_stream.ready.eq(1),
                ]
                with m.If(depack.o_stream.valid & depack.o_stream.last):
                    m.next = "IDLE"

            with m.State("DROP_SINK"):
                m.d.comb += self.sink.ready.eq(1)
                with m.If(self.sink.valid & self.sink.last):
                    m.next = "IDLE"

        # TX: replay the buffered payload with the reply header ---------------------------------
        with m.FSM(name="tx_fsm"):
            with m.State("IDLE"):
                with m.If(pending & (fifo.packet_count != 0)):
                    m.next = "SEND"

            with m.State("SEND"):
                m.d.comb += [
                    pack.i_stream.valid.eq(fifo.o_stream.valid),
                    pack.i_stream.payload.eq(fifo.o_stream.payload),
                    pack.i_stream.first.eq(fifo.o_stream.first),
                    pack.i_stream.last.eq(fifo.o_stream.last),
                    fifo.o_stream.ready.eq(pack.i_stream.ready),

                    self.source.valid.eq(pack.o_stream.valid),
                    self.source.payload.eq(pack.o_stream.payload),
                    self.source.first.eq(pack.o_stream.first),
                    self.source.last.eq(pack.o_stream.last),
                    pack.o_stream.ready.eq(self.source.ready),
                ]
                with m.If(fifo.o_stream.valid & fifo.o_stream.ready &
                          fifo.o_stream.last):
                    m.d.comb += self.echo_pkt.eq(1)
                    m.d.sync += pending.eq(0)
                    m.next = "IDLE"

        return m
