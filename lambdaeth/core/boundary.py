#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Adapter between the byte-wide UDP/IP core and a wider MACCore boundary.

TX goes through a store-and-forward packet FIFO at the MAC width so that the
MAC-side CDC is fed at line rate regardless of the (slower) byte-wide core:
a 32-bit boundary at 50 MHz sustains 1.6 Gbps bursts, above gigabit wire
speed, avoiding TX underruns that would corrupt frames on the wire.
"""

from amaranth.hdl import Module
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_stream import PacketFIFO

from ..common import eth_phy_stream_signature
from ..mac.converter import EthStreamConverter
from ..mac.last_be import TXLastBE
from .layouts import eth_stream_signature


__all__ = ["MACByteBoundary"]


class MACByteBoundary(wiring.Component):
    """Width/framing adapter between :class:`~lambdaeth.core.UDPIPCore` byte
    streams and a :class:`~lambdaeth.mac.MACCore` user boundary.

    Ports
    -----
    eth_tx : In(eth_stream_signature())
        Frames from the core (plain bytes).
    eth_rx : Out(eth_stream_signature())
        Frames to the core (plain bytes).
    mac_tx : Out(eth_phy_stream_signature(mac_dw))
        Connect to ``MACCore.sink``.
    mac_rx : In(eth_phy_stream_signature(mac_dw))
        Connect to ``MACCore.source``.
    """
    def __init__(self, mac_dw=32, tx_fifo_depth=512, tx_packet_depth=8):
        self.mac_dw          = mac_dw
        self.tx_fifo_depth   = tx_fifo_depth
        self.tx_packet_depth = tx_packet_depth
        super().__init__({
            "eth_tx": In(eth_stream_signature()),
            "eth_rx": Out(eth_stream_signature()),
            "mac_tx": Out(eth_phy_stream_signature(mac_dw)),
            "mac_rx": In(eth_phy_stream_signature(mac_dw)),
        })

    def elaborate(self, platform):
        m = Module()

        # TX: bytes -> eth_phy(8) -> eth_phy(mac_dw) -> packet FIFO -> MAC.
        m.submodules.tx_conv  = tx_conv  = EthStreamConverter(8, self.mac_dw)
        m.submodules.tx_pfifo = tx_pfifo = PacketFIFO(
            eth_phy_stream_signature(self.mac_dw),
            payload_depth = self.tx_fifo_depth,
            packet_depth  = self.tx_packet_depth)

        m.d.comb += [
            tx_conv.sink.valid.eq(self.eth_tx.valid),
            tx_conv.sink.p.data.eq(self.eth_tx.payload),
            tx_conv.sink.p.last_be.eq(self.eth_tx.last),
            tx_conv.sink.first.eq(self.eth_tx.first),
            tx_conv.sink.last.eq(self.eth_tx.last),
            self.eth_tx.ready.eq(tx_conv.sink.ready),
        ]
        connect(m, tx_conv.source, tx_pfifo.i_stream)
        connect(m, tx_pfifo.o_stream, flipped(self.mac_tx))

        # RX: MAC -> eth_phy(8) -> last_be termination -> bytes.
        m.submodules.rx_conv = rx_conv = EthStreamConverter(self.mac_dw, 8)
        m.submodules.rx_lb   = rx_lb   = TXLastBE(8)
        connect(m, flipped(self.mac_rx), rx_conv.sink)
        connect(m, rx_conv.source, rx_lb.sink)
        m.d.comb += [
            self.eth_rx.valid.eq(rx_lb.source.valid),
            self.eth_rx.payload.eq(rx_lb.source.p.data),
            self.eth_rx.first.eq(rx_lb.source.first),
            self.eth_rx.last.eq(rx_lb.source.last),
            rx_lb.source.ready.eq(self.eth_rx.ready),
        ]

        return m
