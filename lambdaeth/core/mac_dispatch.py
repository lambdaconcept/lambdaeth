#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Ethernet (MAC-level) dispatch: header insertion/stripping, ethertype demux
and TX arbitration between the ARP and IP layers."""

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_stream import Packetizer, Depacketizer

from .layouts import (eth_stream_signature, mac_header_layout, bswap,
                      ETHERTYPE_ARP, ETHERTYPE_IPV4, BROADCAST_MAC)


__all__ = ["MACDispatch"]


class MACDispatch(wiring.Component):
    """RX: strip the Ethernet header, filter on destination MAC and route by
    ethertype. TX: arbitrate ARP/IP packets and insert the Ethernet header.

    ``arp_tx_mac``/``ip_tx_mac`` carry the destination MAC of the packet
    currently offered on the corresponding sink (held during the packet).
    """
    def __init__(self):
        super().__init__({
            # MAC boundary (plain byte streams, no preamble/FCS).
            "rx":          In(eth_stream_signature()),
            "tx":          Out(eth_stream_signature()),
            # ARP layer.
            "arp_rx":      Out(eth_stream_signature()),
            "arp_tx":      In(eth_stream_signature()),
            "arp_tx_mac":  In(48),
            # IP layer.
            "ip_rx":       Out(eth_stream_signature()),
            "ip_tx":       In(eth_stream_signature()),
            "ip_tx_mac":   In(48),
            # Configuration.
            "mac_address": In(48),
        })

    def elaborate(self, platform):
        m = Module()

        # RX: depacketize + route --------------------------------------------------------------
        m.submodules.depacketizer = depack = Depacketizer(
            mac_header_layout, eth_stream_signature())
        connect(m, flipped(self.rx), depack.i_stream)

        hdr        = depack.header
        mac_match  = Signal()
        m.d.comb += mac_match.eq(
            (bswap(hdr.target_mac) == self.mac_address) |
            (hdr.target_mac == BROADCAST_MAC))

        with m.FSM(name="rx_fsm"):
            with m.State("IDLE"):
                with m.If(depack.o_stream.valid):
                    with m.If(~mac_match):
                        m.next = "DROP"
                    with m.Elif(hdr.ethernet_type == bswap(ETHERTYPE_ARP, 16)):
                        m.next = "ARP"
                    with m.Elif(hdr.ethernet_type == bswap(ETHERTYPE_IPV4, 16)):
                        m.next = "IP"
                    with m.Else():
                        m.next = "DROP"

            with m.State("ARP"):
                m.d.comb += [
                    self.arp_rx.valid.eq(depack.o_stream.valid),
                    self.arp_rx.payload.eq(depack.o_stream.payload),
                    self.arp_rx.first.eq(depack.o_stream.first),
                    self.arp_rx.last.eq(depack.o_stream.last),
                    depack.o_stream.ready.eq(self.arp_rx.ready),
                ]
                with m.If(depack.o_stream.valid & depack.o_stream.ready &
                          depack.o_stream.last):
                    m.next = "IDLE"

            with m.State("IP"):
                m.d.comb += [
                    self.ip_rx.valid.eq(depack.o_stream.valid),
                    self.ip_rx.payload.eq(depack.o_stream.payload),
                    self.ip_rx.first.eq(depack.o_stream.first),
                    self.ip_rx.last.eq(depack.o_stream.last),
                    depack.o_stream.ready.eq(self.ip_rx.ready),
                ]
                with m.If(depack.o_stream.valid & depack.o_stream.ready &
                          depack.o_stream.last):
                    m.next = "IDLE"

            with m.State("DROP"):
                m.d.comb += depack.o_stream.ready.eq(1)
                with m.If(depack.o_stream.valid & depack.o_stream.last):
                    m.next = "IDLE"

        # TX: arbitrate + packetize ------------------------------------------------------------
        # Note: the packetizer free-runs (it offers header beats whenever its
        # output is ready), so its output is only connected to `tx` while a
        # packet is granted.
        m.submodules.packetizer = pack = Packetizer(
            mac_header_layout, eth_stream_signature())

        tx_connect = Signal()
        with m.If(tx_connect):
            m.d.comb += [
                self.tx.valid.eq(pack.o_stream.valid),
                self.tx.payload.eq(pack.o_stream.payload),
                self.tx.first.eq(pack.o_stream.first),
                self.tx.last.eq(pack.o_stream.last),
                pack.o_stream.ready.eq(self.tx.ready),
            ]

        target_mac = Signal(48)
        ethertype  = Signal(16)

        m.d.comb += [
            pack.header.target_mac.eq(bswap(target_mac)),
            pack.header.sender_mac.eq(bswap(self.mac_address)),
            pack.header.ethernet_type.eq(bswap(ethertype)),
        ]

        with m.FSM(name="tx_fsm"):
            with m.State("IDLE"):
                # ARP has priority (short packets, keeps resolution snappy).
                with m.If(self.arp_tx.valid):
                    m.d.sync += [
                        target_mac.eq(self.arp_tx_mac),
                        ethertype.eq(ETHERTYPE_ARP),
                    ]
                    m.next = "ARP"
                with m.Elif(self.ip_tx.valid):
                    m.d.sync += [
                        target_mac.eq(self.ip_tx_mac),
                        ethertype.eq(ETHERTYPE_IPV4),
                    ]
                    m.next = "IP"

            with m.State("ARP"):
                m.d.comb += [
                    tx_connect.eq(1),
                    pack.i_stream.valid.eq(self.arp_tx.valid),
                    pack.i_stream.payload.eq(self.arp_tx.payload),
                    pack.i_stream.first.eq(self.arp_tx.first),
                    pack.i_stream.last.eq(self.arp_tx.last),
                    self.arp_tx.ready.eq(pack.i_stream.ready),
                ]
                with m.If(self.arp_tx.valid & self.arp_tx.ready & self.arp_tx.last):
                    m.next = "IDLE"

            with m.State("IP"):
                m.d.comb += [
                    tx_connect.eq(1),
                    pack.i_stream.valid.eq(self.ip_tx.valid),
                    pack.i_stream.payload.eq(self.ip_tx.payload),
                    pack.i_stream.first.eq(self.ip_tx.first),
                    pack.i_stream.last.eq(self.ip_tx.last),
                    self.ip_tx.ready.eq(pack.i_stream.ready),
                ]
                with m.If(self.ip_tx.valid & self.ip_tx.ready & self.ip_tx.last):
                    m.next = "IDLE"

        return m
