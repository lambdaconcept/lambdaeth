#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""IPv4 layer: header checksum, TX (with ARP resolution) and RX."""

from amaranth.hdl import Module, Signal, Cat
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_stream import Packetizer, Depacketizer

from .layouts import (eth_stream_signature, ipv4_header_layout, bswap,
                      header_wire_image, IPV4_HEADER_LEN, BROADCAST_MAC)
from .arp import arp_request_signature, arp_response_signature


__all__ = ["ipv4_checksum", "IPTX", "IPRX"]


def ipv4_checksum(m, image, name="ipv4_csum"):
    """One's-complement sum over a 160-bit IPv4 header wire image.

    Returns ``(value, ok)``: ``value`` is the checksum to insert (natural
    byte order) when the image has a zero checksum field; ``ok`` is asserted
    when the image (including its checksum field) verifies.
    """
    words = []
    for i in range(IPV4_HEADER_LEN // 2):
        # Big-endian 16-bit word from wire bytes 2i (high) and 2i+1 (low).
        words.append(Cat(image[16*i + 8:16*i + 16], image[16*i:16*i + 8]))

    acc = Signal(21, name=f"{name}_acc")
    m.d.comb += acc.eq(sum(words))

    fold1 = Signal(17, name=f"{name}_fold1")
    fold2 = Signal(16, name=f"{name}_fold2")
    m.d.comb += [
        fold1.eq(acc[:16] + acc[16:]),
        fold2.eq(fold1[:16] + fold1[16]),
    ]

    value = Signal(16, name=f"{name}_value")
    ok    = Signal(name=f"{name}_ok")
    m.d.comb += [
        value.eq(~fold2),
        ok.eq(fold2 == 0xffff),
    ]
    return value, ok


class IPTX(wiring.Component):
    """IPv4 TX: resolve the destination MAC through ARP and packetize.

    Metadata (``dst_ip``/``length``/``protocol``, natural byte order) must be
    valid while the first ``sink`` beat is offered and is latched then.
    ``length`` is the IPv4 payload length in bytes.
    """
    def __init__(self):
        super().__init__({
            "sink":         In(eth_stream_signature()),
            "dst_ip":       In(32),
            "length":       In(16),
            "protocol":     In(8),
            "source":       Out(eth_stream_signature()),
            "target_mac":   Out(48),
            "arp_request":  Out(arp_request_signature()),
            "arp_response": In(arp_response_signature()),
            "mac_address":  In(48),
            "ip_address":   In(32),
            "unreachable":  Out(1),  # Pulse: ARP resolution failed, packet dropped.
        })

    def elaborate(self, platform):
        m = Module()

        sink   = self.sink
        source = self.source

        m.submodules.packetizer = pack = Packetizer(
            ipv4_header_layout, eth_stream_signature())

        # Latched metadata.
        dst_ip   = Signal(32)
        length   = Signal(16)
        protocol = Signal(8)
        dst_mac  = Signal(48)

        total_length = Signal(16)
        m.d.comb += total_length.eq(length + IPV4_HEADER_LEN)

        # Header checksum, computed over the header image with a zero
        # checksum field.
        csum_fields = {
            "ihl":            5,
            "version":        4,
            "dscp_ecn":       0,
            "total_length":   bswap(total_length),
            "identification": 0,
            "flags_frag":     0,
            "ttl":            0x80,
            "protocol":       protocol,
            "checksum":       0,
            "sender_ip":      bswap(self.ip_address),
            "target_ip":      bswap(dst_ip),
        }
        image = header_wire_image(m, ipv4_header_layout, csum_fields, name="iptx_image")
        csum_value, _csum_ok = ipv4_checksum(m, image, name="iptx_csum")

        m.d.comb += [
            pack.header.ihl.eq(5),
            pack.header.version.eq(4),
            pack.header.dscp_ecn.eq(0),
            pack.header.total_length.eq(bswap(total_length)),
            pack.header.identification.eq(0),
            pack.header.flags_frag.eq(0),
            pack.header.ttl.eq(0x80),
            pack.header.protocol.eq(protocol),
            pack.header.checksum.eq(bswap(csum_value)),
            pack.header.sender_ip.eq(bswap(self.ip_address)),
            pack.header.target_ip.eq(bswap(dst_ip)),
            self.target_mac.eq(dst_mac),
        ]

        m.d.comb += self.arp_request.ip_address.eq(dst_ip)

        with m.FSM():
            with m.State("IDLE"):
                with m.If(sink.valid):
                    m.d.sync += [
                        dst_ip.eq(self.dst_ip),
                        length.eq(self.length),
                        protocol.eq(self.protocol),
                    ]
                    # x.x.x.255 or 255.255.255.255: broadcast, no ARP.
                    with m.If(self.dst_ip[0:8] == 0xff):
                        m.d.sync += dst_mac.eq(BROADCAST_MAC)
                        m.next = "SEND"
                    with m.Else():
                        m.next = "ARP_REQUEST"

            with m.State("ARP_REQUEST"):
                m.d.comb += self.arp_request.valid.eq(1)
                with m.If(self.arp_request.ready):
                    m.next = "ARP_WAIT"

            with m.State("ARP_WAIT"):
                with m.If(self.arp_response.valid):
                    m.d.comb += self.arp_response.ready.eq(1)
                    m.d.sync += dst_mac.eq(self.arp_response.mac_address)
                    with m.If(self.arp_response.failed):
                        m.d.comb += self.unreachable.eq(1)
                        m.next = "DROP"
                    with m.Else():
                        m.next = "SEND"

            with m.State("SEND"):
                m.d.comb += [
                    pack.i_stream.valid.eq(sink.valid),
                    pack.i_stream.payload.eq(sink.payload),
                    pack.i_stream.first.eq(sink.first),
                    pack.i_stream.last.eq(sink.last),
                    sink.ready.eq(pack.i_stream.ready),

                    source.valid.eq(pack.o_stream.valid),
                    source.payload.eq(pack.o_stream.payload),
                    source.first.eq(pack.o_stream.first),
                    source.last.eq(pack.o_stream.last),
                    pack.o_stream.ready.eq(source.ready),
                ]
                with m.If(sink.valid & sink.ready & sink.last):
                    m.next = "IDLE"

            with m.State("DROP"):
                m.d.comb += sink.ready.eq(1)
                with m.If(sink.valid & sink.last):
                    m.next = "IDLE"

        return m


class IPRX(wiring.Component):
    """IPv4 RX: validate the header and expose the payload with metadata.

    ``src_ip``/``length``/``protocol`` (natural byte order) are valid while
    the packet is streaming on ``source``. ``length`` is the IPv4 payload
    length in bytes.
    """
    def __init__(self):
        super().__init__({
            "sink":       In(eth_stream_signature()),
            "source":     Out(eth_stream_signature()),
            "src_ip":     Out(32),
            "length":     Out(16),
            "protocol":   Out(8),
            "ip_address": In(32),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.depacketizer = depack = Depacketizer(
            ipv4_header_layout, eth_stream_signature())
        connect(m, flipped(self.sink), depack.i_stream)

        hdr = depack.header
        _value, csum_ok = ipv4_checksum(m, depack.header_raw, name="iprx_csum")

        target_ip = Signal(32)
        m.d.comb += target_ip.eq(bswap(hdr.target_ip))

        valid = Signal()
        m.d.comb += valid.eq(
            (hdr.version == 4) &
            (hdr.ihl == 5) &
            csum_ok &
            ((target_ip == self.ip_address) | (target_ip == 0xffffffff)))

        m.d.comb += [
            self.src_ip.eq(bswap(hdr.sender_ip)),
            self.length.eq(bswap(hdr.total_length) - IPV4_HEADER_LEN),
            self.protocol.eq(hdr.protocol),
        ]

        with m.FSM():
            with m.State("IDLE"):
                with m.If(depack.o_stream.valid):
                    with m.If(valid):
                        m.next = "RECEIVE"
                    with m.Else():
                        m.next = "DROP"

            with m.State("RECEIVE"):
                m.d.comb += [
                    self.source.valid.eq(depack.o_stream.valid),
                    self.source.payload.eq(depack.o_stream.payload),
                    self.source.first.eq(depack.o_stream.first),
                    self.source.last.eq(depack.o_stream.last),
                    depack.o_stream.ready.eq(self.source.ready),
                ]
                with m.If(depack.o_stream.valid & depack.o_stream.ready &
                          depack.o_stream.last):
                    m.next = "IDLE"

            with m.State("DROP"):
                m.d.comb += depack.o_stream.ready.eq(1)
                with m.If(depack.o_stream.valid & depack.o_stream.last):
                    m.next = "IDLE"

        return m
