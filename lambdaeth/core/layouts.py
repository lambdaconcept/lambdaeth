#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Protocol header layouts and byte-order helpers.

:class:`amaranth_stream.HeaderLayout` packs a field's LSB at its byte offset,
i.e. multi-byte fields are serialized little-endian while network protocols
are big-endian. The convention used throughout this package is therefore:

    **header struct fields hold the byte-swapped (wire order) representation**

Use :func:`bswap` to convert between natural values and wire-order fields, in
both directions (it is an involution).
"""

from amaranth.hdl import Cat, Value, Const
from amaranth.lib.data import StructLayout

from amaranth_stream import HeaderLayout, Signature as StreamSignature


__all__ = [
    "bswap",
    "mac_header_layout", "arp_header_layout", "ipv4_header_layout", "udp_header_layout",
    "icmp_header_layout", "tcp_header_layout",
    "header_wire_image",
    "eth_stream_signature", "udp_user_param_layout", "udp_user_signature",
    "ETHERTYPE_ARP", "ETHERTYPE_IPV4",
    "ARP_HWTYPE_ETHERNET", "ARP_PROTO_IPV4", "ARP_OPCODE_REQUEST", "ARP_OPCODE_REPLY",
    "IPV4_PROTOCOL_UDP", "IPV4_PROTOCOL_ICMP", "IPV4_PROTOCOL_TCP", "BROADCAST_MAC",
    "ICMP_TYPE_ECHO_REQUEST", "ICMP_TYPE_ECHO_REPLY",
    "TCP_FLAG_FIN", "TCP_FLAG_SYN", "TCP_FLAG_RST", "TCP_FLAG_PSH",
    "TCP_FLAG_ACK", "TCP_FLAG_URG",
    "MAC_HEADER_LEN", "ARP_HEADER_LEN", "IPV4_HEADER_LEN", "UDP_HEADER_LEN",
    "ICMP_HEADER_LEN", "TCP_HEADER_LEN", "ARP_PACKET_LEN", "ETH_MIN_PAYLOAD_LEN",
]


# Constants ----------------------------------------------------------------------------------------

ETHERTYPE_ARP       = 0x0806
ETHERTYPE_IPV4      = 0x0800
ARP_HWTYPE_ETHERNET = 0x0001
ARP_PROTO_IPV4      = 0x0800
ARP_OPCODE_REQUEST  = 0x0001
ARP_OPCODE_REPLY    = 0x0002
IPV4_PROTOCOL_UDP   = 17
IPV4_PROTOCOL_ICMP  = 1
IPV4_PROTOCOL_TCP   = 6
BROADCAST_MAC       = 0xffffffffffff

ICMP_TYPE_ECHO_REQUEST = 8
ICMP_TYPE_ECHO_REPLY   = 0

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20

MAC_HEADER_LEN      = 14
ARP_HEADER_LEN      = 28
IPV4_HEADER_LEN     = 20
UDP_HEADER_LEN      = 8
ICMP_HEADER_LEN     = 8
TCP_HEADER_LEN      = 20            # Without options (data offset 5).
ETH_MIN_PAYLOAD_LEN = 46            # 64 min frame - 14 header - 4 FCS.
ARP_PACKET_LEN      = ETH_MIN_PAYLOAD_LEN


# Byte-order helper --------------------------------------------------------------------------------

def bswap(value, width=None):
    """Reverse the byte order of ``value`` (int or Value).

    ``width`` (bits) is required for int values and inferred otherwise.
    """
    if isinstance(value, int):
        assert width is not None and width % 8 == 0
        return int.from_bytes(value.to_bytes(width // 8, "big"), "little")
    value = Value.cast(value)
    width = len(value)
    assert width % 8 == 0
    return Cat(value.word_select(width // 8 - 1 - i, 8) for i in range(width // 8))


# Header layouts (offsets in bytes; field values in wire order) -------------------------------------

mac_header_layout = HeaderLayout({
    "target_mac":    (48, 0),
    "sender_mac":    (48, 6),
    "ethernet_type": (16, 12),
})

arp_header_layout = HeaderLayout({
    "hwtype":     (16, 0),
    "proto":      (16, 2),
    "hwsize":     ( 8, 4),
    "protosize":  ( 8, 5),
    "opcode":     (16, 6),
    "sender_mac": (48, 8),
    "sender_ip":  (32, 14),
    "target_mac": (48, 18),
    "target_ip":  (32, 24),
})

# Every byte of the IPv4 header is covered so that checksums can be computed
# from the field values.
ipv4_header_layout = HeaderLayout({
    "ihl":            ( 4, 0, 0),
    "version":        ( 4, 0, 4),
    "dscp_ecn":       ( 8, 1),
    "total_length":   (16, 2),
    "identification": (16, 4),
    "flags_frag":     (16, 6),
    "ttl":            ( 8, 8),
    "protocol":       ( 8, 9),
    "checksum":       (16, 10),
    "sender_ip":      (32, 12),
    "target_ip":      (32, 16),
})

udp_header_layout = HeaderLayout({
    "src_port": (16, 0),
    "dst_port": (16, 2),
    "length":   (16, 4),
    "checksum": (16, 6),
})

# For echo packets, `quench` carries the identifier and sequence number and
# is passed through opaquely.
icmp_header_layout = HeaderLayout({
    "msgtype":  ( 8, 0),
    "code":     ( 8, 1),
    "checksum": (16, 2),
    "quench":   (32, 4),
})

# Fixed 20-byte TCP header; options (data_offset > 5) are handled by the
# consumer. `data_offset` is the high nibble of byte 12 (`reserved` the low
# one); `flags` is byte 13 (FIN=bit0 ... URG=bit5), no byte order issue.
tcp_header_layout = HeaderLayout({
    "src_port":    (16,  0),
    "dst_port":    (16,  2),
    "seq":         (32,  4),
    "ack":         (32,  8),
    "reserved":    ( 4, 12, 0),
    "data_offset": ( 4, 12, 4),
    "flags":       ( 8, 13),
    "window":      (16, 14),
    "checksum":    (16, 16),
    "urgent":      (16, 18),
})


def header_wire_image(m, layout, fields, name="header_image"):
    """Return a Signal holding the wire image of a header built from ``fields``.

    ``fields`` maps field names to Values already in wire order (as stored in
    the header structs). Bytes not covered by any field are zero.
    """
    from amaranth.hdl import Signal
    image = Signal(layout.byte_length * 8, name=name)
    for fname, (width, byte_off, bit_off) in layout.fields.items():
        abs_bit = byte_off * 8 + bit_off
        m.d.comb += image[abs_bit:abs_bit + width].eq(fields[fname])
    return image


# Stream signatures ---------------------------------------------------------------------------------

def eth_stream_signature():
    """Plain 8-bit payload stream used between the network layers."""
    return StreamSignature(8, has_first_last=True)


def udp_user_param_layout():
    """Sideband parameters of the UDP user streams (natural byte order).

    * ``ip``: peer IP (destination on TX, source on RX).
    * ``src_port`` / ``dst_port``: UDP ports (from the board's perspective).
    * ``length``: UDP payload length in bytes.
    """
    return StructLayout({
        "ip":       32,
        "src_port": 16,
        "dst_port": 16,
        "length":   16,
    })


def udp_user_signature():
    return StreamSignature(8, has_first_last=True, param_shape=udp_user_param_layout())
