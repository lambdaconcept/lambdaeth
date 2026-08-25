#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2024 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Common Ethernet constants, stream layouts and helpers.

Stream conventions
------------------

All datapath streams use :class:`amaranth_stream.Signature` with
``has_first_last=True`` and a :class:`amaranth.lib.data.StructLayout` payload:

* ``data``    : ``data_width`` bits of packet data (little-endian byte order,
  byte 0 is transmitted first).
* ``last_be`` : one-hot byte mask qualifying the position of the final valid
  byte. It is only meaningful on the beat where ``last`` is asserted.
* ``error``   : per-byte error mask.

``last_be`` normalization: 8-bit producers (e.g. all xMII PHYs) usually drive
only ``last``. Consumers must therefore treat ``last & (last_be == 0)`` as
"all bytes of this beat are valid" (i.e. an effective mask of
``1 << (data_width // 8 - 1)``). Use :func:`eff_last_be` for this.
"""

from amaranth.hdl import Signal, Value, Mux, unsigned
from amaranth.lib import data

from amaranth_stream import Signature as StreamSignature


__all__ = [
    "eth_mtu_default", "eth_mtu_jumboframe", "eth_min_frame_length",
    "eth_fcs_length", "eth_interpacket_gap", "eth_preamble",
    "ethernet_type_ip", "ethernet_type_arp",
    "eth_phy_layout", "eth_phy_stream_signature", "eff_last_be",
    "convert_ip", "convert_mac",
]

# Ethernet Constants -------------------------------------------------------------------------------

eth_mtu_default      = 1530
eth_mtu_jumboframe   = 9022
eth_min_frame_length = 64
eth_fcs_length       = 4
eth_interpacket_gap  = 12
eth_preamble         = 0xd555555555555555

ethernet_type_ip     = 0x800
ethernet_type_arp    = 0x806

# Stream Layouts -----------------------------------------------------------------------------------

def eth_phy_layout(data_width):
    """Payload layout of the PHY <-> MAC datapath streams."""
    assert data_width % 8 == 0 and data_width >= 8
    return data.StructLayout({
        "data":    unsigned(data_width),
        "last_be": unsigned(data_width // 8),
        "error":   unsigned(data_width // 8),
    })


def eth_phy_stream_signature(data_width):
    """Stream signature of the PHY <-> MAC datapath streams."""
    return StreamSignature(eth_phy_layout(data_width), has_first_last=True)


def eff_last_be(m, stream, name="eff_last_be"):
    """Return the normalized ``last_be`` of ``stream`` as a new Signal.

    When ``last`` is asserted with an all-zero ``last_be`` (the convention of
    8-bit producers which only drive ``last``), the effective mask selects the
    full beat, i.e. the most significant byte is the final valid byte.

    The returned value is only meaningful on beats where ``last`` is asserted.
    """
    nbytes = len(stream.p.last_be)
    sig = Signal(nbytes, name=name)
    m.d.comb += sig.eq(Mux(stream.last & (stream.p.last_be == 0),
                           1 << (nbytes - 1),
                           stream.p.last_be))
    return sig

# Helpers ------------------------------------------------------------------------------------------

def convert_ip(s):
    """Convert a dotted-quad IP address string to an integer (pass-through otherwise)."""
    if isinstance(s, str):
        ip = 0
        for e in s.split("."):
            ip = (ip << 8) + int(e)
        return ip
    return s


def convert_mac(s):
    """Convert a ``aa:bb:cc:dd:ee:ff`` MAC address string to an integer (pass-through otherwise)."""
    if isinstance(s, str):
        mac = 0
        for e in s.replace("-", ":").split(":"):
            mac = (mac << 8) + int(e, 16)
        return mac
    return s
