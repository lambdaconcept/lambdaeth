#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""LambdaEth: Ethernet core for Amaranth HDL, built on amaranth-soc and amaranth-stream."""

from .common import (
    eth_phy_layout, eth_phy_stream_signature, eff_last_be,
    eth_mtu_default, eth_min_frame_length, eth_fcs_length,
    eth_interpacket_gap, eth_preamble,
    convert_ip, convert_mac,
)

__all__ = [
    "eth_phy_layout", "eth_phy_stream_signature", "eff_last_be",
    "eth_mtu_default", "eth_min_frame_length", "eth_fcs_length",
    "eth_interpacket_gap", "eth_preamble",
    "convert_ip", "convert_mac",
]
