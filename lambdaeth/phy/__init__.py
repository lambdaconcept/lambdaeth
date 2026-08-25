#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""PHY layer.

See :mod:`lambdaeth.phy.common` for the PHY convention. Available PHYs:

* :class:`lambdaeth.phy.gw5rgmii.GW5RGMIIPHY` — RGMII on Gowin GW5A (Arora-V).
"""

from .common import phy_members, PHYHWReset, MDIOPinSignature, MDIOController
from .gw5rgmii import GW5RGMIIPHY

__all__ = [
    "phy_members", "PHYHWReset", "MDIOPinSignature", "MDIOController",
    "GW5RGMIIPHY",
]
