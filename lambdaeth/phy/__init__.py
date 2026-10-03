#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""PHY layer.

See :mod:`lambdaeth.phy.common` for the PHY convention. Available PHYs:

* :class:`lambdaeth.phy.gw5rgmii.GW5RGMIIPHY` — RGMII on Gowin GW5A (Arora-V).
* :class:`lambdaeth.phy.ecp5rgmii.ECP5RGMIIPHY` — RGMII on Lattice ECP5
  (Yosys/nextpnr-ecp5 flow).
* :class:`lambdaeth.phy.gw5_1000basex.GW51000BASEXPHY` — 1000BASE-X / SGMII
  on the Gowin GW5A(S)T GTR12 hard SERDES (PCS in
  :mod:`lambdaeth.phy.pcs_1000basex`).
"""

from .common import phy_members, PHYHWReset, MDIOPinSignature, MDIOController
from .gw5rgmii import GW5RGMIIPHY
from .ecp5rgmii import ECP5RGMIIPHY
from .gw5_1000basex import GW51000BASEXPHY
from .pcs_1000basex import PCS

__all__ = [
    "phy_members", "PHYHWReset", "MDIOPinSignature", "MDIOController",
    "GW5RGMIIPHY", "ECP5RGMIIPHY", "GW51000BASEXPHY", "PCS",
]
