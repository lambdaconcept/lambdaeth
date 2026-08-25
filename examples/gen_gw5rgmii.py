#!/usr/bin/env python3
#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Generate Verilog for a GW5A RGMII PHY + MAC core.

The produced module exposes raw RGMII pad signals, the sys-domain MAC streams
and two CSR buses (PHY and MAC). Wire the pads to package pins in your
toplevel (the DDR/delay primitives connect directly to the IOBs).

Usage: pdm run gen-gw5rgmii [output.v]
"""

import sys

from amaranth.hdl import Module, ClockDomain
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect, flipped
from amaranth.back import verilog

from amaranth_soc import csr

from lambdaeth.common import eth_phy_stream_signature
from lambdaeth.mac import MACCore
from lambdaeth.phy import GW5RGMIIPHY, MDIOPinSignature


class GW5RGMIIEthernet(wiring.Component):
    """GW5A RGMII PHY + MAC core, ready for integration."""

    def __init__(self, data_width=8, with_mdio=True):
        # The PHY clock domains are defined here (common ancestor of PHY and
        # MAC), as required by Amaranth 0.6 domain scoping rules.
        self.phy = GW5RGMIIPHY(with_mdio=with_mdio, create_domains=False)
        self.mac = MACCore(self.phy, data_width=data_width)

        members = {
            # MAC user streams (sync domain).
            "sink":    In(eth_phy_stream_signature(data_width)),
            "source":  Out(eth_phy_stream_signature(data_width)),
            # RGMII pads.
            "tx_ctl":  Out(1),
            "tx_data": Out(4),
            "rx_ctl":  In(1),
            "rx_data": In(4),
            "clk_tx":  Out(1),
            "clk_rx":  In(1),
            "rst_n":   Out(1),
            # CSR buses.
            "phy_bus": In(self.phy.bus.signature.flip()),
            "mac_bus": In(self.mac.bus.signature.flip()),
        }
        if with_mdio:
            members["mdc"]  = Out(1)
            members["mdio"] = Out(MDIOPinSignature())
        self.with_mdio = with_mdio

        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        m.domains += ClockDomain(self.phy.rx_domain)
        m.domains += ClockDomain(self.phy.tx_domain)

        m.submodules.phy = phy = self.phy
        m.submodules.mac = mac = self.mac

        # MAC <-> PHY.
        connect(m, mac.phy_tx, phy.tx)
        connect(m, phy.rx, mac.phy_rx)

        # MAC user streams.
        connect(m, flipped(self.sink), mac.sink)
        connect(m, mac.source, flipped(self.source))

        # Pads.
        m.d.comb += [
            self.tx_ctl.eq(phy.tx_ctl),
            self.tx_data.eq(phy.tx_data),
            phy.rx_ctl.eq(self.rx_ctl),
            phy.rx_data.eq(self.rx_data),
            self.clk_tx.eq(phy.clk_tx),
            phy.clk_rx.eq(self.clk_rx),
            self.rst_n.eq(phy.rst_n),
        ]
        if self.with_mdio:
            m.d.comb += [
                self.mdc.eq(phy.mdc),
                self.mdio.o.eq(phy.mdio.o),
                self.mdio.oe.eq(phy.mdio.oe),
                phy.mdio.i.eq(self.mdio.i),
            ]

        # CSR buses.
        connect(m, flipped(self.phy_bus), phy.bus)
        connect(m, flipped(self.mac_bus), mac.bus)

        return m


def main():
    top = GW5RGMIIEthernet()
    output = verilog.convert(top, name="gw5rgmii_ethernet")
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w") as f:
            f.write(output)
        print(f"Wrote {sys.argv[1]} ({len(output)} bytes)")
    else:
        print(output)


if __name__ == "__main__":
    main()
