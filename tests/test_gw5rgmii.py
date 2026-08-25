#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""GW5A RGMII PHY tests.

The Gowin ODDR/IDDR/IODELAY primitives are black boxes and cannot be
simulated, so the PHY is validated by elaboration/netlist inspection and by
integrating it with :class:`MACCore`.
"""

import re
import sys
import pathlib

from amaranth.back import verilog

from lambdaeth.mac import MACCore
from lambdaeth.phy import GW5RGMIIPHY
from lambdaeth.phy.gw5rgmii import GW5RGMIICRG, _delay_taps

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "examples"))
from gen_gw5rgmii import GW5RGMIIEthernet  # noqa: E402


def _count_cells(vlog, name):
    return len(re.findall(rf"^\s*\\?{name}\b(?!_)", vlog, re.MULTILINE))


def _mark_used(elaboratable):
    """Suppress UnusedElaboratable for construction-only inspection tests."""
    elaboratable._MustUse__used = True
    return elaboratable


def test_phy_convention():
    phy = _mark_used(GW5RGMIIPHY())
    assert phy.data_width == 8
    assert phy.tx_clk_freq == 125e6
    assert phy.rx_clk_freq == 125e6
    assert phy.tx_domain == "eth_tx"
    assert phy.rx_domain == "eth_rx"
    # Streams exist with the right polarity.
    assert phy.tx.ready is not None and phy.rx.valid is not None


def test_delay_taps():
    assert _delay_taps(2e-9) == 160
    assert _delay_taps(0.0) == 0


def test_phy_memory_map():
    phy = _mark_used(GW5RGMIIPHY(with_mdio=True))
    names = [reg_name[-1] for _reg, reg_name, _rng in phy.bus.memory_map.resources()]
    assert names == ["reset", "tx_delay", "mdio_w", "mdio_r"]


def test_phy_verilog():
    phy = GW5RGMIIPHY(with_mdio=True)
    vlog = verilog.convert(phy, name="gw5rgmii_phy")

    # 1 tx_ctl + 4 tx_data + 1 clk_tx.
    assert _count_cells(vlog, "ODDR") == 6
    # 1 rx_ctl + 4 rx_data.
    assert _count_cells(vlog, "IDDR") == 5
    # 6 TX-side + 5 RX-side.
    assert _count_cells(vlog, "IODELAY") == 11
    # Static delay of 2 ns = 160 taps on the 5 RX inputs and as the initial
    # value of the dynamic TX clock delay; 0 taps on the 5 TX outputs.
    assert vlog.count(".C_STATIC_DLY(32'd160)") == 6
    assert vlog.count(".C_STATIC_DLY(32'd0)") == 5
    # Dynamic TX clock delay enabled.
    assert '.DYN_DLY_EN("TRUE")' in vlog
    # Pads present.
    for port in ["tx_ctl", "tx_data", "rx_ctl", "rx_data", "clk_tx", "clk_rx",
                 "rst_n", "mdc", "mdio__o", "mdio__oe", "mdio__i"]:
        assert re.search(rf"\b{port}\b", vlog), f"missing pad {port}"


def test_phy_domain_renaming():
    # Two PHYs in one design need distinct clock domains.
    phy0 = GW5RGMIIPHY(tx_domain="eth0_tx", rx_domain="eth0_rx")
    assert phy0.tx_domain == "eth0_tx"
    vlog = verilog.convert(phy0, name="phy0")
    assert "eth0_rx" in vlog


def test_phy_with_external_tx_clk():
    from amaranth.hdl import Signal
    tx_clk = Signal()
    crg = GW5RGMIICRG(tx_clk=tx_clk)
    vlog = verilog.convert(crg, name="crg", ports=[tx_clk, crg.clk_rx, crg.clk_tx])
    assert _count_cells(vlog, "ODDR") == 1


def test_phy_mac_integration_verilog():
    top = GW5RGMIIEthernet(data_width=8, with_mdio=True)
    assert isinstance(top.mac, MACCore)
    vlog = verilog.convert(top, name="gw5rgmii_ethernet")
    assert _count_cells(vlog, "ODDR") == 6
    assert _count_cells(vlog, "IDDR") == 5
    assert _count_cells(vlog, "IODELAY") == 11


def test_phy_mac_integration_32bit_verilog():
    top = GW5RGMIIEthernet(data_width=32, with_mdio=False)
    vlog = verilog.convert(top, name="gw5rgmii_ethernet_32")
    assert "IODELAY" in vlog
