#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""ECP5 RGMII PHY tests.

The Lattice ODDRX1F/IDDRX1F/DELAYG primitives are black boxes and cannot be
simulated, so the PHY is validated by elaboration/netlist inspection and by
integrating it with :class:`MACCore`. The ECPIX-5 example's PLL parameter
search is checked against ``ecppll``'s result.
"""

import re
import sys
import pathlib

import pytest

from amaranth.hdl import Module, Signal, Elaboratable, ClockDomain
from amaranth.lib.wiring import connect
from amaranth.back import verilog

from lambdaeth.mac import MACCore
from lambdaeth.phy import ECP5RGMIIPHY
from lambdaeth.phy.ecp5rgmii import ECP5RGMIICRG, _delay_taps

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "examples"))
from ecpix5_udp_echo import pll_params  # noqa: E402


def _count_cells(vlog, name):
    return len(re.findall(rf"^\s*\\?{name}\b(?!_)", vlog, re.MULTILINE))


def _mark_used(elaboratable):
    """Suppress UnusedElaboratable for construction-only inspection tests."""
    elaboratable._MustUse__used = True
    return elaboratable


class _Ethernet(Elaboratable):
    """PHY + MAC, pads and MAC streams exposed as top-level ports."""
    def __init__(self, data_width, with_mdio):
        self.phy = ECP5RGMIIPHY(with_mdio=with_mdio, create_domains=False)
        self.mac = MACCore(self.phy, data_width=data_width, with_csr=False)

    def elaborate(self, platform):
        m = Module()
        m.domains += ClockDomain("eth_tx")
        m.domains += ClockDomain("eth_rx")
        m.submodules.phy = self.phy
        m.submodules.mac = self.mac
        connect(m, self.mac.phy_tx, self.phy.tx)
        connect(m, self.phy.rx, self.mac.phy_rx)
        return m

    def ports(self):
        phy, mac = self.phy, self.mac
        ports = [phy.tx_ctl, phy.tx_data, phy.rx_ctl, phy.rx_data, phy.clk_tx,
                 phy.clk_rx, phy.rst_n,
                 mac.sink.valid, mac.sink.ready, mac.sink.payload.as_value(),
                 mac.sink.last, mac.source.valid, mac.source.ready,
                 mac.source.payload.as_value(), mac.source.last]
        if phy.with_mdio:
            ports += [phy.mdc, phy.mdio.o, phy.mdio.oe, phy.mdio.i]
        return ports


def test_phy_convention():
    phy = _mark_used(ECP5RGMIIPHY())
    assert phy.data_width == 8
    assert phy.tx_clk_freq == 125e6
    assert phy.rx_clk_freq == 125e6
    assert phy.tx_domain == "eth_tx"
    assert phy.rx_domain == "eth_rx"
    # Streams exist with the right polarity.
    assert phy.tx.ready is not None and phy.rx.valid is not None


def test_delay_taps():
    # 25 ps per DELAYG tap.
    assert _delay_taps(2e-9) == 80
    assert _delay_taps(0.0) == 0
    assert _delay_taps(3.175e-9) == 127
    with pytest.raises(AssertionError):
        _delay_taps(3.2e-9)


def test_phy_memory_map():
    phy = _mark_used(ECP5RGMIIPHY(with_mdio=True))
    names = [reg_name[-1] for _reg, reg_name, _rng in phy.bus.memory_map.resources()]
    assert names == ["reset", "inband_status", "mdio_w", "mdio_r"]

    phy = _mark_used(ECP5RGMIIPHY())
    names = [reg_name[-1] for _reg, reg_name, _rng in phy.bus.memory_map.resources()]
    assert names == ["reset", "inband_status"]


def test_phy_verilog():
    phy = ECP5RGMIIPHY(with_mdio=True, tx_delay=2e-9, rx_delay=1e-9)
    vlog = verilog.convert(phy, name="ecp5rgmii_phy")

    # 1 tx_ctl + 4 tx_data + 1 clk_tx.
    assert _count_cells(vlog, "ODDRX1F") == 6
    # 1 rx_ctl + 4 rx_data.
    assert _count_cells(vlog, "IDDRX1F") == 5
    # 6 TX-side + 5 RX-side, all explicit user-defined delays.
    assert _count_cells(vlog, "DELAYG") == 11
    assert vlog.count('.DEL_MODE("USER_DEFINED")') == 11
    # TX clock: 2 ns = 80 taps; RX inputs: 1 ns = 40 taps x5; TX data/ctl: 0 x5.
    assert vlog.count(".DEL_VALUE(32'd80)") == 1
    assert vlog.count(".DEL_VALUE(32'd40)") == 5
    assert vlog.count(".DEL_VALUE(32'd0)") == 5
    # Pads present.
    for port in ["tx_ctl", "tx_data", "rx_ctl", "rx_data", "clk_tx", "clk_rx",
                 "rst_n", "mdc", "mdio__o", "mdio__oe", "mdio__i"]:
        assert re.search(rf"\b{port}\b", vlog), f"missing pad {port}"


def test_phy_defaults_match_litex_ecpix5():
    phy = ECP5RGMIIPHY()
    vlog = verilog.convert(phy, name="ecp5rgmii_phy_default")
    # LiteX's ECPIX-5 target: tx_delay 2 ns (80 taps), rx_delay 0.
    assert vlog.count(".DEL_VALUE(32'd80)") == 1
    assert vlog.count(".DEL_VALUE(32'd0)") == 10


def test_phy_domain_renaming():
    # Two PHYs in one design need distinct clock domains.
    phy0 = ECP5RGMIIPHY(tx_domain="eth0_tx", rx_domain="eth0_rx")
    assert phy0.tx_domain == "eth0_tx"
    vlog = verilog.convert(phy0, name="phy0")
    assert "eth0_rx" in vlog


def test_phy_with_external_tx_clk():
    tx_clk = Signal()
    crg = ECP5RGMIICRG(tx_clk=tx_clk)
    vlog = verilog.convert(crg, name="crg", ports=[tx_clk, crg.clk_rx, crg.clk_tx])
    assert _count_cells(vlog, "ODDRX1F") == 1
    assert _count_cells(vlog, "DELAYG") == 1


def test_phy_mac_integration_verilog():
    top = _Ethernet(data_width=8, with_mdio=True)
    vlog = verilog.convert(top, name="ecp5rgmii_ethernet", ports=top.ports())
    assert _count_cells(vlog, "ODDRX1F") == 6
    assert _count_cells(vlog, "IDDRX1F") == 5
    assert _count_cells(vlog, "DELAYG") == 11


def test_phy_mac_integration_32bit_verilog():
    top = _Ethernet(data_width=32, with_mdio=False)
    vlog = verilog.convert(top, name="ecp5rgmii_ethernet_32", ports=top.ports())
    assert "DELAYG" in vlog
    assert "mdc" not in vlog


def test_pll_params():
    # ecppll -i 100 -o 50: refclk /2, feedback 1, output /12, VCO 600 MHz.
    assert pll_params(100e6, 50e6) == {"clki_div": 2, "clkfb_div": 1, "clkop_div": 12}
    for f_out in (25e6, 50e6, 62.5e6, 75e6, 100e6, 125e6):
        p = pll_params(100e6, f_out)
        f_vco = 100e6 / p["clki_div"] * p["clkfb_div"] * p["clkop_div"]
        assert 400e6 <= f_vco <= 800e6
        assert abs(f_vco / p["clkop_div"] - f_out) < 1e-3
    with pytest.raises(ValueError):
        pll_params(100e6, 1e6)  # below the VCO range for any legal divider
