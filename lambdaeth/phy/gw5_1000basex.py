#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""1000BASE-X / SGMII PHY for the Gowin GW5A(S)T GTR12 hard SERDES.

The GTR12 lane must be configured (via ``gowin-serdes``) for 1.25 Gb/s,
CPLL, ``width_mode=10``, 8b10b encode/decode, K28.5 word alignment, gear
1:1, CTC off — the configuration of the vendor 1GSERETH example. In that
mode the hard PCS performs 8b/10b and comma alignment; the fabric exchanges
decoded code groups:

* ``FABRIC_LN#_TXDATA_I[9:0]``          = ``{disparity, k, data[7:0]}``
* ``{FABRIC_LN#_RXDATA_O[80], [9:0]}``  = ``{coding_err, disparity_err, k, data[7:0]}``

This PHY only depends on plain signals so ``lambdaeth`` does not import
``gowin_serdes``; the top level connects the ports to a
``gowin_serdes.GowinSerDesLane``::

    lane = group.lanes[0]
    m.d.comb += [
        # Clocks (loop the PCS fabric clocks back, vendor style).
        lane.tx.clk.eq(lane.tx.pcs_clkout),
        lane.rx.clk.eq(lane.rx.pcs_clkout),
        phy.clk_tx.eq(lane.tx.pcs_clkout),
        phy.clk_rx.eq(lane.rx.pcs_clkout),
        # Data.
        lane.tx.data.eq(phy.tx_data),
        lane.tx.fifo_wren.eq(phy.tx_wren),
        phy.tx_afull.eq(lane.tx.fifo_afull),
        phy.rx_data.eq(Cat(lane.rx.data[0:10], lane.rx.data[80])),
        phy.rx_aempty.eq(lane.rx.fifo_aempty),
        lane.rx.fifo_rden.eq(phy.rx_rden),
        # Status / resets.
        phy.pll_ok.eq(lane.status.pll_lock),
        phy.align_link.eq(lane.status.word_align_link),
        lane.reset.pma_rstn.eq(phy.pma_rstn),
        lane.reset.pcs_tx_rst.eq(phy.pcs_tx_rst),
        lane.reset.pcs_rx_rst.eq(phy.pcs_rx_rst),
    ]

Reset sequencing follows the vendor ``serdes_control``: the PMA reset is
released only after PLL-OK (CMU_OK) and the user reset are both seen through
synchronizers in the free-running ``sync`` domain; the ``eth_tx`` domain
reset is gated on PLL-OK and the ``eth_rx`` domain reset additionally on
``ALIGN_LINK`` (word alignment implies a usable recovered clock).
"""

from amaranth.hdl import Module, Signal, ClockDomain, ClockSignal
from amaranth.lib import wiring
from amaranth.lib.cdc import FFSynchronizer, ResetSynchronizer
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_soc import csr

from .common import phy_members, PHYHWReset
from .pcs_1000basex import PCS, BusSynchronizer


__all__ = ["GW51000BASEXCRG", "GW51000BASEXPHY"]


# CRG -----------------------------------------------------------------------------------------------

class GW51000BASEXCRG(wiring.Component):
    """Clock/reset generation for the GTR12-based PCS PHY.

    Direct port of the vendor ``serdes_control`` reset sequencer:

    * ``pma_rstn`` (``FABRIC_LN#_RSTN_I``, active-low) released after the
      selected PLL is locked and the user reset is deasserted, both observed
      through synchronizers in the free-running ``sync`` domain.
    * ``pcs_tx_rst``/``pcs_rx_rst`` (active-high) are its complement.
    * ``tx_domain`` reset gated on PLL-OK, ``rx_domain`` reset additionally
      gated on ``ALIGN_LINK`` (like ``ge_pcs_rstn_tx``/``ge_pcs_rstn_rx``).

    Ports
    -----
    clk_tx, clk_rx : In(1)
        Lane PCS fabric clock outputs (drive the eth domains).
    pll_ok : In(1)
        Lane CMU/PLL lock (``FABRIC_LANE#_CMU_OK_O``).
    align_link : In(1)
        Word aligner lock (``LANE#_ALIGN_LINK``).
    reset_req : In(1)
        Reset request (CSR-driven).
    reset : Out(1)
        Resolved PHY reset.
    pma_rstn, pcs_tx_rst, pcs_rx_rst : Out(1)
        GTR12 lane resets.
    """
    def __init__(self, *, tx_domain="eth_tx", rx_domain="eth_rx",
                 with_hw_init_reset=True, hw_reset_cycles=256,
                 create_domains=True):
        self.tx_domain          = tx_domain
        self.rx_domain          = rx_domain
        self.with_hw_init_reset = with_hw_init_reset
        self.hw_reset_cycles    = hw_reset_cycles
        self.create_domains     = create_domains
        super().__init__({
            "clk_tx":     In(1),
            "clk_rx":     In(1),
            "pll_ok":     In(1),
            "align_link": In(1),
            "reset_req":  In(1),
            "reset":      Out(1),
            "pma_rstn":   Out(1),
            "pcs_tx_rst": Out(1),
            "pcs_rx_rst": Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        # Clock domains.
        if self.create_domains:
            m.domains += ClockDomain(self.rx_domain)
            m.domains += ClockDomain(self.tx_domain)

        m.d.comb += [
            ClockSignal(self.tx_domain).eq(self.clk_tx),
            ClockSignal(self.rx_domain).eq(self.clk_rx),
        ]

        # Reset request.
        if self.with_hw_init_reset:
            m.submodules.hw_reset = hw_reset = PHYHWReset(cycles=self.hw_reset_cycles)
            m.d.comb += self.reset.eq(self.reset_req | hw_reset.reset)
        else:
            m.d.comb += self.reset.eq(self.reset_req)

        # PMA reset release (sync domain, 3-FF synced PLL-OK, vendor style).
        pll_ok_sync = Signal()
        m.submodules.pll_ok_cdc = FFSynchronizer(self.pll_ok, pll_ok_sync, stages=3)
        align_sync = Signal()
        m.submodules.align_cdc = FFSynchronizer(self.align_link, align_sync, stages=3)

        pma_rstn = Signal()
        m.d.sync += pma_rstn.eq(pll_ok_sync & ~self.reset)
        m.d.comb += [
            self.pma_rstn.eq(pma_rstn),
            self.pcs_tx_rst.eq(~pma_rstn),
            self.pcs_rx_rst.eq(~pma_rstn),
        ]

        # Ethernet domain resets: TX gated on PLL-OK, RX on ALIGN_LINK.
        m.submodules.tx_reset_sync = ResetSynchronizer(
            self.reset | ~pll_ok_sync, domain=self.tx_domain)
        m.submodules.rx_reset_sync = ResetSynchronizer(
            self.reset | ~align_sync, domain=self.rx_domain)

        return m


# PHY -----------------------------------------------------------------------------------------------

class GW51000BASEXPHY(wiring.Component):
    """1000BASE-X / SGMII PHY on the Gowin GTR12 hard SERDES.

    Attributes (PHY convention)
    ---------------------------
    data_width = 8, tx_clk_freq = rx_clk_freq = 125e6, tx_domain, rx_domain.

    Parameters
    ----------
    tx_domain / rx_domain : str
        Clock domain names.
    create_domains : bool
        Define the TX/RX clock domains inside the PHY (default). Pass False
        and define them in the enclosing design when they are also used by
        sibling components such as the MAC core (Amaranth 0.6 requires clock
        domains to be defined in a common ancestor of all their users).
    with_hw_init_reset : bool
        Include a power-on reset generator.
    check_period, breaklink_time, more_ack_time, sgmii_ack_time : float
        Clause 37 timer periods in seconds (shrink them in simulation).

    Ports
    -----
    tx : In(eth_phy_stream_signature(8))
    rx : Out(eth_phy_stream_signature(8))
    clk_tx, clk_rx : In — lane PCS fabric clock outputs
    tx_data, tx_wren : Out / tx_afull : In — lane TX FIFO interface
    rx_data, rx_aempty : In / rx_rden : Out — lane RX FIFO interface
    pll_ok, align_link : In — lane status
    pma_rstn, pcs_tx_rst, pcs_rx_rst : Out — lane resets
    link_up : Out(1) — autonegotiation complete (tx_domain)
    bus : In(csr.Signature) — control/status registers
    """

    data_width  = 8
    tx_clk_freq = 125e6
    rx_clk_freq = 125e6

    class Reset(csr.Register, access="rw"):
        reset: csr.Field(csr.action.RW, 1)

    class Ctrl(csr.Register, access="rw"):
        an_bypass: csr.Field(csr.action.RW, 1)

    class Status(csr.Register, access="r"):
        link_up:    csr.Field(csr.action.R, 1)
        is_sgmii:   csr.Field(csr.action.R, 1)
        pll_ok:     csr.Field(csr.action.R, 1)
        align_link: csr.Field(csr.action.R, 1)

    class LpAbi(csr.Register, access="r"):
        lp_abi: csr.Field(csr.action.R, 16)

    def __init__(self, *,
                 tx_domain          = "eth_tx",
                 rx_domain          = "eth_rx",
                 create_domains     = True,
                 with_hw_init_reset = True,
                 hw_reset_cycles    = 256,
                 check_period       = 6e-3,
                 breaklink_time     = 10e-3,
                 more_ack_time      = 10e-3,
                 sgmii_ack_time     = 1.6e-3,
                 csr_addr_width     = 3,
                 csr_data_width     = 8):
        self.tx_domain      = tx_domain
        self.rx_domain      = rx_domain
        self.create_domains = create_domains

        self._crg = GW51000BASEXCRG(
            tx_domain          = tx_domain,
            rx_domain          = rx_domain,
            with_hw_init_reset = with_hw_init_reset,
            hw_reset_cycles    = hw_reset_cycles,
            create_domains     = False,  # Created at the PHY (or design) level.
        )
        self._pcs = PCS(
            tx_domain      = tx_domain,
            rx_domain      = rx_domain,
            clk_freq       = self.tx_clk_freq,
            check_period   = check_period,
            breaklink_time = breaklink_time,
            more_ack_time  = more_ack_time,
            sgmii_ack_time = sgmii_ack_time,
        )

        # CSRs.
        regs = csr.Builder(addr_width=csr_addr_width, data_width=csr_data_width)
        self._reset_reg  = regs.add("reset",  self.Reset())
        self._ctrl_reg   = regs.add("ctrl",   self.Ctrl())
        self._status_reg = regs.add("status", self.Status())
        self._lp_abi_reg = regs.add("lp_abi", self.LpAbi())
        self._bridge = csr.Bridge(regs.as_memory_map())

        members = phy_members(
            self.data_width,
            # SerDes lane fabric interface.
            clk_tx     = In(1),
            clk_rx     = In(1),
            tx_data    = Out(10),
            tx_wren    = Out(1),
            tx_afull   = In(1),
            rx_data    = In(11),
            rx_aempty  = In(1),
            rx_rden    = Out(1),
            pll_ok     = In(1),
            align_link = In(1),
            pma_rstn   = Out(1),
            pcs_tx_rst = Out(1),
            pcs_rx_rst = Out(1),
            # Status.
            link_up    = Out(1),
            # CSR bus.
            bus        = In(csr.Signature(addr_width=csr_addr_width,
                                          data_width=csr_data_width)),
        )
        super().__init__(members)
        self.bus.memory_map = self._bridge.bus.memory_map

    def elaborate(self, platform):
        m = Module()

        # Define the domains at this level so that all submodules (CRG driving
        # the clocks, PCS using them) share a common ancestor definition.
        if self.create_domains:
            m.domains += ClockDomain(self.rx_domain)
            m.domains += ClockDomain(self.tx_domain)

        m.submodules.crg = crg = self._crg
        m.submodules.pcs = pcs = self._pcs

        # Streams.
        connect(m, flipped(self.tx), pcs.tx)
        connect(m, pcs.rx, flipped(self.rx))

        # SerDes lane wiring. The RX code group is registered once on entry
        # and the TX code group once on exit: the GTR12 fabric data pins have
        # multi-ns routing delays and must not feed/absorb combinational
        # cones directly (the PCS is latency-insensitive).
        rx_data_r = Signal(11)
        tx_data_r = Signal(10)
        m.d[self.rx_domain] += rx_data_r.eq(self.rx_data)
        m.d[self.tx_domain] += tx_data_r.eq(pcs.tbi_tx)
        m.d.comb += [
            crg.clk_tx.eq(self.clk_tx),
            crg.clk_rx.eq(self.clk_rx),
            crg.pll_ok.eq(self.pll_ok),
            crg.align_link.eq(self.align_link),
            self.pma_rstn.eq(crg.pma_rstn),
            self.pcs_tx_rst.eq(crg.pcs_tx_rst),
            self.pcs_rx_rst.eq(crg.pcs_rx_rst),
            self.tx_data.eq(tx_data_r),
            pcs.tbi_rx.eq(rx_data_r),
            pcs.tbi_rx_ce.eq(1),
            self.link_up.eq(pcs.link_up),
        ]
        # TX FIFO write qualifier / RX FIFO read enable (vendor serdes_control:
        # registered in the respective eth domains, reset until the domain
        # reset releases).
        m.d[self.tx_domain] += self.tx_wren.eq(~self.tx_afull)
        m.d[self.rx_domain] += self.rx_rden.eq(~self.rx_aempty)

        # CSRs.
        m.submodules.bridge = self._bridge
        connect(m, flipped(self.bus), self._bridge.bus)
        m.d.comb += crg.reset_req.eq(self._reset_reg.f.reset.data)

        m.submodules.an_bypass_cdc = FFSynchronizer(
            self._ctrl_reg.f.an_bypass.data, pcs.an_bypass,
            o_domain=self.tx_domain)

        link_up_sync  = Signal()
        is_sgmii_sync = Signal()
        m.submodules.link_up_cdc  = FFSynchronizer(pcs.link_up, link_up_sync)
        m.submodules.is_sgmii_cdc = FFSynchronizer(pcs.is_sgmii, is_sgmii_sync)
        m.submodules.lp_abi_csr_cdc = lp_abi_csr = \
            BusSynchronizer(16, self.tx_domain, "sync")
        m.d.comb += [
            lp_abi_csr.i.eq(pcs.lp_abi),
            self._status_reg.f.link_up.r_data.eq(link_up_sync),
            self._status_reg.f.is_sgmii.r_data.eq(is_sgmii_sync),
            self._status_reg.f.pll_ok.r_data.eq(self.pll_ok),
            self._status_reg.f.align_link.r_data.eq(self.align_link),
            self._lp_abi_reg.f.lp_abi.r_data.eq(lp_abi_csr.o),
        ]

        return m
