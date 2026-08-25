#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2023 Icenowy Zheng <uwu@icenowy.me> (LiteEth gw5rgmii)
# Copyright (c) 2019-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth ecp5rgmii)
# Copyright (c) 2020 Shawn Hoffman <godisgovernment@gmail.com>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""RGMII PHY for the Gowin GW5A (Arora-V) FPGA family.

Uses the Gowin ``ODDR``/``IDDR`` DDR registers and ``IODELAY`` delay
primitives (12.5 ps per tap). The TX clock delay is runtime-adjustable
through CSR.

Pad ports are plain signals to be wired to package pins by the top level::

    eth   = platform.request("eth",       dir="-")
    clks  = platform.request("eth_clocks", dir="-")
    phy   = GW5RGMIIPHY()
    m.submodules.phy = phy
    # e.g. for outputs:
    buf = io.Buffer("o", eth.tx_ctl); m.submodules += buf
    m.d.comb += buf.o.eq(phy.tx_ctl)
    ...
"""

from amaranth.hdl import (Module, Signal, Instance, ClockSignal, ClockDomain,
                          Const, C, DomainRenamer)
from amaranth.lib import wiring
from amaranth.lib.cdc import ResetSynchronizer
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_soc import csr

from ..common import eth_phy_stream_signature
from .common import phy_members, PHYHWReset, MDIOPinSignature, MDIOController


__all__ = ["GW5RGMIITX", "GW5RGMIIRX", "GW5RGMIICRG", "GW5RGMIIPHY"]


IODELAY_TAP_S = 12.5e-12  # 12.5 ps per IODELAY tap.


def _delay_taps(delay_s):
    taps = int(delay_s / IODELAY_TAP_S)
    assert 0 <= taps < 256, f"IODELAY supports at most 255 taps ({taps} requested)"
    return taps


# RGMII TX -----------------------------------------------------------------------------------------

class GW5RGMIITX(wiring.Component):
    """RGMII TX datapath: 8-bit stream to DDR pads (runs in the ``sync``
    domain; domain-renamed to the PHY TX domain by :class:`GW5RGMIIPHY`).

    Ports
    -----
    sink : In(eth_phy_stream_signature(8))
    tx_ctl : Out(1), pad
    tx_data : Out(4), pad
    """
    def __init__(self):
        super().__init__({
            "sink":    In(eth_phy_stream_signature(8)),
            "tx_ctl":  Out(1),
            "tx_data": Out(4),
        })

    def elaborate(self, platform):
        m = Module()

        sink = self.sink

        tx_ctl_oddr  = Signal()
        tx_data_oddr = Signal(4)

        m.submodules.tx_ctl_oddr = Instance("ODDR",
            i_CLK = ClockSignal("sync"),
            i_D0  = sink.valid,
            i_D1  = sink.valid,
            i_TX  = C(0),
            o_Q0  = tx_ctl_oddr,
        )
        m.submodules.tx_ctl_delay = Instance("IODELAY",
            p_DYN_DLY_EN   = "FALSE",
            p_ADAPT_EN     = "FALSE",
            p_C_STATIC_DLY = 0,
            i_SDTAP        = C(0),
            i_DLYSTEP      = C(0, 8),
            i_VALUE        = C(0),
            i_DI           = tx_ctl_oddr,
            o_DO           = self.tx_ctl,
        )
        for i in range(4):
            m.submodules[f"tx_data{i}_oddr"] = Instance("ODDR",
                i_CLK = ClockSignal("sync"),
                i_D0  = sink.p.data[i],
                i_D1  = sink.p.data[4 + i],
                i_TX  = C(0),
                o_Q0  = tx_data_oddr[i],
            )
            m.submodules[f"tx_data{i}_delay"] = Instance("IODELAY",
                p_DYN_DLY_EN   = "FALSE",
                p_ADAPT_EN     = "FALSE",
                p_C_STATIC_DLY = 0,
                i_SDTAP        = C(0),
                i_DLYSTEP      = C(0, 8),
                i_VALUE        = C(0),
                i_DI           = tx_data_oddr[i],
                o_DO           = self.tx_data[i],
            )

        m.d.comb += sink.ready.eq(1)

        return m


# RGMII RX -----------------------------------------------------------------------------------------

class GW5RGMIIRX(wiring.Component):
    """RGMII RX datapath: DDR pads to 8-bit stream (runs in the ``sync``
    domain; domain-renamed to the PHY RX domain by :class:`GW5RGMIIPHY`).

    Ports
    -----
    source : Out(eth_phy_stream_signature(8))
    rx_ctl : In(1), pad
    rx_data : In(4), pad
    """
    def __init__(self, rx_delay=2e-9):
        self.rx_delay_taps = _delay_taps(rx_delay)
        super().__init__({
            "source":  Out(eth_phy_stream_signature(8)),
            "rx_ctl":  In(1),
            "rx_data": In(4),
        })

    def elaborate(self, platform):
        m = Module()

        source = self.source

        rx_ctl_delayed  = Signal()
        rx_ctl          = Signal()
        rx_data_delayed = Signal(4)
        rx_data         = Signal(8)

        m.submodules.rx_ctl_delay = Instance("IODELAY",
            p_DYN_DLY_EN   = "FALSE",
            p_ADAPT_EN     = "FALSE",
            p_C_STATIC_DLY = self.rx_delay_taps,
            i_SDTAP        = C(0),
            i_DLYSTEP      = C(0, 8),
            i_VALUE        = C(0),
            i_DI           = self.rx_ctl,
            o_DO           = rx_ctl_delayed,
        )
        m.submodules.rx_ctl_iddr = Instance("IDDR",
            i_CLK = ClockSignal("sync"),
            i_D   = rx_ctl_delayed,
            o_Q0  = rx_ctl,
        )
        for i in range(4):
            m.submodules[f"rx_data{i}_delay"] = Instance("IODELAY",
                p_DYN_DLY_EN   = "FALSE",
                p_ADAPT_EN     = "FALSE",
                p_C_STATIC_DLY = self.rx_delay_taps,
                i_SDTAP        = C(0),
                i_DLYSTEP      = C(0, 8),
                i_VALUE        = C(0),
                i_DI           = self.rx_data[i],
                o_DO           = rx_data_delayed[i],
            )
            m.submodules[f"rx_data{i}_iddr"] = Instance("IDDR",
                i_CLK = ClockSignal("sync"),
                i_D   = rx_data_delayed[i],
                o_Q0  = rx_data[i],
                o_Q1  = rx_data[i + 4],
            )

        rx_ctl_d = Signal()
        valid_d  = Signal()
        m.d.sync += [
            rx_ctl_d.eq(rx_ctl),
            source.valid.eq(rx_ctl),
            source.p.data.eq(rx_data),
            valid_d.eq(source.valid),
        ]
        m.d.comb += [
            # End of packet: falling edge of rx_ctl.
            source.last.eq(~rx_ctl & rx_ctl_d),
            # Start of packet: rising edge of valid.
            source.first.eq(source.valid & ~valid_d),
        ]

        return m


# RGMII CRG ----------------------------------------------------------------------------------------

class GW5RGMIICRG(wiring.Component):
    """Clock and reset generation.

    Creates the PHY TX/RX clock domains (both 125 MHz, RX clocked by the
    ``clk_rx`` pad), generates the delayed TX clock output and synchronizes
    the PHY reset into both domains.

    Parameters
    ----------
    tx_domain, rx_domain : str
        Names of the created clock domains.
    with_hw_init_reset : bool
        OR a power-on reset generator into the reset request.
    tx_delay : float
        Initial TX clock delay (seconds).
    tx_clk : Value or None
        External TX clock; when None the RX clock is reused.
    create_domains : bool
        Define the clock domains here. Set to False when the enclosing design
        already defines them (required by Amaranth 0.6 when the domains are
        used outside this component's hierarchy, e.g. by the MAC core).

    Ports
    -----
    clk_rx : In(1), pad
        RGMII RX clock input.
    clk_tx : Out(1), pad
        RGMII TX clock output (delayed).
    tx_delay_taps : In(8)
        Dynamic TX clock delay in IODELAY taps (CSR-driven).
    reset_req : In(1)
        Reset request (CSR-driven).
    reset : Out(1)
        Resolved PHY reset (drives the pad and the domain resets).
    rst_n : Out(1), pad
        Active-low PHY reset pad.
    """
    def __init__(self, *, tx_domain="eth_tx", rx_domain="eth_rx",
                 with_hw_init_reset=True, hw_reset_cycles=256,
                 tx_delay=2e-9, tx_clk=None, create_domains=True):
        self.tx_domain          = tx_domain
        self.rx_domain          = rx_domain
        self.with_hw_init_reset = with_hw_init_reset
        self.hw_reset_cycles    = hw_reset_cycles
        self.tx_delay_taps_init = _delay_taps(tx_delay)
        self.tx_clk             = tx_clk
        self.create_domains     = create_domains
        super().__init__({
            "clk_rx":        In(1),
            "clk_tx":        Out(1),
            "tx_delay_taps": In(8),
            "reset_req":     In(1),
            "reset":         Out(1),
            "rst_n":         Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        # Clock domains.
        if self.create_domains:
            m.domains += ClockDomain(self.rx_domain)
            m.domains += ClockDomain(self.tx_domain)

        m.d.comb += ClockSignal(self.rx_domain).eq(self.clk_rx)
        if self.tx_clk is not None:
            m.d.comb += ClockSignal(self.tx_domain).eq(self.tx_clk)
        else:
            m.d.comb += ClockSignal(self.tx_domain).eq(self.clk_rx)

        # TX clock output, 90° shifted via IODELAY (dynamically adjustable).
        eth_tx_clk_o = Signal()
        m.submodules.clk_tx_oddr = Instance("ODDR",
            i_CLK = ClockSignal(self.tx_domain),
            i_D0  = C(1),
            i_D1  = C(0),
            i_TX  = C(0),
            o_Q0  = eth_tx_clk_o,
        )
        m.submodules.clk_tx_delay = Instance("IODELAY",
            p_DYN_DLY_EN   = "TRUE",
            p_ADAPT_EN     = "FALSE",
            p_C_STATIC_DLY = self.tx_delay_taps_init,
            i_SDTAP        = C(1),
            i_DLYSTEP      = self.tx_delay_taps,
            i_VALUE        = C(0),
            i_DI           = eth_tx_clk_o,
            o_DO           = self.clk_tx,
        )

        # Reset.
        if self.with_hw_init_reset:
            m.submodules.hw_reset = hw_reset = PHYHWReset(cycles=self.hw_reset_cycles)
            m.d.comb += self.reset.eq(self.reset_req | hw_reset.reset)
        else:
            m.d.comb += self.reset.eq(self.reset_req)

        m.d.comb += self.rst_n.eq(~self.reset)

        m.submodules.tx_reset_sync = ResetSynchronizer(self.reset, domain=self.tx_domain)
        m.submodules.rx_reset_sync = ResetSynchronizer(self.reset, domain=self.rx_domain)

        return m


# RGMII PHY ----------------------------------------------------------------------------------------

class GW5RGMIIPHY(wiring.Component):
    """RGMII PHY for Gowin GW5A FPGAs.

    Attributes (PHY convention)
    ---------------------------
    data_width = 8, tx_clk_freq = rx_clk_freq = 125e6, tx_domain, rx_domain.

    Parameters
    ----------
    tx_delay / rx_delay : float
        RGMII clock skews (seconds), 12.5 ps granularity, < 3.2 ns.
    tx_clk : Value or None
        External TX clock; when None the RX clock is reused.
    with_hw_init_reset : bool
        Include a power-on reset generator.
    with_mdio : bool
        Include the MDIO controller (``mdc``/``mdio`` ports and CSRs).
    tx_domain / rx_domain : str
        Clock domain names (change when instantiating several PHYs).
    create_domains : bool
        Define the TX/RX clock domains inside the PHY (default). Pass False
        and define them in the enclosing design when they are also used by
        sibling components such as the MAC core (Amaranth 0.6 requires clock
        domains to be defined in a common ancestor of all their users).

    Ports
    -----
    tx : In(eth_phy_stream_signature(8))
    rx : Out(eth_phy_stream_signature(8))
    tx_ctl, tx_data, clk_tx, rst_n : Out — pads
    rx_ctl, rx_data, clk_rx : In — pads
    mdc : Out(1), mdio : Out(MDIOPinSignature) — pads (only if with_mdio)
    bus : In(csr.Signature) — control/status registers
    """

    data_width  = 8
    tx_clk_freq = 125e6
    rx_clk_freq = 125e6

    class Reset(csr.Register, access="rw"):
        reset: csr.Field(csr.action.RW, 1)

    class TxDelay(csr.Register, access="rw"):
        def __init__(self, init):
            super().__init__({"taps": csr.Field(csr.action.RW, 8, init=init)})

    class MdioW(csr.Register, access="rw"):
        mdc: csr.Field(csr.action.RW, 1)
        oe:  csr.Field(csr.action.RW, 1)
        w:   csr.Field(csr.action.RW, 1)

    class MdioR(csr.Register, access="r"):
        r: csr.Field(csr.action.R, 1)

    def __init__(self, *,
                 tx_delay           = 2e-9,
                 rx_delay           = 2e-9,
                 tx_clk             = None,
                 with_hw_init_reset = True,
                 hw_reset_cycles    = 256,
                 with_mdio          = False,
                 tx_domain          = "eth_tx",
                 rx_domain          = "eth_rx",
                 create_domains     = True,
                 csr_addr_width     = 3,
                 csr_data_width     = 8):
        self.tx_domain      = tx_domain
        self.rx_domain      = rx_domain
        self.with_mdio      = with_mdio
        self.create_domains = create_domains

        self._crg = GW5RGMIICRG(
            tx_domain          = tx_domain,
            rx_domain          = rx_domain,
            with_hw_init_reset = with_hw_init_reset,
            hw_reset_cycles    = hw_reset_cycles,
            tx_delay           = tx_delay,
            tx_clk             = tx_clk,
            create_domains     = False,  # Created at the PHY (or design) level.
        )
        self._tx = GW5RGMIITX()
        self._rx = GW5RGMIIRX(rx_delay=rx_delay)

        # CSRs.
        regs = csr.Builder(addr_width=csr_addr_width, data_width=csr_data_width)
        self._reset_reg    = regs.add("reset",    self.Reset())
        self._tx_delay_reg = regs.add("tx_delay", self.TxDelay(init=self._crg.tx_delay_taps_init))
        if with_mdio:
            self._mdio_w_reg = regs.add("mdio_w", self.MdioW())
            self._mdio_r_reg = regs.add("mdio_r", self.MdioR())
        self._bridge = csr.Bridge(regs.as_memory_map())

        members = phy_members(
            self.data_width,
            # Pads.
            tx_ctl  = Out(1),
            tx_data = Out(4),
            rx_ctl  = In(1),
            rx_data = In(4),
            clk_tx  = Out(1),
            clk_rx  = In(1),
            rst_n   = Out(1),
            # CSR bus.
            bus     = In(csr.Signature(addr_width=csr_addr_width,
                                       data_width=csr_data_width)),
        )
        if with_mdio:
            members["mdc"]  = Out(1)
            members["mdio"] = Out(MDIOPinSignature())

        super().__init__(members)
        self.bus.memory_map = self._bridge.bus.memory_map

    def elaborate(self, platform):
        m = Module()

        # Define the domains at this level so that all submodules (CRG driving
        # the clocks, TX/RX using them) share a common ancestor definition.
        if self.create_domains:
            m.domains += ClockDomain(self.rx_domain)
            m.domains += ClockDomain(self.tx_domain)

        m.submodules.crg = crg = self._crg
        m.submodules.tx  = tx  = DomainRenamer({"sync": self.tx_domain})(self._tx)
        m.submodules.rx  = rx  = DomainRenamer({"sync": self.rx_domain})(self._rx)

        # Streams.
        connect(m, flipped(self.tx), tx.sink)
        connect(m, rx.source, flipped(self.rx))

        # Pads.
        m.d.comb += [
            self.tx_ctl.eq(tx.tx_ctl),
            self.tx_data.eq(tx.tx_data),
            rx.rx_ctl.eq(self.rx_ctl),
            rx.rx_data.eq(self.rx_data),
            self.clk_tx.eq(crg.clk_tx),
            crg.clk_rx.eq(self.clk_rx),
            self.rst_n.eq(crg.rst_n),
        ]

        # CSRs.
        m.submodules.bridge = self._bridge
        connect(m, flipped(self.bus), self._bridge.bus)
        m.d.comb += [
            crg.reset_req.eq(self._reset_reg.f.reset.data),
            crg.tx_delay_taps.eq(self._tx_delay_reg.f.taps.data),
        ]

        # MDIO.
        if self.with_mdio:
            m.submodules.mdio_ctrl = mdio_ctrl = MDIOController()
            m.d.comb += [
                self.mdc.eq(mdio_ctrl.mdc),
                self.mdio.o.eq(mdio_ctrl.mdio.o),
                self.mdio.oe.eq(mdio_ctrl.mdio.oe),
                mdio_ctrl.mdio.i.eq(self.mdio.i),
                mdio_ctrl.ctl_mdc.eq(self._mdio_w_reg.f.mdc.data),
                mdio_ctrl.ctl_oe.eq(self._mdio_w_reg.f.oe.data),
                mdio_ctrl.ctl_w.eq(self._mdio_w_reg.f.w.data),
                self._mdio_r_reg.f.r.r_data.eq(mdio_ctrl.status_r),
            ]

        return m
