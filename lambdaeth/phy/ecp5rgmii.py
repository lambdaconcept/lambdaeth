#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2019-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth ecp5rgmii)
# Copyright (c) 2020 Shawn Hoffman <godisgovernment@gmail.com>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""RGMII PHY for the Lattice ECP5 FPGA family (Yosys/nextpnr-ecp5 "Trellis"
flow or Diamond).

Uses the ECP5 ``ODDRX1F``/``IDDRX1F`` generic DDR registers and ``DELAYG``
static delay primitives (25 ps per tap, 0..127 taps). The RGMII clock skews
are build-time parameters (``tx_delay``/``rx_delay``); the RX in-band link
status (link up, speed, duplex) is exposed through CSR.

The design follows LiteEth's ``ecp5rgmii`` PHY: every DDR pad goes through a
``DELAYG`` (0 taps on TX data/control, ``tx_delay`` on the TX clock,
``rx_delay`` on the RX inputs) so that all pads share the same structural
path. nextpnr honours an explicit numeric ``DEL_VALUE`` regardless of
``DEL_MODE``.

Pad ports are plain signals to be wired to package pins by the top level
(see ``examples/ecpix5_udp_echo.py``)::

    eth = platform.request("eth_rgmii", 0, dir="-")
    phy = ECP5RGMIIPHY(create_domains=False)
    m.submodules.phy = phy
    m.submodules.rx_clk_buf = IOBufferInstance(eth.rx_clk.io, i=rx_clk)
    m.submodules.tx_clk_buf = IOBufferInstance(eth.tx_clk.io, o=phy.clk_tx)
    ...

The clock domains ``eth_tx``/``eth_rx`` both run at 125 MHz from the PHY's
RX clock (the TX clock is the RX clock looped back, delayed by ``tx_delay``
on its way out). Only 1000BASE-T operation is supported (no 10/100 Mbps DDR
to SDR gearing).
"""

from amaranth.hdl import Module, Signal, Instance, ClockSignal, ClockDomain, C, DomainRenamer
from amaranth.lib import wiring
from amaranth.lib.cdc import FFSynchronizer, ResetSynchronizer
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_soc import csr

from ..common import eth_phy_stream_signature
from .common import phy_members, PHYHWReset, MDIOPinSignature, MDIOController


__all__ = ["ECP5RGMIITX", "ECP5RGMIIRX", "ECP5RGMIICRG", "ECP5RGMIIPHY"]


DELAYG_TAP_S = 25e-12  # 25 ps per DELAYG/DELAYF tap.


def _delay_taps(delay_s):
    taps = int(round(delay_s / DELAYG_TAP_S))
    assert 0 <= taps < 128, f"DELAYG supports at most 127 taps ({taps} requested)"
    return taps


def _delayg(name, m, i, o, taps):
    """Static ECP5 delay element between a pad and its DDR register."""
    m.submodules[name] = Instance("DELAYG",
        p_DEL_MODE  = "USER_DEFINED",
        p_DEL_VALUE = taps,
        i_A         = i,
        o_Z         = o,
    )


# RGMII TX -----------------------------------------------------------------------------------------

class ECP5RGMIITX(wiring.Component):
    """RGMII TX datapath: 8-bit stream to DDR pads (runs in the ``sync``
    domain; domain-renamed to the PHY TX domain by :class:`ECP5RGMIIPHY`).

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

        # TX_CTL: TX_EN on the rising edge, TX_EN ^ TX_ER on the falling edge
        # (no errors are ever signalled, so both halves carry `valid`).
        m.submodules.tx_ctl_oddr = Instance("ODDRX1F",
            i_SCLK = ClockSignal("sync"),
            i_RST  = C(0),
            i_D0   = sink.valid,
            i_D1   = sink.valid,
            o_Q    = tx_ctl_oddr,
        )
        _delayg("tx_ctl_delay", m, tx_ctl_oddr, self.tx_ctl, taps=0)
        for i in range(4):
            m.submodules[f"tx_data{i}_oddr"] = Instance("ODDRX1F",
                i_SCLK = ClockSignal("sync"),
                i_RST  = C(0),
                i_D0   = sink.p.data[i],
                i_D1   = sink.p.data[4 + i],
                o_Q    = tx_data_oddr[i],
            )
            _delayg(f"tx_data{i}_delay", m, tx_data_oddr[i], self.tx_data[i], taps=0)

        m.d.comb += sink.ready.eq(1)

        return m


# RGMII RX -----------------------------------------------------------------------------------------

class ECP5RGMIIRX(wiring.Component):
    """RGMII RX datapath: DDR pads to 8-bit stream (runs in the ``sync``
    domain; domain-renamed to the PHY RX domain by :class:`ECP5RGMIIPHY`).

    Ports
    -----
    source : Out(eth_phy_stream_signature(8))
    rx_ctl : In(1), pad
    rx_data : In(4), pad
    inband_status : Out(4)
        RGMII in-band link status sampled while the link is idle:
        bit 0 link up, bits 2:1 speed (0b00 10 Mbps, 0b01 100 Mbps,
        0b10 1000 Mbps), bit 3 full duplex.
    """
    def __init__(self, rx_delay=0e-9):
        self.rx_delay_taps = _delay_taps(rx_delay)
        super().__init__({
            "source":        Out(eth_phy_stream_signature(8)),
            "rx_ctl":        In(1),
            "rx_data":       In(4),
            "inband_status": Out(4),
        })

    def elaborate(self, platform):
        m = Module()

        source = self.source

        rx_ctl_delayed  = Signal()
        rx_ctl          = Signal(2)   # [0] RX_DV (rising), [1] RX_DV ^ RX_ER (falling)
        rx_data_delayed = Signal(4)
        rx_data         = Signal(8)

        _delayg("rx_ctl_delay", m, self.rx_ctl, rx_ctl_delayed, taps=self.rx_delay_taps)
        m.submodules.rx_ctl_iddr = Instance("IDDRX1F",
            i_SCLK = ClockSignal("sync"),
            i_RST  = C(0),
            i_D    = rx_ctl_delayed,
            o_Q0   = rx_ctl[0],
            o_Q1   = rx_ctl[1],
        )
        for i in range(4):
            _delayg(f"rx_data{i}_delay", m, self.rx_data[i], rx_data_delayed[i],
                    taps=self.rx_delay_taps)
            m.submodules[f"rx_data{i}_iddr"] = Instance("IDDRX1F",
                i_SCLK = ClockSignal("sync"),
                i_RST  = C(0),
                i_D    = rx_data_delayed[i],
                o_Q0   = rx_data[i],
                o_Q1   = rx_data[i + 4],
            )

        rx_dv   = Signal()
        rx_dv_d = Signal()
        valid_d = Signal()
        m.d.comb += rx_dv.eq(rx_ctl[0])
        m.d.sync += [
            rx_dv_d.eq(rx_dv),
            source.valid.eq(rx_dv),
            source.p.data.eq(rx_data),
            valid_d.eq(source.valid),
        ]
        m.d.comb += [
            # End of packet: falling edge of RX_DV.
            source.last.eq(~rx_dv & rx_dv_d),
            # Start of packet: rising edge of valid.
            source.first.eq(source.valid & ~valid_d),
        ]

        # In-band status: between frames (RX_DV = RX_ER = 0) the PHY drives
        # link/speed/duplex on RXD[3:0] (RGMII v2.0 §3.4.1).
        with m.If(rx_ctl == 0b00):
            m.d.sync += self.inband_status.eq(rx_data[0:4])

        return m


# RGMII CRG ----------------------------------------------------------------------------------------

class ECP5RGMIICRG(wiring.Component):
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
    hw_reset_cycles : int
        Length of the power-on reset in ``sync`` cycles.
    tx_delay : float
        TX clock delay (seconds, 25 ps granularity, < 3.2 ns).
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
        self.tx_delay_taps      = _delay_taps(tx_delay)
        self.tx_clk             = tx_clk
        self.create_domains     = create_domains
        super().__init__({
            "clk_rx":    In(1),
            "clk_tx":    Out(1),
            "reset_req": In(1),
            "reset":     Out(1),
            "rst_n":     Out(1),
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

        # TX clock output: a DDR-generated replica of the TX clock, shifted by
        # tx_delay so that the PHY samples TXD/TX_CTL away from their edges.
        eth_tx_clk_o = Signal()
        m.submodules.clk_tx_oddr = Instance("ODDRX1F",
            i_SCLK = ClockSignal(self.tx_domain),
            i_RST  = C(0),
            i_D0   = C(1),
            i_D1   = C(0),
            o_Q    = eth_tx_clk_o,
        )
        _delayg("clk_tx_delay", m, eth_tx_clk_o, self.clk_tx, taps=self.tx_delay_taps)

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

class ECP5RGMIIPHY(wiring.Component):
    """RGMII PHY for Lattice ECP5 FPGAs.

    Attributes (PHY convention)
    ---------------------------
    data_width = 8, tx_clk_freq = rx_clk_freq = 125e6, tx_domain, rx_domain.

    Parameters
    ----------
    tx_delay / rx_delay : float
        RGMII clock skews (seconds), 25 ps granularity, < 3.2 ns. Defaults
        (2 ns / 0 ns) are LiteX's values for the ECPIX-5 (KSZ9031RNX): the
        TX clock is shifted a quarter period by the FPGA, the RX clock is
        sampled as it arrives (the clock-tree insertion delay provides the
        skew).
    tx_clk : Value or None
        External TX clock; when None the RX clock is reused.
    with_hw_init_reset : bool
        Include a power-on reset generator.
    hw_reset_cycles : int
        Power-on reset length in ``sync`` cycles (the KSZ9031 needs >= 10 ms).
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
    bus : In(csr.Signature) — control/status registers:
        ``reset`` (rw), ``inband_status`` (r: link_up, speed[2], duplex),
        ``mdio_w``/``mdio_r`` (with_mdio).
    """

    data_width  = 8
    tx_clk_freq = 125e6
    rx_clk_freq = 125e6

    class Reset(csr.Register, access="rw"):
        reset: csr.Field(csr.action.RW, 1)

    class InbandStatus(csr.Register, access="r"):
        link_up: csr.Field(csr.action.R, 1)
        speed:   csr.Field(csr.action.R, 2)
        duplex:  csr.Field(csr.action.R, 1)

    class MdioW(csr.Register, access="rw"):
        mdc: csr.Field(csr.action.RW, 1)
        oe:  csr.Field(csr.action.RW, 1)
        w:   csr.Field(csr.action.RW, 1)

    class MdioR(csr.Register, access="r"):
        r: csr.Field(csr.action.R, 1)

    def __init__(self, *,
                 tx_delay           = 2e-9,
                 rx_delay           = 0e-9,
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

        self._crg = ECP5RGMIICRG(
            tx_domain          = tx_domain,
            rx_domain          = rx_domain,
            with_hw_init_reset = with_hw_init_reset,
            hw_reset_cycles    = hw_reset_cycles,
            tx_delay           = tx_delay,
            tx_clk             = tx_clk,
            create_domains     = False,  # Created at the PHY (or design) level.
        )
        self._tx = ECP5RGMIITX()
        self._rx = ECP5RGMIIRX(rx_delay=rx_delay)

        # CSRs.
        regs = csr.Builder(addr_width=csr_addr_width, data_width=csr_data_width)
        self._reset_reg  = regs.add("reset",         self.Reset())
        self._status_reg = regs.add("inband_status", self.InbandStatus())
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
        m.d.comb += crg.reset_req.eq(self._reset_reg.f.reset.data)

        # In-band status: quasi-static, brought into the CSR (sync) domain
        # bit by bit.
        status_sync = Signal(4)
        m.submodules.status_sync = FFSynchronizer(rx.inband_status, status_sync)
        m.d.comb += [
            self._status_reg.f.link_up.r_data.eq(status_sync[0]),
            self._status_reg.f.speed.r_data.eq(status_sync[1:3]),
            self._status_reg.f.duplex.r_data.eq(status_sync[3]),
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
