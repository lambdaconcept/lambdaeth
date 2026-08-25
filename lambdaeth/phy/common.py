#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""Generic PHY abstractions.

PHY convention
--------------

Every PHY is a :class:`amaranth.lib.wiring.Component` exposing at least:

* ``tx : In(eth_phy_stream_signature(data_width))`` — MAC to PHY stream,
  synchronous to the ``tx_domain`` clock domain.
* ``rx : Out(eth_phy_stream_signature(data_width))`` — PHY to MAC stream,
  synchronous to the ``rx_domain`` clock domain. The PHY cannot be
  backpressured: ``rx.ready`` is ignored and the MAC must drain the stream.

and the following attributes, consumed by :class:`lambdaeth.mac.MACCore`:

* ``data_width`` (int) — stream data width.
* ``tx_clk_freq`` / ``rx_clk_freq`` (float) — clock frequencies.
* ``tx_domain`` / ``rx_domain`` (str) — clock domain names. The PHY creates
  these domains (they propagate design-wide).

Optional attributes: ``tx_gap_cycles``, ``integrated_ifg_inserter``,
``with_preamble_crc``, ``with_padding``.

Pad ports are plain signals; the top level maps them to package pins (e.g.
through :class:`amaranth.lib.io.Buffer` on ports requested with ``dir="-"``).
"""

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.cdc import FFSynchronizer
from amaranth.lib.wiring import In, Out

from ..common import eth_phy_stream_signature


__all__ = ["phy_members", "PHYHWReset", "MDIOPinSignature", "MDIOController"]


def phy_members(data_width, **extra):
    """Return the wiring members every PHY must expose (plus ``extra``)."""
    return {
        "tx": In(eth_phy_stream_signature(data_width)),
        "rx": Out(eth_phy_stream_signature(data_width)),
        **extra,
    }


class PHYHWReset(wiring.Component):
    """Power-on reset generator: asserts ``reset`` for ``cycles`` clock cycles.

    Ports
    -----
    reset : Out(1)
    """
    def __init__(self, cycles=256):
        self.cycles = cycles
        super().__init__({
            "reset": Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        counter      = Signal(range(self.cycles + 1))
        counter_done = Signal()

        m.d.comb += [
            counter_done.eq(counter == self.cycles),
            self.reset.eq(~counter_done),
        ]
        with m.If(~counter_done):
            m.d.sync += counter.eq(counter + 1)

        return m


class MDIOPinSignature(wiring.Signature):
    """Bidirectional MDIO pin (wire to an ``io.Buffer("io", ...)`` or IOBUF).

    Members
    -------
    o : Out(1)
        Output data.
    oe : Out(1)
        Output enable.
    i : In(1)
        Input data.
    """
    def __init__(self):
        super().__init__({
            "o":  Out(1),
            "oe": Out(1),
            "i":  In(1),
        })


class MDIOController(wiring.Component):
    """Bit-banged MDIO controller datapath.

    Software drives ``ctl_mdc``/``ctl_oe``/``ctl_w`` (typically from CSR
    register fields) and reads back ``status_r`` (synchronized from the pin).

    Ports
    -----
    mdc : Out(1)
        MDIO clock pad.
    mdio : Out(MDIOPinSignature)
        MDIO data pad.
    ctl_mdc, ctl_oe, ctl_w : In(1)
        Software controls.
    status_r : Out(1)
        Synchronized MDIO input.
    """
    def __init__(self):
        super().__init__({
            "mdc":      Out(1),
            "mdio":     Out(MDIOPinSignature()),
            "ctl_mdc":  In(1),
            "ctl_oe":   In(1),
            "ctl_w":    In(1),
            "status_r": Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        m.d.comb += [
            self.mdc.eq(self.ctl_mdc),
            self.mdio.oe.eq(self.ctl_oe),
            self.mdio.o.eq(self.ctl_w),
        ]
        m.submodules.r_sync = FFSynchronizer(self.mdio.i, self.status_r)

        return m
