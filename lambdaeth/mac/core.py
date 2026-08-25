#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2021 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2015-2017 Sebastien Bourdeauducq <sb@m-labs.hk>
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""MAC TX/RX datapath core.

The core builds the TX/RX pipelines around clock-domain crossing, data-width
conversion, padding, preamble/CRC and inter-frame gap stages::

           sys domain           |            PHY domains
                                |
   sink ──> [conv] ──> CDC ─────> [conv/last_be] ─> padding ─> CRC ─> preamble ─> gap ─> phy_tx
                                |
 source <── [conv/last] <── CDC <─ [last_be/conv] <─ padding <─ CRC <─ preamble <──────── phy_rx
"""

from amaranth.hdl import Module, Signal, Const, DomainRenamer
from amaranth.lib import wiring
from amaranth.lib.cdc import PulseSynchronizer
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_soc import csr
from amaranth_stream import StreamAsyncFIFO

from ..common import (eth_phy_stream_signature, eth_min_frame_length,
                      eth_fcs_length, eth_mtu_default)
from . import crc, gap, last_be, padding, preamble
from .converter import EthStreamConverter


__all__ = ["MACCore"]


class MACCore(wiring.Component):
    """MAC TX/RX datapath core.

    Parameters
    ----------
    phy : object
        PHY instance (or any object) providing ``data_width``, ``tx_domain``
        and ``rx_domain`` attributes. Optional attributes: ``tx_gap_cycles``
        (int), ``integrated_ifg_inserter`` (bool, skips the gap stage).
    data_width : int
        MAC-side data width.
    with_preamble_crc : bool
        Enable preamble/CRC insertion and checking.
    with_padding : bool
        Enable minimum-frame padding insertion and checking.
    tx_cdc_depth / rx_cdc_depth : int
        CDC FIFO depths.
    eth_mtu : int
        Maximum frame size used by the padding checker.
    with_csr : bool
        Expose a CSR bus with the feature status and RX error counters.

    Ports
    -----
    sink : In(eth_phy_stream_signature(data_width))
        TX frames from the MAC user (``sync`` domain), without preamble/FCS.
    source : Out(eth_phy_stream_signature(data_width))
        RX frames to the MAC user (``sync`` domain), without preamble/FCS.
    phy_tx : Out(eth_phy_stream_signature(phy.data_width))
        Connect to the PHY ``tx`` stream.
    phy_rx : In(eth_phy_stream_signature(phy.data_width))
        Connect to the PHY ``rx`` stream.
    bus : In(csr.Signature) (only if with_csr)
        CSR bus with ``status``, ``preamble_errors`` and ``crc_errors``.
    """

    class Status(csr.Register, access="r"):
        preamble_crc: csr.Field(csr.action.R, 1)
        padding:      csr.Field(csr.action.R, 1)

    class PreambleErrors(csr.Register, access="r"):
        count: csr.Field(csr.action.R, 32)

    class CrcErrors(csr.Register, access="r"):
        count: csr.Field(csr.action.R, 32)

    def __init__(self, phy, data_width=8, *,
                 with_preamble_crc = True,
                 with_padding      = True,
                 tx_cdc_depth      = 32,
                 rx_cdc_depth      = 32,
                 eth_mtu           = eth_mtu_default,
                 with_csr          = True,
                 csr_addr_width    = 4,
                 csr_data_width    = 8):
        assert data_width % 8 == 0

        self.phy_data_width = phy.data_width
        self.data_width     = data_width
        self.tx_domain      = getattr(phy, "tx_domain", "eth_tx")
        self.rx_domain      = getattr(phy, "rx_domain", "eth_rx")
        self.tx_gap_cycles  = getattr(phy, "tx_gap_cycles", None)
        self.with_tx_gap    = not getattr(phy, "integrated_ifg_inserter", False)

        # PHYs can force preamble/CRC and padding support off (e.g. PCS-based PHYs).
        if hasattr(phy, "with_preamble_crc"):
            with_preamble_crc = phy.with_preamble_crc
        if hasattr(phy, "with_padding"):
            with_padding = phy.with_padding

        self.with_preamble_crc = with_preamble_crc
        self.with_padding      = with_padding
        self.tx_cdc_depth      = tx_cdc_depth
        self.rx_cdc_depth      = rx_cdc_depth
        self.eth_mtu           = eth_mtu
        self.with_csr          = with_csr

        if max(data_width, self.phy_data_width) % min(data_width, self.phy_data_width) != 0:
            raise ValueError(f"MAC/PHY width ratio must be an integer "
                             f"({data_width} <-> {self.phy_data_width})")

        members = {
            "sink":   In(eth_phy_stream_signature(data_width)),
            "source": Out(eth_phy_stream_signature(data_width)),
            "phy_tx": Out(eth_phy_stream_signature(self.phy_data_width)),
            "phy_rx": In(eth_phy_stream_signature(self.phy_data_width)),
        }

        if with_csr:
            regs = csr.Builder(addr_width=csr_addr_width, data_width=csr_data_width)
            self._status          = regs.add("status",          self.Status())
            self._preamble_errors = regs.add("preamble_errors", self.PreambleErrors())
            self._crc_errors      = regs.add("crc_errors",      self.CrcErrors())
            self._bridge = csr.Bridge(regs.as_memory_map())
            members["bus"] = In(csr.Signature(addr_width=csr_addr_width,
                                              data_width=csr_data_width))

        super().__init__(members)

        if with_csr:
            self.bus.memory_map = self._bridge.bus.memory_map

    def elaborate(self, platform):
        m = Module()

        core_dw = self.data_width
        phy_dw  = self.phy_data_width
        cd_tx   = self.tx_domain
        cd_rx   = self.rx_domain

        def in_tx(mod):
            return DomainRenamer({"sync": cd_tx})(mod)

        def in_rx(mod):
            return DomainRenamer({"sync": cd_rx})(mod)

        # TX Data-Path (Core --> PHY) ----------------------------------------------------------

        tx_pipeline = []

        if core_dw < phy_dw:
            # Up-convert in sys, then cross at PHY width.
            conv = EthStreamConverter(core_dw, phy_dw)
            m.submodules.tx_converter = conv
            tx_pipeline.append((conv.sink, conv.source))
            cdc_dw = phy_dw
        else:
            cdc_dw = core_dw

        tx_cdc = StreamAsyncFIFO(eth_phy_stream_signature(cdc_dw),
                                 depth=self.tx_cdc_depth,
                                 w_domain="sync", r_domain=cd_tx)
        m.submodules.tx_cdc = tx_cdc
        tx_pipeline.append((tx_cdc.i_stream, tx_cdc.o_stream))

        if core_dw > phy_dw:
            # Down-convert in the PHY TX domain, then terminate on last_be.
            conv = in_tx(EthStreamConverter(core_dw, phy_dw))
            m.submodules.tx_converter = conv
            tx_pipeline.append((conv.sink, conv.source))
            tx_lb = in_tx(last_be.TXLastBE(phy_dw))
            m.submodules.tx_last_be = tx_lb
            tx_pipeline.append((tx_lb.sink, tx_lb.source))

        if self.with_padding:
            tx_padding = in_tx(padding.PaddingInserter(
                phy_dw, eth_min_frame_length - eth_fcs_length))
            m.submodules.tx_padding = tx_padding
            tx_pipeline.append((tx_padding.sink, tx_padding.source))

        if self.with_preamble_crc:
            tx_crc = in_tx(crc.CRC32Inserter(phy_dw))
            m.submodules.tx_crc = tx_crc
            tx_pipeline.append((tx_crc.sink, tx_crc.source))

            tx_preamble = in_tx(preamble.PreambleInserter(phy_dw))
            m.submodules.tx_preamble = tx_preamble
            tx_pipeline.append((tx_preamble.sink, tx_preamble.source))

        if self.with_tx_gap:
            tx_gap = in_tx(gap.Gap(phy_dw, cycles=self.tx_gap_cycles))
            m.submodules.tx_gap = tx_gap
            tx_pipeline.append((tx_gap.sink, tx_gap.source))

        # sink -> stage0 -> ... -> stageN -> phy_tx
        prev = flipped(self.sink)
        for stage_sink, stage_source in tx_pipeline:
            connect(m, prev, stage_sink)
            prev = stage_source
        connect(m, prev, flipped(self.phy_tx))

        # RX Data-Path (PHY --> Core) ----------------------------------------------------------

        rx_pipeline = []
        rx_preamble = None
        rx_crc      = None

        if self.with_preamble_crc:
            rx_preamble = in_rx(preamble.PreambleChecker(phy_dw))
            m.submodules.rx_preamble = rx_preamble
            rx_pipeline.append((rx_preamble.sink, rx_preamble.source))

            rx_crc = in_rx(crc.CRC32Checker(phy_dw))
            m.submodules.rx_crc = rx_crc
            rx_pipeline.append((rx_crc.sink, rx_crc.source))

        if self.with_padding:
            rx_padding = in_rx(padding.PaddingChecker(
                phy_dw, eth_min_frame_length - eth_fcs_length, eth_mtu=self.eth_mtu))
            m.submodules.rx_padding = rx_padding
            rx_pipeline.append((rx_padding.sink, rx_padding.source))

        if phy_dw < core_dw:
            # Qualify last_be, up-convert in the PHY RX domain, cross at core width.
            rx_lb = in_rx(last_be.RXLastBE(phy_dw))
            m.submodules.rx_last_be = rx_lb
            rx_pipeline.append((rx_lb.sink, rx_lb.source))

            conv = in_rx(EthStreamConverter(phy_dw, core_dw))
            m.submodules.rx_converter = conv
            rx_pipeline.append((conv.sink, conv.source))
            cdc_dw = core_dw
        else:
            cdc_dw = phy_dw

        rx_cdc = StreamAsyncFIFO(eth_phy_stream_signature(cdc_dw),
                                 depth=self.rx_cdc_depth,
                                 w_domain=cd_rx, r_domain="sync")
        m.submodules.rx_cdc = rx_cdc
        rx_pipeline.append((rx_cdc.i_stream, rx_cdc.o_stream))

        if phy_dw > core_dw:
            # Down-convert in sys, then terminate on last_be.
            conv = EthStreamConverter(phy_dw, core_dw)
            m.submodules.rx_converter = conv
            rx_pipeline.append((conv.sink, conv.source))
            rx_lb = last_be.TXLastBE(core_dw)
            m.submodules.rx_last_be = rx_lb
            rx_pipeline.append((rx_lb.sink, rx_lb.source))

        # phy_rx -> stage0 -> ... -> stageN -> source
        prev = flipped(self.phy_rx)
        for stage_sink, stage_source in rx_pipeline:
            connect(m, prev, stage_sink)
            prev = stage_source
        connect(m, prev, flipped(self.source))

        # CSR ----------------------------------------------------------------------------------

        if self.with_csr:
            m.submodules.bridge = self._bridge
            connect(m, flipped(self.bus), self._bridge.bus)

            m.d.comb += [
                self._status.f.preamble_crc.r_data.eq(Const(self.with_preamble_crc)),
                self._status.f.padding.r_data.eq(Const(self.with_padding)),
            ]

            preamble_errors = Signal(32)
            crc_errors      = Signal(32)
            m.d.comb += [
                self._preamble_errors.f.count.r_data.eq(preamble_errors),
                self._crc_errors.f.count.r_data.eq(crc_errors),
            ]

            if self.with_preamble_crc:
                preamble_ps = PulseSynchronizer(cd_rx, "sync")
                crc_ps      = PulseSynchronizer(cd_rx, "sync")
                m.submodules.preamble_ps = preamble_ps
                m.submodules.crc_ps      = crc_ps
                m.d.comb += [
                    preamble_ps.i.eq(rx_preamble.error),
                    crc_ps.i.eq(rx_crc.error),
                ]
                with m.If(preamble_ps.o):
                    m.d.sync += preamble_errors.eq(preamble_errors + 1)
                with m.If(crc_ps.o):
                    m.d.sync += crc_errors.eq(crc_errors + 1)

        return m
