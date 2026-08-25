#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""IP protocol dispatch and TX arbitration.

Both components are shaped at build time from plain Python dicts/lists —
protocol ports only exist in the netlist when requested, so optional stack
features (like ICMP) cost nothing when disabled.
"""

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out

from .layouts import eth_stream_signature


__all__ = ["IPRXDispatch", "IPTXArbiter"]


class IPRXDispatch(wiring.Component):
    """Route the IP RX payload stream by protocol number.

    ``protocols`` maps port names to IP protocol numbers; one output stream
    is created per entry (``<name>``). Unmatched protocols are dropped.
    The metadata (``src_ip``/``length``/``protocol``) fans out unchanged from
    the IP RX layer, so only the stream itself is demultiplexed.
    """
    def __init__(self, protocols):
        assert len(protocols) > 0
        self.protocols = dict(protocols)
        members = {
            "sink":     In(eth_stream_signature()),
            "protocol": In(8),
        }
        for name in self.protocols:
            members[name] = Out(eth_stream_signature())
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        with m.FSM():
            with m.State("IDLE"):
                with m.If(self.sink.valid):
                    m.next = "DROP"
                    for name, proto in self.protocols.items():
                        with m.If(self.protocol == proto):
                            m.next = name.upper()

            for name in self.protocols:
                port = getattr(self, name)
                with m.State(name.upper()):
                    m.d.comb += [
                        port.valid.eq(self.sink.valid),
                        port.payload.eq(self.sink.payload),
                        port.first.eq(self.sink.first),
                        port.last.eq(self.sink.last),
                        self.sink.ready.eq(port.ready),
                    ]
                    with m.If(self.sink.valid & self.sink.ready & self.sink.last):
                        m.next = "IDLE"

            with m.State("DROP"):
                m.d.comb += self.sink.ready.eq(1)
                with m.If(self.sink.valid & self.sink.last):
                    m.next = "IDLE"

        return m


class IPTXArbiter(wiring.Component):
    """Per-packet arbiter for IP TX users.

    One input port per name in ``users`` (priority follows list order), each
    with ``<name>`` (stream) and ``<name>_dst_ip``/``<name>_length``/
    ``<name>_protocol`` metadata, muxed onto a single output for
    :class:`~lambdaeth.core.ip.IPTX`.
    """
    def __init__(self, users):
        assert len(users) > 0
        self.users = list(users)
        members = {
            "source":   Out(eth_stream_signature()),
            "dst_ip":   Out(32),
            "length":   Out(16),
            "protocol": Out(8),
        }
        for name in self.users:
            members[name]               = In(eth_stream_signature())
            members[f"{name}_dst_ip"]   = In(32)
            members[f"{name}_length"]   = In(16)
            members[f"{name}_protocol"] = In(8)
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        with m.FSM():
            with m.State("IDLE"):
                # Reversed so that the first user in the list has priority
                # (later assignments override earlier ones).
                for name in reversed(self.users):
                    port = getattr(self, name)
                    with m.If(port.valid):
                        m.next = name.upper()

            for name in self.users:
                port = getattr(self, name)
                with m.State(name.upper()):
                    m.d.comb += [
                        self.source.valid.eq(port.valid),
                        self.source.payload.eq(port.payload),
                        self.source.first.eq(port.first),
                        self.source.last.eq(port.last),
                        port.ready.eq(self.source.ready),
                        self.dst_ip.eq(getattr(self, f"{name}_dst_ip")),
                        self.length.eq(getattr(self, f"{name}_length")),
                        self.protocol.eq(getattr(self, f"{name}_protocol")),
                    ]
                    with m.If(port.valid & port.ready & port.last):
                        m.next = "IDLE"

        return m
