#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""UDP layer: user stream port with sideband parameters.

The user faces two 8-bit streams (:func:`~lambdaeth.core.layouts.udp_user_signature`)
whose ``param`` struct carries, in natural byte order:

* ``ip``: peer IP address (destination on TX, source on RX).
* ``src_port``/``dst_port``: from the board's point of view.
* ``length``: UDP payload length in bytes.

:class:`UDPTX`/:class:`UDPRX` perform no port filtering: all valid UDP packets
addressed to the board are delivered with their ``dst_port`` in the parameters.
Port binding is layered on top with :class:`UDPPortDispatch` (RX demux by
destination port) and :class:`UDPPortArbiter` (TX mux with the source port
forced to the binding) — both shaped at build time from a name → port mapping,
like :mod:`~lambdaeth.core.dispatch`.
"""

from amaranth.hdl import Module, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_stream import Packetizer, Depacketizer

from .layouts import (eth_stream_signature, udp_user_signature, udp_header_layout,
                      bswap, UDP_HEADER_LEN, IPV4_PROTOCOL_UDP)


__all__ = ["UDPTX", "UDPRX", "UDPPortDispatch", "UDPPortArbiter"]


class UDPTX(wiring.Component):
    """UDP TX: packetize user datagrams for the IP layer.

    The ``sink`` parameters are latched on the first beat. The user must
    supply exactly ``length`` payload bytes, ``last`` on the final one.
    """
    def __init__(self):
        super().__init__({
            "sink":     In(udp_user_signature()),
            "source":   Out(eth_stream_signature()),
            # Metadata for the IP layer (valid while the packet streams).
            "dst_ip":   Out(32),
            "length":   Out(16),
            "protocol": Out(8),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.packetizer = pack = Packetizer(
            udp_header_layout, eth_stream_signature())

        # The packetizer free-runs; only expose its output while sending.
        src_connect = Signal()
        with m.If(src_connect):
            m.d.comb += [
                self.source.valid.eq(pack.o_stream.valid),
                self.source.payload.eq(pack.o_stream.payload),
                self.source.first.eq(pack.o_stream.first),
                self.source.last.eq(pack.o_stream.last),
                pack.o_stream.ready.eq(self.source.ready),
            ]

        # Latched parameters.
        peer_ip  = Signal(32)
        src_port = Signal(16)
        dst_port = Signal(16)
        length   = Signal(16)

        udp_length = Signal(16)
        m.d.comb += [
            udp_length.eq(length + UDP_HEADER_LEN),

            pack.header.src_port.eq(bswap(src_port)),
            pack.header.dst_port.eq(bswap(dst_port)),
            pack.header.length.eq(bswap(udp_length)),
            pack.header.checksum.eq(0),  # Optional for IPv4; the MAC FCS covers us.

            self.dst_ip.eq(peer_ip),
            self.length.eq(udp_length),
            self.protocol.eq(IPV4_PROTOCOL_UDP),
        ]

        with m.FSM():
            with m.State("IDLE"):
                with m.If(self.sink.valid):
                    m.d.sync += [
                        peer_ip.eq(self.sink.param.ip),
                        src_port.eq(self.sink.param.src_port),
                        dst_port.eq(self.sink.param.dst_port),
                        length.eq(self.sink.param.length),
                    ]
                    m.next = "SEND"

            with m.State("SEND"):
                m.d.comb += [
                    src_connect.eq(1),
                    pack.i_stream.valid.eq(self.sink.valid),
                    pack.i_stream.payload.eq(self.sink.payload),
                    pack.i_stream.first.eq(self.sink.first),
                    pack.i_stream.last.eq(self.sink.last),
                    self.sink.ready.eq(pack.i_stream.ready),
                ]
                with m.If(self.sink.valid & self.sink.ready & self.sink.last):
                    m.next = "IDLE"

        return m


class UDPRX(wiring.Component):
    """UDP RX: validate, trim to the datagram length and expose to the user.

    Metadata from the IP layer (``src_ip``/``ip_length``/``protocol``) must be
    valid while the first ``sink`` beat is offered.

    Ethernet frames are padded to 60 bytes, so short datagrams arrive with
    trailing padding: the stream is cut after ``length`` payload bytes and the
    remainder is discarded. Zero-length datagrams are dropped (a stream needs
    at least one beat).
    """
    def __init__(self):
        super().__init__({
            "sink":      In(eth_stream_signature()),
            "src_ip":    In(32),
            "ip_length": In(16),
            "protocol":  In(8),
            "source":    Out(udp_user_signature()),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.depacketizer = depack = Depacketizer(
            udp_header_layout, eth_stream_signature())

        hdr = depack.header

        # Latched metadata.
        peer_ip  = Signal(32)
        length   = Signal(16)   # UDP payload length.
        src_port = Signal(16)
        dst_port = Signal(16)

        count = Signal(16)

        # Parameters are from the packet's perspective: src_port = sender's
        # port, dst_port = the board's port the datagram was sent to.
        m.d.comb += [
            self.source.param.ip.eq(peer_ip),
            self.source.param.src_port.eq(src_port),
            self.source.param.dst_port.eq(dst_port),
            self.source.param.length.eq(length),
        ]

        udp_hdr_length = Signal(16)
        m.d.comb += udp_hdr_length.eq(bswap(hdr.length))

        with m.FSM():
            with m.State("IDLE"):
                m.d.comb += depack.i_stream.valid.eq(0)
                with m.If(self.sink.valid):
                    with m.If(self.protocol == IPV4_PROTOCOL_UDP):
                        m.d.sync += peer_ip.eq(self.src_ip)
                        m.next = "HEADER"
                    with m.Else():
                        m.next = "DROP_SINK"

            with m.State("HEADER"):
                # Let the depacketizer consume the UDP header.
                m.d.comb += [
                    depack.i_stream.valid.eq(self.sink.valid),
                    depack.i_stream.payload.eq(self.sink.payload),
                    depack.i_stream.first.eq(self.sink.first),
                    depack.i_stream.last.eq(self.sink.last),
                    self.sink.ready.eq(depack.i_stream.ready),
                ]
                with m.If(depack.o_stream.valid):
                    # Header complete; first payload beat waiting.
                    m.d.sync += [
                        src_port.eq(bswap(hdr.src_port)),
                        dst_port.eq(bswap(hdr.dst_port)),
                        length.eq(udp_hdr_length - UDP_HEADER_LEN),
                        count.eq(0),
                    ]
                    with m.If((udp_hdr_length < UDP_HEADER_LEN + 1)):
                        # Zero-length (or malformed) datagram: drop.
                        m.next = "DROP"
                    with m.Else():
                        m.next = "RECEIVE"
                with m.Elif(self.sink.valid & self.sink.ready & self.sink.last):
                    # Runt: the depacketizer resynchronized; so do we.
                    m.next = "IDLE"

            with m.State("RECEIVE"):
                m.d.comb += [
                    depack.i_stream.valid.eq(self.sink.valid),
                    depack.i_stream.payload.eq(self.sink.payload),
                    depack.i_stream.first.eq(self.sink.first),
                    depack.i_stream.last.eq(self.sink.last),
                    self.sink.ready.eq(depack.i_stream.ready),

                    self.source.valid.eq(depack.o_stream.valid),
                    self.source.payload.eq(depack.o_stream.payload),
                    self.source.first.eq(count == 0),
                    self.source.last.eq(depack.o_stream.last |
                                        (count == length - 1)),
                    depack.o_stream.ready.eq(self.source.ready),
                ]
                with m.If(self.source.valid & self.source.ready):
                    m.d.sync += count.eq(count + 1)
                    with m.If(depack.o_stream.last):
                        m.next = "IDLE"
                    with m.Elif(self.source.last):
                        # Datagram complete; discard the frame padding.
                        m.next = "DROP"

            with m.State("DROP"):
                # Drain the depacketizer output (padding beats).
                m.d.comb += [
                    depack.i_stream.valid.eq(self.sink.valid),
                    depack.i_stream.payload.eq(self.sink.payload),
                    depack.i_stream.first.eq(self.sink.first),
                    depack.i_stream.last.eq(self.sink.last),
                    self.sink.ready.eq(depack.i_stream.ready),
                    depack.o_stream.ready.eq(1),
                ]
                with m.If(depack.o_stream.valid & depack.o_stream.last):
                    m.next = "IDLE"

            with m.State("DROP_SINK"):
                # Not UDP: discard the raw IP payload.
                m.d.comb += self.sink.ready.eq(1)
                with m.If(self.sink.valid & self.sink.last):
                    m.next = "IDLE"

        return m


def _check_port_map(ports, allow_passthrough=False):
    """Validate a user-port name → UDP port number mapping.

    With ``allow_passthrough``, a ``None`` number is accepted (arbiter
    entries that keep the user-supplied ``src_port``).
    """
    ports = dict(ports)
    assert len(ports) > 0
    numbers = []
    for name, number in ports.items():
        assert name.isidentifier(), \
            f"user port name {name!r} must be a valid identifier"
        assert name.upper() not in ("IDLE", "DROP"), \
            f"user port name {name!r} collides with an FSM state"
        if number is None and allow_passthrough:
            continue
        assert isinstance(number, int) and 0 <= number <= 0xffff, \
            f"invalid UDP port number {number!r} for {name!r}"
        numbers.append(number)
    assert len(set(numbers)) == len(numbers), "duplicate UDP port numbers"
    return ports


class UDPPortDispatch(wiring.Component):
    """Route received datagrams to bound user ports by destination UDP port.

    ``ports`` maps user port names to their default UDP port numbers. One
    output stream is created per entry (``<name>``), along with a
    ``<name>_port`` input holding the port number to match — initialized to
    the default, so it may be left undriven or fanned out from a CSR.

    Parameters pass through unchanged (``dst_port`` equals the matched port).
    Datagrams whose ``dst_port`` matches no user port are discarded (``drop``
    pulses once per discarded datagram) — unless ``default`` names an extra
    catch-all output stream, which then receives them instead (with their
    original parameters; used e.g. to keep an unfiltered user stream next to
    the DHCP client's port binding). If several user ports hold the same
    number at runtime, the first one in the mapping wins.

    With a single entry this is already the minimal port filter (one compare,
    forward-or-drop FSM) — filtering is required even for one bound port.
    """
    def __init__(self, ports, default=None):
        self.ports   = _check_port_map(ports)
        self.default = default
        members = {
            "sink": In(udp_user_signature()),
            "drop": Out(1),
        }
        for name, number in self.ports.items():
            members[name]           = Out(udp_user_signature())
            members[f"{name}_port"] = In(16, init=number)
        if default is not None:
            assert default.isidentifier() and default not in self.ports
            assert default.upper() not in ("IDLE", "DROP")
            members[default] = Out(udp_user_signature())
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        forward_names = list(self.ports)
        if self.default is not None:
            forward_names.append(self.default)

        with m.FSM():
            with m.State("IDLE"):
                with m.If(self.sink.valid):
                    if self.default is not None:
                        m.next = self.default.upper()
                    else:
                        m.next = "DROP"
                    # Reversed so that the first user port in the mapping wins
                    # (later assignments override earlier ones).
                    for name in reversed(self.ports):
                        with m.If(self.sink.param.dst_port ==
                                  getattr(self, f"{name}_port")):
                            m.next = name.upper()

            for name in forward_names:
                port = getattr(self, name)
                with m.State(name.upper()):
                    m.d.comb += [
                        port.valid.eq(self.sink.valid),
                        port.payload.eq(self.sink.payload),
                        port.param.eq(self.sink.param),
                        port.first.eq(self.sink.first),
                        port.last.eq(self.sink.last),
                        self.sink.ready.eq(port.ready),
                    ]
                    with m.If(self.sink.valid & self.sink.ready & self.sink.last):
                        m.next = "IDLE"

            if self.default is None:
                with m.State("DROP"):
                    m.d.comb += self.sink.ready.eq(1)
                    with m.If(self.sink.valid & self.sink.last):
                        m.d.comb += self.drop.eq(1)
                        m.next = "IDLE"

        return m


class UDPPortArbiter(wiring.Component):
    """Per-datagram arbiter for user TX streams bound to UDP ports.

    One input stream per entry in ``ports`` (name → default port number;
    priority follows mapping order), muxed onto a single ``source`` for
    :class:`UDPTX`. Stream parameters pass through except ``src_port``, which
    is forced to the user port's bound number (``<name>_port``, initialized
    to the default) — a bound port always sends from its own port. An entry
    whose number is ``None`` is a *passthrough*: its user keeps the
    ``src_port`` it supplies (no ``<name>_port`` input is created).

    With a single entry there is nothing to arbitrate: no FSM or muxes are
    generated at all, only the wiring and the ``src_port`` substitution.
    """
    def __init__(self, ports):
        self.ports = _check_port_map(ports, allow_passthrough=True)
        members = {
            "source": Out(udp_user_signature()),
        }
        for name, number in self.ports.items():
            members[name] = In(udp_user_signature())
            if number is not None:
                members[f"{name}_port"] = In(16, init=number)
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        def forward(port, name):
            stmts = [
                self.source.valid.eq(port.valid),
                self.source.payload.eq(port.payload),
                self.source.param.eq(port.param),
                self.source.first.eq(port.first),
                self.source.last.eq(port.last),
                port.ready.eq(self.source.ready),
            ]
            if self.ports[name] is not None:
                stmts.append(self.source.param.src_port
                             .eq(getattr(self, f"{name}_port")))
            return stmts

        if len(self.ports) == 1:
            # Single user port: degenerate to plain wiring (no FSM, no LUTs
            # beyond the src_port substitution, which is itself just wires).
            (name,) = self.ports
            m.d.comb += forward(getattr(self, name), name)
            return m

        with m.FSM():
            with m.State("IDLE"):
                # Reversed so that the first user port in the mapping has
                # priority (later assignments override earlier ones).
                for name in reversed(self.ports):
                    port = getattr(self, name)
                    with m.If(port.valid):
                        m.next = name.upper()

            for name in self.ports:
                port = getattr(self, name)
                with m.State(name.upper()):
                    m.d.comb += forward(port, name)
                    with m.If(port.valid & port.ready & port.last):
                        m.next = "IDLE"

        return m
