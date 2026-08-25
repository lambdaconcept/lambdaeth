#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""UDP/IP core: ARP + IPv4 + UDP over a MAC frame boundary.

The core runs entirely in the ``sync`` domain on 8-bit streams. ``mac_rx``
and ``mac_tx`` carry complete Ethernet frames (no preamble/FCS); the UDP user
port is a pair of parameterized byte streams (see
:func:`~lambdaeth.core.layouts.udp_user_signature`).

The MAC and IP addresses are plain inputs, intended to be driven from CSR
registers. Configure them before traffic flows (they are sampled per packet).
"""

from amaranth.hdl import Cat, Module, Mux, Signal
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out, connect, flipped

from .layouts import (eth_stream_signature, udp_user_signature,
                      IPV4_PROTOCOL_UDP, IPV4_PROTOCOL_ICMP, IPV4_PROTOCOL_TCP)
from .mac_dispatch import MACDispatch
from .arp import ARP
from .ip import IPTX, IPRX
from .udp import UDPTX, UDPRX, UDPPortDispatch, UDPPortArbiter
from .icmp import ICMPEcho
from .tcp import (TCPServer, TCPClient, TCPRX, TCPEngine, TCPSegDispatch,
                  TCPTXArbiter)
from .dhcp import DHCPClient, DHCP_CLIENT_PORT
from .dispatch import IPRXDispatch, IPTXArbiter


__all__ = ["UDPIPCore", "TCPServer", "TCPClient",
           "eth_stream_signature", "udp_user_signature"]


def _normalize_udp_ports(udp_ports):
    """Normalize the ``udp_ports`` parameter to ``None`` or ``{name: port}``.

    A list/tuple of port numbers is auto-named by index (``p0``, ``p1``, ...);
    a mapping is taken as-is (insertion order = TX priority).
    """
    if udp_ports is None:
        return None
    if not isinstance(udp_ports, dict):
        udp_ports = {f"p{i}": port for i, port in enumerate(udp_ports)}
    return dict(udp_ports)


def _normalize_tcp_ports(tcp_ports):
    """Normalize ``tcp_ports`` to ``None`` or ``{name: TCPServer|TCPClient}``.

    Entries may be plain port numbers (server shorthand), :class:`TCPServer`
    or :class:`TCPClient` specs; lists are auto-named by index. Clients
    without an explicit ``local_port`` get one from the ephemeral range
    (49152 + entry index). Local ports must be unique — they route received
    segments to their engine.
    """
    if tcp_ports is None:
        return None
    if not isinstance(tcp_ports, dict):
        tcp_ports = {f"p{i}": spec for i, spec in enumerate(tcp_ports)}
    specs = {}
    for index, (name, spec) in enumerate(tcp_ports.items()):
        if isinstance(spec, int):
            spec = TCPServer(spec)
        assert isinstance(spec, (TCPServer, TCPClient)), \
            f"tcp_ports[{name!r}]: expected int, TCPServer or TCPClient"
        if spec.local_port is None:
            spec.local_port = 49152 + index
        specs[name] = spec
    locals_ = [spec.local_port for spec in specs.values()]
    assert len(set(locals_)) == len(locals_), \
        f"duplicate TCP local ports: {locals_}"
    return specs


class UDPIPCore(wiring.Component):
    """ARP responder/resolver + IPv4 + UDP (+ optional ICMP echo).

    Parameters
    ----------
    clk_freq : float
        ``sync`` clock frequency (ARP timers).
    arp_entries : int
        ARP cache size.
    with_icmp : bool
        Build the ICMP echo responder (ping). When False, no ICMP logic is
        generated at all: the IP protocol dispatch and TX arbiter shrink to
        the UDP-only fast path and ICMP packets are dropped.
    icmp_fifo_depth : int
        Largest echo data size answered, in bytes.
    udp_ports : None, list of int, or dict of {str: int}
        UDP user port layout, fixed at build time:

        * ``None`` (default): a single *unbound* stream pair ``udp_tx`` /
          ``udp_rx`` receives datagrams to any port and sends from any
          ``src_port`` the user supplies.
        * list/dict: one *bound* stream pair per requested UDP port
          (lists are auto-named by index: ``p0``, ``p1``, ...). Each pair
          only receives datagrams addressed to its port and always sends
          from it; datagrams to unbound ports are dropped (``udp_drop``
          pulses).
        Only the logic the request calls for is generated: the RX
          dispatch is a minimal per-port filter and the TX arbiter
          disappears entirely for a single port.
    tcp_ports : None, list, or dict of {str: spec}
        TCP endpoints, fixed at build time (lists auto-named ``p0``, ...).
        Each entry builds one :class:`~lambdaeth.core.tcp.TCPEngine` (one
        connection at a time) with a byte-stream pair ``tcp_rx_<name>`` /
        ``tcp_tx_<name>`` plus connection controls. An entry is either:

        * an ``int`` or :class:`~lambdaeth.core.tcp.TCPServer` — passive
          open: listen on that port;
        * a :class:`~lambdaeth.core.tcp.TCPClient` — active open: connect
          out to ``ip:port`` (retrying forever, reconnecting after close),
          with ``tcp_remote_ip_<name>``/``tcp_remote_port_<name>`` inputs
          for runtime retargeting.

        ``None`` (default) generates no TCP logic at all. Segments to
        unbound ports are refused with RST; corrupt/malformed segments pulse
        ``tcp_drop``. As with UDP, single-endpoint requests skip all
        arbitration logic.
    tcp_mss, tcp_rx_depth, tcp_rto, tcp_max_retries, tcp_idle_timeout,
    tcp_reconnect_delay
        TCP engine tuning, see :class:`~lambdaeth.core.tcp.TCPEngine`.
    with_dhcp : bool
        Build a DHCP client (:class:`~lambdaeth.core.dhcp.DHCPClient`) on a
        hidden UDP port-68 binding. The core then *owns* its IP address:
        the ``ip_address`` input is replaced by ``dhcp_ip``/``dhcp_bound``
        outputs, the effective address is 0.0.0.0 until a lease is bound
        (nothing is answered before that) and TCP client endpoints hold
        their connection attempts until bound. UDP port 68 is reserved.
        When False (default), no DHCP logic is generated at all.
    dhcp_retry, dhcp_ticks_per_sec
        DHCP client tuning, see :class:`~lambdaeth.core.dhcp.DHCPClient`.

    Ports
    -----
    mac_rx : In(eth_stream_signature())
        Received Ethernet frames (after preamble/CRC stripping).
    mac_tx : Out(eth_stream_signature())
        Ethernet frames to transmit (before preamble/CRC insertion).
    udp_tx : In(udp_user_signature())
        User datagrams to send (only when ``udp_ports=None``).
    udp_rx : Out(udp_user_signature())
        Received user datagrams (only when ``udp_ports=None``).
    udp_tx_<name>, udp_rx_<name> : In/Out(udp_user_signature())
        Bound user stream pairs (only with ``udp_ports``), one per entry.
    udp_port_<name> : In(16)
        Runtime port binding, initialized to the build-time number (leave
        undriven for a fixed port, or drive from a CSR to rebind at runtime).
    tcp_rx_<name>, tcp_tx_<name> : Out/In(eth_stream_signature())
        Per-endpoint TCP byte streams (only with ``tcp_ports``): received
        payload (one stream packet per segment) and bytes to send (cut into
        segments at ``tcp_mss`` or ``last``).
    tcp_port_<name> : In(16)
        Runtime local port binding — the listen port (server) or source
        port (client). Rebinds take effect for the next connection; the
        active connection keeps its port.
    tcp_remote_ip_<name>, tcp_remote_port_<name> : In(32)/In(16)
        Client endpoints only: the target to connect to (retargeting takes
        effect at the next connection attempt).
    tcp_connected_<name>, tcp_peer_closed_<name> : Out(1)
        Connection status. tcp_close_<name> : In(1) requests the final FIN
        once the peer has closed and the application drained its data.
    mac_address : In(48), ip_address : In(32)
        Board addresses (natural byte order), typically CSR-driven. With
        ``with_dhcp`` there is no ``ip_address`` input; instead ``dhcp_ip``
        (Out(32), the leased address, 0 while unbound), ``dhcp_bound``
        (Out(1)) and ``dhcp_event`` (Out(1), pulse per bind/renewal) exist.
    arp_event, udp_rx_pkt, udp_tx_pkt, unreachable : Out(1)
        Single-cycle status pulses (for counters/LEDs). RX/TX pulses count
        datagrams delivered to / accepted from any user port.
    udp_drop : Out(1)
        Pulse per datagram dropped for want of a matching bound port (only
        present with ``udp_ports``).
    tcp_rx_seg, tcp_tx_seg, tcp_drop, tcp_rst : Out(1)
        TCP status pulses (only with ``tcp_ports``): accepted segment,
        transmitted segment, discarded segment, RST sent.
    icmp_pkt : Out(1)
        Pulse per answered ping (only present when ``with_icmp=True``).
    """
    def __init__(self, clk_freq, arp_entries=4, with_icmp=True,
                 icmp_fifo_depth=2048, udp_ports=None, tcp_ports=None,
                 tcp_mss=536, tcp_rx_depth=2048, tcp_rto=0.5,
                 tcp_max_retries=8, tcp_idle_timeout=60.0,
                 tcp_reconnect_delay=1.0, with_dhcp=False, dhcp_retry=4.0,
                 dhcp_ticks_per_sec=None):
        self.clk_freq        = clk_freq
        self.arp_entries     = arp_entries
        self.with_icmp       = with_icmp
        self.icmp_fifo_depth = icmp_fifo_depth
        self.udp_ports       = _normalize_udp_ports(udp_ports)
        self.tcp_ports       = _normalize_tcp_ports(tcp_ports)
        self.tcp_mss         = tcp_mss
        self.tcp_rx_depth    = tcp_rx_depth
        self.tcp_rto         = tcp_rto
        self.tcp_max_retries = tcp_max_retries
        self.tcp_idle_timeout = tcp_idle_timeout
        self.tcp_reconnect_delay = tcp_reconnect_delay
        self.with_dhcp       = with_dhcp
        self.dhcp_retry      = dhcp_retry
        self.dhcp_ticks_per_sec = dhcp_ticks_per_sec
        if with_dhcp and self.udp_ports is not None:
            assert DHCP_CLIENT_PORT not in self.udp_ports.values(), \
                "UDP port 68 is reserved by the DHCP client"
            assert "dhcp" not in self.udp_ports, \
                "the user port name 'dhcp' is reserved with with_dhcp"

        members = {
            "mac_rx":      In(eth_stream_signature()),
            "mac_tx":      Out(eth_stream_signature()),
            "mac_address": In(48),
            "arp_event":   Out(1),
            "udp_rx_pkt":  Out(1),
            "udp_tx_pkt":  Out(1),
            "unreachable": Out(1),
        }
        if with_dhcp:
            members["dhcp_ip"]    = Out(32)
            members["dhcp_bound"] = Out(1)
            members["dhcp_event"] = Out(1)
        else:
            members["ip_address"] = In(32)
        if self.udp_ports is None:
            members["udp_tx"] = In(udp_user_signature())
            members["udp_rx"] = Out(udp_user_signature())
        else:
            for name, number in self.udp_ports.items():
                members[f"udp_tx_{name}"]   = In(udp_user_signature())
                members[f"udp_rx_{name}"]   = Out(udp_user_signature())
                members[f"udp_port_{name}"] = In(16, init=number)
            members["udp_drop"] = Out(1)
        if self.tcp_ports is not None:
            for name, spec in self.tcp_ports.items():
                members[f"tcp_rx_{name}"]          = Out(eth_stream_signature())
                members[f"tcp_tx_{name}"]          = In(eth_stream_signature())
                members[f"tcp_port_{name}"]        = In(16, init=spec.local_port)
                members[f"tcp_connected_{name}"]   = Out(1)
                members[f"tcp_peer_closed_{name}"] = Out(1)
                members[f"tcp_close_{name}"]       = In(1)
                if spec.mode == "client":
                    members[f"tcp_remote_ip_{name}"] = \
                        In(32, init=spec.remote_ip)
                    members[f"tcp_remote_port_{name}"] = \
                        In(16, init=spec.remote_port)
            members["tcp_rx_seg"] = Out(1)
            members["tcp_tx_seg"] = Out(1)
            members["tcp_drop"]   = Out(1)
            members["tcp_rst"]    = Out(1)
        if with_icmp:
            members["icmp_pkt"] = Out(1)
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        m.submodules.dispatch = dispatch = MACDispatch()
        m.submodules.arp      = arp      = ARP(self.clk_freq, entries=self.arp_entries)
        m.submodules.ip_tx    = ip_tx    = IPTX()
        m.submodules.ip_rx    = ip_rx    = IPRX()
        m.submodules.udp_tx_l = udp_tx_l = UDPTX()
        m.submodules.udp_rx_l = udp_rx_l = UDPRX()

        # Effective IP address: static input, or DHCP-owned (0.0.0.0 while
        # unbound, so nothing is answered before the lease).
        if self.with_dhcp:
            m.submodules.dhcp = dhcp = DHCPClient(
                self.clk_freq, retry=self.dhcp_retry,
                ticks_per_sec=self.dhcp_ticks_per_sec)
            # Registered: address changes are rare, and this keeps the mux
            # out of the IP RX/TX compare paths.
            eff_ip = Signal(32)
            m.d.sync += eff_ip.eq(Mux(dhcp.bound, dhcp.leased_ip, 0))
            m.d.comb += [
                dhcp.mac_address.eq(self.mac_address),
                self.dhcp_ip.eq(dhcp.leased_ip),
                self.dhcp_bound.eq(dhcp.bound),
                self.dhcp_event.eq(dhcp.event),
            ]
        else:
            dhcp   = None
            eff_ip = self.ip_address

        # Addresses.
        for mod in (dispatch, arp, ip_tx):
            m.d.comb += mod.mac_address.eq(self.mac_address)
        for mod in (arp, ip_tx, ip_rx):
            m.d.comb += mod.ip_address.eq(eff_ip)

        # MAC boundary.
        connect(m, flipped(self.mac_rx), dispatch.rx)
        connect(m, dispatch.tx, flipped(self.mac_tx))

        # ARP <-> dispatch.
        connect(m, dispatch.arp_rx, arp.rx_sink)
        connect(m, arp.tx_source, dispatch.arp_tx)
        m.d.comb += dispatch.arp_tx_mac.eq(arp.tx_mac)

        # IP <-> dispatch.
        connect(m, dispatch.ip_rx, ip_rx.sink)
        connect(m, ip_tx.source, dispatch.ip_tx)
        m.d.comb += dispatch.ip_tx_mac.eq(ip_tx.target_mac)

        # IP TX <-> ARP table.
        connect(m, ip_tx.arp_request, arp.request)
        connect(m, arp.response, ip_tx.arp_response)

        # IP RX metadata fans out to all protocol handlers.
        m.d.comb += [
            udp_rx_l.src_ip.eq(ip_rx.src_ip),
            udp_rx_l.ip_length.eq(ip_rx.length),
            udp_rx_l.protocol.eq(ip_rx.protocol),
        ]

        # IP protocol composition: dispatch/arbiter shaped by what is
        # enabled. Priority: control (ICMP) first, TCP (timely ACKs) before
        # UDP bulk.
        protocols = {"udp": IPV4_PROTOCOL_UDP}
        if self.with_icmp:
            protocols["icmp"] = IPV4_PROTOCOL_ICMP
        if self.tcp_ports is not None:
            protocols["tcp"] = IPV4_PROTOCOL_TCP

        if len(protocols) == 1:
            # UDP-only fast path (UDPRX drops non-UDP protocols itself).
            connect(m, ip_rx.source, udp_rx_l.sink)
            connect(m, udp_tx_l.source, ip_tx.sink)
            m.d.comb += [
                ip_tx.dst_ip.eq(udp_tx_l.dst_ip),
                ip_tx.length.eq(udp_tx_l.length),
                ip_tx.protocol.eq(udp_tx_l.protocol),
            ]
        else:
            tx_users = [name for name in ("icmp", "tcp", "udp")
                        if name in protocols]
            m.submodules.rx_dispatch = rx_dispatch = IPRXDispatch(protocols)
            m.submodules.tx_arbiter  = tx_arbiter  = IPTXArbiter(tx_users)

            connect(m, ip_rx.source, rx_dispatch.sink)
            m.d.comb += rx_dispatch.protocol.eq(ip_rx.protocol)
            connect(m, rx_dispatch.udp, udp_rx_l.sink)

            connect(m, udp_tx_l.source, tx_arbiter.udp)
            m.d.comb += [
                tx_arbiter.udp_dst_ip.eq(udp_tx_l.dst_ip),
                tx_arbiter.udp_length.eq(udp_tx_l.length),
                tx_arbiter.udp_protocol.eq(udp_tx_l.protocol),
            ]

            if self.with_icmp:
                m.submodules.icmp = icmp = ICMPEcho(
                    fifo_depth=self.icmp_fifo_depth)
                connect(m, rx_dispatch.icmp, icmp.sink)
                m.d.comb += [
                    icmp.src_ip.eq(ip_rx.src_ip),
                    icmp.ip_length.eq(ip_rx.length),
                    icmp.protocol.eq(ip_rx.protocol),
                ]
                connect(m, icmp.source, tx_arbiter.icmp)
                m.d.comb += [
                    tx_arbiter.icmp_dst_ip.eq(icmp.dst_ip),
                    tx_arbiter.icmp_length.eq(icmp.length),
                    tx_arbiter.icmp_protocol.eq(icmp.out_protocol),
                    self.icmp_pkt.eq(icmp.echo_pkt),
                ]

            if self.tcp_ports is not None:
                self._elaborate_tcp(m, ip_rx, rx_dispatch, tx_arbiter,
                                    eff_ip, dhcp)

            connect(m, tx_arbiter.source, ip_tx.sink)
            m.d.comb += [
                ip_tx.dst_ip.eq(tx_arbiter.dst_ip),
                ip_tx.length.eq(tx_arbiter.length),
                ip_tx.protocol.eq(tx_arbiter.protocol),
            ]

        # User ports. The DHCP client, when enabled, occupies a hidden
        # "dhcp" (port 68) entry of the same dispatch/arbiter machinery.
        dhcp_map = {"dhcp": DHCP_CLIENT_PORT} if self.with_dhcp else {}
        if self.udp_ports is None and not self.with_dhcp:
            # Single unbound pair: straight to the UDP layer, no extra logic.
            connect(m, flipped(self.udp_tx), udp_tx_l.sink)
            connect(m, udp_rx_l.source, flipped(self.udp_rx))
            rx_streams = [self.udp_rx]
            tx_streams = [self.udp_tx]
        elif self.udp_ports is None:
            # Unbound pair next to the DHCP binding: port 68 is filtered
            # out, everything else passes through to the user unchanged
            # (including the user's own src_port on TX).
            m.submodules.port_dispatch = port_dispatch = \
                UDPPortDispatch(dhcp_map, default="user")
            m.submodules.port_arbiter = port_arbiter = \
                UDPPortArbiter({**dhcp_map, "user": None})
            connect(m, udp_rx_l.source, port_dispatch.sink)
            connect(m, port_arbiter.source, udp_tx_l.sink)
            connect(m, port_dispatch.user, flipped(self.udp_rx))
            connect(m, flipped(self.udp_tx), port_arbiter.user)
            connect(m, port_dispatch.dhcp, dhcp.sink)
            connect(m, dhcp.source, port_arbiter.dhcp)
            rx_streams = [self.udp_rx]
            tx_streams = [self.udp_tx]
        else:
            # Bound pairs behind the port filter and TX arbiter, both shaped
            # by the request (the arbiter is pure wiring for a single port).
            m.submodules.port_dispatch = port_dispatch = \
                UDPPortDispatch({**dhcp_map, **self.udp_ports})
            m.submodules.port_arbiter = port_arbiter = \
                UDPPortArbiter({**dhcp_map, **self.udp_ports})
            connect(m, udp_rx_l.source, port_dispatch.sink)
            connect(m, port_arbiter.source, udp_tx_l.sink)
            if self.with_dhcp:
                connect(m, port_dispatch.dhcp, dhcp.sink)
                connect(m, dhcp.source, port_arbiter.dhcp)
            for name in self.udp_ports:
                number = getattr(self, f"udp_port_{name}")
                connect(m, getattr(port_dispatch, name),
                        flipped(getattr(self, f"udp_rx_{name}")))
                connect(m, flipped(getattr(self, f"udp_tx_{name}")),
                        getattr(port_arbiter, name))
                m.d.comb += [
                    getattr(port_dispatch, f"{name}_port").eq(number),
                    getattr(port_arbiter,  f"{name}_port").eq(number),
                ]
            m.d.comb += self.udp_drop.eq(port_dispatch.drop)
            rx_streams = [getattr(self, f"udp_rx_{name}") for name in self.udp_ports]
            tx_streams = [getattr(self, f"udp_tx_{name}") for name in self.udp_ports]

        # Status pulses. At most one user stream completes per cycle on each
        # side (single RX dispatch / TX arbiter), so the OR counts datagrams.
        m.d.comb += [
            self.arp_event.eq(arp.event),
            self.udp_rx_pkt.eq(Cat(*(s.valid & s.ready & s.last
                                     for s in rx_streams)).any()),
            self.udp_tx_pkt.eq(Cat(*(s.valid & s.ready & s.last
                                     for s in tx_streams)).any()),
            self.unreachable.eq(ip_tx.unreachable),
        ]

        return m

    def _elaborate_tcp(self, m, ip_rx, rx_dispatch, tx_arbiter, eff_ip, dhcp):
        """One engine per endpoint (server or client) behind a shared
        validating RX and a TX arbiter (both pure wiring for one endpoint)."""
        m.submodules.tcp_rx = tcp_rx = TCPRX(buf_depth=self.tcp_rx_depth)
        connect(m, rx_dispatch.tcp, tcp_rx.sink)
        m.d.comb += [
            tcp_rx.src_ip.eq(ip_rx.src_ip),
            tcp_rx.ip_length.eq(ip_rx.length),
            tcp_rx.protocol.eq(ip_rx.protocol),
            tcp_rx.ip_address.eq(eff_ip),
        ]

        local_ports = {name: spec.local_port
                       for name, spec in self.tcp_ports.items()}
        m.submodules.tcp_dispatch = tcp_dispatch = TCPSegDispatch(local_ports)
        m.submodules.tcp_arbiter = tcp_arbiter = TCPTXArbiter(local_ports)
        m.d.comb += [
            tcp_dispatch.seg.eq(tcp_rx.seg),
            tcp_dispatch.seg_stb.eq(tcp_rx.seg_stb),
            tcp_rx.seg_done.eq(tcp_dispatch.seg_done),
        ]
        connect(m, tcp_rx.seg_payload, tcp_dispatch.seg_payload)

        sent = []
        rsts = []
        for name, spec in self.tcp_ports.items():
            eng = TCPEngine(self.clk_freq,
                            mode             = spec.mode,
                            port_init        = spec.local_port,
                            remote_ip_init   = spec.remote_ip,
                            remote_port_init = spec.remote_port,
                            mss              = self.tcp_mss,
                            rx_depth         = self.tcp_rx_depth,
                            rto              = self.tcp_rto,
                            max_retries      = self.tcp_max_retries,
                            idle_timeout     = self.tcp_idle_timeout,
                            reconnect_delay  = self.tcp_reconnect_delay)
            m.submodules[f"tcp_{name}"] = eng

            port_sig = getattr(self, f"tcp_port_{name}")
            m.d.comb += [
                eng.local_port.eq(port_sig),
                eng.ip_address.eq(eff_ip),
                getattr(tcp_dispatch, f"{name}_port").eq(port_sig),
                eng.seg.eq(getattr(tcp_dispatch, f"{name}_seg")),
                eng.seg_stb.eq(getattr(tcp_dispatch, f"{name}_seg_stb")),
                getattr(tcp_dispatch, f"{name}_seg_done").eq(eng.seg_done),
            ]
            connect(m, getattr(tcp_dispatch, f"{name}_seg_payload"),
                    eng.seg_payload)
            if spec.mode == "client":
                m.d.comb += [
                    eng.remote_ip.eq(getattr(self, f"tcp_remote_ip_{name}")),
                    eng.remote_port
                        .eq(getattr(self, f"tcp_remote_port_{name}")),
                ]
                if dhcp is not None:
                    # No connection attempts before an address is leased.
                    m.d.comb += eng.enable.eq(dhcp.bound)

            # User streams and connection control.
            connect(m, eng.rx_source, flipped(getattr(self, f"tcp_rx_{name}")))
            connect(m, flipped(getattr(self, f"tcp_tx_{name}")), eng.tx_sink)
            m.d.comb += [
                getattr(self, f"tcp_connected_{name}").eq(eng.connected),
                getattr(self, f"tcp_peer_closed_{name}").eq(eng.peer_closed),
                eng.close.eq(getattr(self, f"tcp_close_{name}")),
            ]

            # TX towards the IP arbiter.
            connect(m, eng.source, getattr(tcp_arbiter, name))
            m.d.comb += [
                getattr(tcp_arbiter, f"{name}_dst_ip").eq(eng.dst_ip),
                getattr(tcp_arbiter, f"{name}_length").eq(eng.length),
            ]
            sent.append(eng.seg_sent)
            rsts.append(eng.rst_sent)

        connect(m, tcp_arbiter.source, tx_arbiter.tcp)
        m.d.comb += [
            tx_arbiter.tcp_dst_ip.eq(tcp_arbiter.dst_ip),
            tx_arbiter.tcp_length.eq(tcp_arbiter.length),
            tx_arbiter.tcp_protocol.eq(tcp_arbiter.protocol),
            # Engine emissions are serialized by the arbiter, so the ORs
            # count segments exactly.
            self.tcp_rx_seg.eq(tcp_rx.seg_pulse),
            self.tcp_drop.eq(tcp_rx.drop),
            self.tcp_tx_seg.eq(Cat(*sent).any()),
            self.tcp_rst.eq(Cat(*rsts).any()),
        ]
