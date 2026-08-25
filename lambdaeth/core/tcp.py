#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""TCP layer: one connection engine per user endpoint, server or client.

Model (mirrors the UDP port binding): each requested endpoint gets its own
:class:`TCPEngine` with one user sink/source byte-stream pair. A shared
:class:`TCPRX` validates and buffers incoming segments (store-and-forward, so
the RX chain is never held hostage), :class:`TCPSegDispatch` routes them to
the engine bound to the (local) destination port, and :class:`TCPTXArbiter`
muxes the engines' outgoing segments into the IP TX path. Segments to
unbound ports are routed to the first engine, whose foreign-segment logic
refuses them with RST (connection refused), matching LwIP/RFC 9293
conventions.

The mode is fixed at instantiation (:class:`TCPServer` / :class:`TCPClient`
specs at the core level) and only shapes the *opening* of a connection —
everything from ESTABLISHED on (data transfer, stop-and-wait TX,
retransmission, RST handling, closing) is the same logic in both modes, and
the netlist only contains the opening path of the chosen mode:

* **server** (passive open): LISTEN → SYN-RCVD → ESTABLISHED. Waits for a
  client on ``local_port``; connection attempts while busy are refused.
* **client** (active open): idle → SYN-SENT → ESTABLISHED. Connects from
  ``local_port`` to ``remote_ip:remote_port``; the SYN is retransmitted on
  timeout, and after ``max_retries`` (or an RST refusal, or a finished/
  aborted connection) the engine waits ``reconnect_delay`` and starts over —
  the client keeps trying forever, so it reconnects by itself.

v1 scope (deliberate, mirrors how UDP/ICMP were landed):

* One connection per engine. Both modes only ever *close passively*: the
  peer sends the first FIN (CLOSE-WAIT → LAST-ACK; no FIN-WAIT/TIME-WAIT).
  A lost peer is reaped by an idle timeout (RST + back to start).
* Stop-and-wait TX: a single in-flight segment, retransmitted from a replay
  buffer on timeout; the connection is aborted after ``max_retries``.
  Segments are cut at the *effective* MSS — ``min(mss, peer MSS, 536 when
  the peer sent no option)`` — or at the user's ``last``; larger user
  packets are split.
* RX: in-order only. Out-of-order/unacceptable segments are dropped and
  answered with a duplicate ACK (the peer retransmits). Every acceptable
  data/FIN segment is ACKed immediately. The advertised window tracks the
  free space of the internal RX buffer, so accepted data is never lost.
* The MSS option is the only option used: SYN/SYN-ACK advertise ``mss``
  (so the peer may fill our buffers, e.g. ``mss=1460`` for full frames)
  and the peer's MSS is parsed and honoured on TX. All other received
  options are skipped (but checksummed). No congestion control, window
  scaling, SACK, Nagle, zero-window probing, delayed ACKs, or simultaneous
  open.
* ``close`` is only honoured in CLOSE-WAIT (after ``peer_closed``): assert it
  once the application has queued its final data; the engine then drains its
  TX, sends FIN and finishes the shutdown once the FIN is ACKed.
* The client reuses its fixed ``local_port`` for every attempt; a peer stuck
  in TIME-WAIT answers the new SYN with a stale ACK, which we RST, killing
  the old state — the following retry then connects (self-healing).

Sequence-number comparisons are equality-only (in-order engine), which is
wraparound-safe by construction.
"""

from amaranth.hdl import Module, Signal, Cat, Mux, Array, Const
from amaranth.lib import wiring, enum
from amaranth.lib.data import StructLayout
from amaranth.lib.memory import Memory
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_stream import Depacketizer, PacketFIFO

from ..common import convert_ip
from .layouts import (eth_stream_signature, tcp_header_layout, bswap,
                      header_wire_image, TCP_HEADER_LEN, IPV4_PROTOCOL_TCP,
                      TCP_FLAG_FIN, TCP_FLAG_SYN, TCP_FLAG_RST, TCP_FLAG_PSH,
                      TCP_FLAG_ACK)


__all__ = ["tcp_seg_layout", "TCPServer", "TCPClient", "TCPRX", "TCPEngine",
           "TCPSegDispatch", "TCPTXArbiter"]


class TCPServer:
    """Build-time spec: listen on ``port`` (passive open)."""
    mode = "server"

    def __init__(self, port):
        assert isinstance(port, int) and 0 <= port <= 0xffff
        self.local_port  = port
        self.remote_ip   = 0
        self.remote_port = 0

    def __repr__(self):
        return f"TCPServer({self.local_port})"


class TCPClient:
    """Build-time spec: connect to ``ip:port`` (active open, auto-retry).

    ``local_port`` is the fixed source port of every attempt; when omitted
    the core assigns one from the ephemeral range (49152 + index).
    """
    mode = "client"

    def __init__(self, ip, port, local_port=None):
        assert isinstance(port, int) and 0 <= port <= 0xffff
        self.remote_ip   = convert_ip(ip)
        self.remote_port = port
        self.local_port  = local_port

    def __repr__(self):
        ip = ".".join(str((self.remote_ip >> s) & 0xff)
                      for s in (24, 16, 8, 0))
        return f"TCPClient({ip}:{self.remote_port}, local={self.local_port})"


def tcp_seg_layout():
    """Metadata of a validated received segment (natural byte order)."""
    return StructLayout({
        "src_ip":   32,
        "src_port": 16,
        "dst_port": 16,
        "seq":      32,
        "ack":      32,
        "flags":     8,
        "window":   16,
        "length":   16,     # Payload length (after options), in bytes.
        "mss":      16,     # MSS option value (0 when absent).
    })


def _ones_fold(m, value, width, name):
    """Fold ``value`` (one's-complement partial sum) down to 16 bits."""
    f1 = Signal(17, name=f"{name}_f1")
    f2 = Signal(16, name=f"{name}_f2")
    m.d.comb += [
        f1.eq(value[:16] + value[16:width]),
        f2.eq(f1[:16] + f1[16]),
    ]
    return f2


class TCPRX(wiring.Component):
    """Validate, checksum and buffer one TCP segment at a time.

    Sits on the IP protocol dispatch: ``sink`` carries the IP payload of
    received TCP packets with ``src_ip``/``ip_length`` metadata from the IP
    RX layer (``ip_length`` is authoritative — frames carry Ethernet
    padding). The TCP checksum is verified over the pseudo-header, header,
    options and payload; the MSS option value is extracted into the segment
    metadata (0 when absent) and the options are otherwise discarded.

    A verified segment is *presented*: ``seg_stb`` is held with the metadata
    on ``seg`` while the payload may be read from ``seg_payload``; the
    consumer pulses ``seg_done`` when finished (unread payload is flushed).
    Malformed or corrupt segments pulse ``drop``.
    """
    def __init__(self, buf_depth=2048):
        self.buf_depth = buf_depth
        super().__init__({
            "sink":        In(eth_stream_signature()),
            "src_ip":      In(32),
            "ip_length":   In(16),
            "protocol":    In(8),
            "ip_address":  In(32),      # Pseudo-header destination.
            "seg":         Out(tcp_seg_layout()),
            "seg_stb":     Out(1),
            "seg_payload": Out(eth_stream_signature()),
            "seg_done":    In(1),
            "seg_pulse":   Out(1),      # One pulse per presented segment.
            "drop":        Out(1),      # One pulse per discarded segment.
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.depacketizer = depack = Depacketizer(
            tcp_header_layout, eth_stream_signature())
        m.submodules.fifo = fifo = PacketFIFO(
            eth_stream_signature(), payload_depth=self.buf_depth,
            packet_depth=2, has_abort=True)

        hdr = depack.header

        # Latched segment state.
        src_ip    = Signal(32)
        seg_total = Signal(16)              # TCP header+options+payload.
        plen      = Signal(16)              # Payload length.
        opt_len   = Signal(8)               # Options length in bytes.
        count     = Signal(16)
        reads     = Signal(16)              # Beats read out of the FIFO.
        acc       = Signal(16)              # Folded one's-complement sum.

        # Byte-wise accumulation; options and payload both start at even
        # offsets (20 and data_offset*4), so per-stage parity is count[0].
        add_byte  = Signal(16)
        acc_next  = Signal(17)
        m.d.comb += [
            add_byte.eq(Mux(count[0], depack.o_stream.payload,
                            depack.o_stream.payload << 8)),
            acc_next.eq(acc + add_byte),
        ]
        acc_folded = Signal(16)
        m.d.comb += acc_folded.eq(acc_next[:16] + acc_next[16])

        # Header sum (all 10 words, including the received checksum).
        hdr_words = [Cat(depack.header_raw[16*i + 8:16*i + 16],
                         depack.header_raw[16*i:16*i + 8])
                     for i in range(TCP_HEADER_LEN // 2)]
        hdr_sum_acc = Signal(20)
        m.d.comb += hdr_sum_acc.eq(sum(hdr_words))
        hdr_sum = _ones_fold(m, hdr_sum_acc, 20, "tcprx_hdr")

        # Final verification: pseudo-header + accumulated segment sum (using
        # the latched src_ip: the input is only valid while the packet
        # streams, and VERIFY runs after the tail).
        total_acc = Signal(19)
        m.d.comb += total_acc.eq(
            acc +
            src_ip[16:32] + src_ip[0:16] +
            self.ip_address[16:32] + self.ip_address[0:16] +
            IPV4_PROTOCOL_TCP + seg_total)
        total_sum = _ones_fold(m, total_acc, 19, "tcprx_total")
        csum_ok   = Signal()
        m.d.comb += csum_ok.eq(total_sum == 0xffff)

        # Latched metadata presented to the engines.
        meta = Signal(tcp_seg_layout())
        m.d.comb += [
            self.seg.eq(meta),
            self.seg.length.eq(plen),
            self.seg.src_ip.eq(src_ip),
        ]

        # Option walker (only the MSS option is interpreted; everything is
        # checksummed regardless). Kind 0 ends the list, kind 1 has no
        # length byte, other kinds are kind/len/value with len covering all.
        opt_phase = Signal(2)           # 0 kind, 1 len, 2 value, 3 done.
        opt_kind  = Signal(8)
        opt_left  = Signal(8)

        sink_to_depack = [
            depack.i_stream.valid.eq(self.sink.valid),
            depack.i_stream.payload.eq(self.sink.payload),
            depack.i_stream.first.eq(self.sink.first),
            depack.i_stream.last.eq(self.sink.last),
            self.sink.ready.eq(depack.i_stream.ready),
        ]

        # FIFO read side: muxed between the consumer and internal flushing.
        flush_rd = Signal()
        m.d.comb += [
            self.seg_payload.valid.eq(fifo.o_stream.valid & self.seg_stb),
            self.seg_payload.payload.eq(fifo.o_stream.payload),
            self.seg_payload.first.eq(fifo.o_stream.first),
            self.seg_payload.last.eq(fifo.o_stream.last),
            fifo.o_stream.ready.eq((self.seg_payload.ready & self.seg_stb) |
                                   flush_rd),
        ]
        with m.If(fifo.o_stream.valid & fifo.o_stream.ready):
            m.d.sync += reads.eq(reads + 1)

        data_offset = Signal(4)
        m.d.comb += data_offset.eq(hdr.data_offset)

        with m.FSM():
            with m.State("IDLE"):
                with m.If(self.sink.valid):
                    m.d.sync += [
                        src_ip.eq(self.src_ip),
                        seg_total.eq(self.ip_length),
                        acc.eq(0),
                        count.eq(0),
                        reads.eq(0),
                    ]
                    with m.If((self.protocol == IPV4_PROTOCOL_TCP) &
                              (self.ip_length >= TCP_HEADER_LEN)):
                        m.next = "HEADER"
                    with m.Else():
                        m.next = "DROP_SINK"

            with m.State("HEADER"):
                m.d.comb += sink_to_depack
                with m.If(depack.o_stream.valid):
                    # Header complete (first post-header byte offered).
                    m.d.sync += [
                        meta.src_port.eq(bswap(hdr.src_port)),
                        meta.dst_port.eq(bswap(hdr.dst_port)),
                        meta.seq.eq(bswap(hdr.seq)),
                        meta.ack.eq(bswap(hdr.ack)),
                        meta.flags.eq(hdr.flags),
                        meta.window.eq(bswap(hdr.window)),
                        meta.mss.eq(0),
                        opt_phase.eq(0),
                        acc.eq(hdr_sum),
                        opt_len.eq((data_offset - 5) * 4),
                        plen.eq(seg_total - (data_offset * 4)),
                        count.eq(0),
                    ]
                    with m.If((data_offset < 5) |
                              (seg_total < data_offset * 4) |
                              (seg_total - (data_offset * 4) > self.buf_depth)):
                        m.d.comb += self.drop.eq(1)
                        m.next = "DRAIN_DROP"
                    with m.Elif(data_offset != 5):
                        m.next = "OPTIONS"
                    with m.Else():
                        m.next = "PAYLOAD"
                with m.Elif(self.sink.valid & self.sink.ready & self.sink.last):
                    # Runt: the depacketizer resynchronized; so do we.
                    m.d.comb += self.drop.eq(1)
                    m.next = "IDLE"

            with m.State("OPTIONS"):
                # Consume and checksum the options; pick out the MSS value.
                m.d.comb += sink_to_depack
                m.d.comb += depack.o_stream.ready.eq(1)
                with m.If(depack.o_stream.valid):
                    m.d.sync += [
                        acc.eq(acc_folded),
                        count.eq(count + 1),
                    ]
                    data = depack.o_stream.payload
                    with m.Switch(opt_phase):
                        with m.Case(0):                     # Option kind.
                            with m.If(data == 0):           # End of list.
                                m.d.sync += opt_phase.eq(3)
                            with m.Elif(data != 1):         # 1 = NOP.
                                m.d.sync += [
                                    opt_kind.eq(data),
                                    opt_phase.eq(1),
                                ]
                        with m.Case(1):                     # Option length.
                            with m.If(data < 2):            # Malformed.
                                m.d.sync += opt_phase.eq(3)
                            with m.Else():
                                m.d.sync += opt_left.eq(data - 2)
                                m.d.sync += opt_phase.eq(
                                    Mux(data == 2, 0, 2))
                        with m.Case(2):                     # Option value.
                            with m.If(opt_kind == 2):       # MSS.
                                m.d.sync += meta.mss.eq(
                                    Cat(data, meta.mss[:8]))
                            m.d.sync += opt_left.eq(opt_left - 1)
                            with m.If(opt_left == 1):
                                m.d.sync += opt_phase.eq(0)
                    with m.If(depack.o_stream.last & (count != opt_len - 1)):
                        # Truncated inside the options.
                        m.d.comb += self.drop.eq(1)
                        m.next = "IDLE"
                    with m.Elif(count == opt_len - 1):
                        m.d.sync += count.eq(0)
                        with m.If(depack.o_stream.last):
                            with m.If(plen == 0):
                                m.next = "VERIFY"
                            with m.Else():
                                m.d.comb += self.drop.eq(1)
                                m.next = "IDLE"
                        with m.Else():
                            m.next = "PAYLOAD"

            with m.State("PAYLOAD"):
                with m.If(plen == 0):
                    m.next = "DRAIN_PAD"
                with m.Else():
                    m.d.comb += sink_to_depack
                    m.d.comb += [
                        fifo.i_stream.valid.eq(depack.o_stream.valid),
                        fifo.i_stream.payload.eq(depack.o_stream.payload),
                        fifo.i_stream.first.eq(count == 0),
                        fifo.i_stream.last.eq(count == plen - 1),
                        depack.o_stream.ready.eq(fifo.i_stream.ready),
                    ]
                    with m.If(fifo.i_stream.valid & fifo.i_stream.ready):
                        m.d.sync += [
                            acc.eq(acc_folded),
                            count.eq(count + 1),
                        ]
                        with m.If(depack.o_stream.last & (count != plen - 1)):
                            # Truncated: discard the partial FIFO packet.
                            m.d.comb += [fifo.abort.eq(1), self.drop.eq(1)]
                            m.next = "IDLE"
                        with m.Elif(count == plen - 1):
                            with m.If(depack.o_stream.last):
                                m.next = "VERIFY"
                            with m.Else():
                                m.next = "DRAIN_PAD"

            with m.State("DRAIN_PAD"):
                # Ethernet padding: not part of the segment nor the checksum.
                m.d.comb += sink_to_depack
                m.d.comb += depack.o_stream.ready.eq(1)
                with m.If(depack.o_stream.valid & depack.o_stream.last):
                    m.next = "VERIFY"

            with m.State("DRAIN_DROP"):
                # Malformed segment: discard the rest of the packet.
                m.d.comb += sink_to_depack
                m.d.comb += depack.o_stream.ready.eq(1)
                with m.If(depack.o_stream.valid & depack.o_stream.last):
                    m.next = "IDLE"

            with m.State("VERIFY"):
                with m.If(csum_ok):
                    m.d.comb += self.seg_pulse.eq(1)
                    m.next = "PRESENT"
                with m.Else():
                    m.d.comb += self.drop.eq(1)
                    with m.If(plen != 0):
                        m.next = "FLUSH"    # Committed packet: drain it.
                    with m.Else():
                        m.next = "IDLE"

            with m.State("PRESENT"):
                m.d.comb += self.seg_stb.eq(1)
                with m.If(self.seg_done):
                    with m.If(reads != plen):
                        m.next = "FLUSH"
                    with m.Else():
                        m.next = "IDLE"

            with m.State("FLUSH"):
                m.d.comb += flush_rd.eq(1)
                with m.If(reads == plen):
                    m.next = "IDLE"

            with m.State("DROP_SINK"):
                m.d.comb += self.sink.ready.eq(1)
                with m.If(self.sink.valid & self.sink.last):
                    m.d.comb += self.drop.eq(1)
                    m.next = "IDLE"

        return m


class _Conn(enum.Enum, shape=3):
    LISTEN      = 0     # Server: listening. Client: idle / retry-wait.
    SYN_RCVD    = 1     # Server only.
    ESTABLISHED = 2
    CLOSE_WAIT  = 3
    LAST_ACK    = 4
    SYN_SENT    = 5     # Client only.


class TCPEngine(wiring.Component):
    """One TCP endpoint (server or client), one connection, stop-and-wait TX.

    See the module docstring for scope. The engine consumes validated
    segments (from :class:`TCPRX`, via :class:`TCPSegDispatch`), keeps the
    connection state, buffers received payload for the user (``rx_source``,
    one stream packet per segment) and sends user bytes (``tx_sink``, cut
    into segments at ``mss`` bytes or the user's ``last``).

    ``mode`` selects passive open ("server", waits on ``local_port``) or
    active open ("client", connects from ``local_port`` to ``remote_ip:
    remote_port`` and retries forever); only the requested opening logic is
    generated — everything past the handshake is shared. Segments not
    matching the connection (or, on the first engine, segments to unbound
    ports) are refused with RST. ``connected`` covers ESTABLISHED/
    CLOSE-WAIT; ``peer_closed`` rises on the peer's FIN; assert ``close``
    (in CLOSE-WAIT) to finish the shutdown.
    """
    def __init__(self, clk_freq, mode="server", port_init=0,
                 remote_ip_init=0, remote_port_init=0, mss=536,
                 rx_depth=2048, rx_packets=16, rto=0.5, max_retries=8,
                 idle_timeout=60.0, reconnect_delay=1.0):
        assert mode in ("server", "client")
        assert mss >= 1 and rx_depth <= 0xffff and mss <= rx_depth
        self.mode          = mode
        self.clk_freq      = clk_freq
        self.mss           = mss
        self.rx_depth      = rx_depth
        self.rx_packets    = rx_packets
        self.rto_cycles    = max(2, int(clk_freq * rto))
        self.max_retries   = max_retries
        self.idle_cycles   = int(clk_freq * idle_timeout)
        self.delay_cycles  = max(1, int(clk_freq * reconnect_delay))
        self.segbuf_depth  = 1 << (mss - 1).bit_length()

        members = {
            "local_port":  In(16, init=port_init),
            "ip_address":  In(32),      # Board IP (TX pseudo-header source).
            # Validated segment presentation.
            "seg":         In(tcp_seg_layout()),
            "seg_stb":     In(1),
            "seg_payload": In(eth_stream_signature()),
            "seg_done":    Out(1),
            # User streams and connection control.
            "rx_source":   Out(eth_stream_signature()),
            "tx_sink":     In(eth_stream_signature()),
            "connected":   Out(1),
            "peer_closed": Out(1),
            "close":       In(1),
            # IP TX side.
            "source":      Out(eth_stream_signature()),
            "dst_ip":      Out(32),
            "length":      Out(16),
            "protocol":    Out(8),
            # Status.
            "state_debug": Out(3),
            "seg_sent":    Out(1),
            "rst_sent":    Out(1),
        }
        if mode == "client":
            members["remote_ip"]   = In(32, init=remote_ip_init)
            members["remote_port"] = In(16, init=remote_port_init)
            # Gates *new* connection attempts only (e.g. until DHCP binds).
            members["enable"]      = In(1, init=1)
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        # RX buffer towards the user (its free space is the receive window).
        m.submodules.rx_fifo = rx_fifo = PacketFIFO(
            eth_stream_signature(), payload_depth=self.rx_depth,
            packet_depth=self.rx_packets)
        connect(m, rx_fifo.o_stream, flipped(self.rx_source))

        rx_level = Signal(range(self.rx_depth + 1))
        rx_wr = Signal()
        rx_rd = Signal()
        m.d.comb += [
            rx_wr.eq(rx_fifo.i_stream.valid & rx_fifo.i_stream.ready),
            rx_rd.eq(rx_fifo.o_stream.valid & rx_fifo.o_stream.ready),
        ]
        m.d.sync += rx_level.eq(rx_level + rx_wr - rx_rd)
        rx_free = Signal(16)
        m.d.comb += rx_free.eq(self.rx_depth - rx_level)

        # TX segment replay buffer (retransmit storage).
        m.submodules.segbuf = segbuf = Memory(
            shape=8, depth=self.segbuf_depth, init=[])
        sb_wr = segbuf.write_port()
        sb_rd = segbuf.read_port(domain="sync")

        # Connection state.
        conn      = Signal(_Conn)
        peer_ip   = Signal(32)
        peer_port = Signal(16)
        our_port  = Signal(16)
        irs       = Signal(32)          # Peer's initial sequence number.
        rcv_nxt   = Signal(32)
        snd_una   = Signal(32)
        snd_nxt   = Signal(32)
        peer_wnd  = Signal(16)
        eff_mss   = Signal(range(self.mss + 1), init=min(self.mss, 536))
        iss_ctr   = Signal(32)
        retries   = Signal(range(self.max_retries + 1))
        close_req = Signal()
        m.d.sync += iss_ctr.eq(iss_ctr + 1)

        # Send-side segment limit: our buffer vs the peer's MSS option
        # (536 when absent, per RFC). Latched at connection setup.
        peer_lim = Signal(16)
        eff_next = Signal(range(self.mss + 1))
        m.d.comb += [
            peer_lim.eq(Mux(self.seg.mss != 0, self.seg.mss, 536)),
            eff_next.eq(Mux(peer_lim < self.mss, peer_lim, self.mss)),
        ]

        outstanding = Signal()
        m.d.comb += outstanding.eq(snd_nxt != snd_una)

        est_ish = Signal()
        m.d.comb += est_ish.eq((conn == _Conn.ESTABLISHED) |
                               (conn == _Conn.CLOSE_WAIT))

        m.d.comb += [
            self.connected.eq(est_ish),
            self.state_debug.eq(conn),
            self.protocol.eq(IPV4_PROTOCOL_TCP),
        ]

        # TX staging: user bytes accumulated into the replay buffer.
        fill_len        = Signal(range(self.segbuf_depth + 1))
        pay_sum         = Signal(16)
        tx_data_pending = Signal()      # Buffer frozen, not yet acked.

        user_wr = Signal()
        m.d.comb += [
            self.tx_sink.ready.eq(Mux(est_ish, ~tx_data_pending, 1)),
            user_wr.eq(self.tx_sink.valid & self.tx_sink.ready & est_ish),
            sb_wr.addr.eq(fill_len),
            sb_wr.data.eq(self.tx_sink.payload),
            sb_wr.en.eq(user_wr & ~tx_data_pending),
        ]
        user_add = Signal(17)
        m.d.comb += user_add.eq(pay_sum + Mux(fill_len[0],
                                              self.tx_sink.payload,
                                              self.tx_sink.payload << 8))
        with m.If(user_wr & ~tx_data_pending):
            m.d.sync += [
                fill_len.eq(fill_len + 1),
                pay_sum.eq(user_add[:16] + user_add[16]),
            ]
            with m.If(self.tx_sink.last | (fill_len == eff_mss - 1)):
                m.d.sync += tx_data_pending.eq(1)

        # Pending TX causes (p_synack: server opening; p_syn: client opening).
        p_ack    = Signal()
        p_synack = Signal()
        p_syn    = Signal()
        p_retx   = Signal()
        p_finrtx = Signal()
        p_rst    = Signal()
        r_ip     = Signal(32)
        r_sport  = Signal(16)
        r_dport  = Signal(16)
        r_seq    = Signal(32)
        r_ack    = Signal(32)

        # Timers.
        rto_cnt  = Signal(range(self.rto_cycles + 1))
        rto_fire = Signal()
        with m.If(outstanding):
            with m.If(rto_cnt == 0):
                m.d.comb += rto_fire.eq(1)
                m.d.sync += rto_cnt.eq(self.rto_cycles)
            with m.Else():
                m.d.sync += rto_cnt.eq(rto_cnt - 1)

        idle_fire = Signal()
        if self.idle_cycles > 0:
            idle_cnt = Signal(range(self.idle_cycles + 1))
            with m.If(conn != _Conn.LISTEN):
                with m.If(idle_cnt == 0):
                    m.d.comb += idle_fire.eq(1)
                with m.Else():
                    m.d.sync += idle_cnt.eq(idle_cnt - 1)
        else:
            idle_cnt = Signal(range(2))

        # Client: delay between connection attempts (elapsed at power-on
        # after one initial period, letting autonegotiation settle).
        if self.mode == "client":
            delay_cnt = Signal(range(self.delay_cycles + 1),
                               init=self.delay_cycles)

        def touch_idle():
            return [idle_cnt.eq(self.idle_cycles if self.idle_cycles else 0)]

        def reset_to_listen():
            stmts = [
                conn.eq(_Conn.LISTEN),
                self.peer_closed.eq(0),
                close_req.eq(0),
                tx_data_pending.eq(0),
                fill_len.eq(0),
                pay_sum.eq(0),
                p_ack.eq(0),
                p_synack.eq(0),
                p_syn.eq(0),
                p_retx.eq(0),
                p_finrtx.eq(0),
                retries.eq(0),
                snd_nxt.eq(snd_una),
            ]
            if self.mode == "client":
                stmts.append(delay_cnt.eq(self.delay_cycles))
            return stmts

        def queue_rst_from_seg():
            # LwIP/RFC 9293 refuse convention: seq = SEG.ACK (0 when the
            # segment carries no ACK), ack = SEG.SEQ + SEG.LEN.
            seg = self.seg
            seg_ln = Signal(33, name="rst_seg_ln")
            m.d.comb += seg_ln.eq(seg.seq + seg.length +
                                  seg.flags[1] + seg.flags[0])   # +SYN +FIN
            return [
                p_rst.eq(1),
                r_ip.eq(seg.src_ip),
                r_sport.eq(seg.dst_port),
                r_dport.eq(seg.src_port),
                r_seq.eq(Mux(seg.flags[4], seg.ack, 0)),
                r_ack.eq(seg_ln),
            ]

        def queue_rst_conn():
            return [
                p_rst.eq(1),
                r_ip.eq(peer_ip),
                r_sport.eq(our_port),
                r_dport.eq(peer_port),
                r_seq.eq(snd_nxt),
                r_ack.eq(rcv_nxt),
            ]

        # Retransmission and abort paths, shared between the modes: only the
        # opening state/pending pair differs (SYN-ACK vs SYN), and a failed
        # client *open* aborts silently (nothing to reset yet).
        if self.mode == "server":
            opening_state, opening_pend = _Conn.SYN_RCVD, p_synack
        else:
            opening_state, opening_pend = _Conn.SYN_SENT, p_syn

        with m.If(rto_fire):
            with m.If(retries == self.max_retries):
                if self.mode == "client":
                    with m.If(conn != _Conn.SYN_SENT):
                        m.d.sync += queue_rst_conn()
                else:
                    m.d.sync += queue_rst_conn()
                m.d.sync += reset_to_listen()
            with m.Else():
                m.d.sync += retries.eq(retries + 1)
                with m.If(conn == opening_state):
                    m.d.sync += opening_pend.eq(1)
                with m.Elif(conn == _Conn.LAST_ACK):
                    m.d.sync += p_finrtx.eq(1)
                with m.Elif(est_ish & tx_data_pending):
                    m.d.sync += p_retx.eq(1)

        with m.If(idle_fire & (conn != _Conn.LISTEN)):
            m.d.sync += queue_rst_conn() + reset_to_listen()

        # Client: active open, retried forever (while enabled).
        if self.mode == "client":
            with m.If(conn == _Conn.LISTEN):
                with m.If(delay_cnt != 0):
                    m.d.sync += delay_cnt.eq(delay_cnt - 1)
                with m.Elif(self.enable):
                    m.d.sync += [
                        peer_ip.eq(self.remote_ip),
                        peer_port.eq(self.remote_port),
                        our_port.eq(self.local_port),
                        rcv_nxt.eq(0),          # Unknown until the SYN-ACK.
                        peer_wnd.eq(0),
                        snd_una.eq(iss_ctr),
                        snd_nxt.eq(iss_ctr + 1),
                        p_syn.eq(1),
                        retries.eq(0),
                        rto_cnt.eq(self.rto_cycles),
                        conn.eq(_Conn.SYN_SENT),
                    ] + touch_idle()

        # --- Segment processing ------------------------------------------------------------
        seg = self.seg
        f_fin = seg.flags[0]
        f_syn = seg.flags[1]
        f_rst = seg.flags[2]
        f_ack = seg.flags[4]

        tuple_match = Signal()
        m.d.comb += tuple_match.eq((seg.src_ip == peer_ip) &
                                   (seg.src_port == peer_port) &
                                   (seg.dst_port == our_port))

        ack_ok = Signal()   # Acknowledges everything outstanding.
        m.d.comb += ack_ok.eq(f_ack & outstanding & (seg.ack == snd_nxt))

        in_order  = Signal()
        can_store = Signal()
        m.d.comb += [
            in_order.eq(seg.seq == rcv_nxt),
            can_store.eq((seg.length <= rx_free) &
                         (rx_fifo.packet_count < self.rx_packets)),
        ]

        # Data may complete the handshake and arrive in the same segment.
        est_now = Signal()
        m.d.comb += est_now.eq((conn == _Conn.ESTABLISHED) |
                               ((conn == _Conn.SYN_RCVD) & ack_ok))

        accept_data = Signal()
        m.d.comb += accept_data.eq(est_now & (seg.length != 0) &
                                   in_order & can_store)
        fin_in_order = Signal()
        m.d.comb += fin_in_order.eq(
            f_fin & (est_now | (conn == _Conn.CLOSE_WAIT)) &
            Mux(seg.length != 0, accept_data, in_order) &
            (conn != _Conn.CLOSE_WAIT))    # Duplicate FIN: dup-ACK only.

        copy_cnt = Signal(16)

        with m.FSM(name="seg_fsm"):
            with m.State("IDLE"):
                with m.If(self.seg_stb):
                    m.d.sync += copy_cnt.eq(0)
                    m.next = "EVAL"

            with m.State("EVAL"):
                m.next = "DONE"

                def eval_synchronized():
                    # Shared by both modes: everything from SYN-RCVD /
                    # SYN-SENT completion onwards behaves identically.
                    with m.If(~tuple_match):
                        with m.If(~f_rst):
                            m.d.sync += queue_rst_from_seg()
                    with m.Elif(f_rst):
                        m.d.sync += reset_to_listen()
                    with m.Elif(f_syn & (Const(1) if self.mode == "server"
                                         else Const(0)) &
                                (conn == _Conn.SYN_RCVD) & (seg.seq == irs)):
                        # Retransmitted SYN: resend the SYN-ACK.
                        m.d.sync += [p_synack.eq(1)] + touch_idle()
                    with m.Elif(f_syn):
                        m.d.sync += queue_rst_conn() + reset_to_listen()
                    with m.Else():
                        m.d.sync += touch_idle()
                        # ACK bookkeeping.
                        with m.If(f_ack):
                            m.d.sync += peer_wnd.eq(seg.window)
                            with m.If(ack_ok):
                                m.d.sync += [
                                    snd_una.eq(snd_nxt),
                                    retries.eq(0),
                                ]
                                if self.mode == "server":
                                    with m.If(conn == _Conn.SYN_RCVD):
                                        m.d.sync += conn.eq(_Conn.ESTABLISHED)
                                with m.If(est_ish & tx_data_pending):
                                    m.d.sync += [
                                        tx_data_pending.eq(0),
                                        fill_len.eq(0),
                                        pay_sum.eq(0),
                                        p_retx.eq(0),
                                    ]
                            elif_cond = ((conn == _Conn.SYN_RCVD) &
                                         (seg.ack != snd_nxt)) \
                                if self.mode == "server" else Const(0)
                            with m.Elif(elif_cond):
                                # Unacceptable ACK of our SYN: refuse.
                                m.d.sync += queue_rst_from_seg()

                        # Closing handshake completion. (The ACK block above
                        # already advanced snd_una; also pin snd_nxt so the
                        # pair lands equal — assignment RHS reads old values.)
                        with m.If((conn == _Conn.LAST_ACK) & ack_ok):
                            m.d.sync += reset_to_listen()
                            m.d.sync += snd_nxt.eq(snd_nxt)
                        with m.Else():
                            # Data / FIN.
                            with m.If(accept_data):
                                m.next = "COPY"
                            with m.If((seg.length != 0) | f_fin):
                                with m.If(est_now |
                                          (conn == _Conn.CLOSE_WAIT)):
                                    m.d.sync += p_ack.eq(1)
                            m.d.sync += rcv_nxt.eq(rcv_nxt +
                                Mux(accept_data, seg.length, 0) +
                                fin_in_order)
                            with m.If(fin_in_order):
                                m.d.sync += [
                                    self.peer_closed.eq(1),
                                    conn.eq(_Conn.CLOSE_WAIT),
                                ]

                if self.mode == "server":
                    with m.If(conn == _Conn.LISTEN):
                        with m.If(f_rst):
                            pass
                        with m.Elif(seg.dst_port != self.local_port):
                            # Unbound port (first engine only): refuse.
                            m.d.sync += queue_rst_from_seg()
                        with m.Elif(f_syn & ~f_ack):
                            m.d.sync += [
                                peer_ip.eq(seg.src_ip),
                                peer_port.eq(seg.src_port),
                                our_port.eq(seg.dst_port),
                                irs.eq(seg.seq),
                                rcv_nxt.eq(seg.seq + 1),
                                snd_una.eq(iss_ctr),
                                snd_nxt.eq(iss_ctr + 1),
                                peer_wnd.eq(seg.window),
                                eff_mss.eq(eff_next),
                                p_synack.eq(1),
                                retries.eq(0),
                                rto_cnt.eq(self.rto_cycles),
                                conn.eq(_Conn.SYN_RCVD),
                            ] + touch_idle()
                        with m.Else():
                            # ACK (or anything else) against LISTEN: refuse.
                            m.d.sync += queue_rst_from_seg()
                    with m.Else():
                        eval_synchronized()
                else:
                    with m.If(conn == _Conn.LISTEN):
                        # Client idle: no listener — refuse (incl. unbound
                        # ports when this is the first engine).
                        with m.If(~f_rst):
                            m.d.sync += queue_rst_from_seg()
                    with m.Elif(conn == _Conn.SYN_SENT):
                        with m.If(~tuple_match):
                            with m.If(~f_rst):
                                m.d.sync += queue_rst_from_seg()
                        with m.Elif(f_rst):
                            # Connection refused: retry after the delay.
                            m.d.sync += reset_to_listen()
                        with m.Elif(f_syn & f_ack):
                            with m.If(seg.ack == snd_nxt):
                                # SYN-ACK: complete the handshake (the pure
                                # ACK is sent by the p_ack path).
                                m.d.sync += [
                                    irs.eq(seg.seq),
                                    rcv_nxt.eq(seg.seq + 1),
                                    peer_wnd.eq(seg.window),
                                    eff_mss.eq(eff_next),
                                    snd_una.eq(snd_nxt),
                                    retries.eq(0),
                                    p_syn.eq(0),
                                    p_ack.eq(1),
                                    conn.eq(_Conn.ESTABLISHED),
                                ] + touch_idle()
                            with m.Else():
                                m.d.sync += queue_rst_from_seg()
                        with m.Elif(f_ack & (seg.ack != snd_nxt)):
                            # Stale ACK (e.g. peer TIME-WAIT): RST it so the
                            # old state dies; the next retry connects.
                            m.d.sync += queue_rst_from_seg()
                        # Bare SYN (simultaneous open) or data: ignored.
                    with m.Else():
                        eval_synchronized()

            with m.State("COPY"):
                m.d.comb += [
                    rx_fifo.i_stream.valid.eq(self.seg_payload.valid),
                    rx_fifo.i_stream.payload.eq(self.seg_payload.payload),
                    rx_fifo.i_stream.first.eq(copy_cnt == 0),
                    rx_fifo.i_stream.last.eq(copy_cnt == seg.length - 1),
                    self.seg_payload.ready.eq(rx_fifo.i_stream.ready),
                ]
                with m.If(rx_fifo.i_stream.valid & rx_fifo.i_stream.ready):
                    m.d.sync += copy_cnt.eq(copy_cnt + 1)
                    with m.If(copy_cnt == seg.length - 1):
                        m.next = "DONE"

            with m.State("DONE"):
                m.d.comb += self.seg_done.eq(1)
                m.next = "WAIT_CLEAR"

            with m.State("WAIT_CLEAR"):
                # Hold until the presenter withdraws the segment, so the same
                # segment is never evaluated twice.
                with m.If(~self.seg_stb):
                    m.next = "IDLE"

        # --- Segment transmission ----------------------------------------------------------
        KIND_RST, KIND_SYNACK, KIND_FIN, KIND_DATA, KIND_ACK, KIND_SYN = \
            range(6)

        b_kind  = Signal(3)
        b_ip    = Signal(32)
        b_sport = Signal(16)
        b_dport = Signal(16)
        b_seq   = Signal(32)
        b_ack   = Signal(32)
        b_flags = Signal(8)
        b_wnd   = Signal(16)
        b_len   = Signal(16)
        csum    = Signal(16)

        # SYN and SYN-ACK carry the MSS option (4 bytes, data offset 6), so
        # the peer may fill our buffers instead of assuming 536.
        adv_mss = min(self.mss, 0xffff)
        b_opt   = Signal()
        hdr_len = Signal(5)
        m.d.comb += [
            b_opt.eq((b_kind == KIND_SYN) | (b_kind == KIND_SYNACK)),
            hdr_len.eq(Mux(b_opt, TCP_HEADER_LEN + 4, TCP_HEADER_LEN)),
            self.dst_ip.eq(b_ip),
            self.length.eq(hdr_len + b_len),
        ]

        # Checksum accumulation source words (pseudo-header + header + the
        # optional MSS option words, zero when absent).
        csum_words = Array([
            self.ip_address[16:32], self.ip_address[0:16],     # src (ours)
            b_ip[16:32], b_ip[0:16],                            # dst
            Const(IPV4_PROTOCOL_TCP, 16), hdr_len + b_len,
            b_sport, b_dport,
            b_seq[16:32], b_seq[0:16],
            b_ack[16:32], b_ack[0:16],
            Cat(b_flags, Mux(b_opt, Const(0x60, 8), Const(0x50, 8))),
            b_wnd, Const(0, 16), Const(0, 16),                  # csum=0, urg
            Mux(b_opt, Const(0x0204, 16), Const(0, 16)),        # kind 2 len 4
            Mux(b_opt, Const(adv_mss, 16), Const(0, 16)),
        ])
        csum_idx = Signal(range(len(csum_words) + 1))
        csum_acc = Signal(16)
        csum_add = Signal(17)
        m.d.comb += csum_add.eq(csum_acc + csum_words[csum_idx])

        # Header wire image from the latched fields.
        hdr_image = header_wire_image(m, tcp_header_layout, {
            "src_port":    bswap(b_sport),
            "dst_port":    bswap(b_dport),
            "seq":         bswap(b_seq),
            "ack":         bswap(b_ack),
            "reserved":    0,
            "data_offset": Mux(b_opt, 6, 5),
            "flags":       b_flags,
            "window":      bswap(b_wnd),
            "checksum":    bswap(csum),
            "urgent":      0,
        }, name="tcptx_image")
        opt_image = Array([Const(2, 8), Const(4, 8),
                           Const(adv_mss >> 8, 8), Const(adv_mss & 0xff, 8)])
        opt_idx   = Signal(2)

        emit_cnt = Signal(range(TCP_HEADER_LEN))
        pay_idx  = Signal(range(self.segbuf_depth + 1))
        pay_adv  = Signal()
        m.d.comb += [
            sb_rd.addr.eq(Mux(pay_adv, pay_idx + 1, pay_idx)),
            sb_rd.en.eq(1),
        ]

        fin_ready = Signal()
        m.d.comb += fin_ready.eq((conn == _Conn.CLOSE_WAIT) & close_req &
                                 ~outstanding & ~tx_data_pending &
                                 (fill_len == 0))
        with m.If((conn == _Conn.CLOSE_WAIT) & self.close):
            m.d.sync += close_req.eq(1)

        data_ready = Signal()
        m.d.comb += data_ready.eq(est_ish & tx_data_pending & ~outstanding &
                                  (fill_len <= peer_wnd))

        wnd_now = Signal(16)
        m.d.comb += wnd_now.eq(rx_free)

        with m.FSM(name="tx_fsm"):
            with m.State("IDLE"):
                start = Signal()
                # Priority: RST, SYN-ACK, FIN (new/retx), data (new/retx),
                # pure ACK. Only data folds the payload sum into the
                # checksum accumulator.
                with m.If(p_rst):
                    m.d.sync += [
                        b_kind.eq(KIND_RST), b_ip.eq(r_ip),
                        b_sport.eq(r_sport), b_dport.eq(r_dport),
                        b_seq.eq(r_seq), b_ack.eq(r_ack),
                        b_flags.eq(TCP_FLAG_RST | TCP_FLAG_ACK),
                        b_wnd.eq(0), b_len.eq(0), csum_acc.eq(0),
                    ]
                    m.d.comb += start.eq(1)
                if self.mode == "client":
                    with m.Elif(p_syn):
                        m.d.sync += [
                            b_kind.eq(KIND_SYN), b_ip.eq(peer_ip),
                            b_sport.eq(our_port), b_dport.eq(peer_port),
                            b_seq.eq(snd_una), b_ack.eq(0),
                            b_flags.eq(TCP_FLAG_SYN),
                            b_wnd.eq(wnd_now), b_len.eq(0), csum_acc.eq(0),
                        ]
                        m.d.comb += start.eq(1)
                if self.mode == "server":
                    with m.Elif(p_synack):
                        m.d.sync += [
                            b_kind.eq(KIND_SYNACK), b_ip.eq(peer_ip),
                            b_sport.eq(our_port), b_dport.eq(peer_port),
                            b_seq.eq(snd_una), b_ack.eq(rcv_nxt),
                            b_flags.eq(TCP_FLAG_SYN | TCP_FLAG_ACK),
                            b_wnd.eq(wnd_now), b_len.eq(0), csum_acc.eq(0),
                        ]
                        m.d.comb += start.eq(1)
                with m.Elif(fin_ready | p_finrtx):
                    m.d.sync += [
                        b_kind.eq(KIND_FIN), b_ip.eq(peer_ip),
                        b_sport.eq(our_port), b_dport.eq(peer_port),
                        b_seq.eq(snd_una), b_ack.eq(rcv_nxt),
                        b_flags.eq(TCP_FLAG_FIN | TCP_FLAG_ACK),
                        b_wnd.eq(wnd_now), b_len.eq(0), csum_acc.eq(0),
                    ]
                    m.d.comb += start.eq(1)
                with m.Elif(p_retx | data_ready):
                    m.d.sync += [
                        b_kind.eq(KIND_DATA), b_ip.eq(peer_ip),
                        b_sport.eq(our_port), b_dport.eq(peer_port),
                        b_seq.eq(snd_una), b_ack.eq(rcv_nxt),
                        b_flags.eq(TCP_FLAG_ACK | TCP_FLAG_PSH),
                        b_wnd.eq(wnd_now), b_len.eq(fill_len),
                        csum_acc.eq(pay_sum),
                    ]
                    m.d.comb += start.eq(1)
                with m.Elif(p_ack & (conn != _Conn.LISTEN)):
                    m.d.sync += [
                        b_kind.eq(KIND_ACK), b_ip.eq(peer_ip),
                        b_sport.eq(our_port), b_dport.eq(peer_port),
                        b_seq.eq(snd_nxt), b_ack.eq(rcv_nxt),
                        b_flags.eq(TCP_FLAG_ACK),
                        b_wnd.eq(wnd_now), b_len.eq(0), csum_acc.eq(0),
                    ]
                    m.d.comb += start.eq(1)
                with m.If(start):
                    m.d.sync += [
                        csum_idx.eq(0),
                        emit_cnt.eq(0),
                        pay_idx.eq(0),
                    ]
                    m.next = "CSUM"

            with m.State("CSUM"):
                m.d.sync += [
                    csum_acc.eq(csum_add[:16] + csum_add[16]),
                    csum_idx.eq(csum_idx + 1),
                ]
                with m.If(csum_idx == len(csum_words) - 1):
                    m.next = "CSUM_DONE"

            with m.State("CSUM_DONE"):
                m.d.sync += csum.eq(~csum_acc)
                m.next = "EMIT_HDR"

            with m.State("EMIT_HDR"):
                m.d.comb += [
                    self.source.valid.eq(1),
                    self.source.payload.eq(
                        hdr_image.word_select(emit_cnt, 8)),
                    self.source.first.eq(emit_cnt == 0),
                    self.source.last.eq((emit_cnt == TCP_HEADER_LEN - 1) &
                                        (b_len == 0) & ~b_opt),
                ]
                with m.If(self.source.ready):
                    with m.If(emit_cnt == TCP_HEADER_LEN - 1):
                        with m.If(b_opt):
                            m.d.sync += opt_idx.eq(0)
                            m.next = "EMIT_OPT"
                        with m.Elif(b_len == 0):
                            m.next = "FINISH"
                        with m.Else():
                            m.next = "EMIT_PAY"
                    with m.Else():
                        m.d.sync += emit_cnt.eq(emit_cnt + 1)

            with m.State("EMIT_OPT"):
                m.d.comb += [
                    self.source.valid.eq(1),
                    self.source.payload.eq(opt_image[opt_idx]),
                    self.source.last.eq((opt_idx == 3) & (b_len == 0)),
                ]
                with m.If(self.source.ready):
                    m.d.sync += opt_idx.eq(opt_idx + 1)
                    with m.If(opt_idx == 3):
                        with m.If(b_len == 0):
                            m.next = "FINISH"
                        with m.Else():
                            m.next = "EMIT_PAY"

            with m.State("EMIT_PAY"):
                m.d.comb += [
                    self.source.valid.eq(1),
                    self.source.payload.eq(sb_rd.data),
                    self.source.last.eq(pay_idx == b_len - 1),
                ]
                with m.If(self.source.ready):
                    m.d.comb += pay_adv.eq(1)
                    m.d.sync += pay_idx.eq(pay_idx + 1)
                    with m.If(pay_idx == b_len - 1):
                        m.next = "FINISH"

            with m.State("FINISH"):
                m.d.comb += self.seg_sent.eq(1)
                with m.Switch(b_kind):
                    with m.Case(KIND_RST):
                        m.d.comb += self.rst_sent.eq(1)
                        m.d.sync += p_rst.eq(0)
                    with m.Case(KIND_SYN):
                        m.d.sync += p_syn.eq(0)
                        with m.If(conn == _Conn.SYN_SENT):
                            m.d.sync += [
                                snd_nxt.eq(snd_una + 1),
                                rto_cnt.eq(self.rto_cycles),
                            ]
                    with m.Case(KIND_SYNACK):
                        m.d.sync += p_synack.eq(0)
                        with m.If(conn == _Conn.SYN_RCVD):
                            m.d.sync += [
                                snd_nxt.eq(snd_una + 1),
                                rto_cnt.eq(self.rto_cycles),
                            ]
                    with m.Case(KIND_FIN):
                        m.d.sync += p_finrtx.eq(0)
                        with m.If(conn == _Conn.CLOSE_WAIT):
                            m.d.sync += [
                                snd_nxt.eq(snd_una + 1),
                                conn.eq(_Conn.LAST_ACK),
                                rto_cnt.eq(self.rto_cycles),
                            ]
                        with m.Elif(conn == _Conn.LAST_ACK):
                            m.d.sync += rto_cnt.eq(self.rto_cycles)
                    with m.Case(KIND_DATA):
                        m.d.sync += p_retx.eq(0)
                        with m.If(est_ish):
                            m.d.sync += [
                                snd_nxt.eq(snd_una + b_len),
                                rto_cnt.eq(self.rto_cycles),
                            ]
                with m.If((b_kind != KIND_RST) & (b_ack == rcv_nxt)):
                    m.d.sync += p_ack.eq(0)
                m.next = "IDLE"

        return m


class TCPSegDispatch(wiring.Component):
    """Route validated segments to the engine bound to the destination port.

    ``ports`` maps engine names to default listen ports; ``<name>_port``
    inputs carry the current bindings (fed from the same signals as the
    engines'). Metadata fans out to every engine; ``seg_stb`` and the
    payload stream are steered to the matching engine — or to the *first*
    engine when nothing matches, whose foreign-segment logic answers RST
    (connection refused). With a single engine this is pure wiring.
    """
    def __init__(self, ports):
        self.ports = dict(ports)
        assert len(self.ports) > 0
        members = {
            "seg":         In(tcp_seg_layout()),
            "seg_stb":     In(1),
            "seg_payload": In(eth_stream_signature()),
            "seg_done":    Out(1),
        }
        for name, number in self.ports.items():
            members[f"{name}_port"]        = In(16, init=number)
            members[f"{name}_seg"]         = Out(tcp_seg_layout())
            members[f"{name}_seg_stb"]     = Out(1)
            members[f"{name}_seg_payload"] = Out(eth_stream_signature())
            members[f"{name}_seg_done"]    = In(1)
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        names = list(self.ports)
        for name in names:
            m.d.comb += getattr(self, f"{name}_seg").eq(self.seg)

        if len(names) == 1:
            (name,) = names
            m.d.comb += [
                getattr(self, f"{name}_seg_stb").eq(self.seg_stb),
                getattr(self, f"{name}_seg_payload").valid
                    .eq(self.seg_payload.valid),
                getattr(self, f"{name}_seg_payload").payload
                    .eq(self.seg_payload.payload),
                getattr(self, f"{name}_seg_payload").first
                    .eq(self.seg_payload.first),
                getattr(self, f"{name}_seg_payload").last
                    .eq(self.seg_payload.last),
                self.seg_payload.ready
                    .eq(getattr(self, f"{name}_seg_payload").ready),
                self.seg_done.eq(getattr(self, f"{name}_seg_done")),
            ]
            return m

        # Latch the selection at presentation start so a mid-segment port
        # rebind (CSR write) cannot switch engines while copying.
        sel = Signal(range(len(names)))
        stb_d = Signal()
        m.d.sync += stb_d.eq(self.seg_stb)
        with m.If(self.seg_stb & ~stb_d):
            m.d.sync += sel.eq(0)   # Default: first engine refuses.
            for i, name in reversed(list(enumerate(names))):
                with m.If(self.seg.dst_port == getattr(self, f"{name}_port")):
                    m.d.sync += sel.eq(i)

        seen = Signal()     # Selection valid one cycle after seg_stb rises.
        m.d.comb += seen.eq(self.seg_stb & stb_d)

        for i, name in enumerate(names):
            port_payload = getattr(self, f"{name}_seg_payload")
            with m.If(seen & (sel == i)):
                m.d.comb += [
                    getattr(self, f"{name}_seg_stb").eq(1),
                    port_payload.valid.eq(self.seg_payload.valid),
                    self.seg_payload.ready.eq(port_payload.ready),
                    self.seg_done.eq(getattr(self, f"{name}_seg_done")),
                ]
            m.d.comb += [
                port_payload.payload.eq(self.seg_payload.payload),
                port_payload.first.eq(self.seg_payload.first),
                port_payload.last.eq(self.seg_payload.last),
            ]

        return m


class TCPTXArbiter(wiring.Component):
    """Per-segment arbiter for the engines' TX streams.

    One input per engine name (priority follows mapping order) with
    ``<name>_dst_ip``/``<name>_length`` sidebands, muxed onto a single
    output for the IP TX arbiter. With a single engine this is pure wiring.
    """
    def __init__(self, ports):
        self.ports = dict(ports)
        assert len(self.ports) > 0
        members = {
            "source":   Out(eth_stream_signature()),
            "dst_ip":   Out(32),
            "length":   Out(16),
            "protocol": Out(8),
        }
        for name in self.ports:
            members[name]             = In(eth_stream_signature())
            members[f"{name}_dst_ip"] = In(32)
            members[f"{name}_length"] = In(16)
        super().__init__(members)

    def elaborate(self, platform):
        m = Module()

        m.d.comb += self.protocol.eq(IPV4_PROTOCOL_TCP)

        def forward(name):
            port = getattr(self, name)
            return [
                self.source.valid.eq(port.valid),
                self.source.payload.eq(port.payload),
                self.source.first.eq(port.first),
                self.source.last.eq(port.last),
                port.ready.eq(self.source.ready),
                self.dst_ip.eq(getattr(self, f"{name}_dst_ip")),
                self.length.eq(getattr(self, f"{name}_length")),
            ]

        names = list(self.ports)
        if len(names) == 1:
            m.d.comb += forward(names[0])
            return m

        with m.FSM():
            with m.State("IDLE"):
                for name in reversed(names):
                    with m.If(getattr(self, name).valid):
                        m.next = name.upper()

            for name in names:
                port = getattr(self, name)
                with m.State(name.upper()):
                    m.d.comb += forward(name)
                    with m.If(port.valid & port.ready & port.last):
                        m.next = "IDLE"

        return m
