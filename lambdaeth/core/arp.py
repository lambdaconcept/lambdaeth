#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""ARP: responder, cache and resolver.

Interfaces use natural byte order; conversion to wire order happens at the
packetizer/depacketizer boundary.
"""

from amaranth.hdl import Module, Signal, Mux
from amaranth.lib import wiring
from amaranth.lib.memory import Memory
from amaranth.lib.wiring import In, Out, connect, flipped

from amaranth_stream import Packetizer, Depacketizer

from .layouts import (eth_stream_signature, arp_header_layout, bswap,
                      ARP_HWTYPE_ETHERNET, ARP_PROTO_IPV4,
                      ARP_OPCODE_REQUEST, ARP_OPCODE_REPLY,
                      ARP_HEADER_LEN, ARP_PACKET_LEN, BROADCAST_MAC)


__all__ = ["arp_event_signature", "arp_request_signature", "arp_response_signature",
           "ARPRX", "ARPTX", "ARPTable", "ARP"]


def arp_event_signature():
    """ARP RX event (to the table) / TX command (from the table)."""
    return wiring.Signature({
        "valid":       Out(1),
        "ready":       In(1),
        "reply":       Out(1),
        "request":     Out(1),
        "ip_address":  Out(32),
        "mac_address": Out(48),
    })


def arp_request_signature():
    return wiring.Signature({
        "valid":      Out(1),
        "ready":      In(1),
        "ip_address": Out(32),
    })


def arp_response_signature():
    return wiring.Signature({
        "valid":       Out(1),
        "ready":       In(1),
        "failed":      Out(1),
        "mac_address": Out(48),
    })


class ARPRX(wiring.Component):
    """Parse received ARP packets and emit table events.

    Events are single-cycle (if the table is busy the event is lost; the
    protocol compensates with retries).
    """
    def __init__(self):
        super().__init__({
            "sink":        In(eth_stream_signature()),
            "event":       Out(arp_event_signature()),
            "mac_address": In(48),
            "ip_address":  In(32),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.depacketizer = depack = Depacketizer(
            arp_header_layout, eth_stream_signature())
        connect(m, flipped(self.sink), depack.i_stream)

        hdr = depack.header

        valid = Signal()
        m.d.comb += valid.eq(
            (hdr.hwtype    == bswap(ARP_HWTYPE_ETHERNET, 16)) &
            (hdr.proto     == bswap(ARP_PROTO_IPV4, 16)) &
            (hdr.hwsize    == 6) &
            (hdr.protosize == 4) &
            (bswap(hdr.target_ip) == self.ip_address))

        m.d.comb += [
            self.event.ip_address.eq(bswap(hdr.sender_ip)),
            self.event.mac_address.eq(bswap(hdr.sender_mac)),
            self.event.reply.eq(hdr.opcode == bswap(ARP_OPCODE_REPLY, 16)),
            self.event.request.eq(hdr.opcode == bswap(ARP_OPCODE_REQUEST, 16)),
        ]

        with m.FSM():
            with m.State("IDLE"):
                with m.If(depack.o_stream.valid):
                    m.next = "EVENT"

            with m.State("EVENT"):
                m.d.comb += self.event.valid.eq(valid &
                                                (self.event.reply | self.event.request))
                m.next = "DRAIN"

            with m.State("DRAIN"):
                m.d.comb += depack.o_stream.ready.eq(1)
                with m.If(depack.o_stream.valid & depack.o_stream.last):
                    m.next = "IDLE"

        return m


class ARPTX(wiring.Component):
    """Send ARP requests/replies (commands from the table).

    ``source`` carries the ARP packet (28 bytes + zero padding to 46);
    ``target_mac`` holds the resolved destination MAC for the MAC layer while
    the packet is streaming.
    """
    def __init__(self):
        super().__init__({
            "sink":        In(arp_event_signature()),
            "source":      Out(eth_stream_signature()),
            "target_mac":  Out(48),
            "mac_address": In(48),
            "ip_address":  In(32),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.packetizer = pack = Packetizer(
            arp_header_layout, eth_stream_signature())

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

        # Latched command.
        is_reply = Signal()
        cmd_ip   = Signal(32)
        cmd_mac  = Signal(48)

        m.d.comb += [
            pack.header.hwtype.eq(bswap(ARP_HWTYPE_ETHERNET, 16)),
            pack.header.proto.eq(bswap(ARP_PROTO_IPV4, 16)),
            pack.header.hwsize.eq(6),
            pack.header.protosize.eq(4),
            pack.header.sender_mac.eq(bswap(self.mac_address)),
            pack.header.sender_ip.eq(bswap(self.ip_address)),
            pack.header.target_ip.eq(bswap(cmd_ip)),
            pack.header.opcode.eq(Mux(is_reply,
                                      bswap(ARP_OPCODE_REPLY, 16),
                                      bswap(ARP_OPCODE_REQUEST, 16))),
            pack.header.target_mac.eq(Mux(is_reply, bswap(cmd_mac), 0)),
            self.target_mac.eq(Mux(is_reply, cmd_mac, BROADCAST_MAC)),
        ]

        # Zero padding payload (ARP packet padded to the Ethernet minimum).
        pad_beats = ARP_PACKET_LEN - ARP_HEADER_LEN
        count     = Signal(range(pad_beats))

        with m.FSM():
            with m.State("IDLE"):
                m.d.sync += count.eq(0)
                with m.If(self.sink.valid):
                    m.d.sync += [
                        is_reply.eq(self.sink.reply),
                        cmd_ip.eq(self.sink.ip_address),
                        cmd_mac.eq(self.sink.mac_address),
                    ]
                    m.next = "SEND"

            with m.State("SEND"):
                m.d.comb += [
                    src_connect.eq(1),
                    pack.i_stream.valid.eq(1),
                    pack.i_stream.payload.eq(0),
                    pack.i_stream.first.eq(count == 0),
                    pack.i_stream.last.eq(count == pad_beats - 1),
                ]
                with m.If(pack.i_stream.ready):
                    m.d.sync += count.eq(count + 1)
                    with m.If(pack.i_stream.last):
                        m.d.comb += self.sink.ready.eq(1)
                        m.next = "IDLE"

        return m


class ARPTable(wiring.Component):
    """ARP cache and resolver (port of LiteEthARPTable/Cache).

    * Replies to incoming ARP requests (through ``source`` -> :class:`ARPTX`).
    * Learns from incoming ARP replies.
    * Resolves IPs on ``request``/``response``, sending ARP requests with
      retries on cache misses.
    * The cache is cleared periodically (crude aging).
    """
    def __init__(self, clk_freq, entries=4, max_requests=8,
                 request_timeout=100e-3, clear_period=1.0):
        self.clk_freq        = clk_freq
        self.entries         = max(entries, 2)
        self.max_requests    = max_requests
        self.request_cycles  = max(int(request_timeout*clk_freq), 4)
        self.clear_cycles    = max(int(clear_period*clk_freq), 4)
        super().__init__({
            "sink":     In(arp_event_signature()),    # From ARPRX.
            "source":   Out(arp_event_signature()),   # To ARPTX.
            "request":  In(arp_request_signature()),
            "response": Out(arp_response_signature()),
        })

    def elaborate(self, platform):
        m = Module()

        sink     = self.sink
        source   = self.source
        request  = self.request
        response = self.response

        # Cache memory: {valid, mac, ip}.
        m.submodules.mem = mem = Memory(shape=81, depth=self.entries, init=[])
        wr = mem.write_port()
        rd = mem.read_port()

        rd_valid = rd.data[80]
        rd_mac   = rd.data[32:80]
        rd_ip    = rd.data[0:32]

        update_count = Signal(range(self.entries))
        search_count = Signal(range(self.entries))
        error        = Signal()
        response_mac = Signal(48)

        # Periodic cache clear.
        clear_timer = Signal(range(self.clear_cycles + 1))
        clear_now   = Signal()
        m.d.comb += clear_now.eq(clear_timer == self.clear_cycles)

        # Request retry timer.
        request_pending    = Signal()
        request_counter    = Signal(range(self.max_requests))
        request_ip_address = Signal(32)
        request_timer      = Signal(range(self.request_cycles + 1))
        request_timeout    = Signal()
        m.d.comb += request_timeout.eq(request_timer == self.request_cycles)
        with m.If(request_pending & ~request_timeout):
            m.d.sync += request_timer.eq(request_timer + 1)
        with m.If(~request_pending):
            m.d.sync += request_timer.eq(0)

        with m.FSM():
            with m.State("CLEAR"):
                m.d.comb += [
                    wr.en.eq(1),
                    wr.addr.eq(update_count),
                    wr.data.eq(0),
                ]
                m.d.sync += update_count.eq(update_count + 1)
                with m.If(update_count == self.entries - 1):
                    m.d.sync += update_count.eq(0)
                    m.next = "IDLE"

            with m.State("IDLE"):
                with m.If(~clear_now):
                    m.d.sync += clear_timer.eq(clear_timer + 1)
                with m.If(sink.valid & sink.request):
                    m.next = "SEND_REPLY"
                with m.Elif(sink.valid & sink.reply):
                    m.next = "UPDATE_TABLE"
                with m.Elif(request.valid):
                    m.d.sync += search_count.eq(0)
                    m.next = "SEARCH"
                with m.Elif(request_pending & request_timeout):
                    m.next = "CHECK_REQUEST"
                with m.Elif(clear_now):
                    m.d.sync += [clear_timer.eq(0), update_count.eq(0)]
                    m.next = "CLEAR"

            with m.State("SEND_REPLY"):
                m.d.comb += [
                    source.valid.eq(1),
                    source.reply.eq(1),
                    source.ip_address.eq(sink.ip_address),
                    source.mac_address.eq(sink.mac_address),
                ]
                with m.If(source.ready):
                    # Opportunistically learn the requester.
                    m.next = "UPDATE_TABLE"

            with m.State("UPDATE_TABLE"):
                m.d.comb += [
                    wr.en.eq(1),
                    wr.addr.eq(update_count),
                    wr.data[0:32].eq(sink.ip_address),
                    wr.data[32:80].eq(sink.mac_address),
                    wr.data[80].eq(1),
                ]
                with m.If(update_count == self.entries - 1):
                    m.d.sync += update_count.eq(0)
                with m.Else():
                    m.d.sync += update_count.eq(update_count + 1)
                with m.If(request_pending & (request_ip_address == sink.ip_address)):
                    m.d.sync += [
                        request_pending.eq(0),
                        response_mac.eq(sink.mac_address),
                    ]
                    m.next = "PRESENT_RESPONSE"
                with m.Else():
                    m.next = "IDLE"

            with m.State("SEARCH"):
                # Issue read of entry `search_count`; data valid next cycle.
                m.d.comb += rd.addr.eq(search_count)
                m.next = "COMPARE"

            with m.State("COMPARE"):
                m.d.comb += rd.addr.eq(search_count)  # Hold for stability.
                with m.If(rd_valid & (rd_ip == request.ip_address)):
                    m.d.sync += error.eq(0)
                    m.next = "RESPONSE"
                with m.Elif(search_count == self.entries - 1):
                    m.d.sync += error.eq(1)
                    m.next = "RESPONSE"
                with m.Else():
                    m.d.sync += search_count.eq(search_count + 1)
                    m.next = "SEARCH"

            with m.State("RESPONSE"):
                m.d.comb += rd.addr.eq(search_count)  # Keep read data stable.
                with m.If(error):
                    # Miss: start the ARP request sequence.
                    m.d.comb += request.ready.eq(1)
                    m.d.sync += [
                        request_counter.eq(0),
                        request_pending.eq(1),
                        request_timer.eq(self.request_cycles),  # Fire at once.
                        request_ip_address.eq(request.ip_address),
                    ]
                    m.next = "IDLE"
                with m.Else():
                    m.d.comb += [
                        request.ready.eq(1),
                        response.valid.eq(1),
                        response.failed.eq(0),
                        response.mac_address.eq(rd_mac),
                    ]
                    with m.If(response.ready):
                        m.next = "IDLE"
                    with m.Else():
                        m.next = "WAIT_RESPONSE_ACK"

            with m.State("WAIT_RESPONSE_ACK"):
                m.d.comb += [
                    response.valid.eq(1),
                    response.mac_address.eq(rd_mac),
                ]
                m.d.comb += rd.addr.eq(search_count)
                with m.If(response.ready):
                    m.next = "IDLE"

            with m.State("CHECK_REQUEST"):
                with m.If(request_counter == self.max_requests - 1):
                    m.d.sync += [
                        request_counter.eq(0),
                        request_pending.eq(0),
                    ]
                    m.next = "PRESENT_FAILED"
                with m.Else():
                    m.next = "SEND_REQUEST"

            with m.State("SEND_REQUEST"):
                m.d.comb += [
                    source.valid.eq(1),
                    source.request.eq(1),
                    source.ip_address.eq(request_ip_address),
                ]
                with m.If(source.ready):
                    m.d.sync += [
                        request_counter.eq(request_counter + 1),
                        request_timer.eq(0),
                    ]
                    m.next = "IDLE"

            with m.State("PRESENT_FAILED"):
                m.d.comb += [
                    response.valid.eq(1),
                    response.failed.eq(1),
                ]
                with m.If(response.ready):
                    m.next = "IDLE"

            with m.State("PRESENT_RESPONSE"):
                m.d.comb += [
                    response.valid.eq(1),
                    response.failed.eq(0),
                    response.mac_address.eq(response_mac),
                ]
                with m.If(response.ready):
                    m.next = "IDLE"

        return m


class ARP(wiring.Component):
    """Complete ARP block: responder + cache + resolver."""
    def __init__(self, clk_freq, entries=4):
        self.clk_freq = clk_freq
        self.entries  = entries
        super().__init__({
            "rx_sink":     In(eth_stream_signature()),    # From MAC dispatch.
            "tx_source":   Out(eth_stream_signature()),   # To MAC arbiter.
            "tx_mac":      Out(48),                       # Destination MAC.
            "request":     In(arp_request_signature()),   # From IP TX.
            "response":    Out(arp_response_signature()),
            "mac_address": In(48),
            "ip_address":  In(32),
            "event":       Out(1),                        # Pulse: valid ARP event received.
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.rx    = rx    = ARPRX()
        m.submodules.tx    = tx    = ARPTX()
        m.submodules.table = table = ARPTable(self.clk_freq, entries=self.entries)

        connect(m, flipped(self.rx_sink), rx.sink)
        connect(m, tx.source, flipped(self.tx_source))
        connect(m, rx.event, table.sink)
        connect(m, table.source, tx.sink)

        m.d.comb += [
            self.tx_mac.eq(tx.target_mac),
            rx.mac_address.eq(self.mac_address),
            rx.ip_address.eq(self.ip_address),
            tx.mac_address.eq(self.mac_address),
            tx.ip_address.eq(self.ip_address),
            self.event.eq(rx.event.valid),
        ]

        connect(m, flipped(self.request), table.request)
        connect(m, table.response, flipped(self.response))

        return m
