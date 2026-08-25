#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Tests of the TCP engines (passive open, one connection per listen port).

The DUT loops every TCP port back as an echo server, mirroring the hardware
example (including the close fabric). The testbench plays the remote client
over plain MAC frames.
"""

import random

import pytest

from amaranth.hdl import Module, Signal, Elaboratable
from amaranth.lib.wiring import connect
from amaranth.sim import Simulator

from amaranth_stream import PacketFIFO

from lambdaeth.core import (UDPIPCore, TCPServer, TCPClient,
                            eth_stream_signature)

from .net_helpers import (build_eth, build_arp, build_tcp_frame, ParsedFrame,
                          mac_bytes, ip_bytes,
                          TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK)
from .test_udpip_core import send_frame, recv_frame, make_sim

BOARD_MAC = 0x024c45544800
BOARD_IP  = 0xc0a80a32          # 192.168.10.50
HOST_MAC  = 0x60cf847491a3
HOST_IP   = 0xc0a80a78          # 192.168.10.120

RTO = 0.004                     # 4000 cycles at the 1 MHz test clock.


class TCPEchoDUT(Elaboratable):
    """UDP/IP core with TCP echo servers on every listen port.

    Mirrors the hardware example fabric: rx -> PacketFIFO -> tx, plus the
    close rule (close once the peer closed and the loop drained).
    """
    def __init__(self, tcp_ports, **kwargs):
        kwargs.setdefault("tcp_rto", RTO)
        kwargs.setdefault("tcp_idle_timeout", 0)
        kwargs.setdefault("tcp_reconnect_delay", 0.002)    # 2000 cycles.
        self.core = UDPIPCore(clk_freq=1e6, tcp_ports=tcp_ports, **kwargs)

    def elaborate(self, platform):
        m = Module()
        m.submodules.core = core = self.core
        for name in core.tcp_ports:
            fifo = PacketFIFO(eth_stream_signature(),
                              payload_depth=2048, packet_depth=8)
            m.submodules[f"echo_{name}"] = fifo
            rx = getattr(core, f"tcp_rx_{name}")
            tx = getattr(core, f"tcp_tx_{name}")
            connect(m, rx, fifo.i_stream)
            connect(m, fifo.o_stream, tx)

            # Close once the peer closed and every received byte was fed
            # back into the engine.
            rx_bytes = Signal(32)
            tx_bytes = Signal(32)
            with m.If(rx.valid & rx.ready):
                m.d.sync += rx_bytes.eq(rx_bytes + 1)
            with m.If(tx.valid & tx.ready):
                m.d.sync += tx_bytes.eq(tx_bytes + 1)
            m.d.comb += getattr(core, f"tcp_close_{name}").eq(
                getattr(core, f"tcp_peer_closed_{name}") &
                (rx_bytes == tx_bytes))
        m.d.comb += [
            core.mac_address.eq(BOARD_MAC),
            core.ip_address.eq(BOARD_IP),
        ]
        return m


class Peer:
    """Remote TCP client model over the MAC frame streams."""
    def __init__(self, core, sport, dport, seq=0x10000):
        self.core  = core
        self.sport = sport
        self.dport = dport
        self.seq   = seq            # Next sequence number to send.
        self.ack   = 0              # Next expected board sequence number.

    def _frame(self, flags, payload=b"", seq=None, ack=None, window=0xffff,
               options=b"", bad_checksum=False):
        return build_tcp_frame(
            HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP, self.sport, self.dport,
            (self.seq if seq is None else seq) & 0xffffffff,
            (self.ack if ack is None else ack) & 0xffffffff,
            flags, payload, window, options, bad_checksum)

    async def send(self, ctx, flags, payload=b"", **kw):
        await send_frame(ctx, self.core.mac_rx, self._frame(flags, payload, **kw))

    async def recv_seg(self, ctx, timeout=40000):
        """Receive one TCP segment addressed to us (checksum-verified)."""
        seg = ParsedFrame(await recv_frame(ctx, self.core.mac_tx,
                                           timeout=timeout))
        assert seg.ethertype == 0x0800 and seg.ip_protocol == 6
        assert seg.ip_csum_ok and seg.tcp_csum_ok
        assert seg.tcp_src_port == self.dport
        assert seg.tcp_dst_port == self.sport
        return seg

    async def connect(self, ctx, options=b""):
        """Three-way handshake; returns the board's SYN-ACK."""
        await self.send(ctx, TCP_SYN, ack=0, options=options)
        synack = await self.recv_seg(ctx)
        assert synack.tcp_flag_syn and synack.tcp_flag_ack
        assert not synack.tcp_flag_rst
        assert synack.tcp_ack == (self.seq + 1) & 0xffffffff
        self.seq = (self.seq + 1) & 0xffffffff
        self.ack = (synack.tcp_seq + 1) & 0xffffffff
        await self.send(ctx, TCP_ACK)
        return synack

    async def send_data(self, ctx, payload):
        await self.send(ctx, TCP_PSH | TCP_ACK, payload)
        self.seq = (self.seq + len(payload)) & 0xffffffff

    async def expect_echo(self, ctx, payload):
        """Collect segments until our data is ACKed and echoed back."""
        acked = echoed = False
        data = b""
        while not (acked and echoed):
            seg = await self.recv_seg(ctx)
            assert not seg.tcp_flag_rst and not seg.tcp_flag_fin
            if seg.tcp_ack == self.seq and seg.tcp_flag_ack:
                acked = True
            if seg.tcp_payload:
                assert seg.tcp_seq == (self.ack + len(data)) & 0xffffffff
                data += seg.tcp_payload
                if data == payload:
                    echoed = True
                assert len(data) <= len(payload)
        self.ack = (self.ack + len(data)) & 0xffffffff
        await self.send(ctx, TCP_ACK)


class ServerPeer:
    """Host-side TCP *server* model: accepts the board's active open."""
    def __init__(self, core, lport, iss=0x5a0000):
        self.core  = core
        self.lport = lport
        self.iss   = iss

    async def wait_syn(self, ctx, timeout=60000):
        """Wait for the board's SYN, answering ARP requests on the way."""
        while True:
            frame = ParsedFrame(await recv_frame(ctx, self.core.mac_tx,
                                                 timeout=timeout))
            if frame.ethertype == 0x0806 and frame.arp_opcode == 1 and \
                    frame.arp_target_ip == ip_bytes(HOST_IP):
                reply = build_eth(BOARD_MAC, HOST_MAC, 0x0806,
                                  build_arp(2, HOST_MAC, HOST_IP,
                                            BOARD_MAC, BOARD_IP))
                await send_frame(ctx, self.core.mac_rx, reply)
                continue
            assert frame.ethertype == 0x0800 and frame.ip_protocol == 6
            assert frame.tcp_csum_ok and frame.ip_csum_ok
            assert frame.tcp_dst_port == self.lport
            assert frame.tcp_flag_syn and not frame.tcp_flag_ack
            assert not frame.tcp_payload
            return frame

    async def accept(self, ctx, timeout=60000):
        """SYN -> SYN-ACK -> ACK; returns a connected :class:`Peer`."""
        syn = await self.wait_syn(ctx, timeout)
        peer = Peer(self.core, self.lport, syn.tcp_src_port, seq=self.iss)
        peer.ack = (syn.tcp_seq + 1) & 0xffffffff
        await peer.send(ctx, TCP_SYN | TCP_ACK)
        peer.seq = (peer.seq + 1) & 0xffffffff
        ack = await peer.recv_seg(ctx)
        assert ack.tcp_flag_ack and not ack.tcp_flag_syn
        assert not ack.tcp_flag_rst
        assert ack.tcp_ack == peer.seq
        assert ack.tcp_seq == peer.ack
        return peer


async def arp_handshake(ctx, core):
    request = build_eth(0xffffffffffff, HOST_MAC, 0x0806,
                        build_arp(1, HOST_MAC, HOST_IP, 0, BOARD_IP))
    await send_frame(ctx, core.mac_rx, request)
    await recv_frame(ctx, core.mac_tx)


async def expect_no_frame(ctx, core, cycles=3000):
    ctx.set(core.mac_tx.ready, 1)
    for _ in range(cycles):
        _clk, _rst, valid = await ctx.tick().sample(core.mac_tx.valid)
        assert not valid, "unexpected TX frame"
    ctx.set(core.mac_tx.ready, 0)


def test_handshake():
    """SYN -> SYN-ACK -> ACK establishes; window advertises the RX buffer."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44000, 2000)
        synack = await peer.connect(ctx)
        assert synack.tcp_window == 2048
        for _ in range(50):
            await ctx.tick()
        assert ctx.get(core.tcp_connected_p0) == 1

    sim.add_testbench(tb)
    sim.run()


@pytest.mark.parametrize("seq0", [0x10000, 0xfffffffa])   # incl. wraparound
def test_echo(seq0):
    """Data is ACKed and echoed back on the same connection."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core
    prng = random.Random(3)
    payload = bytes(prng.randrange(256) for _ in range(100))

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44001, 2000, seq=seq0)
        await peer.connect(ctx)
        await peer.send_data(ctx, payload)
        await peer.expect_echo(ctx, payload)
        # Second exchange on the same connection.
        await peer.send_data(ctx, b"again")
        await peer.expect_echo(ctx, b"again")

    sim.add_testbench(tb)
    sim.run()


def test_syn_with_options():
    """SYN options (MSS etc.) are skipped and checksummed correctly."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core
    mss_opt = bytes([2, 4, 0x05, 0xb4])     # MSS 1460.

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44002, 2000)
        await peer.connect(ctx, options=mss_opt)
        await peer.send_data(ctx, b"with options")
        await peer.expect_echo(ctx, b"with options")

    sim.add_testbench(tb)
    sim.run()


def test_duplicate_segment_dup_acked():
    """A retransmitted (duplicate) data segment is dup-ACKed, not re-echoed."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44003, 2000)
        await peer.connect(ctx)
        old_seq = peer.seq
        await peer.send_data(ctx, b"hello")
        await peer.expect_echo(ctx, b"hello")
        # Replay the same segment (peer retransmission).
        await peer.send(ctx, TCP_PSH | TCP_ACK, b"hello", seq=old_seq)
        dup = await peer.recv_seg(ctx)
        assert dup.tcp_flag_ack and not dup.tcp_payload
        assert dup.tcp_ack == peer.seq       # Still the cumulative ACK.
        await expect_no_frame(ctx, core)     # No duplicate echo.

    sim.add_testbench(tb)
    sim.run()


def test_out_of_order_dropped():
    """A future-sequence segment is dropped and dup-ACKed."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44004, 2000)
        await peer.connect(ctx)
        await peer.send(ctx, TCP_PSH | TCP_ACK, b"future",
                        seq=peer.seq + 1000)
        dup = await peer.recv_seg(ctx)
        assert dup.tcp_ack == peer.seq and not dup.tcp_payload
        # In-order data still works.
        await peer.send_data(ctx, b"present")
        await peer.expect_echo(ctx, b"present")

    sim.add_testbench(tb)
    sim.run()


def test_retransmission():
    """An unACKed echo segment is retransmitted identically after the RTO."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44005, 2000)
        await peer.connect(ctx)
        await peer.send(ctx, TCP_PSH | TCP_ACK, b"echo me")
        peer.seq += len(b"echo me")

        first = None
        seen_data = 0
        # Withhold the ACK: collect the first transmission and at least one
        # retransmission of the same segment.
        while seen_data < 2:
            seg = await peer.recv_seg(ctx)
            if seg.tcp_payload:
                if first is None:
                    first = seg
                else:
                    assert seg.tcp_seq == first.tcp_seq
                    assert seg.tcp_payload == first.tcp_payload
                seen_data += 1
        # Now acknowledge; no further retransmissions.
        peer.ack = (first.tcp_seq + len(first.tcp_payload)) & 0xffffffff
        await peer.send(ctx, TCP_ACK)
        await expect_no_frame(ctx, core, cycles=6000)

    sim.add_testbench(tb)
    sim.run()


def test_close_and_reconnect():
    """Peer FIN -> board ACK+FIN -> peer ACK -> back to LISTEN; the port
    accepts a fresh connection afterwards."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44006, 2000)
        await peer.connect(ctx)
        await peer.send_data(ctx, b"bye")
        await peer.expect_echo(ctx, b"bye")

        await peer.send(ctx, TCP_FIN | TCP_ACK)
        fin_seq = peer.seq
        peer.seq += 1                       # FIN consumes one.
        # Expect the ACK of our FIN and the board's FIN (possibly combined).
        got_fin = None
        while got_fin is None:
            seg = await peer.recv_seg(ctx)
            assert not seg.tcp_flag_rst
            if seg.tcp_flag_fin:
                got_fin = seg
            assert seg.tcp_ack == peer.seq  # Our FIN is acknowledged.
        assert got_fin.tcp_seq == peer.ack
        peer.ack += 1
        await peer.send(ctx, TCP_ACK)

        for _ in range(100):
            await ctx.tick()
        assert ctx.get(core.tcp_connected_p0) == 0

        # Fresh connection on the same port.
        peer2 = Peer(core, 44007, 2000, seq=0x777)
        await peer2.connect(ctx)
        await peer2.send_data(ctx, b"hello again")
        await peer2.expect_echo(ctx, b"hello again")

    sim.add_testbench(tb)
    sim.run()


def test_rst_aborts_connection():
    """A matching RST tears the connection down; the port re-listens."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44008, 2000)
        await peer.connect(ctx)
        await peer.send(ctx, TCP_RST | TCP_ACK)
        for _ in range(200):
            await ctx.tick()
        assert ctx.get(core.tcp_connected_p0) == 0
        peer2 = Peer(core, 44009, 2000, seq=0x999)
        await peer2.connect(ctx)

    sim.add_testbench(tb)
    sim.run()


def test_ack_in_listen_refused():
    """A stray ACK against a listening port draws RST (seq = its ack)."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44010, 2000)
        await peer.send(ctx, TCP_ACK, seq=0x1234, ack=0x5678)
        rst = await peer.recv_seg(ctx)
        assert rst.tcp_flag_rst
        assert rst.tcp_seq == 0x5678

    sim.add_testbench(tb)
    sim.run()


def test_unbound_port_refused():
    """SYN to a port nobody listens on draws RST (connection refused)."""
    dut = TCPEchoDUT([2000, 2001])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44011, 9999, seq=0x4242)
        await peer.send(ctx, TCP_SYN, ack=0)
        rst = await peer.recv_seg(ctx)
        assert rst.tcp_flag_rst
        assert rst.tcp_seq == 0
        assert rst.tcp_ack == 0x4243        # SYN counts as one.
        # The bound ports still work.
        peer2 = Peer(core, 44012, 2001)
        await peer2.connect(ctx)
        await peer2.send_data(ctx, b"alive")
        await peer2.expect_echo(ctx, b"alive")

    sim.add_testbench(tb)
    sim.run()


def test_busy_port_refuses_second_client():
    """A second client's SYN against a busy port is refused with RST,
    without disturbing the established connection."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44013, 2000)
        await peer.connect(ctx)
        intruder = Peer(core, 44014, 2000, seq=0x2222)
        await intruder.send(ctx, TCP_SYN, ack=0)
        rst = await intruder.recv_seg(ctx)
        assert rst.tcp_flag_rst and rst.tcp_ack == 0x2223
        # Original connection unharmed.
        await peer.send_data(ctx, b"still mine")
        await peer.expect_echo(ctx, b"still mine")

    sim.add_testbench(tb)
    sim.run()


def test_two_ports_independent():
    """Two listen ports carry two simultaneous connections."""
    dut = TCPEchoDUT([2000, 2001])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        a = Peer(core, 44015, 2000, seq=0x100)
        b = Peer(core, 44016, 2001, seq=0x200)
        await a.connect(ctx)
        await b.connect(ctx)
        await a.send_data(ctx, b"alpha")
        await a.expect_echo(ctx, b"alpha")
        await b.send_data(ctx, b"beta")
        await b.expect_echo(ctx, b"beta")
        await a.send_data(ctx, b"alpha2")
        await a.expect_echo(ctx, b"alpha2")
        assert ctx.get(core.tcp_connected_p0) == 1
        assert ctx.get(core.tcp_connected_p1) == 1

    sim.add_testbench(tb)
    sim.run()


def test_bad_checksum_dropped():
    """A corrupt segment is silently dropped; the connection survives."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44017, 2000)
        await peer.connect(ctx)
        await peer.send(ctx, TCP_PSH | TCP_ACK, b"corrupt", bad_checksum=True)
        await expect_no_frame(ctx, core)
        await peer.send_data(ctx, b"pristine")
        await peer.expect_echo(ctx, b"pristine")

    sim.add_testbench(tb)
    sim.run()


def test_zero_window_respected():
    """The engine holds data while the peer advertises a zero window and
    resumes on a window update."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44018, 2000)
        await peer.connect(ctx)
        # Close the window, then send data to be echoed.
        await peer.send(ctx, TCP_ACK, window=0)
        await peer.send(ctx, TCP_PSH | TCP_ACK, b"stuck", window=0)
        peer.seq += 5
        # Only the ACK of our data may arrive; no echo while wnd=0.
        seg = await peer.recv_seg(ctx)
        assert seg.tcp_ack == peer.seq and not seg.tcp_payload
        await expect_no_frame(ctx, core)
        # Window update releases the echo.
        await peer.send(ctx, TCP_ACK, window=4096)
        seg = await peer.recv_seg(ctx)
        assert seg.tcp_payload == b"stuck"
        peer.ack += 5
        await peer.send(ctx, TCP_ACK)

    sim.add_testbench(tb)
    sim.run()


def test_fin_piggybacked_on_data():
    """Data + FIN + ACK in a single segment (smoltcp: established_fin with
    payload): the data is delivered and echoed, the FIN counted, and the
    close handshake completes."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core
    payload = b"last words"

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44019, 2000)
        await peer.connect(ctx)

        await peer.send(ctx, TCP_PSH | TCP_ACK | TCP_FIN, payload)
        peer.seq += len(payload) + 1        # Data + FIN.

        # Expect: ACK covering data+FIN, the echoed data, then the board FIN.
        data = b""
        got_fin = None
        while got_fin is None:
            seg = await peer.recv_seg(ctx)
            assert not seg.tcp_flag_rst
            assert seg.tcp_ack == peer.seq  # Data and FIN acknowledged.
            if seg.tcp_payload:
                assert seg.tcp_seq == (peer.ack + len(data)) & 0xffffffff
                data += seg.tcp_payload
                peer_ack = (peer.ack + len(data)) & 0xffffffff
                await peer.send(ctx, TCP_ACK, ack=peer_ack)
            if seg.tcp_flag_fin:
                got_fin = seg
        assert data == payload
        assert got_fin.tcp_seq == (peer.ack + len(payload)) & 0xffffffff
        peer.ack = (got_fin.tcp_seq + 1) & 0xffffffff
        await peer.send(ctx, TCP_ACK)
        for _ in range(100):
            await ctx.tick()
        assert ctx.get(core.tcp_connected_p0) == 0

    sim.add_testbench(tb)
    sim.run()


def test_fin_with_handshake_ack():
    """SYN-RCVD receiving ACK+data+FIN in one segment (smoltcp:
    syn_received_fin): handshake completes, data accepted, FIN counted —
    the reply ACKs seq + len + 1."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core
    payload = b"abcdef"

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44020, 2000)
        await peer.send(ctx, TCP_SYN, ack=0)
        synack = await peer.recv_seg(ctx)
        peer.seq += 1
        peer.ack = (synack.tcp_seq + 1) & 0xffffffff

        # Third handshake segment carries data and FIN at once.
        await peer.send(ctx, TCP_ACK | TCP_PSH | TCP_FIN, payload)
        peer.seq += len(payload) + 1

        seg = await peer.recv_seg(ctx)
        assert seg.tcp_ack == peer.seq      # seq + 6 + 1, as in smoltcp.

    sim.add_testbench(tb)
    sim.run()


def test_rst_in_syn_rcvd():
    """RST instead of the handshake ACK aborts the half-open connection and
    the port listens again (smoltcp: syn_received_rst)."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44021, 2000)
        await peer.send(ctx, TCP_SYN, ack=0)
        synack = await peer.recv_seg(ctx)
        peer.seq += 1
        peer.ack = (synack.tcp_seq + 1) & 0xffffffff
        await peer.send(ctx, TCP_RST)
        for _ in range(200):
            await ctx.tick()
        # Fresh connection succeeds.
        peer2 = Peer(core, 44022, 2000, seq=0xabc)
        await peer2.connect(ctx)
        await peer2.send_data(ctx, b"recovered")
        await peer2.expect_echo(ctx, b"recovered")

    sim.add_testbench(tb)
    sim.run()


def test_lost_last_ack_recovered_by_fin_retransmit():
    """If the peer never ACKs our FIN (LAST-ACK), the engine retransmits
    FIN|ACK after the RTO — which also re-acknowledges the peer's FIN."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44023, 2000)
        await peer.connect(ctx)
        await peer.send(ctx, TCP_FIN | TCP_ACK)
        peer.seq += 1

        fins = []
        while len(fins) < 2:                # First FIN + one retransmission.
            seg = await peer.recv_seg(ctx)
            assert seg.tcp_ack == peer.seq
            if seg.tcp_flag_fin:
                fins.append(seg)
        assert fins[0].tcp_seq == fins[1].tcp_seq
        peer.ack = (fins[0].tcp_seq + 1) & 0xffffffff
        await peer.send(ctx, TCP_ACK)
        for _ in range(200):
            await ctx.tick()
        assert ctx.get(core.tcp_connected_p0) == 0
        peer2 = Peer(core, 44024, 2000, seq=0xdef)
        await peer2.connect(ctx)

    sim.add_testbench(tb)
    sim.run()


def test_fin_after_gap_dup_acked():
    """A FIN+data segment beyond rcv_nxt is not processed (smoltcp:
    established_fin_after_missing): dup-ACK only, connection stays open."""
    dut = TCPEchoDUT([2000])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        peer = Peer(core, 44025, 2000)
        await peer.connect(ctx)
        await peer.send(ctx, TCP_PSH | TCP_ACK | TCP_FIN, b"123456",
                        seq=peer.seq + 6)   # Gap: the first 6 bytes missing.
        dup = await peer.recv_seg(ctx)
        assert dup.tcp_ack == peer.seq and not dup.tcp_payload
        assert not dup.tcp_flag_fin
        for _ in range(100):
            await ctx.tick()
        assert ctx.get(core.tcp_connected_p0) == 1
        assert ctx.get(core.tcp_peer_closed_p0) == 0
        # Fill the gap: everything is accepted in order.
        await peer.send_data(ctx, b"abcdef")
        await peer.expect_echo(ctx, b"abcdef")

    sim.add_testbench(tb)
    sim.run()


# Client mode -----------------------------------------------------------------------------------

def test_client_connects_and_echoes():
    """The client engine opens the connection itself (SYN from the board),
    completes the handshake and echoes server data."""
    dut = TCPEchoDUT([TCPClient(HOST_IP, 5001, local_port=49200)])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        server = ServerPeer(core, 5001)
        peer = await server.accept(ctx)
        assert peer.dport == 49200          # Fixed client source port.
        for _ in range(50):
            await ctx.tick()
        assert ctx.get(core.tcp_connected_p0) == 1
        await peer.send_data(ctx, b"hello board")
        await peer.expect_echo(ctx, b"hello board")
        await peer.send_data(ctx, b"more")
        await peer.expect_echo(ctx, b"more")

    sim.add_testbench(tb)
    sim.run()


def test_client_syn_retransmitted_until_answered():
    """An unanswered SYN is retransmitted (same ISS); answering a later
    attempt completes the handshake."""
    dut = TCPEchoDUT([TCPClient(HOST_IP, 5001, local_port=49200)])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        server = ServerPeer(core, 5001)
        syns = [await server.wait_syn(ctx) for _ in range(3)]
        assert syns[1].tcp_seq == syns[0].tcp_seq   # Retransmissions.
        assert syns[2].tcp_seq == syns[0].tcp_seq
        peer = await server.accept(ctx)             # Answer the next one.
        await peer.send_data(ctx, b"finally")
        await peer.expect_echo(ctx, b"finally")

    sim.add_testbench(tb)
    sim.run()


def test_client_refused_then_retries():
    """An RST to the SYN (connection refused) makes the client back off for
    reconnect_delay and try again."""
    dut = TCPEchoDUT([TCPClient(HOST_IP, 5001, local_port=49200)])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        server = ServerPeer(core, 5001)
        syn1 = await server.wait_syn(ctx)
        # Refuse: RST with seq=0, ack=iss+1 (as a real stack would).
        rst = build_tcp_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                              5001, syn1.tcp_src_port,
                              0, (syn1.tcp_seq + 1) & 0xffffffff,
                              TCP_RST | TCP_ACK)
        await send_frame(ctx, core.mac_rx, rst)
        # Next attempt arrives after the reconnect delay and succeeds.
        peer = await server.accept(ctx)
        await peer.send_data(ctx, b"second try")
        await peer.expect_echo(ctx, b"second try")

    sim.add_testbench(tb)
    sim.run()


def test_client_close_then_reconnects():
    """After the server closes (FIN handshake), the client reconnects by
    itself following the reconnect delay."""
    dut = TCPEchoDUT([TCPClient(HOST_IP, 5001, local_port=49200)])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        server = ServerPeer(core, 5001)
        peer = await server.accept(ctx)
        await peer.send_data(ctx, b"first life")
        await peer.expect_echo(ctx, b"first life")

        # Server closes; board ACKs and FINs back once drained.
        await peer.send(ctx, TCP_FIN | TCP_ACK)
        peer.seq += 1
        got_fin = None
        while got_fin is None:
            seg = await peer.recv_seg(ctx)
            assert not seg.tcp_flag_rst
            assert seg.tcp_ack == peer.seq
            if seg.tcp_flag_fin:
                got_fin = seg
        peer.ack = (got_fin.tcp_seq + 1) & 0xffffffff
        await peer.send(ctx, TCP_ACK)

        # The client comes back on its own.
        server2 = ServerPeer(core, 5001, iss=0x660000)
        peer2 = await server2.accept(ctx)
        await peer2.send_data(ctx, b"second life")
        await peer2.expect_echo(ctx, b"second life")

    sim.add_testbench(tb)
    sim.run()


def test_client_and_server_mix():
    """One core: a server endpoint and a client endpoint working at once,
    sharing TCPRX/dispatch/arbiter."""
    dut = TCPEchoDUT([TCPServer(2000),
                      TCPClient(HOST_IP, 5001, local_port=49200)])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        # Board's client connects out to us.
        server = ServerPeer(core, 5001)
        cli = await server.accept(ctx)
        # We connect into the board's server.
        srv = Peer(core, 44100, 2000, seq=0x321)
        await srv.connect(ctx)

        await cli.send_data(ctx, b"to the client engine")
        await cli.expect_echo(ctx, b"to the client engine")
        await srv.send_data(ctx, b"to the server engine")
        await srv.expect_echo(ctx, b"to the server engine")
        assert ctx.get(core.tcp_connected_p0) == 1
        assert ctx.get(core.tcp_connected_p1) == 1

    sim.add_testbench(tb)
    sim.run()


def test_client_stale_ack_rst_then_connects():
    """A stale ACK answering our SYN (peer in TIME-WAIT) draws an RST that
    kills the old state; the retry then completes (self-healing)."""
    dut = TCPEchoDUT([TCPClient(HOST_IP, 5001, local_port=49200)])
    sim = make_sim(dut)
    core = dut.core

    async def tb(ctx):
        await arp_handshake(ctx, core)
        server = ServerPeer(core, 5001)
        syn = await server.wait_syn(ctx)
        # TIME-WAIT-style stale ACK (wrong ack number, no SYN).
        stale = build_tcp_frame(HOST_MAC, HOST_IP, BOARD_MAC, BOARD_IP,
                                5001, syn.tcp_src_port,
                                0x11111111, 0x22222222, TCP_ACK)
        await send_frame(ctx, core.mac_rx, stale)
        rst = await Peer(core, 5001, syn.tcp_src_port).recv_seg(ctx)
        assert rst.tcp_flag_rst
        assert rst.tcp_seq == 0x22222222    # seq = the stale segment's ack.
        # The connection attempt is still alive: answer a following SYN.
        peer = await server.accept(ctx)
        await peer.send_data(ctx, b"healed")
        await peer.expect_echo(ctx, b"healed")

    sim.add_testbench(tb)
    sim.run()


def test_tcp_spec_validation():
    with pytest.raises(AssertionError):
        # Duplicate local ports (server port vs explicit client local).
        UDPIPCore(clk_freq=1e6,
                  tcp_ports=[TCPServer(2000),
                             TCPClient(HOST_IP, 5001, local_port=2000)])
    with pytest.raises(AssertionError):
        UDPIPCore(clk_freq=1e6, tcp_ports=["nope"])


def test_member_shapes_and_netlist():
    """TCP logic and members exist only when requested; single-port
    dispatch/arbiter degenerate to wiring."""
    from amaranth.back import rtlil
    from lambdaeth.core.tcp import TCPSegDispatch, TCPTXArbiter

    legacy = UDPIPCore(clk_freq=1e6)
    assert not hasattr(legacy, "tcp_rx_seg")
    one = UDPIPCore(clk_freq=1e6, tcp_ports=[2000])
    for name in ("tcp_rx_p0", "tcp_tx_p0", "tcp_port_p0", "tcp_connected_p0",
                 "tcp_peer_closed_p0", "tcp_close_p0", "tcp_rx_seg",
                 "tcp_drop", "tcp_rst"):
        assert hasattr(one, name)
    named = UDPIPCore(clk_freq=1e6, tcp_ports={"ctl": 5000})
    assert hasattr(named, "tcp_rx_ctl")

    arb1 = rtlil.convert(TCPTXArbiter({"a": 1}), name="a1")
    arb2 = rtlil.convert(TCPTXArbiter({"a": 1, "b": 2}), name="a2")
    assert "fsm_state" not in arb1 and "fsm_state" in arb2
    dsp1 = rtlil.convert(TCPSegDispatch({"a": 1}), name="d1")
    assert "cell" not in dsp1    # Single port: pure wiring, zero cells.
    dsp2 = rtlil.convert(TCPSegDispatch({"a": 1, "b": 2}), name="d2")
    assert "cell" in dsp2
    legacy_rtlil = rtlil.convert(UDPIPCore(clk_freq=1e6), name="core_x")
    assert "tcp_rx" not in legacy_rtlil
