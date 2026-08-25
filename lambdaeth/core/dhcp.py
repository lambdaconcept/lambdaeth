#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""DHCP client: acquire and maintain the board's IPv4 address (RFC 2131).

Rides the UDP layer as a bound port-68 user (a hidden entry of the UDP port
dispatch/arbiter), so no special datapath is needed: DISCOVER/REQUEST go out
as ordinary UDP datagrams to 255.255.255.255:67 (the IP layer broadcasts
without ARP; the source IP is the core's effective IP, which is 0.0.0.0
while unbound) and, because the BOOTP *broadcast flag* is set in every
request, the server's OFFER/ACK come back to 255.255.255.255:68 and pass IP
RX without an assigned address.

State machine: DISCOVER → (OFFER) → REQUEST → (ACK) → BOUND, retrying the
current step every ``retry`` seconds and restarting from DISCOVER (fresh
xid) on NAK. At half the lease a broadcast renewal REQUEST (``ciaddr`` set,
rebinding style) is sent, repeated until ACKed; when the lease runs out the
address is dropped and discovery restarts.

v1 simplifications (fine for LAN use): no ARP probing of the offered
address, no gratuitous ARP announcement, no unicast RENEW (broadcast
renewal only), no DECLINE/RELEASE, first OFFER wins, requests carry no
parameter-request-list (the lease/server-id options every server sends are
enough). Replies are validated by op/xid/chaddr/magic-cookie, so foreign
clients' broadcasts are ignored.
"""

from amaranth.hdl import Module, Signal, Cat, Mux
from amaranth.lib import wiring
from amaranth.lib.wiring import In, Out

from .layouts import udp_user_signature


__all__ = ["DHCPClient", "DHCP_CLIENT_PORT", "DHCP_SERVER_PORT"]


DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
DHCP_MESSAGE_LEN = 300          # Fixed TX size (BOOTP minimum).

_MSG_DISCOVER = 1
_MSG_OFFER    = 2
_MSG_REQUEST  = 3
_MSG_ACK      = 5
_MSG_NAK      = 6

_OPT_REQUESTED_IP = 50
_OPT_LEASE_TIME   = 51
_OPT_MSG_TYPE     = 53
_OPT_SERVER_ID    = 54
_OPT_END          = 255

_COOKIE = (0x63, 0x82, 0x53, 0x63)

_KIND_DISCOVER   = 0
_KIND_REQ_SELECT = 1            # After an OFFER (options 50 + 54).
_KIND_REQ_RENEW  = 2            # Lease renewal (ciaddr set, no options).


class DHCPClient(wiring.Component):
    """DHCP client on a bound UDP port-68 stream pair.

    Parameters
    ----------
    clk_freq : float
        ``sync`` clock frequency.
    retry : float
        Seconds between retransmissions of the current step.
    default_lease : int
        Lease seconds assumed when the ACK lacks option 51.
    ticks_per_sec : int or None
        Cycles per lease-countdown second (default ``int(clk_freq)``;
        shrink it in simulation).

    Ports
    -----
    sink / source : udp user streams
        Connect to a UDP port binding for port 68 (source ``dst_port`` is
        67, ``ip`` broadcast; ``src_port`` is forced by the binding).
    mac_address : In(48)
        Board MAC (chaddr).
    bound : Out(1), leased_ip / server_ip : Out(32)
        Lease state (``leased_ip`` is 0 when unbound). ``bound`` stays high
        through renewals.
    event : Out(1)
        One pulse per successful bind/renewal ACK.
    state_debug : Out(3)
    """
    def __init__(self, clk_freq, retry=4.0, default_lease=300,
                 ticks_per_sec=None):
        self.retry_cycles  = max(2, int(clk_freq * retry))
        self.default_lease = default_lease
        self.ticks_per_sec = max(2, int(ticks_per_sec or int(clk_freq)))
        super().__init__({
            "sink":        In(udp_user_signature()),
            "source":      Out(udp_user_signature()),
            "mac_address": In(48),
            "bound":       Out(1),
            "leased_ip":   Out(32),
            "server_ip":   Out(32),
            "event":       Out(1),
            "state_debug": Out(3),
        })

    def elaborate(self, platform):
        m = Module()

        mac = self.mac_address

        # Transaction state.
        xid_ctr  = Signal(32)
        xid      = Signal(32)
        offer_ip = Signal(32)
        sid      = Signal(32)           # Server identifier (option 54).
        m.d.sync += xid_ctr.eq(xid_ctr + 0x9e3779b9)    # Stride the ids.

        # Lease bookkeeping (in seconds).
        lease_secs = Signal(32)
        t1_secs    = Signal(32)
        tick_cnt   = Signal(range(self.ticks_per_sec))
        sec_stb    = Signal()
        with m.If(tick_cnt == self.ticks_per_sec - 1):
            m.d.sync += tick_cnt.eq(0)
            m.d.comb += sec_stb.eq(1)
        with m.Else():
            m.d.sync += tick_cnt.eq(tick_cnt + 1)

        retry_cnt  = Signal(range(self.retry_cycles + 1))
        retry_fire = Signal()
        with m.If(retry_cnt == 0):
            m.d.comb += retry_fire.eq(1)
        with m.Else():
            m.d.sync += retry_cnt.eq(retry_cnt - 1)

        # --- TX: fixed 300-byte BOOTP frame, byte-muxed from state --------------------------
        tx_kind = Signal(2)
        tx_go   = Signal()
        tx_idx  = Signal(range(DHCP_MESSAGE_LEN))
        tx_busy = Signal()

        is_select = Signal()
        is_renew  = Signal()
        m.d.comb += [
            is_select.eq(tx_kind == _KIND_REQ_SELECT),
            is_renew.eq(tx_kind == _KIND_REQ_RENEW),
        ]

        # The byte mux is wide (300 cases); it feeds a register (prefetched
        # one index ahead) so the stream path stays short.
        byte     = Signal(8)
        byte_r   = Signal(8)
        mux_idx  = Signal(range(DHCP_MESSAGE_LEN))
        with m.Switch(mux_idx):
            with m.Case(0):
                m.d.comb += byte.eq(1)                      # op: BOOTREQUEST
            with m.Case(1):
                m.d.comb += byte.eq(1)                      # htype: ethernet
            with m.Case(2):
                m.d.comb += byte.eq(6)                      # hlen
            for i in range(4):                              # xid (big-endian)
                with m.Case(4 + i):
                    m.d.comb += byte.eq(xid.word_select(3 - i, 8))
            with m.Case(10):
                m.d.comb += byte.eq(0x80)                   # broadcast flag
            for i in range(4):                              # ciaddr (renewal)
                with m.Case(12 + i):
                    m.d.comb += byte.eq(Mux(is_renew,
                        self.leased_ip.word_select(3 - i, 8), 0))
            for i in range(6):                              # chaddr
                with m.Case(28 + i):
                    m.d.comb += byte.eq(mac.word_select(5 - i, 8))
            for i, value in enumerate(_COOKIE):
                with m.Case(236 + i):
                    m.d.comb += byte.eq(value)
            with m.Case(240):
                m.d.comb += byte.eq(_OPT_MSG_TYPE)
            with m.Case(241):
                m.d.comb += byte.eq(1)
            with m.Case(242):
                m.d.comb += byte.eq(Mux(tx_kind == _KIND_DISCOVER,
                                        _MSG_DISCOVER, _MSG_REQUEST))
            # Selecting REQUEST carries options 50 + 54; other messages end
            # right here (the tail zeros are legal PAD options).
            with m.Case(243):
                m.d.comb += byte.eq(Mux(is_select, _OPT_REQUESTED_IP,
                                        _OPT_END))
            with m.Case(244):
                m.d.comb += byte.eq(Mux(is_select, 4, 0))
            for i in range(4):
                with m.Case(245 + i):
                    m.d.comb += byte.eq(Mux(is_select,
                        offer_ip.word_select(3 - i, 8), 0))
            with m.Case(249):
                m.d.comb += byte.eq(Mux(is_select, _OPT_SERVER_ID, 0))
            with m.Case(250):
                m.d.comb += byte.eq(Mux(is_select, 4, 0))
            for i in range(4):
                with m.Case(251 + i):
                    m.d.comb += byte.eq(Mux(is_select,
                        sid.word_select(3 - i, 8), 0))
            with m.Case(255):
                m.d.comb += byte.eq(Mux(is_select, _OPT_END, 0))
            with m.Default():
                m.d.comb += byte.eq(0)

        m.d.comb += [
            self.source.param.ip.eq(0xffffffff),
            self.source.param.dst_port.eq(DHCP_SERVER_PORT),
            self.source.param.src_port.eq(DHCP_CLIENT_PORT),  # Forced anyway.
            self.source.param.length.eq(DHCP_MESSAGE_LEN),
        ]

        advance = Signal()
        m.d.comb += mux_idx.eq(Mux(advance, tx_idx + 1, tx_idx))
        m.d.sync += byte_r.eq(byte)

        with m.FSM(name="tx_fsm"):
            with m.State("IDLE"):
                with m.If(tx_go):
                    m.d.sync += tx_idx.eq(0)
                    m.next = "PRIME"
            with m.State("PRIME"):
                # byte_r picks up byte 0 this cycle.
                m.d.comb += tx_busy.eq(1)
                m.next = "SEND"
            with m.State("SEND"):
                m.d.comb += [
                    tx_busy.eq(1),
                    self.source.valid.eq(1),
                    self.source.payload.eq(byte_r),
                    self.source.first.eq(tx_idx == 0),
                    self.source.last.eq(tx_idx == DHCP_MESSAGE_LEN - 1),
                ]
                with m.If(self.source.ready):
                    m.d.comb += advance.eq(1)
                    m.d.sync += tx_idx.eq(tx_idx + 1)
                    with m.If(tx_idx == DHCP_MESSAGE_LEN - 1):
                        m.next = "IDLE"

        # --- RX: streaming BOOTP/option parser (never backpressures) ------------------------
        m.d.comb += self.sink.ready.eq(1)

        rx_idx    = Signal(16)
        r_op_ok   = Signal()
        r_xid_ok  = Signal()
        r_ch_ok   = Signal()
        r_ck_ok   = Signal()
        r_yiaddr  = Signal(32)
        o_msg     = Signal(8)
        o_sid     = Signal(32)
        o_lease   = Signal(32)
        opt_state = Signal(2)           # 0 code, 1 len, 2 value, 3 done.
        opt_code  = Signal(8)
        opt_left  = Signal(8)
        rx_done   = Signal()
        rx_valid  = Signal()

        m.d.sync += rx_done.eq(0)
        m.d.comb += rx_valid.eq(r_op_ok & r_xid_ok & r_ch_ok & r_ck_ok &
                                (o_msg != 0))

        data = self.sink.payload
        with m.If(self.sink.valid):
            idx = Signal.like(rx_idx)
            m.d.comb += idx.eq(Mux(self.sink.first, 0, rx_idx))
            m.d.sync += rx_idx.eq(idx + 1)

            with m.If(self.sink.first):
                # Reset per-datagram state; byte 0 is the op field.
                m.d.sync += [
                    r_op_ok.eq(data == 2),                  # BOOTREPLY
                    r_xid_ok.eq(1),
                    r_ch_ok.eq(1),
                    r_ck_ok.eq(1),
                    r_yiaddr.eq(0),
                    o_msg.eq(0),
                    o_sid.eq(0),
                    o_lease.eq(0),
                    opt_state.eq(0),
                ]
            with m.Else():
                for i in range(4):
                    with m.If((idx == 4 + i) &
                              (data != xid.word_select(3 - i, 8))):
                        m.d.sync += r_xid_ok.eq(0)
                with m.If((idx >= 16) & (idx < 20)):
                    m.d.sync += r_yiaddr.eq(Cat(data, r_yiaddr[:24]))
                for i in range(6):
                    with m.If((idx == 28 + i) &
                              (data != mac.word_select(5 - i, 8))):
                        m.d.sync += r_ch_ok.eq(0)
                for i, value in enumerate(_COOKIE):
                    with m.If((idx == 236 + i) & (data != value)):
                        m.d.sync += r_ck_ok.eq(0)

                with m.If(idx >= 240):
                    with m.Switch(opt_state):
                        with m.Case(0):                     # Option code.
                            with m.If(data == _OPT_END):
                                m.d.sync += opt_state.eq(3)
                            with m.Elif(data != 0):         # 0 = PAD.
                                m.d.sync += [
                                    opt_code.eq(data),
                                    opt_state.eq(1),
                                ]
                        with m.Case(1):                     # Option length.
                            m.d.sync += opt_left.eq(data)
                            m.d.sync += opt_state.eq(Mux(data == 0, 0, 2))
                        with m.Case(2):                     # Option value.
                            with m.Switch(opt_code):
                                with m.Case(_OPT_MSG_TYPE):
                                    m.d.sync += o_msg.eq(data)
                                with m.Case(_OPT_SERVER_ID):
                                    m.d.sync += o_sid.eq(Cat(data,
                                                             o_sid[:24]))
                                with m.Case(_OPT_LEASE_TIME):
                                    m.d.sync += o_lease.eq(Cat(data,
                                                               o_lease[:24]))
                            m.d.sync += opt_left.eq(opt_left - 1)
                            with m.If(opt_left == 1):
                                m.d.sync += opt_state.eq(0)

            with m.If(self.sink.last):
                m.d.sync += rx_done.eq(1)

        # --- Main state machine --------------------------------------------------------------
        lease_new = Signal(32)
        m.d.comb += lease_new.eq(Mux(o_lease != 0, o_lease,
                                     self.default_lease))

        # Lease countdown (runs while an address is held).
        with m.If(self.bound & sec_stb & (lease_secs != 0)):
            m.d.sync += lease_secs.eq(lease_secs - 1)

        with m.FSM(name="main_fsm") as fsm:
            with m.State("DISCOVER"):
                with m.If(~tx_busy):
                    m.d.sync += [
                        xid.eq(xid_ctr),
                        tx_kind.eq(_KIND_DISCOVER),
                        retry_cnt.eq(self.retry_cycles),
                    ]
                    m.d.comb += tx_go.eq(1)
                    m.next = "SELECTING"

            with m.State("SELECTING"):
                with m.If(rx_done & rx_valid & (o_msg == _MSG_OFFER) &
                          (r_yiaddr != 0)):
                    m.d.sync += [
                        offer_ip.eq(r_yiaddr),
                        sid.eq(o_sid),
                    ]
                    m.next = "REQUEST"
                with m.Elif(retry_fire):
                    m.next = "DISCOVER"

            with m.State("REQUEST"):
                with m.If(~tx_busy):
                    m.d.sync += [
                        tx_kind.eq(_KIND_REQ_SELECT),
                        retry_cnt.eq(self.retry_cycles),
                    ]
                    m.d.comb += tx_go.eq(1)
                    m.next = "REQUESTING"

            with m.State("REQUESTING"):
                with m.If(rx_done & rx_valid):
                    with m.If(o_msg == _MSG_ACK):
                        m.d.sync += [
                            self.bound.eq(1),
                            self.leased_ip.eq(r_yiaddr),
                            self.server_ip.eq(Mux(o_sid != 0, o_sid, sid)),
                            lease_secs.eq(lease_new),
                            t1_secs.eq(lease_new >> 1),
                        ]
                        m.d.comb += self.event.eq(1)
                        m.next = "BOUND"
                    with m.Elif(o_msg == _MSG_NAK):
                        m.next = "DISCOVER"
                with m.Elif(retry_fire):
                    m.next = "DISCOVER"

            with m.State("BOUND"):
                with m.If(lease_secs == 0):
                    # Lease expired: drop the address, start over.
                    m.d.sync += [
                        self.bound.eq(0),
                        self.leased_ip.eq(0),
                    ]
                    m.next = "DISCOVER"
                with m.Elif(sec_stb & (lease_secs == t1_secs)):
                    m.next = "RENEW"

            with m.State("RENEW"):
                with m.If(~tx_busy):
                    m.d.sync += [
                        xid.eq(xid_ctr),
                        tx_kind.eq(_KIND_REQ_RENEW),
                        retry_cnt.eq(self.retry_cycles),
                    ]
                    m.d.comb += tx_go.eq(1)
                    m.next = "RENEWING"

            with m.State("RENEWING"):
                with m.If(lease_secs == 0):
                    m.d.sync += [
                        self.bound.eq(0),
                        self.leased_ip.eq(0),
                    ]
                    m.next = "DISCOVER"
                with m.Elif(rx_done & rx_valid):
                    with m.If(o_msg == _MSG_ACK):
                        m.d.sync += [
                            lease_secs.eq(lease_new),
                            t1_secs.eq(lease_new >> 1),
                        ]
                        m.d.comb += self.event.eq(1)
                        m.next = "BOUND"
                    with m.Elif(o_msg == _MSG_NAK):
                        m.d.sync += [
                            self.bound.eq(0),
                            self.leased_ip.eq(0),
                        ]
                        m.next = "DISCOVER"
                with m.Elif(retry_fire):
                    m.next = "RENEW"

        for i, name in enumerate(("DISCOVER", "SELECTING", "REQUEST",
                                  "REQUESTING", "BOUND", "RENEW",
                                  "RENEWING")):
            with m.If(fsm.ongoing(name)):
                m.d.comb += self.state_debug.eq(i)

        return m
