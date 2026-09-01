#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# Copyright (c) 2018-2020 Sebastien Bourdeauducq <sb@m-labs.hk> (MiSoC PCS)
# Copyright (c) 2024 Florent Kermarrec <florent@enjoy-digital.fr> (LiteEth PCS)
# Copyright (c) 2026 LambdaEth contributors
# SPDX-License-Identifier: BSD-2-Clause

"""1000BASE-X / SGMII PCS (IEEE 802.3 Clause 36/37), vendor-independent.

Port of LiteEth's ``liteeth/phy/pcs_1000basex.py`` reshaped for transceivers
whose *hard* PCS performs the 8b/10b encode/decode and comma word alignment
(e.g. the Gowin GTR12). Compared to LiteEth, the fabric 8b10b encoder/decoder
and the 10/20-bit gearbox are dropped; the code-group boundary becomes:

* TX (:class:`PCSTX`): emits one code group per ``eth_tx`` cycle as
  ``{disparity, k, data[7:0]}`` (10 bits). ``disparity`` is the running
  disparity the hard encoder must *start* the code group with (0 = negative,
  1 = positive) — the fabric tracks it with :class:`RunningDisparity` because
  the /I1/ vs /I2/ selection depends on it.
* RX (:class:`PCSRX`): consumes one decoded code group per ``eth_rx`` cycle
  as ``{coding_err, disparity_err, k, data[7:0]}`` (11 bits).

The :class:`PCS` wrapper adds the Clause 37 auto-negotiation FSM (1000BASE-X
and SGMII, auto-detected from the link partner ability bit 0), the /C/
config-register consistency checks and the link timers, and exposes
``eth_phy`` 8-bit streams compatible with :class:`lambdaeth.mac.MACCore`
(full frames including preamble and FCS, exactly like the RGMII PHY).

Code-group timing note: every ordered set is two code groups, and all FSMs
emit/consume exactly one code group per cycle, so even/odd alignment is
maintained by construction on TX. On RX the transceiver's comma alignment
guarantees /K28.5/ lands on the even position.
"""

from amaranth.hdl import Module, Signal, Cat, Mux, DomainRenamer
from amaranth.lib import wiring
from amaranth.lib.cdc import PulseSynchronizer
from amaranth.lib.wiring import In, Out, connect, flipped

from ..common import eth_phy_stream_signature


__all__ = [
    "K", "D", "RunningDisparity", "WaitTimer", "BusSynchronizer",
    "PCSSGMIITimer", "PCSTX", "PCSRX", "PCS",
    "SGMII_1000MBPS_SPEED", "SGMII_100MBPS_SPEED", "SGMII_10MBPS_SPEED",
]


# 8b/10b code group helpers -------------------------------------------------------------------------

def K(x, y):
    """Control code group Kx.y as an 8-bit symbol value."""
    return (y << 5) | x


def D(x, y):
    """Data code group Dx.y as an 8-bit symbol value."""
    return (y << 5) | x


# SGMII speeds (config_reg bits [11:10]) ------------------------------------------------------------

SGMII_1000MBPS_SPEED = 0b10
SGMII_100MBPS_SPEED  = 0b01
SGMII_10MBPS_SPEED   = 0b00


# Helpers -------------------------------------------------------------------------------------------

class WaitTimer(wiring.Component):
    """Assert ``done`` after ``t`` cycles of continuous ``wait`` (LiteX WaitTimer).

    Ports
    -----
    wait : In(1)
    done : Out(1)
    """
    def __init__(self, t):
        self.t = int(t)
        super().__init__({
            "wait": In(1),
            "done": Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        count = Signal(range(self.t + 1), init=self.t)

        m.d.comb += self.done.eq(count == 0)
        with m.If(self.wait):
            with m.If(~self.done):
                m.d.sync += count.eq(count - 1)
        with m.Else():
            m.d.sync += count.eq(self.t)

        return m


class BusSynchronizer(wiring.Component):
    """Multi-bit CDC: continuously snapshots ``i`` (in ``i_domain``) into ``o``
    (in ``o_domain``) with a request/acknowledge handshake so that ``o`` only
    ever changes to a coherent snapshot of ``i``.

    A retry timeout keeps the handshake alive across ``i_domain`` resets
    (e.g. the ``eth_rx`` domain being held in reset while the link is down).

    Ports
    -----
    i : In(width), ``i_domain``
    o : Out(width), ``o_domain``
    """
    def __init__(self, width, i_domain, o_domain):
        self.i_domain = i_domain
        self.o_domain = o_domain
        super().__init__({
            "i": In(width),
            "o": Out(width),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules.req_ps = req_ps = PulseSynchronizer(self.o_domain, self.i_domain)
        m.submodules.ack_ps = ack_ps = PulseSynchronizer(self.i_domain, self.o_domain)

        # i_domain: capture on request, acknowledge one cycle later (so the
        # snapshot register is stable long before the ack reaches o_domain).
        capture  = Signal.like(self.i)
        ack_pend = Signal()
        with m.If(req_ps.o):
            m.d[self.i_domain] += [
                capture.eq(self.i),
                ack_pend.eq(1),
            ]
        with m.Elif(ack_pend):
            m.d[self.i_domain] += ack_pend.eq(0)
        m.d.comb += ack_ps.i.eq(ack_pend)

        # o_domain: issue requests back-to-back; retry on timeout (lost
        # handshake across an i_domain reset).
        pending = Signal()
        timeout = Signal(6)
        with m.If(~pending):
            m.d.comb += req_ps.i.eq(1)
            m.d[self.o_domain] += [
                pending.eq(1),
                timeout.eq(0),
            ]
        with m.Else():
            m.d[self.o_domain] += timeout.eq(timeout + 1)
            with m.If(ack_ps.o):
                m.d[self.o_domain] += [
                    self.o.eq(capture),  # Stable by protocol.
                    pending.eq(0),
                ]
            with m.Elif(timeout.all()):
                m.d[self.o_domain] += pending.eq(0)

        return m


# Running Disparity ---------------------------------------------------------------------------------

class RunningDisparity(wiring.Component):
    """8b/10b running-disparity tracker (Widmer-Franaszek classification).

    Direct translation of the Gowin 1GSERETH ``encoder_8b10b_disparity``
    module: given the (k, d) code group presented this cycle, computes the
    running disparity after it. ``disparity`` is the RD *before* the current
    code group, i.e. the value the hard encoder must start this group with
    (0 = negative RD, 1 = positive RD).

    Ports
    -----
    k : In(1)
    d : In(8)
    ce : In(1)
    disparity : Out(1)
    """
    def __init__(self):
        super().__init__({
            "k":         In(1),
            "d":         In(8),
            "ce":        In(1),
            "disparity": Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        a, b, c, dd, e, f, g, h = (self.d[i] for i in range(8))
        k = self.k

        cur = Signal()  # 0: negative RD; 1: positive RD.
        m.d.comb += self.disparity.eq(cur)

        # Figure 3 - 5B/6B classification, L functions.
        aeqb = Signal()
        ceqd = Signal()
        l13  = Signal()
        l31  = Signal()
        l22  = Signal()
        m.d.comb += [
            aeqb.eq((a & b) | (~a & ~b)),
            ceqd.eq((c & dd) | (~c & ~dd)),
            l13.eq((~aeqb & ~c & ~dd) | (~ceqd & ~a & ~b)),
            l31.eq((~aeqb &  c &  dd) | (~ceqd &  a &  b)),
            l22.eq((a & b & ~c & ~dd) | (c & dd & ~a & ~b) | (~aeqb & ~ceqd)),
        ]

        # Figure 5 - disparity classifications.
        pd_1s6 = Signal()
        ndos6  = Signal()
        pdos6  = Signal()
        ndos4  = Signal()
        pdos4  = Signal()
        m.d.comb += [
            pd_1s6.eq((e & dd & ~c & ~b & ~a) | (~e & ~l22 & ~l31)),
            ndos6.eq(pd_1s6),
            pdos6.eq(k | (e & ~l22 & ~l13)),
            ndos4.eq(~f & ~g),
            pdos4.eq(f & g & h),
        ]

        # Figure 6 - control of complementation.
        disparity6 = Signal()
        nxt        = Signal()
        m.d.comb += [
            disparity6.eq(cur ^ (ndos6 | pdos6)),
            nxt.eq((pdos4 | ndos4) ^ disparity6),
        ]

        with m.If(self.ce):
            m.d.sync += cur.eq(nxt)

        return m


# PCS SGMII Timer -----------------------------------------------------------------------------------

class PCSSGMIITimer(wiring.Component):
    """Byte repetition timer for SGMII 10/100 Mb/s rate adaptation.

    ``done`` is continuously asserted at gigabit speed; at 100 (10) Mb/s it
    asserts once every 10 (100) enabled cycles.

    Ports
    -----
    speed : In(2)
    enable : In(1)
    ce : In(1)
    done : Out(1)
    """
    def __init__(self):
        super().__init__({
            "speed":  In(2),
            "enable": In(1),
            "ce":     In(1),
            "done":   Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        count = Signal(range(100))

        m.d.comb += self.done.eq(count == 0)
        with m.If(self.ce):
            with m.If(~self.enable | self.done):
                with m.Switch(self.speed):
                    with m.Case(SGMII_10MBPS_SPEED):
                        m.d.sync += count.eq(99)
                    with m.Case(SGMII_100MBPS_SPEED):
                        m.d.sync += count.eq(9)
                    with m.Default():
                        m.d.sync += count.eq(0)
            with m.Else():
                m.d.sync += count.eq(count - 1)

        return m


# PCS TX --------------------------------------------------------------------------------------------

class PCSTX(wiring.Component):
    """PCS TX FSM: 8-bit ``eth_phy`` stream to (disparity, k, data) code groups.

    Runs in the ``sync`` domain (domain-renamed to ``eth_tx`` by
    :class:`PCS`). ``tx_data`` is registered: ``{disparity, k, d}`` where
    ``disparity`` is the running disparity the transceiver's hard 8b10b
    encoder must start this code group with.

    Ordered sets: /C1//C2/ configuration (when ``config_valid``), /I1//I2/
    idle (disparity-correcting), /S/ start (replaces the first preamble
    byte), /T//R/ end with even-boundary /R/ padding. SGMII 10/100 byte
    repetition is controlled by ``sgmii_speed``.

    Ports
    -----
    sink : In(eth_phy_stream_signature(8))
    tx_data : Out(10)
    config_valid : In(1)
    config_reg : In(16)
    sgmii_speed : In(2)
    """
    def __init__(self):
        super().__init__({
            "sink":         In(eth_phy_stream_signature(8)),
            "tx_data":      Out(10),
            "config_valid": In(1),
            "config_reg":   In(16),
            "sgmii_speed":  In(2),
        })

    def elaborate(self, platform):
        m = Module()

        sink = self.sink

        count  = Signal()  # Byte counter for config register.
        parity = Signal()  # Even/odd cycle parity for /R/ extension.
        ctype  = Signal()  # Toggles /C1//C2/ config type.

        m.submodules.disp = disp = RunningDisparity()
        m.submodules.timer = timer = PCSSGMIITimer()
        m.d.comb += [
            timer.speed.eq(self.sgmii_speed),
            timer.ce.eq(1),
        ]

        tx_k = Signal()
        tx_d = Signal(8)
        m.d.comb += [
            disp.k.eq(tx_k),
            disp.d.eq(tx_d),
            disp.ce.eq(1),
        ]
        # {disparity, k, d}: disp.disparity is the RD *before* this code
        # group, registered together with it.
        m.d.sync += self.tx_data.eq(Cat(tx_d, tx_k, disp.disparity))

        m.d.sync += parity.eq(~parity)

        with m.FSM():
            with m.State("START"):
                m.d.comb += [
                    tx_k.eq(1),
                    tx_d.eq(K(28, 5)),
                ]
                # Wait for valid Config.
                with m.If(self.config_valid):
                    m.d.sync += count.eq(0)
                    m.next = "CONFIG-D"
                # Wait for valid Data.
                with m.Else():
                    with m.If(sink.valid):
                        m.d.comb += [
                            sink.ready.eq(timer.done),
                            tx_d.eq(K(27, 7)),  # Start-of-packet /S/.
                        ]
                        m.next = "DATA"
                    with m.Else():
                        m.next = "IDLE"
            with m.State("CONFIG-D"):
                # Send Configuration Word.
                with m.Switch(ctype):
                    with m.Case(0b0):
                        m.d.comb += tx_d.eq(D(21, 5))  # /C1/.
                    with m.Case(0b1):
                        m.d.comb += tx_d.eq(D(2, 2))   # /C2/.
                m.d.sync += ctype.eq(~ctype)
                m.next = "CONFIG-REG"
            with m.State("CONFIG-REG"):
                # Send Configuration Register.
                m.d.sync += count.eq(count + 1)
                with m.Switch(count):
                    with m.Case(0):
                        m.d.comb += tx_d.eq(self.config_reg[:8])  # LSB.
                    with m.Case(1):
                        m.d.comb += tx_d.eq(self.config_reg[8:])  # MSB.
                with m.If(count == (2 - 1)):
                    m.next = "START"
            with m.State("IDLE"):
                # Send Idle words, correcting the running disparity to
                # negative: /I1/ after positive RD, /I2/ after negative RD.
                with m.If(disp.disparity):
                    m.d.comb += tx_d.eq(D(16, 2))  # /I2/.
                with m.Else():
                    m.d.comb += tx_d.eq(D(5, 6))   # /I1/.
                m.next = "START"
            with m.State("DATA"):
                # Send Data.
                m.d.comb += timer.enable.eq(1)
                with m.If(sink.valid):
                    m.d.comb += [
                        sink.ready.eq(timer.done),
                        tx_d.eq(sink.p.data),
                    ]
                    # Cut the frame on ``last`` so that back-to-back frames
                    # (no valid gap) are still delimited correctly.
                    with m.If(timer.done & sink.last):
                        m.next = "TERMINATE"
                with m.Else():
                    m.d.comb += [
                        tx_k.eq(1),
                        tx_d.eq(K(29, 7)),  # End-of-packet /T/.
                    ]
                    m.next = "CARRIER-EXTEND"
            with m.State("TERMINATE"):
                m.d.comb += [
                    tx_k.eq(1),
                    tx_d.eq(K(29, 7)),      # End-of-packet /T/.
                ]
                m.next = "CARRIER-EXTEND"
            with m.State("CARRIER-EXTEND"):
                # Extend carrier with /R/ symbols up to an even boundary.
                m.d.comb += [
                    tx_k.eq(1),
                    tx_d.eq(K(23, 7)),      # Carrier Extend /R/.
                ]
                with m.If(parity):
                    m.next = "START"

        return m


# PCS RX --------------------------------------------------------------------------------------------

class PCSRX(wiring.Component):
    """PCS RX FSM: decoded (k, data) code groups to an 8-bit ``eth_phy`` stream.

    Runs in the ``sync`` domain (domain-renamed to ``eth_rx`` by
    :class:`PCS`). ``rx_data`` is ``{coding_err, disparity_err, k, d}`` as
    produced by the transceiver's hard 8b10b decoder; ``ce`` qualifies each
    code group (tie to 1 for gear 1:1 transceivers).

    The source stream cannot be backpressured (``source.ready`` is ignored):
    /S/ reconstitutes the first preamble byte (0x55) with ``first`` set, the
    final data byte is emitted with ``last`` set on the /T/ cycle through a
    one-beat skid buffer, and invalid code groups terminate the frame with an
    ``error`` + ``last`` beat.

    Ports
    -----
    source : Out(eth_phy_stream_signature(8))
    rx_data : In(11)
    ce : In(1)
    seen_valid_ci : Out(1)
    seen_config_reg : Out(1)
    config_reg : Out(16)
    sgmii_speed : In(2)
    """
    def __init__(self):
        super().__init__({
            "source":          Out(eth_phy_stream_signature(8)),
            "rx_data":         In(11),
            "ce":              In(1),
            "seen_valid_ci":   Out(1),
            "seen_config_reg": Out(1),
            "config_reg":      Out(16),
            "sgmii_speed":     In(2),
        })

    def elaborate(self, platform):
        m = Module()

        source = self.source

        rx_d       = self.rx_data[0:8]
        rx_k       = self.rx_data[8]
        rx_invalid = self.rx_data[9] | self.rx_data[10]  # disparity_err | coding_err.

        count = Signal()  # Byte counter for config register.

        # SGMII Timer (byte decimation at 10/100 Mb/s).
        m.submodules.timer = timer = PCSSGMIITimer()
        m.d.comb += [
            timer.speed.eq(self.sgmii_speed),
            timer.ce.eq(self.ce),
        ]

        # One-beat skid buffer: a data byte is only emitted once the *next*
        # code group is known, so that ``last`` can be asserted on the final
        # byte (decided by the /T/ or error code group).
        buf_valid = Signal()
        buf_first = Signal()
        buf_data  = Signal(8)

        push_valid = Signal()
        push_first = Signal()
        push_data  = Signal(8)
        flush_last = Signal()  # /T/ seen: emit buffered byte with last.
        flush_err  = Signal()  # Invalid code group: emit error + last.

        with m.If(flush_err):
            m.d.comb += [
                source.valid.eq(1),
                source.p.data.eq(buf_data),
                source.first.eq(buf_valid & buf_first),
                source.last.eq(1),
                source.p.error.eq(1),
            ]
            m.d.sync += buf_valid.eq(0)
        with m.Elif(flush_last):
            m.d.comb += [
                source.valid.eq(buf_valid),
                source.p.data.eq(buf_data),
                source.first.eq(buf_first),
                source.last.eq(1),
            ]
            m.d.sync += buf_valid.eq(0)
        with m.Elif(self.ce):
            with m.If(push_valid):
                m.d.comb += [
                    # Emit the previous byte (not last: the frame goes on).
                    source.valid.eq(buf_valid),
                    source.p.data.eq(buf_data),
                    source.first.eq(buf_first),
                ]
                m.d.sync += [
                    buf_valid.eq(1),
                    buf_first.eq(push_first),
                    buf_data.eq(push_data),
                ]

        with m.FSM():
            with m.State("START"):
                with m.If(self.ce):
                    # Wait for a K-character.
                    with m.If(rx_k):
                        # K-character is Config or Idle K28.5.
                        with m.If(rx_d == K(28, 5)):
                            m.d.sync += count.eq(0)
                            m.next = "CONFIG-D-OR-IDLE"
                        # K-character is Start-of-packet /S/.
                        with m.If(rx_d == K(27, 7)):
                            m.d.comb += [
                                timer.enable.eq(1),
                                push_valid.eq(1),
                                push_first.eq(1),
                                push_data.eq(0x55),  # First Preamble Byte.
                            ]
                            m.next = "DATA"
            with m.State("CONFIG-D-OR-IDLE"):
                with m.If(self.ce):
                    with m.If(~rx_k & ~rx_invalid):
                        # Check for Configuration Word.
                        with m.If((rx_d == D(21, 5)) |  # /C1/.
                                  (rx_d == D(2, 2))):   # /C2/.
                            m.d.comb += self.seen_valid_ci.eq(1)
                            m.next = "CONFIG-REG"
                        # Check for Idle Word.
                        with m.If((rx_d == D(5, 6)) |   # /I1/.
                                  (rx_d == D(16, 2))):  # /I2/.
                            m.d.comb += self.seen_valid_ci.eq(1)
                            m.next = "START"
                    with m.Else():
                        m.next = "ERROR"
            with m.State("CONFIG-REG"):
                with m.If(self.ce):
                    with m.If(~rx_k & ~rx_invalid):
                        # Receive Configuration Register.
                        m.d.sync += count.eq(count + 1)
                        with m.Switch(count):
                            with m.Case(0b0):
                                m.d.sync += self.config_reg[0:8].eq(rx_d)   # LSB.
                            with m.Case(0b1):
                                m.d.sync += self.config_reg[8:16].eq(rx_d)  # MSB.
                        with m.If(count == (2 - 1)):
                            m.d.comb += self.seen_config_reg.eq(1)
                            m.next = "START"
                    with m.Else():
                        m.next = "ERROR"
            with m.State("DATA"):
                with m.If(self.ce):
                    with m.If(~rx_k & ~rx_invalid):
                        # Receive Data.
                        m.d.comb += [
                            timer.enable.eq(1),
                            push_valid.eq(timer.done),
                            push_data.eq(rx_d),
                        ]
                    with m.Elif(rx_k & (rx_d == K(29, 7)) & ~rx_invalid):
                        # K-character is End-of-packet /T/.
                        m.d.comb += flush_last.eq(1)
                        m.next = "START"
                    with m.Else():
                        m.d.comb += flush_err.eq(1)
                        m.next = "ERROR"
            with m.State("ERROR"):
                m.next = "START"

        return m


# PCS -----------------------------------------------------------------------------------------------

class PCS(wiring.Component):
    """1000BASE-X / SGMII PCS with Clause 37 auto-negotiation.

    Streams follow the lambdaeth PHY convention: ``tx`` is consumed in the
    ``tx_domain``, ``rx`` is produced in the ``rx_domain`` (no backpressure).
    ``tbi_tx``/``tbi_rx`` carry the (disparity, k, data) code groups of the
    transceiver's hard 8b10b PCS.

    SGMII is auto-detected from bit 0 of the received configuration register
    (the mode the link partner advertises is mirrored back), so the same
    netlist links up against both 1000BASE-X and SGMII (PHY-side) partners.

    Parameters
    ----------
    tx_domain, rx_domain : str
        Clock domain names (must be created by the enclosing design).
    clk_freq : float
        ``tx_domain`` clock frequency, for the link timers.
    check_period, breaklink_time, more_ack_time, sgmii_ack_time : float
        Clause 37 timer periods in seconds (shrink them in simulation).

    Ports
    -----
    tx : In(eth_phy_stream_signature(8))
    rx : Out(eth_phy_stream_signature(8))
    tbi_tx : Out(10)
        ``{disparity, k, d}``, ``tx_domain``.
    tbi_rx : In(11)
        ``{coding_err, disparity_err, k, d}``, ``rx_domain``.
    tbi_rx_ce : In(1)
        Code group qualifier for ``tbi_rx`` (tie to 1 for gear 1:1).
    an_bypass : In(1)
        Disable Clause 37 autonegotiation (``tx_domain``): send idles/data
        immediately and report ``link_up`` unconditionally. For link
        partners with autonegotiation disabled (forced 1000BASE-X).
    link_up : Out(1)
        Autonegotiation complete (``tx_domain``).
    restart : Out(1)
        Pulses when autonegotiation restarts (``tx_domain``).
    align : Out(1)
        High while waiting for ability match (comma alignment window).
    lp_abi : Out(16)
        Link partner ability (``tx_domain``).
    is_sgmii : Out(1)
        Link partner uses SGMII framing (``tx_domain``).
    """
    def __init__(self, *, tx_domain="eth_tx", rx_domain="eth_rx", clk_freq=125e6,
                 check_period=6e-3, breaklink_time=10e-3, more_ack_time=10e-3,
                 sgmii_ack_time=1.6e-3):
        self.tx_domain = tx_domain
        self.rx_domain = rx_domain
        self.clk_freq  = clk_freq

        self.check_period   = check_period
        self.breaklink_time = breaklink_time
        self.more_ack_time  = more_ack_time
        self.sgmii_ack_time = sgmii_ack_time

        self._tx = PCSTX()
        self._rx = PCSRX()

        super().__init__({
            "tx":        In(eth_phy_stream_signature(8)),
            "rx":        Out(eth_phy_stream_signature(8)),
            "tbi_tx":    Out(10),
            "tbi_rx":    In(11),
            "tbi_rx_ce": In(1),
            "an_bypass": In(1),
            "link_up":   Out(1),
            "restart":   Out(1),
            "align":     Out(1),
            "lp_abi":    Out(16),
            "is_sgmii":  Out(1),
        })

    def elaborate(self, platform):
        m = Module()

        cd_tx = self.tx_domain
        cd_rx = self.rx_domain

        m.submodules.pcs_tx = tx = DomainRenamer({"sync": cd_tx})(self._tx)
        m.submodules.pcs_rx = rx = DomainRenamer({"sync": cd_rx})(self._rx)

        # Streams.
        connect(m, flipped(self.tx), tx.sink)
        connect(m, rx.source, flipped(self.rx))

        # TBI.
        m.d.comb += [
            self.tbi_tx.eq(tx.tx_data),
            rx.rx_data.eq(self.tbi_rx),
            rx.ce.eq(self.tbi_rx_ce),
        ]

        # Signals.
        config_empty = Signal()
        is_sgmii     = Signal()
        linkdown     = Signal()
        autoneg_ack  = Signal()
        m.d.comb += self.is_sgmii.eq(is_sgmii)

        # Pulse synchronizers (rx_domain -> tx_domain).
        m.submodules.seen_valid_ci_ps = seen_valid_ci = \
            PulseSynchronizer(cd_rx, cd_tx)
        m.submodules.rx_config_reg_abi_ps = rx_config_reg_abi = \
            PulseSynchronizer(cd_rx, cd_tx)
        m.submodules.rx_config_reg_ack_ps = rx_config_reg_ack = \
            PulseSynchronizer(cd_rx, cd_tx)
        m.d.comb += seen_valid_ci.i.eq(rx.seen_valid_ci)

        # Link partner ability CDC (rx_domain -> tx_domain).
        lp_abi_rx = Signal(16)  # rx_domain copy.
        with m.If(rx.seen_config_reg):
            m.d[cd_rx] += lp_abi_rx.eq(rx.config_reg)
        m.submodules.lp_abi_cdc = lp_abi = BusSynchronizer(16, cd_rx, cd_tx)
        m.d.comb += [
            lp_abi.i.eq(lp_abi_rx),
            self.lp_abi.eq(lp_abi.o),
        ]

        # Timers.
        in_tx = DomainRenamer({"sync": cd_tx})
        m.submodules.breaklink_timer = breaklink_timer = \
            in_tx(WaitTimer(self.breaklink_time * self.clk_freq))
        m.submodules.more_ack_timer = more_ack_timer = \
            in_tx(WaitTimer(self.more_ack_time * self.clk_freq))
        m.submodules.sgmii_ack_timer = sgmii_ack_timer = \
            in_tx(WaitTimer(self.sgmii_ack_time * self.clk_freq))

        # Checker: valid /C/ or /I/ ordered sets must keep arriving.
        checker_max   = int(self.check_period * self.clk_freq)
        checker_count = Signal(range(checker_max + 1))
        checker_tick  = Signal()
        checker_error = Signal()
        m.d[cd_tx] += checker_tick.eq(0)
        with m.If(checker_count == 0):
            m.d[cd_tx] += [
                checker_tick.eq(1),
                checker_count.eq(checker_max),
            ]
        with m.Else():
            m.d[cd_tx] += checker_count.eq(checker_count - 1)
        with m.If(seen_valid_ci.o):
            m.d[cd_tx] += checker_error.eq(0)
        with m.If(checker_tick):
            m.d[cd_tx] += checker_error.eq(1)

        # Linkdown/Speed detection (tx_domain).
        sgmii_speed_valid = Signal()
        sgmii_tx_speed    = Signal(2)
        m.d.comb += [
            is_sgmii.eq(lp_abi.o[0]),
            sgmii_speed_valid.eq(lp_abi.o[10:12] != 0b11),
            sgmii_tx_speed.eq(Mux(sgmii_speed_valid, lp_abi.o[10:12],
                                  SGMII_1000MBPS_SPEED)),
        ]
        # Detect that link is down:
        # - 1000BASE-X : linkup can be inferred by non-empty reg.
        # - SGMII      : linkup is indicated with bit 15.
        with m.If(~is_sgmii):
            m.d.comb += [
                linkdown.eq(lp_abi.o == 0),
                tx.sgmii_speed.eq(SGMII_1000MBPS_SPEED),
            ]
        with m.Else():
            m.d.comb += [
                linkdown.eq(~lp_abi.o[15] | ~sgmii_speed_valid),
                tx.sgmii_speed.eq(sgmii_tx_speed),
            ]
        # RX speed from the rx_domain copy (no cross-domain sampling).
        rx_is_sgmii = Signal()
        m.d.comb += [
            rx_is_sgmii.eq(lp_abi_rx[0]),
            rx.sgmii_speed.eq(Mux(rx_is_sgmii & (lp_abi_rx[10:12] != 0b11),
                                  lp_abi_rx[10:12], SGMII_1000MBPS_SPEED)),
        ]

        # TX Config.
        with m.If(~config_empty):
            m.d.comb += [
                tx.config_reg[0].eq(is_sgmii),       # SGMII: SGMII in-use.
                tx.config_reg[5].eq(~is_sgmii),      # 1000BASE-X: Full-duplex.
                tx.config_reg[14].eq(autoneg_ack),   # Acknowledge Bit.
            ]
            with m.If(is_sgmii):
                m.d.comb += [
                    tx.config_reg[10:12].eq(sgmii_tx_speed),  # SGMII: Speed.
                    tx.config_reg[12].eq(1),                  # SGMII: Full-duplex.
                    tx.config_reg[15].eq(self.link_up),       # SGMII: Link-up.
                ]

        # Autonegotiation FSM (Clause 37), tx_domain.
        with m.FSM(domain=cd_tx):
            # AN_ENABLE.
            with m.State("AUTONEG-BREAKLINK"):
                m.d.comb += [
                    tx.config_valid.eq(1),
                    config_empty.eq(1),
                    breaklink_timer.wait.eq(1),
                ]
                with m.If(breaklink_timer.done):
                    m.next = "AUTONEG-WAIT-ABI"
            # ABILITY_DETECT.
            with m.State("AUTONEG-WAIT-ABI"):
                m.d.comb += [
                    self.align.eq(1),
                    tx.config_valid.eq(1),
                ]
                with m.If(rx_config_reg_abi.o):
                    m.next = "AUTONEG-WAIT-ACK"
                with m.If(checker_tick & checker_error):
                    m.d.comb += self.restart.eq(1)
                    m.next = "AUTONEG-BREAKLINK"
            # ACKNOWLEDGE_DETECT.
            with m.State("AUTONEG-WAIT-ACK"):
                m.d.comb += [
                    tx.config_valid.eq(1),
                    autoneg_ack.eq(1),
                ]
                with m.If(rx_config_reg_ack.o):
                    m.next = "AUTONEG-SEND-MORE-ACK"
                with m.If(checker_tick & checker_error):
                    m.d.comb += self.restart.eq(1)
                    m.next = "AUTONEG-BREAKLINK"
            # COMPLETE_ACKNOWLEDGE.
            with m.State("AUTONEG-SEND-MORE-ACK"):
                m.d.comb += [
                    tx.config_valid.eq(1),
                    autoneg_ack.eq(1),
                    more_ack_timer.wait.eq(~is_sgmii),
                    sgmii_ack_timer.wait.eq(is_sgmii),
                ]
                with m.If((is_sgmii & sgmii_ack_timer.done) |
                          (~is_sgmii & more_ack_timer.done)):
                    m.next = "RUNNING"
                with m.If(checker_tick & checker_error):
                    m.d.comb += self.restart.eq(1)
                    m.next = "AUTONEG-BREAKLINK"
            # LINK_OK.
            with m.State("RUNNING"):
                m.d.comb += self.link_up.eq(~linkdown)
                with m.If((checker_tick & checker_error) | linkdown):
                    m.d.comb += self.restart.eq(1)
                    m.next = "AUTONEG-BREAKLINK"

        # RX Config (and consistency check), rx_domain.
        #
        # Per IEEE 802.3 Clause 37, ability_match ignores the Acknowledge bit
        # (bit 14): a consistent stream of /C/ registers always signals an
        # ability match, and additionally an acknowledge match when bit 14 is
        # set. (LiteEth signals only one of the two, which deadlocks when two
        # instances of this FSM negotiate against each other and enter
        # ability detect at different times.)
        rx_config_reg_count = Signal(4)
        rx_config_reg_last  = Signal(16)
        rx_config_reg_noack = Signal(16)
        m.d.comb += rx_config_reg_noack.eq(rx.config_reg & ~(1 << 14))
        with m.If(rx.seen_config_reg):
            # Consistency Count/Check.
            m.d[cd_rx] += rx_config_reg_last.eq(rx_config_reg_noack)
            with m.If(rx_config_reg_noack != rx_config_reg_last):
                m.d[cd_rx] += rx_config_reg_count.eq(8 - 1)
            with m.Else():
                with m.If(rx_config_reg_count != 0):
                    m.d[cd_rx] += rx_config_reg_count.eq(rx_config_reg_count - 1)
                with m.Else():
                    # When RX Config is consistent:
                    # Ability match.
                    m.d.comb += rx_config_reg_abi.i.eq(1)
                    # Acknowledgement.
                    with m.If(rx.config_reg[14]):
                        m.d.comb += rx_config_reg_ack.i.eq(1)

        # Autonegotiation bypass: idles/data immediately, link forced up
        # (overrides the FSM outputs above).
        with m.If(self.an_bypass):
            m.d.comb += [
                tx.config_valid.eq(0),
                self.link_up.eq(1),
                self.restart.eq(0),
                self.align.eq(0),
            ]

        return m
