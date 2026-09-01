# LambdaEth

A small, hardware-proven **Ethernet stack for [Amaranth HDL](https://amaranth-lang.org/)** —
a port of [LiteEth](https://github.com/enjoy-digital/liteeth) built on
`amaranth-soc` (CSR/Wishbone) and `amaranth-stream` (streams, packets, CDC),
extended well beyond the original with a TCP engine (server *and* client)
and a DHCP client.

Everything below is verified in simulation (155 tests) **and on real
hardware** — a Sipeed Tang Mega 138K Pro dock (Gowin GW5AST-138B) talking to
Linux hosts on a live LAN, over both the RTL8211F **RGMII** PHY and the
GTR12 hard-SERDES **1000BASE-X (SFP)** PHY, including binding a lease from a
production DHCP server and Clause 37 autonegotiation against commercial
switches on two SFP cages at once.

## Features

| Layer | What you get |
|---|---|
| PHY | **RGMII** (Gowin GW5A IOLOGIC) and **1000BASE-X / SGMII** (IEEE 802.3 Clause 36/37 PCS on the Gowin GTR12 hard SERDES via [gowin-serdes](https://github.com/key2/gowin-serdes)) |
| MAC | Preamble/SFD, CRC32 FCS insert/check, min-frame padding, IPG, RX/TX clock-domain crossing, 8↔32-bit width conversion, store-and-forward TX (no mid-frame underruns) |
| ARP | Responder + resolver with a small cache, request retry/timeout |
| IPv4 | Header checksum generate/verify, broadcast TX (no ARP), length metadata fan-out |
| ICMP | Echo responder (ping), buffered, incremental checksum rewrite |
| UDP | One *unbound* stream pair (all ports), or **N bound ports** requested at build time — one stream pair each, runtime-rebindable via CSR |
| TCP | **N endpoints at build time, each server (listen) or client (connect out)**. Stop-and-wait v1: in-order RX, RTO retransmission, RST refusals, passive close, idle-timeout reaping. Clients retry/reconnect forever |
| DHCP | Optional client: DISCOVER→OFFER→REQUEST→ACK, T1 renewal, lease expiry restart. The core owns its IP; the lease is readable over CSR |

Every feature is **netlist-optional and build-time shaped**: what you don't
request is not in the netlist, and degenerate cases collapse (a single UDP
port needs no TX arbiter, a single TCP endpoint needs no dispatch — pure
wiring, asserted by tests).

## Architecture

```
RGMII pads ── GW5RGMIIPHY ─────────┐ (eth_tx/eth_rx @125 MHz, 8-bit eth_phy streams)
SFP ── GTR12 ── GW51000BASEXPHY ───┤
                  │ tx/rx
              MACCore(data_width=32)      preamble/CRC/padding/gap + CDC
                  │ sink/source (32-bit eth_phy streams, sync @50 MHz)
              MACByteBoundary             8↔32 + store-and-forward TX PacketFIFO
                  │ eth_tx/eth_rx (plain 8-bit byte streams)
              UDPIPCore                   MACDispatch → ARP / IPRX/IPTX
                  │                         └ IPRXDispatch/IPTXArbiter (protocol demux/mux)
                  │                             ├ UDPRX/UDPTX ── UDPPortDispatch/UDPPortArbiter
                  │                             │                (unbound stream and/or N bound ports)
                  │                             ├ TCPRX → TCPSegDispatch → TCPEngine×N → TCPTXArbiter
                  │                             ├ DHCPClient  (hidden UDP port-68 binding)
                  │                             └ ICMPEcho
              CSRs (mac, ports, counters, dhcp_ip) ← WishboneCSRBridge ← UARTWishboneBridge ← UART
```

The byte-wide core runs in the `sync` domain (e.g. 50 MHz ⇒ ~400 Mbps
sustained); the 32-bit MAC boundary buffers whole frames so the gigabit wire
side always bursts at line rate.

## Getting started

LambdaEth expects its (patched) dependencies as sibling checkouts:

```
workspace/
├── lambdaeth/          # this repository
├── amaranth-soc/       # https://github.com/key2/amaranth-soc        @ 559658d
├── amaranth-stream/    # https://github.com/key2/amaranth-stream     @ fc42307
├── amaranth-boards/    # https://github.com/amaranth-lang/amaranth-boards @ f270d21 + patches/amaranth-boards.diff
└── PHY/
    └── gowin-serdes/   # https://github.com/key2/gowin-serdes (GTR12 SERDES, for the 1000BASE-X PHY)
```

```sh
git clone https://github.com/key2/lambdaeth
git clone https://github.com/key2/amaranth-soc
git clone https://github.com/key2/amaranth-stream
git clone https://github.com/amaranth-lang/amaranth-boards
git clone https://github.com/key2/gowin-serdes PHY/gowin-serdes

git -C amaranth-boards apply ../lambdaeth/patches/amaranth-boards.diff   # Tang Mega 138K Pro: RGMII/ephy_clk resources, UART pins, GW5A part parsing

cd lambdaeth
pdm install          # Python >= 3.11; installs the siblings as editable deps
pdm run pytest -q    # 155 tests
```

## Usage

### Instantiating the core

`UDPIPCore` is a regular `wiring.Component`; you feed it Ethernet frames
(byte streams, no preamble/FCS) on `mac_rx`/`mac_tx` — usually from
`MACCore` + `MACByteBoundary` — and request user endpoints at build time:

```python
from lambdaeth.core import UDPIPCore, TCPServer, TCPClient

core = UDPIPCore(
    clk_freq  = 50e6,                     # timers (ARP, TCP RTO, DHCP lease)
    with_icmp = True,                     # answer ping
    udp_ports = [8000, 8001],             # one bound stream pair per port
    tcp_ports = [                         # one engine per endpoint
        TCPServer(2000),                  #   listen on :2000
        TCPClient("192.168.10.120", 5001) #   connect out, retry forever
    ],
    with_dhcp = True,                     # acquire the IP from the network
)
```

All ports/addresses are runtime-tunable through plain input signals
(`udp_port_p0`, `tcp_port_p0`, `tcp_remote_ip_p1`, ... — typically driven
from CSR registers; leave them undriven to keep the build-time defaults).

### UDP

With `udp_ports=[8000, ...]` each port is a *bound socket*: `udp_rx_p0`
only delivers datagrams addressed to it, `udp_tx_p0` always sends from it
(`src_port` is forced), and datagrams to unbound ports are dropped
(`udp_drop` pulses). A UDP echo server is one FIFO per port:

```python
from amaranth_stream import PacketFIFO
from lambdaeth.core import udp_user_signature

echo = PacketFIFO(udp_user_signature(), payload_depth=2048, packet_depth=8)
m.submodules.echo = echo
connect(m, core.udp_rx_p0, echo.i_stream)
m.d.comb += [
    core.udp_tx_p0.valid.eq(echo.o_stream.valid),
    core.udp_tx_p0.payload.eq(echo.o_stream.payload),
    core.udp_tx_p0.first.eq(echo.o_stream.first),
    core.udp_tx_p0.last.eq(echo.o_stream.last),
    echo.o_stream.ready.eq(core.udp_tx_p0.ready),
    # Reply to the sender, at its source port (our src_port is the binding).
    core.udp_tx_p0.param.ip.eq(echo.o_stream.param.ip),
    core.udp_tx_p0.param.dst_port.eq(echo.o_stream.param.src_port),
    core.udp_tx_p0.param.length.eq(echo.o_stream.param.length),
]
```

With `udp_ports=None` (default) you get a single unfiltered `udp_rx`/`udp_tx`
pair instead: every datagram is delivered with its `dst_port` in the stream
parameters, and you choose the `src_port` on TX.

### TCP

Each endpoint exposes one byte-stream pair plus connection controls:

```python
rx = core.tcp_rx_p0        # received payload (one stream packet per segment)
tx = core.tcp_tx_p0        # bytes to send (cut into segments at MSS or `last`)
core.tcp_connected_p0      # ESTABLISHED/CLOSE-WAIT
core.tcp_peer_closed_p0    # peer sent FIN
core.tcp_close_p0          # request our FIN (honoured after peer_closed)
```

A TCP echo server/loop with a clean shutdown (close once the peer closed and
every received byte went back out):

```python
echo = PacketFIFO(eth_stream_signature(), payload_depth=2048, packet_depth=8)
m.submodules.echo = echo
connect(m, core.tcp_rx_p0, echo.i_stream)
connect(m, echo.o_stream, core.tcp_tx_p0)

rx_bytes = Signal(32)
tx_bytes = Signal(32)
with m.If(core.tcp_rx_p0.valid & core.tcp_rx_p0.ready):
    m.d.sync += rx_bytes.eq(rx_bytes + 1)
with m.If(core.tcp_tx_p0.valid & core.tcp_tx_p0.ready):
    m.d.sync += tx_bytes.eq(tx_bytes + 1)
m.d.comb += core.tcp_close_p0.eq(core.tcp_peer_closed_p0 &
                                 (rx_bytes == tx_bytes))
```

Servers refuse extra clients and unbound ports with RST; clients
(`TCPClient(ip, port, local_port=None)`) open the connection themselves,
retransmit the SYN on timeout, back off and retry after refusals, and
reconnect automatically after every close — point one at a host running
`nc -l 5001` and it will just keep coming back.

### DHCP

With `with_dhcp=True` the core has **no `ip_address` input** — it owns its
address. `dhcp_ip` (32-bit output, 0 while unbound) and `dhcp_bound` mirror
the lease; wire `dhcp_ip` to a read-only CSR to see the address from the
host. Nothing is answered before a lease is bound, and TCP clients hold
their connection attempts until then. Leases renew at T1 automatically and
fall back to a fresh discovery on expiry.

### Full SoC example

`examples/tang_mega_138k_udp_echo.py` puts it all together for the Tang Mega
138K Pro dock: PHY + MAC + core + echo fabrics + a UART→Wishbone→CSR bridge
exposing MAC/IP/ports/counters/status (see `scripts/csrctl.py`).

## Hardware demo — RGMII (Tang Mega 138K Pro dock)

```sh
# Build (Gowin IDE; the wrapper fixes env quirks — set GOWIN_IDE to your install):
GW_SH=$PWD/scripts/gw_sh_wrapper pdm run python examples/tang_mega_138k_udp_echo.py \
    --ip 192.168.10.50 \
    --udp-port 8000 --udp-port 8001 --udp-port 8002 \
    --tcp-port 2000 --tcp-port 2001 \
    --tcp-client 192.168.10.120:5001        # or: --dhcp

# Flash (SRAM, volatile):
sudo openFPGALoader -b tangmega138k build/tang_mega_138k_udp_echo/udp_echo.fs

# Exercise it from the host:
ping -c 5 192.168.10.50
pdm run python scripts/udp_echo_test.py --ip 192.168.10.50 --expect-drop-port 9999
pdm run python scripts/tcp_echo_test.py --ip 192.168.10.50          # echo/close/reconnect/refuse
pdm run python scripts/tcp_client_test.py --port 5001               # the board connects to *us*
sudo $PWD/.venv/bin/python scripts/dhcp_test_server.py              # if the LAN has no DHCP server

# Poke the CSRs over the UART bridge (/dev/ttyUSB2 by default):
pdm run python scripts/csrctl.py dump
pdm run python scripts/csrctl.py read dhcp_ip                       # leased address (with --dhcp)
pdm run python scripts/csrctl.py write udp_port_p0 9000             # rebind a UDP stream live
pdm run python scripts/csrctl.py write tcp_remote_port_p2 5002      # retarget the TCP client
```

Measured on hardware: ICMP RTT ~0.15 ms, UDP echo RTT ~90 µs, TCP echo
~70 kB/s per connection (stop-and-wait ⇒ one MSS per RTT — a demo-grade,
deliberately simple TCP).

### TCP throughput benchmark

SYN/SYN-ACK advertise our MSS (`--tcp-mss`, default 536; 1460 fills
standard Ethernet frames from BRAM buffers) and the peer's MSS option is
honoured on TX. A `--tcp-bench` build replaces the first two TCP echo
servers with a byte *sink* (PC→FPGA, counted in the `bench_rx_bytes` CSR —
no echoing, so nothing waits on the reverse path) and a pattern *source*
(FPGA→PC, `bench_tx_bytes`); `scripts/tcp_bench.py` measures both:

```sh
GW_SH=$PWD/scripts/gw_sh_wrapper pdm run python examples/tang_mega_138k_udp_echo.py \
    --ip 192.168.10.50 --tcp-bench --tcp-mss 1460 --tcp-rx-depth 8192 --rx-cdc-depth 4096
pdm run python scripts/tcp_bench.py --ip 192.168.10.50
```

Measured against a Linux host over gigabit (sys clock 50 MHz):

| Direction | MSS 536 (defaults) | MSS 1460 (bench build) |
|---|---|---|
| PC → FPGA (upload) | ~18 MB/s (144 Mbit/s) | **24.75 MB/s (198 Mbit/s)** |
| FPGA → PC (download) | 5.4 MB/s (43 Mbit/s) | **7.5 MB/s (60 Mbit/s)** |

Upload sits at 99 % of the architectural ceiling: every byte crosses the
byte-wide core twice (checksum-validating store-and-forward, then the copy
to the user buffer) ⇒ 50 MHz / 2 = 25 MB/s. Download is stop-and-wait
(one segment per round trip, ~195 µs each at MSS 1460); a small in-flight
window would be the next step if that direction ever matters.

## Hardware demo — 1000BASE-X over SFP (GTR12 SERDES)

`lambdaeth/phy/pcs_1000basex.py` is a vendor-independent port of LiteEth's
1000BASE-X PCS reshaped for transceivers whose *hard* PCS performs the
8b/10b coding and comma alignment: the fabric exchanges decoded code groups
(`{disparity, k, data}` TX / `{coding_err, disparity_err, k, data}` RX) and
keeps the Clause 36 ordered-set framing plus the full Clause 37
autonegotiation FSM (1000BASE-X and SGMII, auto-detected from the partner).
Notable deltas vs. LiteEth: a `RunningDisparity` tracker feeds the hard
encoder's starting-disparity hint, `ability_match` ignores the ACK bit per
IEEE (LiteEth's variant deadlocks when two of its own instances negotiate),
frames are also delimited by `last` (back-to-back safe), and an `an_bypass`
control forces the link up for partners with autonegotiation disabled.

`lambdaeth/phy/gw5_1000basex.py` wraps it for the Gowin GTR12
(via [gowin-serdes](https://github.com/key2/gowin-serdes): 1.25 Gb/s, CPLL,
10-bit fabric width, 8b10b + K28.5 alignment — the generated CSR blob is
byte-identical to the Gowin IDE 1GSERETH reference), with the vendor
`serdes_control` reset sequencing (PMA reset after PLL-OK, `eth_rx` reset
gated on word alignment) and CSRs for reset/an_bypass/status/lp_abi.

`examples/tang_mega_138k_1000basex.py` drives both SFP cages of the dock at
once (GTR12 quad 1 lanes 0/1, 125 MHz on Q1 REFPAD0): lane 0 carries the
full UDP/TCP/ICMP stack, lane 1 an autoneg-only partner PHY, plus per-lane
RX frame counters and CSR-armable 64-byte frame sniffers. SFP TX_DISABLE
(R18/M20) is driven low — a floating pin leaves the module lasers off — and
RX_LOS (V18/W18) is readable in `core__sfp_status`.

```sh
# Self-test without SFP modules: serdes near-end loopback, the PHY
# negotiates against itself and the TCP stack connects to itself:
GW_SH=$PWD/scripts/gw_sh_wrapper pdm run python examples/tang_mega_138k_1000basex.py \
    --loopback nes --tcp-client 192.168.10.60:2000
sudo openFPGALoader -b tangmega138k --ftdi-serial 2023102515 \
    build/tang_mega_138k_1000basex/basex_echo.fs
CSR="pdm run python scripts/csrctl.py --port /dev/ttyUSB9 --csr-map build/tang_mega_138k_1000basex/csr.json"
$CSR read phy__status        # -> 0x0d = link_up | pll_ok | align_link
$CSR read core__tcp_status   # -> 0x11 = server + self-connecting client ESTABLISHED

# Real link: build without --loopback, plug SFP modules:
GW_SH=$PWD/scripts/gw_sh_wrapper pdm run python examples/tang_mega_138k_1000basex.py
ping -c 3 192.168.10.60                     # over the fiber, via SFP0
$CSR read phy1__lp_abi                      # SFP1 partner ability word
$CSR write core__snap_ctrl 3                # arm both frame sniffers
$CSR read core__snap1_w0                    # ... captured frame bytes (w0..w15)
```

Verified on hardware: both lanes autonegotiate simultaneously against
commercial switches (`lp_abi` 0x41a0 / 0x4020), ICMP/UDP/TCP echo run
end-to-end over the fiber (ping ~0.23 ms), and the lane-1 sniffer captured
live link-local traffic — a Pioneer CDJ-3000 PRO DJ LINK keep-alive
broadcast (169.254.116.4 → 169.254.255.255, UDP 50000, `"Qspt1WmJOL"`
signature) decoded through the hard 8b10b + fabric PCS.

## Host-side tools

| Script | Purpose |
|---|---|
| `scripts/csrctl.py` | CSR read/write/dump over the UART bridge (raw termios, stdlib only) |
| `scripts/udp_echo_test.py` | Per-port UDP echo validation + unbound-port drop check |
| `scripts/tcp_echo_test.py` | TCP servers: echo (incl. >MSS payloads), clean close, reconnect, concurrent ports, busy/unbound RST |
| `scripts/tcp_client_test.py` | Listens; the board's TCP client connects, echoes, closes, reconnects |
| `scripts/dhcp_test_server.py` | Minimal MAC-filtered DHCP server (stdlib; sudo for port 67) |
| `scripts/gw_sh_wrapper` | Runs the Gowin IDE `gw_sh` headless with its bundled Qt/fontconfig |

## Design notes

* **Wire byte order**: header struct fields hold byte-swapped (wire-order)
  values; convert with `layouts.bswap()` and compare against pre-swapped
  constants.
* **Metadata is latched signals**, not stream parameters, at every protocol
  layer; only the UDP user streams carry real per-packet `param`s.
* **Store-and-forward where it matters**: TCP RX validates the checksum over
  a buffered segment before anything acts on it, TCP TX keeps a replay
  buffer for retransmission, and the RX chain is never held hostage by a
  stalled user (dup-ACK + drop instead).
* **Sequence arithmetic is equality-only** in the in-order TCP engine, which
  makes it wraparound-safe by construction.
* Timers (ARP, TCP RTO/idle/reconnect, DHCP retry/lease) all derive from
  `clk_freq` constructor parameters and are shrunk in simulation.

## Limitations (v1, by design)

* TCP: one connection per endpoint, in-order RX only, stop-and-wait TX
  (single in-flight segment of up to `tcp_mss` bytes, capped by the peer's
  MSS option), passive close only, no congestion control / window scaling /
  SACK / zero-window probing. The MSS option is the only option sent or
  interpreted.
* DHCP: broadcast renewal (rebinding style), first OFFER wins, no ARP
  probing / gratuitous announce / DECLINE / RELEASE.
* CRC-errored frames are flagged but not dropped ahead of the core (a
  corrupt frame can desync one packet; self-recovering).
* 1000BASE-X PCS: SGMII framing (bit 0 mirroring, speed bits) is implemented
  and simulated, but only the gigabit rate is hardware-proven; 10/100 byte
  repetition is untested on hardware.
* Sustained throughput is capped by the byte-wide core (~400 Mbps at
  50 MHz); the wire side still runs true gigabit bursts.

## Testing

```sh
pdm run pytest -q          # 155 tests
```

Layer tests drive plain MAC frames against Python reference
builders/parsers (`tests/net_helpers.py`); wire-level system tests push
preamble+FCS frames through the full MAC across three clock domains; several
TCP edge-case tests mirror [smoltcp](https://github.com/smoltcp-rs/smoltcp)'s
`socket/tcp.rs` corpus. The final gate has always been the Linux kernel over
a real cable.

## License

Two-clause BSD, like LiteEth — see [LICENSE](LICENSE).

Portions derived from [LiteEth](https://github.com/enjoy-digital/liteeth),
Copyright (c) 2015-2023 Florent Kermarrec. TCP, DHCP and the port-binding
layers are original LambdaEth work.
