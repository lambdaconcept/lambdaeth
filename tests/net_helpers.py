#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Reference Ethernet/ARP/IPv4/UDP frame builders and parsers for tests."""

import struct


def mac_bytes(mac):
    return mac.to_bytes(6, "big")


def ip_bytes(ip):
    return ip.to_bytes(4, "big")


def ipv4_checksum(header):
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def build_eth(dst_mac, src_mac, ethertype, payload, pad=True):
    frame = mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack(">H", ethertype)
    frame += payload
    if pad and len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def build_arp(opcode, sender_mac, sender_ip, target_mac, target_ip):
    return (struct.pack(">HHBBH", 1, 0x0800, 6, 4, opcode) +
            mac_bytes(sender_mac) + ip_bytes(sender_ip) +
            mac_bytes(target_mac) + ip_bytes(target_ip))


def build_ipv4(src_ip, dst_ip, protocol, payload, ttl=0x40, ident=0, flags_frag=0):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s",
                      0x45, 0, total, ident, flags_frag, ttl, protocol, 0,
                      ip_bytes(src_ip), ip_bytes(dst_ip))
    csum = ipv4_checksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", csum) + hdr[12:]
    return hdr + payload


def build_udp(src_port, dst_port, payload):
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def icmp_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def build_icmp_echo(ident, seq, payload, msgtype=8):
    packet = struct.pack(">BBHHH", msgtype, 0, 0, ident, seq) + payload
    csum = icmp_checksum(packet)
    return packet[:2] + struct.pack(">H", csum) + packet[4:]


def build_ping_frame(src_mac, src_ip, dst_mac, dst_ip, ident, seq, payload,
                     msgtype=8):
    icmp = build_icmp_echo(ident, seq, payload, msgtype=msgtype)
    ip   = build_ipv4(src_ip, dst_ip, 1, icmp)
    return build_eth(dst_mac, src_mac, 0x0800, ip)


def build_udp_frame(src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port, payload):
    udp = build_udp(src_port, dst_port, payload)
    ip  = build_ipv4(src_ip, dst_ip, 17, udp)
    return build_eth(dst_mac, src_mac, 0x0800, ip)


# TCP ------------------------------------------------------------------------------------------

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


def tcp_checksum(src_ip, dst_ip, segment):
    """TCP checksum over the pseudo-header and the full segment."""
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack(">BBH", 0, 6,
                                                               len(segment))
    return icmp_checksum(pseudo + segment)     # Same one's-complement sum.


def build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b"",
              window=0xffff, options=b"", bad_checksum=False):
    """Build a TCP segment (with valid pseudo-header checksum by default)."""
    assert len(options) % 4 == 0
    data_offset = 5 + len(options) // 4
    hdr = struct.pack(">HHIIBBHHH", src_port, dst_port, seq & 0xffffffff,
                      ack & 0xffffffff, data_offset << 4, flags, window, 0, 0)
    segment = hdr + options + payload
    csum = tcp_checksum(src_ip, dst_ip, segment)
    if bad_checksum:
        csum ^= 0x5555
    return segment[:16] + struct.pack(">H", csum) + segment[18:]


def build_tcp_frame(src_mac, src_ip, dst_mac, dst_ip, src_port, dst_port,
                    seq, ack, flags, payload=b"", window=0xffff, options=b"",
                    bad_checksum=False):
    tcp = build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags,
                    payload, window, options, bad_checksum)
    ip  = build_ipv4(src_ip, dst_ip, 6, tcp)
    return build_eth(dst_mac, src_mac, 0x0800, ip)


# DHCP -----------------------------------------------------------------------------------------

DHCP_COOKIE = bytes([0x63, 0x82, 0x53, 0x63])


def dhcp_option(code, data):
    return bytes([code, len(data)]) + data


def build_dhcp(op, xid, mac, msg_type, yiaddr=0, ciaddr=0, options=b"",
               flags=0x8000):
    """Raw BOOTP/DHCP payload (padded to 300 bytes)."""
    msg = struct.pack(">BBBBIHH", op, 1, 6, 0, xid, 0, flags)
    msg += ip_bytes(ciaddr) + ip_bytes(yiaddr) + b"\x00" * 8
    msg += mac_bytes(mac) + b"\x00" * 10
    msg += b"\x00" * 192
    msg += DHCP_COOKIE
    msg += dhcp_option(53, bytes([msg_type])) + options + b"\xff"
    if len(msg) < 300:
        msg += b"\x00" * (300 - len(msg))
    return msg


def build_dhcp_reply_frame(server_mac, server_ip, client_mac, xid, msg_type,
                           yiaddr, lease=300, sid=None, chaddr=None):
    """OFFER/ACK/NAK as a server would broadcast it (client set the
    broadcast flag): IP 255.255.255.255, Ethernet broadcast."""
    sid = sid if sid is not None else server_ip
    opts = (dhcp_option(54, ip_bytes(sid)) +
            dhcp_option(51, struct.pack(">I", lease)))
    payload = build_dhcp(2, xid, chaddr if chaddr is not None else client_mac,
                         msg_type, yiaddr=yiaddr, options=opts)
    udp = build_udp(67, 68, payload)
    ip  = build_ipv4(server_ip, 0xffffffff, 17, udp)
    return build_eth(0xffffffffffff, server_mac, 0x0800, ip)


def parse_dhcp(payload):
    """Parse a BOOTP/DHCP payload into fields + an options dict."""
    d = {}
    (d["op"], d["htype"], d["hlen"], d["hops"], d["xid"], d["secs"],
     d["flags"]) = struct.unpack(">BBBBIHH", payload[:12])
    d["ciaddr"] = payload[12:16]
    d["yiaddr"] = payload[16:20]
    d["chaddr"] = payload[28:34]
    d["cookie_ok"] = payload[236:240] == DHCP_COOKIE
    opts = {}
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        length = payload[i + 1]
        opts[code] = payload[i + 2:i + 2 + length]
        i += 2 + length
    d["options"] = opts
    return d


class ParsedFrame:
    def __init__(self, data):
        data = bytes(data)
        self.raw = data
        self.dst_mac, self.src_mac = data[0:6], data[6:12]
        self.ethertype = struct.unpack(">H", data[12:14])[0]
        self.payload = data[14:]

        if self.ethertype == 0x0806:
            (self.arp_hwtype, self.arp_proto, self.arp_hwsize, self.arp_protosize,
             self.arp_opcode) = struct.unpack(">HHBBH", self.payload[0:8])
            self.arp_sender_mac = self.payload[8:14]
            self.arp_sender_ip  = self.payload[14:18]
            self.arp_target_mac = self.payload[18:24]
            self.arp_target_ip  = self.payload[24:28]

        if self.ethertype == 0x0800:
            ip = self.payload
            self.ip_header    = ip[0:20]
            self.ip_verihl    = ip[0]
            self.ip_total_len = struct.unpack(">H", ip[2:4])[0]
            self.ip_protocol  = ip[9]
            self.ip_checksum  = struct.unpack(">H", ip[10:12])[0]
            self.ip_src       = ip[12:16]
            self.ip_dst       = ip[16:20]
            self.ip_payload   = ip[20:self.ip_total_len]
            self.ip_csum_ok   = ipv4_checksum(self.ip_header) == 0
            if self.ip_protocol == 17:
                udp = self.ip_payload
                (self.udp_src_port, self.udp_dst_port,
                 self.udp_length, self.udp_checksum) = struct.unpack(">HHHH", udp[0:8])
                self.udp_payload = udp[8:self.udp_length]
            if self.ip_protocol == 1:
                icmp = self.ip_payload
                (self.icmp_type, self.icmp_code, self.icmp_checksum,
                 self.icmp_ident, self.icmp_seq) = struct.unpack(">BBHHH", icmp[0:8])
                self.icmp_payload = icmp[8:]
                self.icmp_csum_ok = icmp_checksum(
                    icmp[:2] + b"\x00\x00" + icmp[4:]) == self.icmp_checksum
            if self.ip_protocol == 6:
                tcp = self.ip_payload
                (self.tcp_src_port, self.tcp_dst_port, self.tcp_seq,
                 self.tcp_ack, offs, self.tcp_flags, self.tcp_window,
                 self.tcp_checksum, self.tcp_urgent) = \
                    struct.unpack(">HHIIBBHHH", tcp[0:20])
                self.tcp_data_offset = offs >> 4
                self.tcp_options = tcp[20:self.tcp_data_offset * 4]
                self.tcp_payload = tcp[self.tcp_data_offset * 4:]
                src = int.from_bytes(self.ip_src, "big")
                dst = int.from_bytes(self.ip_dst, "big")
                self.tcp_csum_ok = tcp_checksum(src, dst, tcp) == 0
                for name, bit in (("fin", 0), ("syn", 1), ("rst", 2),
                                  ("psh", 3), ("ack", 4)):
                    setattr(self, f"tcp_flag_{name}",
                            bool(self.tcp_flags & (1 << bit)))
