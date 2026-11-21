"""
WirePulse Core OSI 7-Layer Protocol Dissector Engine.

Dissects raw link-layer frames into byte-exact hierarchical OSI LayerNodes & FieldNodes
plus a flattened field index for Display Filter AST evaluation.
"""
from __future__ import annotations

import base64
import ipaddress
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..pcap_io import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_LOOP,
    DLT_NULL,
    DLT_RAW,
)
from .dns_parser import parse_dns
from .dpi import classify_tcp_app, classify_udp_app
from .models import FieldNode, LayerNode, PacketRecord
from .oui import format_mac, lookup_oui
from .tls_ja3 import parse_tls

ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q VLAN",
    0x86DD: "IPv6",
    0x88CC: "LLDP",
    0x888E: "EAPOL",
}

IP_PROTOS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-in-IPv4",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

ICMP_TYPES = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo (ping) request",
    11: "Time-to-live exceeded",
    12: "Parameter problem",
}

ICMPV6_TYPES = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    128: "Echo (ping) request",
    129: "Echo (ping) reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
}

DHCP_MSG_TYPES = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    4: "Decline",
    5: "ACK",
    6: "NAK",
    7: "Release",
    8: "Inform",
}

TCP_FLAG_BITS = [
    (0x0100, "NS", "tcp.flags.ns"),
    (0x0080, "CWR", "tcp.flags.cwr"),
    (0x0040, "ECE", "tcp.flags.ece"),
    (0x0020, "URG", "tcp.flags.urg"),
    (0x0010, "ACK", "tcp.flags.ack"),
    (0x0008, "PSH", "tcp.flags.psh"),
    (0x0004, "RST", "tcp.flags.rst"),
    (0x0002, "SYN", "tcp.flags.syn"),
    (0x0001, "FIN", "tcp.flags.fin"),
]


def _ones_complement_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class ProtocolDissector:
    """Stateful OSI L2-L7 dissector (tracks first timestamp & relative TCP seq baselines)."""

    def __init__(self) -> None:
        self._first_ts: Optional[float] = None
        self._prev_ts: Optional[float] = None
        self._tcp_isn: Dict[Tuple[str, int, str, int], int] = {}

    def reset(self) -> None:
        self._first_ts = None
        self._prev_ts = None
        self._tcp_isn.clear()

    def dissect(
        self,
        no: int,
        raw: bytes,
        timestamp: float,
        origlen: int,
        linktype: int = DLT_EN10MB,
    ) -> PacketRecord:
        if self._first_ts is None:
            self._first_ts = timestamp
        rel_time = max(0.0, timestamp - self._first_ts)
        delta_time = max(0.0, timestamp - self._prev_ts) if self._prev_ts is not None else 0.0
        self._prev_ts = timestamp

        pkt = PacketRecord(
            no=no,
            timestamp=timestamp,
            rel_time=rel_time,
            delta_time=delta_time,
            caplen=len(raw),
            origlen=origlen,
            linktype=linktype,
            raw=raw,
        )

        # Frame Metadata Layer (OSI L1/Physical framing summary)
        utc_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        frame_fields = [
            FieldNode("frame.number", f"Frame Number: {no}", no, 0, len(raw), 1),
            FieldNode("frame.len", f"Frame Length: {origlen} bytes ({origlen * 8} bits)", origlen, 0, len(raw), 1),
            FieldNode("frame.cap_len", f"Capture Length: {len(raw)} bytes ({len(raw) * 8} bits)", len(raw), 0, len(raw), 1),
            FieldNode("frame.time", f"Arrival Time: {utc_iso}", utc_iso, 0, 0, 1),
            FieldNode("frame.time_relative", f"Time since first frame: {rel_time:.6f} seconds", round(rel_time, 6), 0, 0, 1),
            FieldNode("frame.time_delta", f"Time delta from previous frame: {delta_time:.6f} seconds", round(delta_time, 6), 0, 0, 1),
            FieldNode("frame.encap_type", f"Link-Layer Header Type: DLT={linktype}", linktype, 0, 0, 1),
        ]
        frame_layer = LayerNode(
            protocol="FRAME",
            title=f"Frame {no}: {origlen} bytes on wire ({origlen * 8} bits), {len(raw)} bytes captured",
            osi_layer=1,
            offset=0,
            length=len(raw),
            fields=frame_fields,
        )
        pkt.layers.append(frame_layer)
        pkt.add_field_index("frame.number", no)
        pkt.add_field_index("frame.len", origlen)
        pkt.add_field_index("frame.cap_len", len(raw))
        pkt.add_field_index("frame.time_relative", rel_time)

        # Dispatch L2 Data Link Layer
        ethertype, l3_offset = self._dissect_l2(pkt, raw, linktype)

        # Dispatch L3 Network Layer
        if ethertype == 0x0800:
            self._dissect_ipv4(pkt, raw, l3_offset)
        elif ethertype == 0x86DD:
            self._dissect_ipv6(pkt, raw, l3_offset)
        elif ethertype == 0x0806:
            self._dissect_arp(pkt, raw, l3_offset)
        elif ethertype == 0x88CC:
            pkt.protocol = "LLDP"
            pkt.protocols.append("lldp")
            pkt.info = "Link Layer Discovery Protocol"
        elif not pkt.info:
            pkt.info = f"EtherType 0x{ethertype:04x} ({len(raw) - l3_offset} bytes)"

        # Finalize frame.protocols & info index
        frame_protos = ":".join(pkt.protocols)
        frame_layer.fields.append(FieldNode("frame.protocols", f"Protocols in frame: {frame_protos}", frame_protos, 0, len(raw), 1))
        pkt.add_field_index("frame.protocols", frame_protos)
        pkt.add_field_index("info", pkt.info)
        pkt.add_field_index("protocol", pkt.protocol)
        return pkt

    def _dissect_l2(self, pkt: PacketRecord, raw: bytes, linktype: int) -> Tuple[int, int]:
        if linktype == DLT_RAW:
            if len(raw) >= 1:
                ver = raw[0] >> 4
                return (0x0800 if ver == 4 else 0x86DD if ver == 6 else 0), 0
            return 0, 0

        if linktype in (DLT_NULL, DLT_LOOP):
            if len(raw) < 4:
                return 0, 0
            fam_le = struct.unpack_from("<I", raw, 0)[0]
            fam_be = struct.unpack_from(">I", raw, 0)[0]
            fam = fam_le if fam_le in (2, 10, 24, 28, 30) else fam_be
            et = 0x0800 if fam == 2 else (0x86DD if fam in (10, 24, 28, 30) else 0)
            pkt.protocols.append("null")
            pkt.layers.append(
                LayerNode(
                    protocol="NULL",
                    title=f"Null/Loopback (Family: {ETHERTYPES.get(et, fam)})",
                    osi_layer=2,
                    offset=0,
                    length=4,
                    fields=[FieldNode("null.family", f"Family: {ETHERTYPES.get(et, fam)} ({fam})", fam, 0, 4, 2)],
                )
            )
            return et, 4

        if linktype == DLT_LINUX_SLL and len(raw) >= 16:
            pkt_type, arphrd, addr_len = struct.unpack_from("!HHH", raw, 0)
            ethertype = struct.unpack_from("!H", raw, 14)[0]
            mac = format_mac(raw[6 : 6 + min(addr_len, 6)]) if addr_len >= 6 else ""
            pkt.protocols.append("sll")
            pkt.src = mac or "linux-sll"
            pkt.dst = "host"
            pkt.layers.append(
                LayerNode(
                    protocol="SLL",
                    title=f"Linux Cooked Capture v1 (Proto: {ETHERTYPES.get(ethertype, hex(ethertype))})",
                    osi_layer=2,
                    offset=0,
                    length=16,
                    fields=[
                        FieldNode("sll.pkttype", f"Packet type: {pkt_type}", pkt_type, 0, 2, 2),
                        FieldNode("sll.hatype", f"Link-layer address type: {arphrd}", arphrd, 2, 2, 2),
                        FieldNode("sll.src.eth", f"Source address: {mac}", mac, 6, 6, 2),
                        FieldNode("sll.etype", f"Protocol: {ETHERTYPES.get(ethertype, hex(ethertype))} (0x{ethertype:04x})", f"0x{ethertype:04x}", 14, 2, 2),
                    ],
                )
            )
            return ethertype, 16

        if linktype == DLT_LINUX_SLL2 and len(raw) >= 20:
            ethertype = struct.unpack_from("!H", raw, 0)[0]
            if_idx = struct.unpack_from("!I", raw, 4)[0]
            mac = format_mac(raw[12:18])
            pkt.protocols.append("sll2")
            pkt.src = mac
            pkt.dst = "host"
            pkt.layers.append(
                LayerNode(
                    protocol="SLL2",
                    title=f"Linux Cooked Capture v2 (IfIndex={if_idx}, Proto={ETHERTYPES.get(ethertype, hex(ethertype))})",
                    osi_layer=2,
                    offset=0,
                    length=20,
                    fields=[
                        FieldNode("sll2.etype", f"Protocol: 0x{ethertype:04x}", f"0x{ethertype:04x}", 0, 2, 2),
                        FieldNode("sll2.ifindex", f"Interface index: {if_idx}", if_idx, 4, 4, 2),
                        FieldNode("sll2.src.eth", f"Source MAC: {mac}", mac, 12, 6, 2),
                    ],
                )
            )
            return ethertype, 20

        # Default: Ethernet II (DLT_EN10MB)
        if len(raw) < 14:
            pkt.protocol = "ETH"
            pkt.info = f"Truncated Ethernet frame ({len(raw)} bytes)"
            return 0, len(raw)

        dst_mac = format_mac(raw[0:6])
        src_mac = format_mac(raw[6:12])
        dst_vendor = lookup_oui(dst_mac)
        src_vendor = lookup_oui(src_mac)
        ethertype = struct.unpack_from("!H", raw, 12)[0]
        off = 14

        pkt.src = src_mac
        pkt.dst = dst_mac
        pkt.protocol = "ETH"
        pkt.protocols.append("eth")
        pkt.add_field_index("eth.src", src_mac)
        pkt.add_field_index("eth.dst", dst_mac)
        pkt.add_field_index("eth.addr", src_mac)
        pkt.add_field_index("eth.addr", dst_mac)

        src_disp = f"{src_mac} ({src_vendor})" if src_vendor else src_mac
        dst_disp = f"{dst_mac} ({dst_vendor})" if dst_vendor else dst_mac

        eth_fields = [
            FieldNode("eth.dst", f"Destination: {dst_disp}", dst_mac, 0, 6, 2),
            FieldNode("eth.src", f"Source: {src_disp}", src_mac, 6, 6, 2),
            FieldNode("eth.type", f"Type: {ETHERTYPES.get(ethertype, 'Unknown')} (0x{ethertype:04x})", f"0x{ethertype:04x}", 12, 2, 2),
        ]
        pkt.layers.append(
            LayerNode(
                protocol="ETH",
                title=f"Ethernet II, Src: {src_disp}, Dst: {dst_disp}",
                osi_layer=2,
                offset=0,
                length=14,
                fields=eth_fields,
            )
        )

        # IEEE 802.1Q VLAN Tag
        if ethertype == 0x8100 and len(raw) >= 18:
            tci, inner_et = struct.unpack_from("!HH", raw, 14)
            pcp = (tci >> 13) & 0x7
            dei = (tci >> 12) & 0x1
            vid = tci & 0x0FFF
            pkt.protocols.append("vlan")
            pkt.add_field_index("vlan.id", vid)
            pkt.layers.append(
                LayerNode(
                    protocol="VLAN",
                    title=f"802.1Q Virtual LAN, PRI: {pcp}, DEI: {dei}, ID: {vid}",
                    osi_layer=2,
                    offset=14,
                    length=4,
                    fields=[
                        FieldNode("vlan.priority", f"Priority: {pcp}", pcp, 14, 2, 2),
                        FieldNode("vlan.id", f"VLAN ID: {vid}", vid, 14, 2, 2),
                        FieldNode("vlan.etype", f"Type: {ETHERTYPES.get(inner_et, hex(inner_et))} (0x{inner_et:04x})", f"0x{inner_et:04x}", 16, 2, 2),
                    ],
                )
            )
            ethertype = inner_et
            off = 18

        pkt.add_field_index("eth.type", f"0x{ethertype:04x}")
        return ethertype, off

    def _dissect_arp(self, pkt: PacketRecord, raw: bytes, off: int) -> None:
        pkt.protocol = "ARP"
        pkt.protocols.append("arp")
        pkt.osi_top_layer = 2
        if off + 28 > len(raw):
            pkt.info = "Malformed ARP"
            return

        htype, ptype, hlen, plen, opcode = struct.unpack_from("!HHBBH", raw, off)
        sha = format_mac(raw[off + 8 : off + 14])
        spa = str(ipaddress.IPv4Address(raw[off + 14 : off + 18]))
        tha = format_mac(raw[off + 18 : off + 24])
        tpa = str(ipaddress.IPv4Address(raw[off + 24 : off + 28]))

        op_str = {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"}.get(opcode, f"opcode={opcode}")
        is_gratuitous = (spa == tpa)

        pkt.src = spa
        pkt.dst = tpa if opcode == 2 else "Broadcast"
        if opcode == 1:
            pkt.info = f"Gratuitous ARP for {spa} (Request)" if is_gratuitous else f"Who has {tpa}? Tell {spa}"
        elif opcode == 2:
            pkt.info = f"{spa} is at {sha}" + (" (Gratuitous)" if is_gratuitous else "")
        else:
            pkt.info = f"ARP {op_str} {spa} -> {tpa}"

        pkt.add_field_index("arp.opcode", opcode)
        pkt.add_field_index("arp.src.hw_mac", sha)
        pkt.add_field_index("arp.src.proto_ipv4", spa)
        pkt.add_field_index("arp.dst.hw_mac", tha)
        pkt.add_field_index("arp.dst.proto_ipv4", tpa)
        pkt.add_field_index("ip.addr", spa)
        pkt.add_field_index("ip.addr", tpa)

        pkt.layers.append(
            LayerNode(
                protocol="ARP",
                title=f"Address Resolution Protocol ({op_str})",
                osi_layer=2,
                offset=off,
                length=28,
                fields=[
                    FieldNode("arp.hw.type", f"Hardware type: Ethernet ({htype})", htype, off, 2, 2),
                    FieldNode("arp.proto.type", f"Protocol type: IPv4 (0x{ptype:04x})", f"0x{ptype:04x}", off + 2, 2, 2),
                    FieldNode("arp.hw.size", f"Hardware size: {hlen}", hlen, off + 4, 1, 2),
                    FieldNode("arp.proto.size", f"Protocol size: {plen}", plen, off + 5, 1, 2),
                    FieldNode("arp.opcode", f"Opcode: {op_str} ({opcode})", opcode, off + 6, 2, 2),
                    FieldNode("arp.src.hw_mac", f"Sender MAC address: {sha}", sha, off + 8, 6, 2),
                    FieldNode("arp.src.proto_ipv4", f"Sender IP address: {spa}", spa, off + 14, 4, 2),
                    FieldNode("arp.dst.hw_mac", f"Target MAC address: {tha}", tha, off + 18, 6, 2),
                    FieldNode("arp.dst.proto_ipv4", f"Target IP address: {tpa}", tpa, off + 24, 4, 2),
                ],
            )
        )

    def _dissect_ipv4(self, pkt: PacketRecord, raw: bytes, off: int) -> None:
        if off + 20 > len(raw):
            pkt.protocol = "IPv4"
            pkt.info = "Truncated IPv4 header"
            return

        ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, checksum = struct.unpack_from("!BBHHHBBH", raw, off)
        version = ver_ihl >> 4
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or off + ihl > len(raw):
            pkt.protocol = "IPv4"
            pkt.info = f"Invalid IPv4 header length ({ihl})"
            return

        src_bytes = raw[off + 12 : off + 16]
        dst_bytes = raw[off + 16 : off + 20]
        src_ip = str(ipaddress.IPv4Address(src_bytes))
        dst_ip = str(ipaddress.IPv4Address(dst_bytes))

        df = (flags_frag >> 14) & 1
        mf = (flags_frag >> 13) & 1
        frag_off = (flags_frag & 0x1FFF) * 8

        # Verify IPv4 header checksum
        hdr_bytes = raw[off : off + ihl]
        chk_valid = (_ones_complement_checksum(hdr_bytes) == 0)

        proto_name = IP_PROTOS.get(proto, f"IPProto({proto})")
        pkt.src = src_ip
        pkt.dst = dst_ip
        pkt.protocol = "IPv4"
        pkt.protocols.append("ip")
        pkt.osi_top_layer = 3

        pkt.add_field_index("ip.version", version)
        pkt.add_field_index("ip.hdr_len", ihl)
        pkt.add_field_index("ip.len", total_len)
        pkt.add_field_index("ip.id", f"0x{ident:04x}")
        pkt.add_field_index("ip.ttl", ttl)
        pkt.add_field_index("ip.proto", proto)
        pkt.add_field_index("ip.src", src_ip)
        pkt.add_field_index("ip.dst", dst_ip)
        pkt.add_field_index("ip.addr", src_ip)
        pkt.add_field_index("ip.addr", dst_ip)
        pkt.add_field_index("ip.checksum_valid", chk_valid)

        ip_fields = [
            FieldNode("ip.version", f"Version: {version}", version, off, 1, 3),
            FieldNode("ip.hdr_len", f"Header Length: {ihl} bytes ({ihl // 4})", ihl, off, 1, 3),
            FieldNode("ip.dsfield", f"Differentiated Services Field: 0x{tos:02x} (DSCP {tos >> 2}, ECN {tos & 3})", tos, off + 1, 1, 3),
            FieldNode("ip.len", f"Total Length: {total_len}", total_len, off + 2, 2, 3),
            FieldNode("ip.id", f"Identification: 0x{ident:04x} ({ident})", f"0x{ident:04x}", off + 4, 2, 3),
            FieldNode(
                "ip.flags",
                f"Flags: 0x{flags_frag >> 13:x} (DF={df}, MF={mf}), Fragment Offset: {frag_off}",
                flags_frag >> 13,
                off + 6,
                2,
                3,
                children=[
                    FieldNode("ip.flags.df", f"Don't fragment: {'Set' if df else 'Not set'}", bool(df), off + 6, 1, 3),
                    FieldNode("ip.flags.mf", f"More fragments: {'Set' if mf else 'Not set'}", bool(mf), off + 6, 1, 3),
                    FieldNode("ip.frag_offset", f"Fragment Offset: {frag_off}", frag_off, off + 6, 2, 3),
                ],
            ),
            FieldNode("ip.ttl", f"Time to Live: {ttl}", ttl, off + 8, 1, 3),
            FieldNode("ip.proto", f"Protocol: {proto_name} ({proto})", proto, off + 9, 1, 3),
            FieldNode(
                "ip.checksum",
                f"Header Checksum: 0x{checksum:04x} [{'correct' if chk_valid else 'incorrect / offload'}]",
                f"0x{checksum:04x}",
                off + 10,
                2,
                3,
                severity=None if chk_valid else "info",
            ),
            FieldNode("ip.src", f"Source Address: {src_ip}", src_ip, off + 12, 4, 3),
            FieldNode("ip.dst", f"Destination Address: {dst_ip}", dst_ip, off + 16, 4, 3),
        ]

        pkt.layers.append(
            LayerNode(
                protocol="IPv4",
                title=f"Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}",
                osi_layer=3,
                offset=off,
                length=ihl,
                fields=ip_fields,
            )
        )

        payload_off = off + ihl
        payload_len = max(0, min(len(raw) - payload_off, total_len - ihl)) if total_len >= ihl else max(0, len(raw) - payload_off)

        if frag_off > 0:
            pkt.protocol = "IPv4"
            pkt.info = f"Fragmented IP protocol (proto={proto_name}, off={frag_off}, len={payload_len})"
            return

        pseudo_hdr_prefix = src_bytes + dst_bytes
        if proto == 6:
            self._dissect_tcp(pkt, raw, payload_off, payload_len, pseudo_hdr_prefix, is_ipv6=False)
        elif proto == 17:
            self._dissect_udp(pkt, raw, payload_off, payload_len)
        elif proto == 1:
            self._dissect_icmp(pkt, raw, payload_off, payload_len)
        else:
            pkt.protocol = proto_name
            pkt.protocols.append(proto_name.lower())
            pkt.info = f"{proto_name} ({payload_len} bytes)"

    def _dissect_ipv6(self, pkt: PacketRecord, raw: bytes, off: int) -> None:
        if off + 40 > len(raw):
            pkt.protocol = "IPv6"
            pkt.info = "Truncated IPv6 header"
            return

        vtcfl, plen, next_hdr, hop_limit = struct.unpack_from("!IHBB", raw, off)
        version = (vtcfl >> 28) & 0xF
        tclass = (vtcfl >> 20) & 0xFF
        flow_lbl = vtcfl & 0xFFFFF
        src_bytes = raw[off + 8 : off + 24]
        dst_bytes = raw[off + 24 : off + 40]
        src_ip = str(ipaddress.IPv6Address(src_bytes))
        dst_ip = str(ipaddress.IPv6Address(dst_bytes))

        proto_name = IP_PROTOS.get(next_hdr, f"NextHdr({next_hdr})")
        pkt.src = src_ip
        pkt.dst = dst_ip
        pkt.protocol = "IPv6"
        pkt.protocols.append("ipv6")
        pkt.osi_top_layer = 3

        pkt.add_field_index("ipv6.src", src_ip)
        pkt.add_field_index("ipv6.dst", dst_ip)
        pkt.add_field_index("ipv6.addr", src_ip)
        pkt.add_field_index("ipv6.addr", dst_ip)
        pkt.add_field_index("ipv6.hlim", hop_limit)
        pkt.add_field_index("ipv6.nxt", next_hdr)
        pkt.add_field_index("ip.addr", src_ip)
        pkt.add_field_index("ip.addr", dst_ip)

        pkt.layers.append(
            LayerNode(
                protocol="IPv6",
                title=f"Internet Protocol Version 6, Src: {src_ip}, Dst: {dst_ip}",
                osi_layer=3,
                offset=off,
                length=40,
                fields=[
                    FieldNode("ipv6.version", f"Version: {version}", version, off, 1, 3),
                    FieldNode("ipv6.tclass", f"Traffic Class: 0x{tclass:02x}", tclass, off, 2, 3),
                    FieldNode("ipv6.flow", f"Flow Label: 0x{flow_lbl:05x}", f"0x{flow_lbl:05x}", off + 1, 3, 3),
                    FieldNode("ipv6.plen", f"Payload Length: {plen}", plen, off + 4, 2, 3),
                    FieldNode("ipv6.nxt", f"Next Header: {proto_name} ({next_hdr})", next_hdr, off + 6, 1, 3),
                    FieldNode("ipv6.hlim", f"Hop Limit: {hop_limit}", hop_limit, off + 7, 1, 3),
                    FieldNode("ipv6.src", f"Source Address: {src_ip}", src_ip, off + 8, 16, 3),
                    FieldNode("ipv6.dst", f"Destination Address: {dst_ip}", dst_ip, off + 24, 16, 3),
                ],
            )
        )

        payload_off = off + 40
        payload_len = min(len(raw) - payload_off, plen)
        pseudo_hdr_prefix = src_bytes + dst_bytes

        if next_hdr == 6:
            self._dissect_tcp(pkt, raw, payload_off, payload_len, pseudo_hdr_prefix, is_ipv6=True)
        elif next_hdr == 17:
            self._dissect_udp(pkt, raw, payload_off, payload_len)
        elif next_hdr == 58:
            self._dissect_icmpv6(pkt, raw, payload_off, payload_len)
        else:
            pkt.protocol = proto_name
            pkt.protocols.append(proto_name.lower())
            pkt.info = f"IPv6 {proto_name} ({payload_len} bytes)"

    def _dissect_icmp(self, pkt: PacketRecord, raw: bytes, off: int, length: int) -> None:
        pkt.protocol = "ICMP"
        pkt.protocols.append("icmp")
        pkt.osi_top_layer = 3
        if length < 4 or off + 4 > len(raw):
            pkt.info = "Malformed ICMP"
            return

        itype, icode, chk = struct.unpack_from("!BBH", raw, off)
        type_name = ICMP_TYPES.get(itype, f"Type {itype}")
        pkt.add_field_index("icmp.type", itype)
        pkt.add_field_index("icmp.code", icode)

        fields = [
            FieldNode("icmp.type", f"Type: {itype} ({type_name})", itype, off, 1, 3),
            FieldNode("icmp.code", f"Code: {icode}", icode, off + 1, 1, 3),
            FieldNode("icmp.checksum", f"Checksum: 0x{chk:04x}", f"0x{chk:04x}", off + 2, 2, 3),
        ]
        if itype in (0, 8) and length >= 8 and off + 8 <= len(raw):
            ident, seq = struct.unpack_from("!HH", raw, off + 4)
            fields.append(FieldNode("icmp.ident", f"Identifier: 0x{ident:04x} ({ident})", ident, off + 4, 2, 3))
            fields.append(FieldNode("icmp.seq", f"Sequence Number: {seq}", seq, off + 6, 2, 3))
            pkt.add_field_index("icmp.seq", seq)
            pkt.info = f"{type_name} id=0x{ident:04x}, seq={seq}, len={length}"
        else:
            pkt.info = f"{type_name} (code={icode}, len={length})"

        pkt.layers.append(
            LayerNode(
                protocol="ICMP",
                title=f"Internet Control Message Protocol ({type_name})",
                osi_layer=3,
                offset=off,
                length=length,
                fields=fields,
            )
        )

    def _dissect_icmpv6(self, pkt: PacketRecord, raw: bytes, off: int, length: int) -> None:
        pkt.protocol = "ICMPv6"
        pkt.protocols.append("icmpv6")
        pkt.osi_top_layer = 3
        if length < 4 or off + 4 > len(raw):
            pkt.info = "Malformed ICMPv6"
            return

        itype, icode, chk = struct.unpack_from("!BBH", raw, off)
        type_name = ICMPV6_TYPES.get(itype, f"Type {itype}")
        pkt.add_field_index("icmpv6.type", itype)
        pkt.add_field_index("icmpv6.code", icode)
        fields = [
            FieldNode("icmpv6.type", f"Type: {itype} ({type_name})", itype, off, 1, 3),
            FieldNode("icmpv6.code", f"Code: {icode}", icode, off + 1, 1, 3),
            FieldNode("icmpv6.checksum", f"Checksum: 0x{chk:04x}", f"0x{chk:04x}", off + 2, 2, 3),
        ]
        if itype in (135, 136) and length >= 24 and off + 24 <= len(raw):
            target = str(ipaddress.IPv6Address(raw[off + 8 : off + 24]))
            fields.append(FieldNode("icmpv6.nd.ns.target_address", f"Target Address: {target}", target, off + 8, 16, 3))
            pkt.info = f"{type_name} for {target}"
        else:
            pkt.info = f"{type_name} (code={icode})"

        pkt.layers.append(
            LayerNode(
                protocol="ICMPv6",
                title=f"Internet Control Message Protocol v6 ({type_name})",
                osi_layer=3,
                offset=off,
                length=length,
                fields=fields,
            )
        )

    def _dissect_tcp(
        self,
        pkt: PacketRecord,
        raw: bytes,
        off: int,
        seg_len: int,
        pseudo_ip_bytes: bytes,
        is_ipv6: bool,
    ) -> None:
        pkt.protocol = "TCP"
        pkt.protocols.append("tcp")
        pkt.osi_top_layer = 4
        if seg_len < 20 or off + 20 > len(raw):
            pkt.info = "Truncated TCP segment"
            return

        sport, dport, seq, ack, off_flags, window, checksum, urg_ptr = struct.unpack_from("!HHIIHHHH", raw, off)
        data_off = ((off_flags >> 12) & 0xF) * 4
        flags = off_flags & 0x01FF
        if data_off < 20 or off + data_off > len(raw):
            data_off = 20

        payload_off = off + data_off
        payload_len = max(0, min(len(raw) - payload_off, seg_len - data_off))

        # Relative Sequence / Ack calculation per direction
        dir_key = (pkt.src, sport, pkt.dst, dport)
        rev_key = (pkt.dst, dport, pkt.src, sport)
        if dir_key not in self._tcp_isn:
            self._tcp_isn[dir_key] = seq
        rel_seq = (seq - self._tcp_isn[dir_key]) & 0xFFFFFFFF
        rel_ack = (ack - self._tcp_isn[rev_key]) & 0xFFFFFFFF if (flags & 0x0010) and rev_key in self._tcp_isn else 0

        # Verify TCP checksum with IPv4/IPv6 pseudo-header
        tcp_segment = raw[off : off + seg_len]
        if is_ipv6:
            pseudo = pseudo_ip_bytes + struct.pack("!IBBBB", seg_len, 0, 0, 0, 6)
        else:
            pseudo = pseudo_ip_bytes + struct.pack("!BBH", 0, 6, seg_len)
        chk_valid = (_ones_complement_checksum(pseudo + tcp_segment) == 0)

        active_flag_names: List[str] = []
        flag_children: List[FieldNode] = []
        for bit, fname, fkey in TCP_FLAG_BITS:
            is_set = bool(flags & bit)
            if is_set:
                active_flag_names.append(fname)
            pkt.add_field_index(fkey, is_set)
            flag_children.append(
                FieldNode(fkey, f"{fname}: {'Set' if is_set else 'Not set'}", is_set, off + 12, 2, 4)
            )
        flags_str = ", ".join(active_flag_names) if active_flag_names else "NONE"

        pkt.src_port = sport
        pkt.dst_port = dport
        pkt.tcp_seq = seq
        pkt.tcp_ack = ack
        pkt.tcp_flags = flags
        pkt.tcp_flags_str = flags_str
        pkt.tcp_window = window
        pkt.tcp_payload_offset = payload_off
        pkt.tcp_payload_len = payload_len

        pkt.add_field_index("tcp.srcport", sport)
        pkt.add_field_index("tcp.dstport", dport)
        pkt.add_field_index("tcp.port", sport)
        pkt.add_field_index("tcp.port", dport)
        pkt.add_field_index("tcp.seq", rel_seq)
        pkt.add_field_index("tcp.seq_raw", seq)
        pkt.add_field_index("tcp.ack", rel_ack)
        pkt.add_field_index("tcp.len", payload_len)
        pkt.add_field_index("tcp.window_size", window)
        pkt.add_field_index("tcp.flags", f"0x{flags:03x}")

        # Parse TCP Options (MSS, Window Scale, SACK Permitted, Timestamps)
        opt_nodes: List[FieldNode] = []
        opt_pos = off + 20
        opt_end = off + data_off
        while opt_pos < opt_end:
            kind = raw[opt_pos]
            if kind == 0:
                opt_nodes.append(FieldNode("tcp.options.eol", "End of Option List (EOL)", 0, opt_pos, 1, 4))
                break
            if kind == 1:
                opt_nodes.append(FieldNode("tcp.options.nop", "No-Operation (NOP)", 1, opt_pos, 1, 4))
                opt_pos += 1
                continue
            if opt_pos + 1 >= opt_end:
                break
            olen = raw[opt_pos + 1]
            if olen < 2 or opt_pos + olen > opt_end:
                break
            if kind == 2 and olen == 4:
                mss = struct.unpack_from("!H", raw, opt_pos + 2)[0]
                opt_nodes.append(FieldNode("tcp.options.mss", f"Maximum Segment Size: {mss} bytes", mss, opt_pos, 4, 4))
            elif kind == 3 and olen == 3:
                wscale = raw[opt_pos + 2]
                opt_nodes.append(FieldNode("tcp.options.wscale", f"Window Scale: {wscale} (multiply by {1 << wscale})", wscale, opt_pos, 3, 4))
            elif kind == 4 and olen == 2:
                opt_nodes.append(FieldNode("tcp.options.sack_perm", "SACK Permitted", True, opt_pos, 2, 4))
            elif kind == 8 and olen == 10:
                tsval, tsecr = struct.unpack_from("!II", raw, opt_pos + 2)
                opt_nodes.append(FieldNode("tcp.options.timestamp", f"Timestamps: TSval={tsval}, TSecr={tsecr}", f"{tsval}/{tsecr}", opt_pos, 10, 4))
            else:
                opt_nodes.append(FieldNode(f"tcp.options.kind_{kind}", f"TCP Option Kind {kind} (len={olen})", kind, opt_pos, olen, 4))
            opt_pos += olen

        tcp_fields = [
            FieldNode("tcp.srcport", f"Source Port: {sport}", sport, off, 2, 4),
            FieldNode("tcp.dstport", f"Destination Port: {dport}", dport, off + 2, 2, 4),
            FieldNode("tcp.seq", f"Sequence Number: {rel_seq} (relative) [raw: {seq}]", rel_seq, off + 4, 4, 4),
            FieldNode("tcp.ack", f"Acknowledgment Number: {rel_ack} (relative) [raw: {ack}]", rel_ack, off + 8, 4, 4),
            FieldNode("tcp.hdr_len", f"Header Length: {data_off} bytes ({data_off // 4})", data_off, off + 12, 1, 4),
            FieldNode("tcp.flags", f"Flags: 0x{flags:03x} ({flags_str})", f"0x{flags:03x}", off + 12, 2, 4, children=flag_children),
            FieldNode("tcp.window_size", f"Window: {window}", window, off + 14, 2, 4, severity="warn" if window == 0 and not (flags & 0x0004) else None),
            FieldNode("tcp.checksum", f"Checksum: 0x{checksum:04x} [{'correct' if chk_valid else 'unverified / offload'}]", f"0x{checksum:04x}", off + 16, 2, 4),
            FieldNode("tcp.urgent_pointer", f"Urgent Pointer: {urg_ptr}", urg_ptr, off + 18, 2, 4),
            FieldNode("tcp.len", f"TCP Segment Payload Length: {payload_len}", payload_len, payload_off if payload_len > 0 else off, payload_len, 4),
        ]
        if opt_nodes:
            tcp_fields.append(FieldNode("tcp.options", f"Options: ({data_off - 20} bytes)", data_off - 20, off + 20, data_off - 20, 4, children=opt_nodes))

        pkt.layers.append(
            LayerNode(
                protocol="TCP",
                title=f"Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Seq: {rel_seq}, Ack: {rel_ack}, Len: {payload_len}",
                osi_layer=4,
                offset=off,
                length=data_off,
                fields=tcp_fields,
            )
        )

        pkt.info = f"{sport} → {dport} [{flags_str}] Seq={rel_seq} Ack={rel_ack} Win={window} Len={payload_len}"

        # Dispatch Application Layer via DPI
        if payload_len > 0:
            payload = raw[payload_off : payload_off + payload_len]
            app_proto, dpi_method = classify_tcp_app(payload, sport, dport)
            pkt.dpi_method = dpi_method
            if app_proto:
                self._dissect_tcp_app(pkt, raw, payload_off, payload_len, app_proto, dpi_method)

    def _dissect_tcp_app(
        self, pkt: PacketRecord, raw: bytes, off: int, length: int, app_proto: str, dpi_method: str
    ) -> None:
        payload = raw[off : off + length]
        if app_proto == "HTTP":
            self._dissect_http(pkt, raw, off, length, dpi_method)
        elif app_proto == "HTTP2":
            pkt.protocol = "HTTP2"
            pkt.protocols.append("http2")
            pkt.osi_top_layer = 7
            pkt.info = "HTTP/2 Magic Connection Preface"
            pkt.layers.append(
                LayerNode(
                    protocol="HTTP2",
                    title="HyperText Transfer Protocol 2",
                    osi_layer=7,
                    offset=off,
                    length=length,
                    fields=[
                        FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, min(24, length), 7),
                        FieldNode("http2.magic", "Magic: PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n", "HTTP/2", off, min(24, length), 7),
                    ],
                )
            )
        elif app_proto == "TLS":
            layer, proto_label, info, idx = parse_tls(raw, off, length)
            layer.fields.insert(0, FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, min(5, length), 6))
            pkt.layers.append(layer)
            pkt.protocol = proto_label
            pkt.protocols.append("tls")
            pkt.osi_top_layer = 6
            pkt.info = info
            for k, vals in idx.items():
                for v in vals:
                    pkt.add_field_index(k, v)
        elif app_proto == "DNS" and length >= 14:
            layer, info, idx = parse_dns(raw, off + 2, length - 2, is_mdns=False)
            pkt.layers.append(layer)
            pkt.protocol = "DNS"
            pkt.protocols.append("dns")
            pkt.osi_top_layer = 7
            pkt.info = info
            for k, vals in idx.items():
                for v in vals:
                    pkt.add_field_index(k, v)
        elif app_proto == "SSH":
            pkt.protocol = "SSH"
            pkt.protocols.append("ssh")
            pkt.osi_top_layer = 7
            text = payload[:128].decode("ascii", errors="ignore").strip()
            if payload.startswith(b"SSH-"):
                banner = text.splitlines()[0]
                pkt.info = f"Protocol ({banner})"
                pkt.add_field_index("ssh.protocol", banner)
                fields = [
                    FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, length, 7),
                    FieldNode("ssh.protocol", f"Protocol Banner: {banner}", banner, off, len(banner), 7),
                ]
            else:
                pkt.info = f"Encrypted SSH Packet (len={length})"
                fields = [
                    FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, length, 7),
                    FieldNode("ssh.encrypted", f"Encrypted Packet Data ({length} bytes)", length, off, length, 7),
                ]
            pkt.layers.append(LayerNode("SSH", "SSH Protocol", 7, off, length, fields))
        elif app_proto in ("FTP", "SMTP"):
            pkt.protocol = app_proto
            pkt.protocols.append(app_proto.lower())
            pkt.osi_top_layer = 7
            line = payload.decode("utf-8", errors="replace").splitlines()[0] if payload else ""
            pkt.info = f"{app_proto}: {line[:120]}"
            pkt.add_field_index(f"{app_proto.lower()}.command", line)
            pkt.layers.append(
                LayerNode(
                    protocol=app_proto,
                    title=f"{'File Transfer Protocol' if app_proto == 'FTP' else 'Simple Mail Transfer Protocol'}",
                    osi_layer=7,
                    offset=off,
                    length=length,
                    fields=[
                        FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, length, 7),
                        FieldNode(f"{app_proto.lower()}.line", f"Command / Reply: {line}", line, off, min(len(line), length), 7),
                    ],
                )
            )
        elif app_proto == "WEBSOCKET":
            pkt.protocol = "WebSocket"
            pkt.protocols.append("websocket")
            pkt.osi_top_layer = 7
            b0, b1 = payload[0], payload[1]
            opcode = b0 & 0xF
            masked = bool(b1 & 0x80)
            plen = b1 & 0x7F
            op_names = {1: "Text", 2: "Binary", 8: "Close", 9: "Ping", 10: "Pong"}
            ws_data = payload[2 + (4 if masked else 0) : 2 + (4 if masked else 0) + plen]
            if masked and len(payload) >= 6:
                mkey = payload[2:6]
                ws_data = bytes(b ^ mkey[i % 4] for i, b in enumerate(ws_data))
            preview = ws_data.decode("utf-8", errors="replace")[:100]
            pkt.info = f"WebSocket {op_names.get(opcode, opcode)} [{ 'Masked' if masked else 'Unmasked' }] {preview}"
            pkt.layers.append(
                LayerNode(
                    protocol="WebSocket",
                    title=f"WebSocket ({op_names.get(opcode, opcode)})",
                    osi_layer=7,
                    offset=off,
                    length=length,
                    fields=[
                        FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, 2, 7),
                        FieldNode("websocket.opcode", f"Opcode: {op_names.get(opcode, opcode)} ({opcode})", opcode, off, 1, 7),
                        FieldNode("websocket.masked", f"Masked: {masked}", masked, off + 1, 1, 7),
                        FieldNode("websocket.payload", f"Unmasked Payload: {preview}", preview, off + 2 + (4 if masked else 0), plen, 7),
                    ],
                )
            )
        elif app_proto in ("REDIS", "MYSQL"):
            pkt.protocol = app_proto
            pkt.protocols.append(app_proto.lower())
            pkt.osi_top_layer = 7
            preview = payload[:100].decode("utf-8", errors="replace").replace("\r\n", " ")
            pkt.info = f"{app_proto}: {preview}"
            pkt.layers.append(
                LayerNode(
                    protocol=app_proto,
                    title=f"{app_proto} Application Protocol",
                    osi_layer=7,
                    offset=off,
                    length=length,
                    fields=[
                        FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, length, 7),
                        FieldNode(f"{app_proto.lower()}.payload", f"Payload: {preview}", preview, off, length, 7),
                    ],
                )
            )

    def _dissect_http(self, pkt: PacketRecord, raw: bytes, off: int, length: int, dpi_method: str) -> None:
        pkt.protocol = "HTTP"
        pkt.protocols.append("http")
        pkt.osi_top_layer = 7
        payload = raw[off : off + length]

        sep_idx = payload.find(b"\r\n\r\n")
        sep_len = 4
        if sep_idx == -1:
            sep_idx = payload.find(b"\n\n")
            sep_len = 2

        head_bytes = payload[:sep_idx] if sep_idx != -1 else payload
        body_bytes = payload[sep_idx + sep_len :] if sep_idx != -1 else b""
        lines = head_bytes.decode("utf-8", errors="replace").splitlines()
        if not lines:
            pkt.info = f"HTTP Continuation ({length} bytes)"
            return

        first_line = lines[0].strip()
        fields: List[FieldNode] = [
            FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, min(len(first_line), length), 7)
        ]

        is_response = first_line.startswith("HTTP/")
        if is_response:
            parts = first_line.split(" ", 2)
            ver = parts[0] if len(parts) > 0 else "HTTP/1.1"
            code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            phrase = parts[2] if len(parts) > 2 else ""
            pkt.info = f"{ver} {code} {phrase}".strip()
            pkt.add_field_index("http.response.code", code)
            pkt.add_field_index("http.response.phrase", phrase)
            fields.append(FieldNode("http.response.line", f"Status Line: {first_line}", first_line, off, len(first_line), 7))
            fields.append(FieldNode("http.response.code", f"Status Code: {code}", code, off + len(ver) + 1, 3, 7))
        else:
            sp1 = first_line.find(" ")
            sp2 = first_line.rfind(" HTTP/")
            if sp1 != -1 and sp2 > sp1:
                method = first_line[:sp1]
                uri = first_line[sp1 + 1 : sp2]
                ver = first_line[sp2 + 1 :]
            else:
                parts = first_line.split(" ")
                method = parts[0] if len(parts) > 0 else "GET"
                uri = parts[1] if len(parts) > 1 else "/"
                ver = parts[2] if len(parts) > 2 else "HTTP/1.1"
            pkt.info = f"{method} {uri} {ver}"
            pkt.add_field_index("http.request.method", method)
            pkt.add_field_index("http.request.uri", uri)
            fields.append(FieldNode("http.request.line", f"Request Line: {first_line}", first_line, off, len(first_line), 7))
            fields.append(FieldNode("http.request.method", f"Request Method: {method}", method, off, len(method), 7))
            fields.append(FieldNode("http.request.uri", f"Request URI: {uri}", uri, off + len(method) + 1, len(uri), 7))

        # Parse HTTP Headers with byte offsets
        cursor = off + len(lines[0]) + (2 if b"\r\n" in payload[: len(lines[0]) + 4] else 1)
        for line in lines[1:]:
            line_len = len(line.encode("utf-8", errors="ignore"))
            if ":" in line:
                hname, hval = line.split(":", 1)
                hname_clean = hname.strip()
                hval_clean = hval.strip()
                hkey_l = hname_clean.lower()
                fkey = f"http.{hkey_l.replace('-', '_')}"
                sev = None
                extra_children: List[FieldNode] = []

                if hkey_l == "host":
                    pkt.add_field_index("http.host", hval_clean)
                    if not is_response:
                        pkt.info = f"{pkt.info} (Host: {hval_clean})"
                elif hkey_l == "user-agent":
                    pkt.add_field_index("http.user_agent", hval_clean)
                elif hkey_l == "content-type":
                    pkt.add_field_index("http.content_type", hval_clean)
                elif hkey_l == "cookie":
                    pkt.add_field_index("http.cookie", hval_clean)
                elif hkey_l == "authorization":
                    pkt.add_field_index("http.authorization", hval_clean)
                    sev = "warn"
                    if hval_clean.lower().startswith("basic "):
                        try:
                            dec = base64.b64decode(hval_clean[6:].strip()).decode("utf-8", errors="replace")
                            extra_children.append(
                                FieldNode("http.authbasic", f"Decoded Basic Credentials: {dec}", dec, cursor, line_len, 7, severity="error")
                            )
                        except Exception:
                            pass

                fields.append(
                    FieldNode(fkey, f"{hname_clean}: {hval_clean}", hval_clean, cursor, min(line_len, off + length - cursor), 7, severity=sev, children=extra_children)
                )
            cursor += line_len + 2

        if body_bytes:
            body_off = off + sep_idx + sep_len
            body_preview = body_bytes[:512].decode("utf-8", errors="replace")
            pkt.add_field_index("http.file_data", body_preview)
            fields.append(
                FieldNode("http.file_data", f"Message Body ({len(body_bytes)} bytes): {body_preview[:160]}", body_preview, body_off, len(body_bytes), 7)
            )

        pkt.layers.append(
            LayerNode(
                protocol="HTTP",
                title=f"Hypertext Transfer Protocol ({'Response' if is_response else 'Request'})",
                osi_layer=7,
                offset=off,
                length=length,
                fields=fields,
            )
        )

    def _dissect_udp(self, pkt: PacketRecord, raw: bytes, off: int, dgram_len: int) -> None:
        pkt.protocol = "UDP"
        pkt.protocols.append("udp")
        pkt.osi_top_layer = 4
        if dgram_len < 8 or off + 8 > len(raw):
            pkt.info = "Truncated UDP datagram"
            return

        sport, dport, ulen, checksum = struct.unpack_from("!HHHH", raw, off)
        payload_off = off + 8
        payload_len = max(0, min(len(raw) - payload_off, ulen - 8)) if ulen >= 8 else max(0, len(raw) - payload_off)

        pkt.src_port = sport
        pkt.dst_port = dport
        pkt.add_field_index("udp.srcport", sport)
        pkt.add_field_index("udp.dstport", dport)
        pkt.add_field_index("udp.port", sport)
        pkt.add_field_index("udp.port", dport)
        pkt.add_field_index("udp.length", ulen)

        pkt.layers.append(
            LayerNode(
                protocol="UDP",
                title=f"User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}, Len: {payload_len}",
                osi_layer=4,
                offset=off,
                length=8,
                fields=[
                    FieldNode("udp.srcport", f"Source Port: {sport}", sport, off, 2, 4),
                    FieldNode("udp.dstport", f"Destination Port: {dport}", dport, off + 2, 2, 4),
                    FieldNode("udp.length", f"Length: {ulen}", ulen, off + 4, 2, 4),
                    FieldNode("udp.checksum", f"Checksum: 0x{checksum:04x}", f"0x{checksum:04x}", off + 6, 2, 4),
                ],
            )
        )

        pkt.info = f"{sport} → {dport} Len={payload_len}"

        if payload_len > 0:
            payload = raw[payload_off : payload_off + payload_len]
            app_proto, dpi_method = classify_udp_app(payload, sport, dport)
            pkt.dpi_method = dpi_method
            if app_proto in ("DNS", "MDNS"):
                layer, info, idx = parse_dns(raw, payload_off, payload_len, is_mdns=(app_proto == "MDNS"))
                layer.fields.insert(0, FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, payload_off, min(12, payload_len), 7))
                pkt.layers.append(layer)
                pkt.protocol = "mDNS" if app_proto == "MDNS" else "DNS"
                pkt.protocols.append("dns")
                if app_proto == "MDNS":
                    pkt.protocols.append("mdns")
                pkt.osi_top_layer = 7
                pkt.info = info
                for k, vals in idx.items():
                    for v in vals:
                        pkt.add_field_index(k, v)
            elif app_proto == "DHCP":
                self._dissect_dhcp(pkt, raw, payload_off, payload_len, dpi_method)
            elif app_proto == "QUIC":
                self._dissect_quic(pkt, raw, payload_off, payload_len, dpi_method)
            elif app_proto == "NTP":
                pkt.protocol = "NTP"
                pkt.protocols.append("ntp")
                pkt.osi_top_layer = 7
                b0 = payload[0]
                ver = (b0 >> 3) & 0x7
                mode = b0 & 0x7
                mode_names = {3: "client", 4: "server", 5: "broadcast"}
                pkt.info = f"NTP Version {ver}, {mode_names.get(mode, f'mode {mode}')}"
                pkt.layers.append(
                    LayerNode(
                        protocol="NTP",
                        title=f"Network Time Protocol (v{ver})",
                        osi_layer=7,
                        offset=payload_off,
                        length=payload_len,
                        fields=[
                            FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, payload_off, 1, 7),
                            FieldNode("ntp.version", f"Version: {ver}", ver, payload_off, 1, 7),
                            FieldNode("ntp.mode", f"Mode: {mode_names.get(mode, mode)} ({mode})", mode, payload_off, 1, 7),
                        ],
                    )
                )
            elif app_proto == "SSDP":
                pkt.protocol = "SSDP"
                pkt.protocols.append("ssdp")
                pkt.osi_top_layer = 7
                first = payload.decode("utf-8", errors="replace").splitlines()[0]
                pkt.info = first[:120]
                pkt.layers.append(
                    LayerNode(
                        protocol="SSDP",
                        title="Simple Service Discovery Protocol",
                        osi_layer=7,
                        offset=payload_off,
                        length=payload_len,
                        fields=[
                            FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, payload_off, len(first), 7),
                            FieldNode("ssdp.line", f"Request/Notify: {first}", first, payload_off, len(first), 7),
                        ],
                    )
                )
            elif app_proto == "STUN":
                pkt.protocol = "STUN"
                pkt.protocols.append("stun")
                pkt.osi_top_layer = 7
                mtype = struct.unpack_from("!H", payload, 0)[0]
                pkt.info = f"STUN Message Type 0x{mtype:04x} (Len={payload_len})"
                pkt.layers.append(
                    LayerNode(
                        protocol="STUN",
                        title="Session Traversal Utilities for NAT (STUN)",
                        osi_layer=7,
                        offset=payload_off,
                        length=payload_len,
                        fields=[
                            FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, payload_off + 4, 4, 7),
                            FieldNode("stun.type", f"Message Type: 0x{mtype:04x}", f"0x{mtype:04x}", payload_off, 2, 7),
                        ],
                    )
                )

    def _dissect_dhcp(self, pkt: PacketRecord, raw: bytes, off: int, length: int, dpi_method: str) -> None:
        pkt.protocol = "DHCP"
        pkt.protocols.append("dhcp")
        pkt.osi_top_layer = 7
        op = raw[off]
        xid = struct.unpack_from("!I", raw, off + 4)[0]
        yiaddr = str(ipaddress.IPv4Address(raw[off + 16 : off + 20]))
        chaddr = format_mac(raw[off + 28 : off + 34])

        msg_type_name = "Request" if op == 1 else "Reply"
        hostname = ""
        opt_fields: List[FieldNode] = []
        pos = off + 240
        end = min(len(raw), off + length)
        while pos < end:
            code = raw[pos]
            if code == 255:
                break
            if code == 0:
                pos += 1
                continue
            if pos + 1 >= end:
                break
            olen = raw[pos + 1]
            val = raw[pos + 2 : pos + 2 + olen]
            if code == 53 and olen >= 1:
                msg_type_name = DHCP_MSG_TYPES.get(val[0], str(val[0]))
                opt_fields.append(FieldNode("dhcp.option.dhcp", f"Option (53) DHCP Message Type: {msg_type_name}", msg_type_name, pos, 2 + olen, 7))
            elif code == 12:
                hostname = val.decode("utf-8", errors="replace")
                opt_fields.append(FieldNode("dhcp.option.hostname", f"Option (12) Host Name: {hostname}", hostname, pos, 2 + olen, 7))
            elif code == 50 and olen == 4:
                req_ip = str(ipaddress.IPv4Address(val))
                opt_fields.append(FieldNode("dhcp.option.requested_ip", f"Option (50) Requested IP: {req_ip}", req_ip, pos, 2 + olen, 7))
            elif code == 51 and olen == 4:
                lease = struct.unpack_from("!I", val, 0)[0]
                opt_fields.append(FieldNode("dhcp.option.lease_time", f"Option (51) Lease Time: {lease}s", lease, pos, 2 + olen, 7))
            pos += 2 + olen

        pkt.info = f"DHCP {msg_type_name} - Transaction ID 0x{xid:08x}" + (f" ({hostname})" if hostname else "")
        pkt.add_field_index("dhcp.type", msg_type_name)
        fields = [
            FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off + 236, 4, 7),
            FieldNode("dhcp.id", f"Transaction ID: 0x{xid:08x}", f"0x{xid:08x}", off + 4, 4, 7),
            FieldNode("dhcp.ip.your", f"Your (client) IP: {yiaddr}", yiaddr, off + 16, 4, 7),
            FieldNode("dhcp.hw.mac_addr", f"Client MAC: {chaddr}", chaddr, off + 28, 6, 7),
        ] + opt_fields
        pkt.layers.append(LayerNode("DHCP", f"Dynamic Host Configuration Protocol ({msg_type_name})", 7, off, length, fields))

    def _dissect_quic(self, pkt: PacketRecord, raw: bytes, off: int, length: int, dpi_method: str) -> None:
        pkt.protocol = "QUIC"
        pkt.protocols.append("quic")
        pkt.osi_top_layer = 7
        b0 = raw[off]
        is_long = bool(b0 & 0x80)
        fields = [FieldNode("dpi.method", f"Identification Method: {dpi_method}", dpi_method, off, min(6, length), 7)]
        if is_long and length >= 7:
            ltype = (b0 >> 4) & 0x3
            ltype_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
            qver = struct.unpack_from("!I", raw, off + 1)[0]
            ver_name = "RFC 9000 v1" if qver == 1 else ("v2" if qver == 0x6B3343CF else f"0x{qver:08x}")
            dcid_len = raw[off + 5]
            dcid = raw[off + 6 : off + 6 + dcid_len].hex() if off + 6 + dcid_len <= off + length else ""
            pkt.info = f"QUIC {ltype_names.get(ltype, ltype)}, Version={ver_name}, DCID={dcid[:16]}"
            pkt.add_field_index("quic.version", ver_name)
            pkt.add_field_index("quic.dcid", dcid)
            fields.extend([
                FieldNode("quic.header_form", "Header Form: Long Header (1)", "Long", off, 1, 7),
                FieldNode("quic.long.packet_type", f"Packet Type: {ltype_names.get(ltype, ltype)}", ltype_names.get(ltype, str(ltype)), off, 1, 7),
                FieldNode("quic.version", f"Version: {ver_name} (0x{qver:08x})", ver_name, off + 1, 4, 7),
                FieldNode("quic.dcid", f"Destination Connection ID ({dcid_len}B): {dcid}", dcid, off + 6, dcid_len, 7),
            ])
        else:
            pkt.info = f"QUIC Protected Payload (Short Header, {length} bytes)"
            fields.append(FieldNode("quic.header_form", "Header Form: Short Header (0)", "Short", off, 1, 7))
        pkt.layers.append(LayerNode("QUIC", "QUIC IETF Transport Protocol", 7, off, length, fields))
