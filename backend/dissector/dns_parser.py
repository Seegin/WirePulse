"""
RFC 1035 / mDNS Binary Dissector with pointer-compression decompression
and exact byte-offset tracking for WirePulse.
"""
from __future__ import annotations

import ipaddress
import struct
from typing import Any, Dict, List, Tuple

from .models import FieldNode, LayerNode

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}

DNS_RCODES = {
    0: "No error",
    1: "Format error",
    2: "Server failure",
    3: "No such name (NXDOMAIN)",
    4: "Not implemented",
    5: "Refused",
}


def decode_dns_name(buf: bytes, start: int, dns_base: int) -> Tuple[str, int]:
    """
    Decode a DNS domain name starting at `start` (relative to `buf`, where DNS message
    begins at `dns_base`). Returns (name_str, next_offset_in_buf).
    Cycle-safe against malicious pointer loops.
    """
    labels: List[str] = []
    pos = start
    end_pos = start
    jumped = False
    visited = set()
    limit = len(buf)

    while pos < limit:
        if pos in visited:
            labels.append("<loop>")
            break
        visited.add(pos)

        length = buf[pos]
        if length == 0:
            if not jumped:
                end_pos = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= limit:
                if not jumped:
                    end_pos = limit
                break
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end_pos = pos + 2
                jumped = True
            target = dns_base + ptr
            if target >= limit:
                break
            pos = target
        else:
            pos += 1
            if pos + length > limit:
                labels.append(buf[pos:limit].decode("utf-8", errors="replace"))
                if not jumped:
                    end_pos = limit
                break
            labels.append(buf[pos : pos + length].decode("utf-8", errors="replace"))
            pos += length
            if not jumped:
                end_pos = pos

    name = ".".join(labels) if labels else "<Root>"
    return name, max(end_pos, start + 1)


def parse_dns(raw: bytes, offset: int, length: int, is_mdns: bool = False) -> Tuple[LayerNode, str, Dict[str, List[Any]]]:
    """Dissect DNS / mDNS message at raw[offset : offset + length]."""
    idx: Dict[str, List[Any]] = {}
    proto_name = "mDNS" if is_mdns else "DNS"
    fields: List[FieldNode] = []

    if length < 12 or offset + 12 > len(raw):
        layer = LayerNode(
            protocol=proto_name,
            title=f"{'Multicast ' if is_mdns else ''}Domain Name System (Malformed)",
            osi_layer=7,
            offset=offset,
            length=length,
            fields=fields,
        )
        return layer, "Malformed DNS", idx

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", raw, offset)
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF

    is_resp = qr == 1
    idx.setdefault("dns.id", []).append(f"0x{txid:04x}")
    idx.setdefault("dns.flags.response", []).append(is_resp)
    idx.setdefault("dns.flags.rcode", []).append(rcode)
    idx.setdefault("dns.count.queries", []).append(qdcount)
    idx.setdefault("dns.count.answers", []).append(ancount)

    fields.append(FieldNode("dns.id", f"Transaction ID: 0x{txid:04x}", f"0x{txid:04x}", offset, 2, 7))
    flag_children = [
        FieldNode("dns.flags.response", f"Response: {'Message is a response' if is_resp else 'Message is a query'}", is_resp, offset + 2, 2, 7),
        FieldNode("dns.flags.opcode", f"Opcode: {opcode}", opcode, offset + 2, 2, 7),
        FieldNode("dns.flags.authoritative", f"Authoritative: {aa}", bool(aa), offset + 2, 2, 7),
        FieldNode("dns.flags.truncated", f"Truncated: {tc}", bool(tc), offset + 2, 2, 7),
        FieldNode("dns.flags.recdesired", f"Recursion desired: {rd}", bool(rd), offset + 2, 2, 7),
        FieldNode("dns.flags.recavail", f"Recursion available: {ra}", bool(ra), offset + 2, 2, 7),
        FieldNode(
            "dns.flags.rcode",
            f"Reply code: {DNS_RCODES.get(rcode, str(rcode))} ({rcode})",
            rcode,
            offset + 2,
            2,
            7,
            severity="warn" if rcode != 0 else None,
        ),
    ]
    fields.append(FieldNode("dns.flags", f"Flags: 0x{flags:04x} ({'Response' if is_resp else 'Query'}, {DNS_RCODES.get(rcode, rcode)})", f"0x{flags:04x}", offset + 2, 2, 7, children=flag_children))
    fields.append(FieldNode("dns.count.queries", f"Questions: {qdcount}", qdcount, offset + 4, 2, 7))
    fields.append(FieldNode("dns.count.answers", f"Answer RRs: {ancount}", ancount, offset + 6, 2, 7))
    fields.append(FieldNode("dns.count.auth_rr", f"Authority RRs: {nscount}", nscount, offset + 8, 2, 7))
    fields.append(FieldNode("dns.count.add_rr", f"Additional RRs: {arcount}", arcount, offset + 10, 2, 7))

    pos = offset + 12
    end_limit = min(len(raw), offset + length)
    q_summaries: List[str] = []
    a_summaries: List[str] = []

    # Parse Questions
    q_nodes: List[FieldNode] = []
    q_start = pos
    for _ in range(min(qdcount, 32)):
        if pos >= end_limit:
            break
        item_start = pos
        qname, next_pos = decode_dns_name(raw, pos, offset)
        if next_pos + 4 > end_limit:
            pos = end_limit
            break
        qtype, qclass = struct.unpack_from("!HH", raw, next_pos)
        qtype_str = DNS_TYPES.get(qtype, f"TYPE{qtype}")
        pos = next_pos + 4
        q_summaries.append(f"{qtype_str} {qname}")
        idx.setdefault("dns.qry.name", []).append(qname)
        idx.setdefault("dns.qry.type", []).append(qtype_str)
        q_nodes.append(
            FieldNode(
                "dns.qry",
                f"{qname}: type {qtype_str}, class {'IN' if (qclass & 0x7FFF) == 1 else qclass}",
                qname,
                item_start,
                pos - item_start,
                7,
                children=[
                    FieldNode("dns.qry.name", f"Name: {qname}", qname, item_start, next_pos - item_start, 7),
                    FieldNode("dns.qry.type", f"Type: {qtype_str} ({qtype})", qtype_str, next_pos, 2, 7),
                    FieldNode("dns.qry.class", f"Class: 0x{qclass:04x}", qclass, next_pos + 2, 2, 7),
                ],
            )
        )
    if q_nodes:
        fields.append(FieldNode("dns.queries", f"Queries ({len(q_nodes)})", len(q_nodes), q_start, pos - q_start, 7, children=q_nodes))

    # Parse Answers / Authority / Additional
    def parse_rr_section(count: int, title: str, section_key: str, collect_summary: bool) -> None:
        nonlocal pos
        rr_nodes: List[FieldNode] = []
        sec_start = pos
        for _ in range(min(count, 32)):
            if pos >= end_limit:
                break
            rr_start = pos
            rname, next_pos = decode_dns_name(raw, pos, offset)
            if next_pos + 10 > end_limit:
                pos = end_limit
                break
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", raw, next_pos)
            rdata_off = next_pos + 10
            if rdata_off + rdlen > end_limit:
                pos = end_limit
                break
            rdata = raw[rdata_off : rdata_off + rdlen]
            pos = rdata_off + rdlen
            rtype_str = DNS_TYPES.get(rtype, f"TYPE{rtype}")

            val_str = rdata.hex()
            if rtype == 1 and rdlen == 4:
                val_str = str(ipaddress.IPv4Address(rdata))
                idx.setdefault("dns.a", []).append(val_str)
            elif rtype == 28 and rdlen == 16:
                val_str = str(ipaddress.IPv6Address(rdata))
                idx.setdefault("dns.aaaa", []).append(val_str)
            elif rtype in (2, 5, 12):
                val_str, _ = decode_dns_name(raw, rdata_off, offset)
                if rtype == 5:
                    idx.setdefault("dns.cname", []).append(val_str)
            elif rtype == 15 and rdlen >= 3:
                pref = struct.unpack_from("!H", rdata, 0)[0]
                exch, _ = decode_dns_name(raw, rdata_off + 2, offset)
                val_str = f"pref={pref} {exch}"
            elif rtype == 16 and rdlen >= 1:
                txts = []
                tp = 0
                while tp < rdlen:
                    tlen = rdata[tp]
                    tp += 1
                    txts.append(rdata[tp : tp + tlen].decode("utf-8", errors="replace"))
                    tp += tlen
                val_str = " ".join(txts)
                idx.setdefault("dns.txt", []).append(val_str)

            idx.setdefault("dns.resp.name", []).append(rname)
            if collect_summary:
                a_summaries.append(f"{rtype_str} {val_str}")
            rr_nodes.append(
                FieldNode(
                    f"{section_key}.rr",
                    f"{rname}: type {rtype_str}, TTL {ttl}, {val_str}",
                    val_str,
                    rr_start,
                    pos - rr_start,
                    7,
                    children=[
                        FieldNode("dns.resp.name", f"Name: {rname}", rname, rr_start, next_pos - rr_start, 7),
                        FieldNode("dns.resp.type", f"Type: {rtype_str} ({rtype})", rtype_str, next_pos, 2, 7),
                        FieldNode("dns.resp.ttl", f"Time to live: {ttl}s", ttl, next_pos + 4, 4, 7),
                        FieldNode("dns.resp.data", f"Data ({rdlen} bytes): {val_str}", val_str, rdata_off, rdlen, 7),
                    ],
                )
            )
        if rr_nodes:
            fields.append(FieldNode(section_key, f"{title} ({len(rr_nodes)})", len(rr_nodes), sec_start, pos - sec_start, 7, children=rr_nodes))

    parse_rr_section(ancount, "Answers", "dns.answers", True)
    parse_rr_section(nscount, "Authoritative nameservers", "dns.authority", False)
    parse_rr_section(arcount, "Additional records", "dns.additional", False)

    if is_resp:
        q_part = q_summaries[0] if q_summaries else ""
        if rcode != 0:
            info = f"Standard query response 0x{txid:04x} {DNS_RCODES.get(rcode, rcode)} {q_part}".strip()
        elif a_summaries:
            info = f"Standard query response 0x{txid:04x} {q_part} -> {', '.join(a_summaries[:3])}".strip()
        else:
            info = f"Standard query response 0x{txid:04x} {q_part}".strip()
    else:
        info = f"Standard query 0x{txid:04x} {', '.join(q_summaries[:2])}".strip()

    layer = LayerNode(
        protocol=proto_name,
        title=f"{'Multicast ' if is_mdns else ''}Domain Name System ({'response' if is_resp else 'query'})",
        osi_layer=7,
        offset=offset,
        length=length,
        fields=fields,
    )
    return layer, info, idx
