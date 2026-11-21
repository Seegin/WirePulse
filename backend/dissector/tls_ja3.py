"""
TLS 1.0 - 1.3 Dissector + SNI / ALPN / Cipher Suite Decoder + JA3 & JA3S Fingerprinting.

Implements Salesforce's JA3 / JA3S specification (GREASE filtering included)
and flags deprecated TLS versions or weak cipher suites for security auditing.
"""
from __future__ import annotations

import hashlib
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import FieldNode, LayerNode

TLS_CONTENT_TYPES = {
    20: "Change Cipher Spec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat",
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

HANDSHAKE_TYPES = {
    0: "Hello Request",
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    8: "Encrypted Extensions",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
}

CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
}

WEAK_CIPHERS = {0x0000, 0x0004, 0x0005, 0x000A, 0x002F, 0x0035}

EXTENSION_NAMES = {
    0: "server_name (SNI)",
    5: "status_request (OCSP)",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation (ALPN)",
    18: "signed_certificate_timestamp",
    23: "extended_master_secret",
    27: "compress_certificate",
    35: "session_ticket",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    65281: "renegotiation_info",
}

# RFC 8701 GREASE values to exclude from JA3 calculation
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Curated sample JA3 fingerprint signatures for instant client identification
KNOWN_JA3 = {
    "773906b0efdefa24a7f2b8eb6985bf37": "Python urllib3 / requests",
    "e7d705a3286e19ea42f587b344ee6865": "Tor / Firefox ESR",
    "b32309a26951912be7dba376398abc3b": "Chrome / Chromium",
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit / Go TLS",
}


def is_tls_record(payload: bytes) -> bool:
    if len(payload) < 5:
        return False
    ctype = payload[0]
    ver = struct.unpack_from("!H", payload, 1)[0]
    rec_len = struct.unpack_from("!H", payload, 3)[0]
    if ctype not in (20, 21, 22, 23):
        return False
    if ver not in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304):
        return False
    if rec_len == 0 or rec_len > 16384 + 2048:
        return False
    return True


def parse_tls(raw: bytes, offset: int, length: int) -> Tuple[LayerNode, str, str, Dict[str, List[Any]]]:
    """
    Dissect TLS record(s) at raw[offset : offset + length].
    Returns (LayerNode, protocol_label, info_summary, fields_index).
    """
    idx: Dict[str, List[Any]] = {}
    fields: List[FieldNode] = []
    pos = offset
    end_limit = min(len(raw), offset + length)

    proto_label = "TLS"
    info_parts: List[str] = []

    record_idx = 0
    while pos + 5 <= end_limit and record_idx < 8:
        ctype = raw[pos]
        rec_ver = struct.unpack_from("!H", raw, pos + 1)[0]
        rec_len = struct.unpack_from("!H", raw, pos + 3)[0]
        if ctype not in TLS_CONTENT_TYPES or rec_ver not in TLS_VERSIONS:
            break

        ver_str = TLS_VERSIONS[rec_ver]
        ctype_str = TLS_CONTENT_TYPES[ctype]
        rec_total = min(5 + rec_len, end_limit - pos)
        idx.setdefault("tls.record.content_type", []).append(ctype)
        idx.setdefault("tls.record.version", []).append(ver_str)

        if proto_label == "TLS":
            proto_label = ver_str.replace(" ", "v")

        rec_children = [
            FieldNode("tls.record.content_type", f"Content Type: {ctype_str} ({ctype})", ctype, pos, 1, 6),
            FieldNode(
                "tls.record.version",
                f"Version: {ver_str} (0x{rec_ver:04x})",
                ver_str,
                pos + 1,
                2,
                6,
                severity="warn" if rec_ver <= 0x0302 else None,
            ),
            FieldNode("tls.record.length", f"Length: {rec_len}", rec_len, pos + 3, 2, 6),
        ]

        body_start = pos + 5
        body_end = min(pos + 5 + rec_len, end_limit)

        if ctype == 22 and body_start + 4 <= body_end:
            hs_type = raw[body_start]
            hs_len = (raw[body_start + 1] << 16) | (raw[body_start + 2] << 8) | raw[body_start + 3]
            hs_name = HANDSHAKE_TYPES.get(hs_type, f"Handshake ({hs_type})")
            idx.setdefault("tls.handshake.type", []).append(hs_type)

            hs_children: List[FieldNode] = [
                FieldNode("tls.handshake.type", f"Handshake Type: {hs_name} ({hs_type})", hs_type, body_start, 1, 6),
                FieldNode("tls.handshake.length", f"Length: {hs_len}", hs_len, body_start + 1, 3, 6),
            ]

            sni_found: Optional[str] = None
            if hs_type == 1:
                sni_found, neg_ver = _parse_client_hello(raw, body_start + 4, body_end, hs_children, idx)
                if neg_ver:
                    proto_label = neg_ver.replace(" ", "v")
                info_parts.append(f"Client Hello{f' (SNI={sni_found})' if sni_found else ''}")
            elif hs_type == 2:
                neg_ver, cipher_name = _parse_server_hello(raw, body_start + 4, body_end, hs_children, idx)
                if neg_ver:
                    proto_label = neg_ver.replace(" ", "v")
                info_parts.append(f"Server Hello{f' ({cipher_name})' if cipher_name else ''}")
            elif hs_type == 11:
                # Extract printable CN/domain hints from X.509 certificate blob
                cert_blob = raw[body_start + 4 : body_end]
                domains = sorted(set(re.findall(rb"[a-zA-Z0-9][a-zA-Z0-9.-]{2,60}\.[a-zA-Z]{2,10}", cert_blob)))
                if domains:
                    dom_list = [d.decode("ascii", errors="ignore") for d in domains[:4]]
                    hs_children.append(
                        FieldNode("tls.cert.domains", f"Observed Certificate Names: {', '.join(dom_list)}", ", ".join(dom_list), body_start + 4, body_end - (body_start + 4), 6)
                    )
                    idx.setdefault("tls.cert.subject", []).extend(dom_list)
                info_parts.append("Certificate")
            else:
                info_parts.append(hs_name)

            rec_children.append(
                FieldNode("tls.handshake", f"Handshake Protocol: {hs_name}", hs_name, body_start, body_end - body_start, 6, children=hs_children)
            )
        elif ctype == 21 and body_start + 2 <= body_end:
            level = raw[body_start]
            desc = raw[body_start + 1]
            lvl_str = "Fatal" if level == 2 else "Warning"
            rec_children.append(
                FieldNode("tls.alert", f"Alert Message: Level {lvl_str} ({level}), Description ({desc})", f"{lvl_str}:{desc}", body_start, 2, 6, severity="warn")
            )
            info_parts.append(f"Alert ({lvl_str}, desc={desc})")
        elif ctype == 23:
            info_parts.append(f"Application Data ({rec_len} bytes)")
        else:
            info_parts.append(ctype_str)

        fields.append(
            FieldNode(
                "tls.record",
                f"{ver_str} Record Layer: {ctype_str} ({rec_len} bytes)",
                ctype_str,
                pos,
                rec_total,
                6,
                children=rec_children,
            )
        )
        pos += 5 + rec_len
        record_idx += 1

    layer = LayerNode(
        protocol=proto_label,
        title=f"Transport Layer Security ({proto_label})",
        osi_layer=6,
        offset=offset,
        length=length,
        fields=fields,
    )
    info = ", ".join(info_parts) if info_parts else "TLS Record"
    return layer, proto_label, info, idx


def _parse_client_hello(
    raw: bytes, start: int, end: int, out_fields: List[FieldNode], idx: Dict[str, List[Any]]
) -> Tuple[Optional[str], Optional[str]]:
    pos = start
    if pos + 34 > end:
        return None, None
    client_ver = struct.unpack_from("!H", raw, pos)[0]
    ver_str = TLS_VERSIONS.get(client_ver, f"0x{client_ver:04x}")
    out_fields.append(FieldNode("tls.handshake.version", f"Version: {ver_str} (0x{client_ver:04x})", ver_str, pos, 2, 6))
    idx.setdefault("tls.handshake.version", []).append(ver_str)
    pos += 2

    random_hex = raw[pos : pos + 32].hex()
    out_fields.append(FieldNode("tls.handshake.random", f"Random: {random_hex[:24]}...", random_hex, pos, 32, 6))
    pos += 32

    if pos >= end:
        return None, None
    sid_len = raw[pos]
    pos += 1 + sid_len
    if pos + 2 > end:
        return None, None

    cs_len = struct.unpack_from("!H", raw, pos)[0]
    cs_off = pos + 2
    pos = cs_off + cs_len
    if pos > end:
        return None, None

    ja3_ciphers: List[str] = []
    cs_children: List[FieldNode] = []
    weak_found: List[str] = []
    for i in range(0, cs_len, 2):
        cid = struct.unpack_from("!H", raw, cs_off + i)[0]
        cname = CIPHER_SUITES.get(cid, f"0x{cid:04x}")
        if cid not in GREASE_VALUES:
            ja3_ciphers.append(str(cid))
        sev = None
        if cid in WEAK_CIPHERS:
            weak_found.append(cname)
            sev = "warn"
        cs_children.append(FieldNode("tls.handshake.ciphersuite", f"Cipher Suite: {cname} (0x{cid:04x})", cname, cs_off + i, 2, 6, severity=sev))
        idx.setdefault("tls.handshake.ciphersuite", []).append(cname)
    out_fields.append(FieldNode("tls.handshake.ciphersuites", f"Cipher Suites ({cs_len // 2} suites)", cs_len // 2, cs_off - 2, cs_len + 2, 6, children=cs_children[:24]))

    if pos >= end:
        return None, None
    comp_len = raw[pos]
    pos += 1 + comp_len

    sni_name: Optional[str] = None
    best_supported_ver: Optional[str] = None
    ja3_exts: List[str] = []
    ja3_groups: List[str] = []
    ja3_ec_fmts: List[str] = []

    if pos + 2 <= end:
        ext_total = struct.unpack_from("!H", raw, pos)[0]
        pos += 2
        ext_end = min(pos + ext_total, end)
        ext_nodes: List[FieldNode] = []
        ext_start_all = pos
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", raw, pos)
            edata_off = pos + 4
            if edata_off + elen > ext_end:
                break
            ename = EXTENSION_NAMES.get(etype, f"Extension ({etype})")
            if etype not in GREASE_VALUES:
                ja3_exts.append(str(etype))

            e_children: List[FieldNode] = []
            # SNI
            if etype == 0 and elen >= 5:
                sni_list_len = struct.unpack_from("!H", raw, edata_off)[0]
                if 2 + sni_list_len <= elen:
                    name_type = raw[edata_off + 2]
                    name_len = struct.unpack_from("!H", raw, edata_off + 3)[0]
                    if name_type == 0 and 5 + name_len <= elen:
                        sni_name = raw[edata_off + 5 : edata_off + 5 + name_len].decode("utf-8", errors="replace")
                        idx.setdefault("tls.handshake.sni", []).append(sni_name)
                        e_children.append(FieldNode("tls.handshake.sni", f"Server Name: {sni_name}", sni_name, edata_off + 5, name_len, 6))
            # Supported Groups (Elliptic Curves)
            elif etype == 10 and elen >= 2:
                glen = struct.unpack_from("!H", raw, edata_off)[0]
                for gi in range(0, min(glen, elen - 2), 2):
                    g = struct.unpack_from("!H", raw, edata_off + 2 + gi)[0]
                    if g not in GREASE_VALUES:
                        ja3_groups.append(str(g))
            # EC Point Formats
            elif etype == 11 and elen >= 1:
                flen = raw[edata_off]
                for fi in range(min(flen, elen - 1)):
                    ja3_ec_fmts.append(str(raw[edata_off + 1 + fi]))
            # ALPN
            elif etype == 16 and elen >= 3:
                alpn_list = []
                ap = edata_off + 2
                aend = edata_off + elen
                while ap < aend:
                    plen = raw[ap]
                    ap += 1
                    if ap + plen <= aend:
                        alpn_list.append(raw[ap : ap + plen].decode("ascii", errors="replace"))
                    ap += plen
                if alpn_list:
                    idx.setdefault("tls.handshake.alpn", []).extend(alpn_list)
                    e_children.append(FieldNode("tls.handshake.alpn", f"ALPN Protocols: {', '.join(alpn_list)}", ", ".join(alpn_list), edata_off, elen, 6))
            # Supported Versions
            elif etype == 43 and elen >= 3:
                vlen = raw[edata_off]
                vers = []
                for vi in range(0, min(vlen, elen - 1), 2):
                    v = struct.unpack_from("!H", raw, edata_off + 1 + vi)[0]
                    if v in TLS_VERSIONS:
                        vers.append(TLS_VERSIONS[v])
                if "TLS 1.3" in vers:
                    best_supported_ver = "TLS 1.3"
                if vers:
                    e_children.append(FieldNode("tls.handshake.supported_versions", f"Supported Versions: {', '.join(vers)}", ", ".join(vers), edata_off, elen, 6))

            ext_nodes.append(
                FieldNode(f"tls.ext.{etype}", f"Extension: {ename} (len={elen})", ename, pos, 4 + elen, 6, children=e_children)
            )
            pos = edata_off + elen

        if ext_nodes:
            out_fields.append(FieldNode("tls.extensions", f"Extensions ({len(ext_nodes)})", len(ext_nodes), ext_start_all, pos - ext_start_all, 6, children=ext_nodes))

    # Compute JA3 fingerprint: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    ja3_str = ",".join([
        str(client_ver),
        "-".join(ja3_ciphers),
        "-".join(ja3_exts),
        "-".join(ja3_groups),
        "-".join(ja3_ec_fmts),
    ])
    ja3_md5 = hashlib.md5(ja3_str.encode("ascii")).hexdigest()
    ja3_match = KNOWN_JA3.get(ja3_md5, "")
    idx.setdefault("tls.ja3", []).append(ja3_md5)
    idx.setdefault("tls.ja3_full", []).append(ja3_str)
    out_fields.append(
        FieldNode(
            "tls.ja3",
            f"JA3 Fingerprint: {ja3_md5}{f' ({ja3_match})' if ja3_match else ''}",
            ja3_md5,
            start,
            max(1, end - start),
            6,
            children=[
                FieldNode("tls.ja3_full", f"JA3 Fullstring: {ja3_str}", ja3_str, start, max(1, end - start), 6)
            ],
        )
    )
    if weak_found:
        idx.setdefault("tls.weak_cipher", []).extend(weak_found)
    return sni_name, best_supported_ver


def _parse_server_hello(
    raw: bytes, start: int, end: int, out_fields: List[FieldNode], idx: Dict[str, List[Any]]
) -> Tuple[Optional[str], Optional[str]]:
    pos = start
    if pos + 35 > end:
        return None, None
    srv_ver = struct.unpack_from("!H", raw, pos)[0]
    ver_str = TLS_VERSIONS.get(srv_ver, f"0x{srv_ver:04x}")
    out_fields.append(FieldNode("tls.handshake.version", f"Version: {ver_str} (0x{srv_ver:04x})", ver_str, pos, 2, 6))
    pos += 34  # ver + 32B random

    sid_len = raw[pos]
    pos += 1 + sid_len
    if pos + 3 > end:
        return ver_str, None

    cipher_id = struct.unpack_from("!H", raw, pos)[0]
    cipher_name = CIPHER_SUITES.get(cipher_id, f"0x{cipher_id:04x}")
    sev = "warn" if cipher_id in WEAK_CIPHERS else None
    out_fields.append(FieldNode("tls.handshake.ciphersuite", f"Selected Cipher Suite: {cipher_name} (0x{cipher_id:04x})", cipher_name, pos, 2, 6, severity=sev))
    idx.setdefault("tls.handshake.ciphersuite", []).append(cipher_name)
    if cipher_id in WEAK_CIPHERS:
        idx.setdefault("tls.weak_cipher", []).append(cipher_name)
    pos += 3  # cipher + compression

    neg_ver = ver_str
    ja3s_exts: List[str] = []
    if pos + 2 <= end:
        ext_total = struct.unpack_from("!H", raw, pos)[0]
        pos += 2
        ext_end = min(pos + ext_total, end)
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", raw, pos)
            if pos + 4 + elen > ext_end:
                break
            ja3s_exts.append(str(etype))
            if etype == 43 and elen == 2:
                v = struct.unpack_from("!H", raw, pos + 4)[0]
                if v in TLS_VERSIONS:
                    neg_ver = TLS_VERSIONS[v]
            pos += 4 + elen

    ja3s_str = f"{srv_ver},{cipher_id},{'-'.join(ja3s_exts)}"
    ja3s_md5 = hashlib.md5(ja3s_str.encode("ascii")).hexdigest()
    idx.setdefault("tls.ja3s", []).append(ja3s_md5)
    out_fields.append(FieldNode("tls.ja3s", f"JA3S Fingerprint: {ja3s_md5}", ja3s_md5, start, max(1, end - start), 6))
    return neg_ver, cipher_name
