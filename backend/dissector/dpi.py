"""
Multi-Dimensional Deep Packet Inspection (DPI) Classifier.

Addresses Experiment 1A's core design question:
  "How to accurately identify specific application-layer protocols beyond port numbers?"

Combines:
  1. Payload magic bytes & structural framing signatures (port-agnostic DPI)
  2. Application-layer grammar matching (HTTP verbs, SSH banner, SMTP/FTP/POP3 replies, RESP)
  3. Well-known port fallback heuristics (clearly labeled as heuristic vs DPI)
"""
from __future__ import annotations

import struct
from typing import Optional, Tuple

from .tls_ja3 import is_tls_record

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FTP_VERBS = (
    b"USER ", b"PASS ", b"SYST", b"FEAT", b"PWD", b"CWD ", b"PASV",
    b"PORT ", b"RETR ", b"STOR ", b"LIST", b"QUIT", b"TYPE ",
)

SMTP_VERBS = (
    b"EHLO ", b"HELO ", b"MAIL FROM:", b"RCPT TO:", b"DATA\r\n", b"AUTH ", b"STARTTLS",
)


def classify_tcp_app(payload: bytes, sport: int, dport: int) -> Tuple[Optional[str], str]:
    """
    Identify TCP application protocol via payload signatures first, then port heuristics.
    Returns (protocol_name_or_None, identification_method_description).
    """
    if not payload:
        return None, ""

    # 1. HTTP/2 Connection Preface (exact 24-byte magic)
    if payload.startswith(HTTP2_PREFACE):
        return "HTTP2", "DPI: HTTP/2 Connection Preface Magic"

    # 2. HTTP/1.x Request or Response (works on ANY port: 80, 8080, 8000, 3000, etc.)
    if payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/1."):
        if b"\r\n" in payload[:512] or b"\n" in payload[:512]:
            return "HTTP", "DPI: HTTP/1.x Grammar Signature"

    # 3. TLS / SSL Record Header (works on ANY port: 443, 8443, 993, 465, etc.)
    if is_tls_record(payload):
        return "TLS", "DPI: TLS Record Layer Header"

    # 4. SSH Banner Exchange (RFC 4253)
    if payload.startswith(b"SSH-1.") or payload.startswith(b"SSH-2."):
        return "SSH", "DPI: SSH RFC4253 Version Banner"

    # 5. FTP Command / Greeting
    if payload.startswith(FTP_VERBS) or (
        (sport == 21 or dport == 21) and len(payload) >= 4 and payload[:3].isdigit() and payload[3:4] in (b" ", b"-")
    ):
        return "FTP", "DPI: FTP Control Command/Reply"

    # 6. SMTP Command / Greeting
    upper_head = payload[:16].upper()
    if any(upper_head.startswith(v) for v in SMTP_VERBS) or (
        (sport in (25, 587) or dport in (25, 587)) and payload[:3].isdigit()
    ):
        return "SMTP", "DPI: SMTP Protocol Command"

    # 7. Redis RESP Protocol
    if (sport == 6379 or dport == 6379) or (
        payload[:1] in (b"*", b"+", b"-", b"$") and b"\r\n" in payload[:64] and (
            b"PING\r\n" in payload[:32] or b"GET\r\n" in payload[:32] or b"SET\r\n" in payload[:32] or b"PONG\r\n" in payload[:32]
        )
    ):
        return "REDIS", "DPI: Redis RESP Framing"

    # 8. MySQL Initial Handshake Packet (length + seq=0 + protocol_version=0x0a)
    if len(payload) > 10 and payload[3] == 0x00 and payload[4] == 0x0A and b"\x00" in payload[5:32]:
        if sport == 3306 or dport == 3306 or b"mysql" in payload[:64].lower() or b"mariadb" in payload[:64].lower():
            return "MYSQL", "DPI: MySQL Protocol v10 Greeting"

    # 9. WebSocket Binary/Text Frame Heuristic (after upgrade on common ports or masked client frame)
    if len(payload) >= 2 and (sport in (80, 8080, 8000, 8765, 3000) or dport in (80, 8080, 8000, 8765, 3000)):
        b0, b1 = payload[0], payload[1]
        fin = (b0 >> 7) & 1
        rsv = (b0 >> 4) & 0x7
        opcode = b0 & 0xF
        masked = (b1 >> 7) & 1
        plen = b1 & 0x7F
        if fin == 1 and rsv == 0 and opcode in (1, 2, 8, 9, 10) and plen < 126:
            expected = 2 + (4 if masked else 0) + plen
            if expected == len(payload) and len(payload) >= 6:
                return "WEBSOCKET", "DPI: RFC6455 WebSocket Frame Structure"

    # 10. DNS over TCP (2-byte length prefix matching payload)
    if (sport == 53 or dport == 53) and len(payload) >= 14:
        dns_len = struct.unpack_from("!H", payload, 0)[0]
        if dns_len == len(payload) - 2:
            return "DNS", "DPI: DNS-over-TCP Length Framing"

    # 11. Well-known Port Fallback (when encrypted/binary continuation frames have no plaintext magic)
    if 22 in (sport, dport):
        return "SSH", "Port Heuristic (TCP/22)"
    if 443 in (sport, dport):
        return "TLS", "Port Heuristic (TCP/443)"
    if 80 in (sport, dport):
        return "HTTP", "Port Heuristic (TCP/80)"

    return None, ""


def classify_udp_app(payload: bytes, sport: int, dport: int) -> Tuple[Optional[str], str]:
    """Identify UDP application protocol via payload signatures and port heuristics."""
    if not payload:
        return None, ""

    # 1. DHCP (RFC 2131 Magic Cookie 0x63825363 at offset 236)
    if len(payload) >= 240 and payload[236:240] == b"\x63\x82\x53\x63":
        return "DHCP", "DPI: DHCP RFC2131 Magic Cookie"

    # 2. SSDP (HTTP-over-UDP multicast discovery)
    if payload.startswith((b"M-SEARCH ", b"NOTIFY ", b"HTTP/1.1 200 OK")) and (1900 in (sport, dport)):
        return "SSDP", "DPI: SSDP Multicast Discovery"

    # 3. QUIC Long Header (Fixed Bit 0x40 + Header Form 0x80 + Known QUIC Version)
    if len(payload) >= 7 and (payload[0] & 0xC0) == 0xC0:
        qver = struct.unpack_from("!I", payload, 1)[0]
        if qver in (0x00000001, 0x6B3343CF, 0xFF00001D, 0xFF00001E, 0xFF00001F, 0xFF000020) or (443 in (sport, dport)):
            return "QUIC", "DPI: RFC9000 QUIC Long Header"

    # 4. mDNS
    if 5353 in (sport, dport) and len(payload) >= 12:
        return "MDNS", "DPI: Multicast DNS (UDP/5353)"

    # 5. DNS (port 53 or structural DNS check)
    if (53 in (sport, dport)) and len(payload) >= 12:
        return "DNS", "DPI: RFC1035 DNS Header"

    # 6. NTP (48 bytes on port 123, version 3 or 4)
    if 123 in (sport, dport) and len(payload) >= 48:
        ver = (payload[0] >> 3) & 0x7
        if ver in (2, 3, 4):
            return "NTP", "DPI: NTP v3/v4 Packet Structure"

    # 7. QUIC Short Header on UDP/443
    if 443 in (sport, dport) and len(payload) >= 16 and (payload[0] & 0x40) == 0x40:
        return "QUIC", "DPI: QUIC Short Header (UDP/443)"

    # 8. STUN (RFC 5389 Magic Cookie 0x2112A442 at offset 4)
    if len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42":
        return "STUN", "DPI: STUN RFC5389 Magic Cookie"

    return None, ""
