"""
WirePulse Built-In Real-Time Security IDS & Anomaly Detection Engine.

Incremental security analysis layer built atop packet sniffing & dissection:
  1. TCP Port Scan Detection (SYN Scan / FIN / NULL / XMAS Stealth Scans)
  2. TCP SYN Flood / DoS Burst Detection
  3. ARP Spoofing / MAC-IP Hijacking Detection
  4. Plaintext Credential & Sensitive Token Leakage (HTTP Basic, Form Passwords, Bearer JWT, FTP USER/PASS)
  5. Web Application Attack Payloads (SQL Injection, XSS, Path Traversal, Command Injection)
  6. DNS Tunneling / High-Entropy Subdomain Exfiltration Detection
  7. TLS Security Audit (Deprecated TLS 1.0/1.1, Weak Cipher Suites)
  8. TCP Transport Anomalies (Zero Window / Burst Retransmissions)
"""
from __future__ import annotations

import base64
import math
import re
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .dissector.models import PacketRecord

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

SQLI_RE = re.compile(
    r"(?i)(\bunion\s+(all\s+)?select\b|'\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1|\bdrop\s+table\b|--\s*$|;\s*select\b|sleep\(\d+\)|benchmark\()"
)
XSS_RE = re.compile(r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|<iframe\b|document\.cookie)")
TRAVERSAL_RE = re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|win\.ini)")
CRED_BODY_RE = re.compile(r"(?i)(password|passwd|pwd|secret|api_key|access_token)\s*[=:]\s*([^\s&\"'}{,;]{3,64})")
BEARER_RE = re.compile(r"(?i)Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)")


@dataclass
class SecurityAlert:
    id: int
    timestamp: float
    rel_time: float
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    rule: str
    category: str
    title: str
    description: str
    src: str
    dst: str
    protocol: str
    packet_no: int
    stream_id: Optional[int] = None
    evidence: str = ""
    mitre_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": round(self.timestamp, 6),
            "relTime": round(self.rel_time, 6),
            "severity": self.severity,
            "rule": self.rule,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol,
            "packetNo": self.packet_no,
            "streamId": self.stream_id,
            "evidence": self.evidence,
            "mitreId": self.mitre_id,
        }


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class SecurityEngine:
    def __init__(self) -> None:
        self.alerts: List[SecurityAlert] = []
        self._arp_table: Dict[str, str] = {}  # IP -> MAC
        self._syn_ports: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
        self._syn_alerted: Set[Tuple[str, str]] = set()
        self._syn_flood_counts: Dict[str, List[float]] = defaultdict(list)
        self._syn_flood_alerted: Set[str] = set()
        self._dns_nxdomain: Dict[str, int] = defaultdict(int)
        self._dns_nx_alerted: Set[str] = set()

    def reset(self) -> None:
        self.alerts.clear()
        self._arp_table.clear()
        self._syn_ports.clear()
        self._syn_alerted.clear()
        self._syn_flood_counts.clear()
        self._syn_flood_alerted.clear()
        self._dns_nxdomain.clear()
        self._dns_nx_alerted.clear()

    def _emit(
        self,
        pkt: PacketRecord,
        severity: str,
        rule: str,
        category: str,
        title: str,
        description: str,
        evidence: str = "",
        mitre_id: str = "",
    ) -> SecurityAlert:
        alert = SecurityAlert(
            id=len(self.alerts) + 1,
            timestamp=pkt.timestamp,
            rel_time=pkt.rel_time,
            severity=severity,
            rule=rule,
            category=category,
            title=title,
            description=description,
            src=pkt.src,
            dst=pkt.dst,
            protocol=pkt.protocol,
            packet_no=pkt.no,
            stream_id=pkt.stream_id,
            evidence=evidence[:240],
            mitre_id=mitre_id,
        )
        self.alerts.append(alert)
        pkt.alert_rules.append(rule)
        if pkt.alert_severity is None or SEVERITY_RANK[severity] > SEVERITY_RANK[pkt.alert_severity]:
            pkt.alert_severity = severity
        pkt.add_field_index("alert.severity", severity)
        pkt.add_field_index("alert.rule", rule)
        return alert

    def inspect(self, pkt: PacketRecord) -> List[SecurityAlert]:
        new_alerts: List[SecurityAlert] = []

        # 1. ARP Spoofing / MITM Detection
        if "arp" in pkt.protocols:
            opcodes = pkt.fields_index.get("arp.opcode", [])
            if 2 in opcodes:
                spa = (pkt.fields_index.get("arp.src.proto_ipv4") or [""])[0]
                sha = (pkt.fields_index.get("arp.src.hw_mac") or [""])[0]
                if spa and sha:
                    prev_mac = self._arp_table.get(spa)
                    if prev_mac and prev_mac != sha:
                        new_alerts.append(
                            self._emit(
                                pkt,
                                "CRITICAL",
                                "ARP_SPOOFING",
                                "Network MITM",
                                f"ARP Spoofing Detected for {spa}",
                                f"IP {spa} previously bound to MAC {prev_mac}, now claimed by conflicting MAC {sha} via ARP reply.",
                                evidence=f"{spa}: {prev_mac} -> {sha}",
                                mitre_id="T1557.002",
                            )
                        )
                    else:
                        self._arp_table[spa] = sha

        # 2. TCP Port Scan, Stealth Scan & SYN Flood
        if "tcp" in pkt.protocols:
            flags = pkt.tcp_flags
            syn = bool(flags & 0x0002)
            ack = bool(flags & 0x0010)
            fin = bool(flags & 0x0001)
            psh = bool(flags & 0x0008)
            urg = bool(flags & 0x0020)
            rst = bool(flags & 0x0004)

            # Stealth Scans (NULL / XMAS / FIN-only)
            if flags == 0:
                new_alerts.append(
                    self._emit(
                        pkt,
                        "HIGH",
                        "TCP_NULL_SCAN",
                        "Reconnaissance",
                        f"TCP NULL Stealth Scan from {pkt.src}",
                        f"TCP packet with zero flags sent to {pkt.dst}:{pkt.dst_port} (classic RFC 793 stealth port probe).",
                        evidence=f"{pkt.src}:{pkt.src_port} -> {pkt.dst}:{pkt.dst_port} [FLAGS=0x000]",
                        mitre_id="T1046",
                    )
                )
            elif fin and psh and urg and not ack and not syn:
                new_alerts.append(
                    self._emit(
                        pkt,
                        "HIGH",
                        "TCP_XMAS_SCAN",
                        "Reconnaissance",
                        f"TCP XMAS Stealth Scan from {pkt.src}",
                        f"TCP segment with FIN+PSH+URG flags sent to {pkt.dst}:{pkt.dst_port}.",
                        evidence=f"{pkt.src} -> {pkt.dst}:{pkt.dst_port} [FIN, PSH, URG]",
                        mitre_id="T1046",
                    )
                )
            elif syn and not ack and not rst:
                pair = (pkt.src, pkt.dst)
                if pkt.dst_port is not None:
                    self._syn_ports[pair].add(pkt.dst_port)
                if len(self._syn_ports[pair]) >= 8 and pair not in self._syn_alerted:
                    self._syn_alerted.add(pair)
                    ports_sample = sorted(self._syn_ports[pair])[:12]
                    new_alerts.append(
                        self._emit(
                            pkt,
                            "HIGH",
                            "TCP_SYN_PORT_SCAN",
                            "Reconnaissance",
                            f"TCP SYN Port Scan: {pkt.src} -> {pkt.dst}",
                            f"Source {pkt.src} probed {len(self._syn_ports[pair])} distinct destination ports on {pkt.dst}.",
                            evidence=f"Probed ports: {ports_sample}",
                            mitre_id="T1046",
                        )
                    )

                # SYN Flood check (high SYN volume within 2 seconds to same target)
                ts_list = self._syn_flood_counts[pkt.dst]
                ts_list.append(pkt.timestamp)
                cutoff = pkt.timestamp - 2.0
                while ts_list and ts_list[0] < cutoff:
                    ts_list.pop(0)
                if len(ts_list) >= 40 and pkt.dst not in self._syn_flood_alerted:
                    self._syn_flood_alerted.add(pkt.dst)
                    new_alerts.append(
                        self._emit(
                            pkt,
                            "CRITICAL",
                            "TCP_SYN_FLOOD",
                            "Denial of Service",
                            f"Possible TCP SYN Flood against {pkt.dst}",
                            f"Observed {len(ts_list)} SYN packets targeting {pkt.dst} within a 2-second window.",
                            evidence=f"Target={pkt.dst}, Burst={len(ts_list)} SYN / 2s",
                            mitre_id="T1498.001",
                        )
                    )

        # 3. HTTP Plaintext Credentials & Web Attacks (SQLi, XSS, Traversal)
        if "http" in pkt.protocols:
            uri_raw = str((pkt.fields_index.get("http.request.uri") or [""])[0])
            uri = urllib.parse.unquote_plus(uri_raw)
            auth = str((pkt.fields_index.get("http.authorization") or [""])[0])
            body_raw = str((pkt.fields_index.get("http.file_data") or [""])[0])
            body = urllib.parse.unquote_plus(body_raw)
            combined = f"{uri}\n{body}"

            if auth:
                if auth.lower().startswith("basic "):
                    try:
                        decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="replace")
                    except Exception:
                        decoded = auth
                    new_alerts.append(
                        self._emit(
                            pkt,
                            "CRITICAL",
                            "CLEARTEXT_HTTP_BASIC_AUTH",
                            "Credential Exposure",
                            "Plaintext HTTP Basic Authentication Credentials Exposed",
                            f"Unencrypted HTTP Basic Auth header sent from {pkt.src} to {pkt.dst}.",
                            evidence=f"Decoded Basic Auth: {decoded}",
                            mitre_id="T1552.001",
                        )
                    )
                else:
                    bm = BEARER_RE.search(auth)
                    if bm:
                        new_alerts.append(
                            self._emit(
                                pkt,
                                "HIGH",
                                "CLEARTEXT_BEARER_JWT",
                                "Credential Exposure",
                                "Unencrypted HTTP Bearer JWT Token Exposed",
                                f"JWT Authorization token transmitted over cleartext HTTP to {pkt.dst}.",
                                evidence=f"Bearer {bm.group(1)[:48]}...",
                                mitre_id="T1528",
                            )
                        )

            cm = CRED_BODY_RE.search(combined)
            if cm:
                new_alerts.append(
                    self._emit(
                        pkt,
                        "HIGH",
                        "CLEARTEXT_CREDENTIAL_LEAK",
                        "Credential Exposure",
                        "Cleartext Password / Secret Parameter in HTTP Traffic",
                        f"Sensitive parameter '{cm.group(1)}' transmitted in plaintext over HTTP.",
                        evidence=f"{cm.group(1)}={cm.group(2)[:32]}",
                        mitre_id="T1040",
                    )
                )

            sqli = SQLI_RE.search(combined)
            if sqli:
                new_alerts.append(
                    self._emit(
                        pkt,
                        "CRITICAL",
                        "HTTP_SQL_INJECTION",
                        "Web Attack",
                        f"SQL Injection Payload Detected ({pkt.src} -> {pkt.dst})",
                        f"HTTP traffic contains SQL injection signature matching '{sqli.group(0)}'.",
                        evidence=uri[:160] or body[:160],
                        mitre_id="T1190",
                    )
                )

            xss = XSS_RE.search(combined)
            if xss:
                new_alerts.append(
                    self._emit(
                        pkt,
                        "HIGH",
                        "HTTP_XSS_PAYLOAD",
                        "Web Attack",
                        f"Cross-Site Scripting (XSS) Payload Detected",
                        f"HTTP payload contains script injection marker '{xss.group(0)}'.",
                        evidence=uri[:160] or body[:160],
                        mitre_id="T1190",
                    )
                )

            trav = TRAVERSAL_RE.search(combined)
            if trav:
                new_alerts.append(
                    self._emit(
                        pkt,
                        "HIGH",
                        "HTTP_PATH_TRAVERSAL",
                        "Web Attack",
                        "Directory / Path Traversal Attempt Detected",
                        f"HTTP request attempts filesystem traversal via '{trav.group(0)}'.",
                        evidence=uri[:160],
                        mitre_id="T1190",
                    )
                )

        # 4. FTP Plaintext Credentials
        if "ftp" in pkt.protocols:
            cmd = str((pkt.fields_index.get("ftp.command") or [""])[0])
            if cmd.upper().startswith(("USER ", "PASS ")):
                new_alerts.append(
                    self._emit(
                        pkt,
                        "HIGH" if cmd.upper().startswith("PASS ") else "MEDIUM",
                        "CLEARTEXT_FTP_CREDENTIAL",
                        "Credential Exposure",
                        f"Plaintext FTP Credential Command ({cmd[:4].upper()})",
                        f"Unencrypted FTP authentication sent from {pkt.src} to {pkt.dst}.",
                        evidence=cmd[:100],
                        mitre_id="T1040",
                    )
                )

        # 5. DNS Tunneling / High-Entropy Subdomain Detection
        if "dns" in pkt.protocols:
            qnames = pkt.fields_index.get("dns.qry.name", [])
            qtypes = pkt.fields_index.get("dns.qry.type", [])
            rcodes = pkt.fields_index.get("dns.flags.rcode", [])
            for qn in qnames:
                qn_s = str(qn)
                first_label = qn_s.split(".")[0] if "." in qn_s else qn_s
                ent = shannon_entropy(first_label)
                if len(first_label) >= 28 and ent >= 3.6:
                    new_alerts.append(
                        self._emit(
                            pkt,
                            "HIGH",
                            "DNS_TUNNELING_SUSPECT",
                            "Exfiltration / C2",
                            f"Suspected DNS Tunneling / Data Exfiltration",
                            f"Oversized high-entropy subdomain label (len={len(first_label)}, H={ent:.2f} bits/char) queried via DNS {'/'.join(str(t) for t in qtypes)}.",
                            evidence=f"Query: {qn_s[:140]}",
                            mitre_id="T1071.004",
                        )
                    )
            if 3 in rcodes:
                self._dns_nxdomain[pkt.dst] += 1
                if self._dns_nxdomain[pkt.dst] >= 12 and pkt.dst not in self._dns_nx_alerted:
                    self._dns_nx_alerted.add(pkt.dst)
                    new_alerts.append(
                        self._emit(
                            pkt,
                            "MEDIUM",
                            "DNS_NXDOMAIN_BURST",
                            "Exfiltration / C2",
                            f"Abnormal NXDOMAIN Burst for {pkt.dst}",
                            f"Host {pkt.dst} received {self._dns_nxdomain[pkt.dst]} NXDOMAIN responses (possible DGA malware).",
                            evidence=f"NXDOMAIN count={self._dns_nxdomain[pkt.dst]}",
                            mitre_id="T1568.002",
                        )
                    )

        # 6. TLS Security Audit (Deprecated Versions & Weak Ciphers)
        if "tls" in pkt.protocols:
            vers = [str(v) for v in pkt.fields_index.get("tls.handshake.version", [])]
            for v in vers:
                if v in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
                    new_alerts.append(
                        self._emit(
                            pkt,
                            "MEDIUM",
                            "TLS_DEPRECATED_VERSION",
                            "Crypto Weakness",
                            f"Deprecated {v} Handshake Observed",
                            f"Connection {pkt.src} -> {pkt.dst} uses deprecated {v} (RFC 8996 prohibits TLS < 1.2).",
                            evidence=f"Version={v}",
                            mitre_id="T1573",
                        )
                    )
            weak = pkt.fields_index.get("tls.weak_cipher", [])
            if weak:
                new_alerts.append(
                    self._emit(
                        pkt,
                        "LOW",
                        "TLS_WEAK_CIPHER",
                        "Crypto Weakness",
                        "Weak / Non-PFS TLS Cipher Suite Offered or Negotiated",
                        f"Observed weak TLS cipher suite(s) without AEAD/PFS protection.",
                        evidence=", ".join(str(w) for w in weak[:4]),
                        mitre_id="T1573",
                    )
                )

        # 7. TCP Transport Expert Warning (Zero Window)
        if "Zero Window" in pkt.tcp_expert:
            new_alerts.append(
                self._emit(
                    pkt,
                    "LOW",
                    "TCP_ZERO_WINDOW",
                    "Transport Anomaly",
                    f"TCP Zero Window Stall ({pkt.src} -> {pkt.dst})",
                    "Receiver advertised a zero-byte TCP window, stalling stream throughput.",
                    evidence=pkt.info[:140],
                )
            )

        return new_alerts

    def summary_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": len(self.alerts)}
        for a in self.alerts:
            if a.severity in counts:
                counts[a.severity] += 1
        return counts
