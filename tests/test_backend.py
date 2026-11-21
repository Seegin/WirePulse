"""
Comprehensive automated tests for WirePulse Backend:
  - C11 Native libpcap engine + BPF validation
  - OSI 7-layer dissector (L2-L7, DPI, DNS, TLS/JA3)
  - Recursive Descent Display Filter Compiler & Logic Evaluator
  - TCP Stream Reassembly, Expert Analysis & Sequence Ladder Diagram
  - OS Process Attribution
  - Security IDS Rules (ARP Spoof, SYN Scan, XMAS/NULL, SQLi, XSS, Traversal, Creds, DNS Tunnel, TLS Audit)
  - Wireshark sharkd Dual-Engine Dissection & Lua Dissector Generator
  - PCAP round-trip export/import
"""
from __future__ import annotations

import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.capture_manager import CaptureManager
from backend.demo_generator import ensure_sample_pcap
from backend.filter_engine import FilterSyntaxError, compile_filter, validate_filter


class TestWirePulseBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mgr = CaptureManager(PROJECT_ROOT)
        res = cls.mgr.load_demo_capture(realtime=False)
        assert res["ok"], f"Demo load failed: {res}"

    def test_01_native_pcap_and_bpf(self) -> None:
        ifaces = self.mgr.list_interfaces()
        self.assertTrue(ifaces["nativeEngine"]["available"])
        self.assertIn("libpcap", ifaces["nativeEngine"]["version"].lower())
        self.assertGreater(len(ifaces["nativeInterfaces"]), 0)

        self.assertTrue(self.mgr.native.validate_bpf("tcp port 80 or port 443")["valid"])
        self.assertFalse(self.mgr.native.validate_bpf("not_a_bpf_keyword (((")["valid"])

    def test_02_protocols_and_dpi_dissected(self) -> None:
        protos = {p.protocol for p in self.mgr.packets}
        for expected in ("ARP", "DHCP", "DNS", "TLSv1.3", "HTTP", "FTP", "SSH", "QUIC", "ICMP", "ICMPv6"):
            self.assertIn(expected, protos, f"Missing protocol {expected} in {protos}")

        # Verify DPI detected HTTP on non-standard port 8888
        port8888_http = [p for p in self.mgr.packets if p.protocol == "HTTP" and (p.src_port == 8888 or p.dst_port == 8888)]
        self.assertGreaterEqual(len(port8888_http), 2)
        self.assertIn("DPI:", port8888_http[0].dpi_method)

        # Verify TLS SNI & JA3 extracted
        tls_ch = [p for p in self.mgr.packets if p.fields_index.get("tls.handshake.sni")]
        self.assertGreaterEqual(len(tls_ch), 1)
        self.assertEqual(tls_ch[0].fields_index["tls.handshake.sni"][0], "github.com")
        self.assertEqual(len(tls_ch[0].fields_index["tls.ja3"][0]), 32)

    def test_03_display_filter_compiler_and_logic(self) -> None:
        # Complex logic with parentheses, negation, relational ops, contains, CIDR, IN set
        q1 = self.mgr.query_packets("(http or dns) and not (ip.src == 10.212.5.199)")
        self.assertTrue(q1["ok"])
        self.assertGreater(q1["totalMatched"], 0)
        for p in q1["packets"]:
            self.assertIn(p["protocol"], ("HTTP", "DNS"))
            self.assertNotEqual(p["src"], "10.212.5.199")

        # CIDR matching
        q2 = self.mgr.query_packets("ip.src == 10.212.5.0/24 && tcp.port in {80, 443, 8888}")
        self.assertTrue(q2["ok"])
        self.assertGreater(q2["totalMatched"], 5)

        # Regex & contains
        q3 = self.mgr.query_packets('http.request.uri contains "UNION SELECT" || dns.qry.name matches "c2-beacon\\.net$"')
        self.assertTrue(q3["ok"])
        self.assertEqual(q3["totalMatched"], 2)

        # Process & Alert filtering
        q4 = self.mgr.query_packets('proc.name == "chrome.exe" and tls')
        self.assertTrue(q4["ok"])
        self.assertGreater(q4["totalMatched"], 0)

        q5 = self.mgr.query_packets('alert.severity == "CRITICAL"')
        self.assertTrue(q5["ok"])
        self.assertGreaterEqual(q5["totalMatched"], 3)

        # Syntax error detection
        bad = validate_filter("tcp.port == && (http")
        self.assertFalse(bad["valid"])
        self.assertIsNotNone(bad["error"])

    def test_04_stream_reassembly_and_sequence_diagram(self) -> None:
        streams = self.mgr.streams.list_streams(proto="tcp")
        self.assertGreaterEqual(len(streams), 5)

        # Find port 8888 HTTP stream which contains intentional retransmission
        http_8888 = [s for s in streams if s["serverPort"] == 8888]
        self.assertEqual(len(http_8888), 1)
        self.assertEqual(http_8888[0]["retransmissions"], 1)
        self.assertIsNotNone(http_8888[0]["rttMs"])

        followed = self.mgr.streams.follow_stream("tcp", http_8888[0]["streamId"])
        self.assertIsNotNone(followed)
        # Retransmission deduplicated -> exactly 2 turns (1 GET request, 1 200 OK response)
        self.assertEqual(len(followed["turns"]), 2)
        self.assertFalse(followed["turns"][0]["isBinary"])
        self.assertIn("GET /api/v1/courses", followed["turns"][0]["text"])
        self.assertIn("GET /api/v1/courses", followed["turns"][0]["ascii"])
        self.assertIn("Software and System Security", followed["turns"][1]["text"])
        # Sequence diagram captures all handshake + data + retransmission + FIN frames
        self.assertGreaterEqual(len(followed["sequence"]), 8)

        # Verify encrypted TLS stream turns have isBinary=True and ZERO mojibake/U+FFFD/control chars
        tls_streams = [s for s in streams if s["appProtocol"].startswith("TLS") and s["totalBytes"] > 0]
        self.assertGreaterEqual(len(tls_streams), 1)
        tls_followed = self.mgr.streams.follow_stream("tcp", tls_streams[0]["streamId"])
        self.assertTrue(any(t["isBinary"] for t in tls_followed["turns"]))
        for turn in tls_followed["turns"]:
            self.assertNotIn("\ufffd", turn["text"])
            self.assertNotIn("\ufffd", turn["ascii"])
            for ch in turn["text"]:
                cp = ord(ch)
                if ch not in ("\r", "\n", "\t"):
                    self.assertFalse(cp < 0x20 or (0x7F <= cp <= 0x9F), f"Control char leaked: {hex(cp)}")

    def test_05_os_process_attribution(self) -> None:
        procs = self.mgr.processes.list_processes()
        names = {p["name"] for p in procs}
        self.assertIn("chrome.exe", names)
        self.assertIn("curl.exe", names)
        self.assertIn("nmap", names)
        chrome_streams = self.mgr.streams.list_streams(process_name="chrome.exe")
        self.assertGreaterEqual(len(chrome_streams), 3)

    def test_06_security_ids_rules(self) -> None:
        rules = {a.rule for a in self.mgr.security.alerts}
        expected_rules = {
            "ARP_SPOOFING",
            "TCP_SYN_PORT_SCAN",
            "TCP_XMAS_SCAN",
            "TCP_NULL_SCAN",
            "CLEARTEXT_HTTP_BASIC_AUTH",
            "CLEARTEXT_CREDENTIAL_LEAK",
            "HTTP_SQL_INJECTION",
            "HTTP_XSS_PAYLOAD",
            "HTTP_PATH_TRAVERSAL",
            "CLEARTEXT_FTP_CREDENTIAL",
            "DNS_TUNNELING_SUSPECT",
            "TLS_DEPRECATED_VERSION",
            "TLS_WEAK_CIPHER",
        }
        missing = expected_rules - rules
        self.assertEqual(missing, set(), f"Missing IDS rules: {missing}")

    def test_07_wireshark_dual_engine_and_lua_generator(self) -> None:
        lua = self.mgr.wireshark.generate_lua_dissector(
            proto_name="ucas_sft",
            description="UCAS Secure File Transfer",
            transport="tcp",
            port=9090,
            magic_hex="55434153",
            fields=[
                {"name": "magic", "label": "Magic Header", "type": "uint32", "length": 4},
                {"name": "opcode", "label": "Packet Type", "type": "uint8", "length": 1},
                {"name": "length", "label": "Payload Length", "type": "uint32", "length": 4},
            ],
        )
        self.assertIn('Proto("ucas_sft"', lua)
        self.assertIn("DissectorTable.get(\"tcp.port\")", lua)

        if self.mgr.wireshark.env.available:
            # Find TLS ClientHello packet and dissect via real Wireshark sharkd/libwireshark!
            tls_pkt = next(p for p in self.mgr.packets if p.fields_index.get("tls.handshake.sni"))
            ws_res = self.mgr.get_packet_wireshark_detail(tls_pkt.no)
            self.assertTrue(ws_res["ok"], f"Wireshark dissection failed: {ws_res}")
            self.assertGreaterEqual(len(ws_res["layers"]), 4)
            print(f"\n[OK] Verified live Wireshark libwireshark dissection via: {ws_res['engine']} ({len(ws_res['layers'])} layers)")

    def test_08_pcap_roundtrip_and_sample(self) -> None:
        sample_path = os.path.join(PROJECT_ROOT, "samples", "wirepulse_security_lab.pcap")
        ensure_sample_pcap(sample_path)
        self.assertTrue(os.path.isfile(sample_path))

        exported = self.mgr.export_pcap_bytes("http")
        mgr2 = CaptureManager(PROJECT_ROOT)
        imp = mgr2.import_pcap_bytes(exported, "filtered_http.pcap")
        self.assertTrue(imp["ok"])
        self.assertGreater(imp["status"]["totalPackets"], 0)
        for p in mgr2.packets:
            self.assertEqual(p.protocol, "HTTP")


if __name__ == "__main__":
    unittest.main(verbosity=2)
