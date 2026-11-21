"""
WirePulse Unified Capture Manager & Analytics Telemetry Hub.

Orchestrates:
  1. Native C11 libpcap / Npcap Capture Engine (via ctypes -> libwirepulse_pcap.so / .dll)
  2. Wireshark dumpcap Capture Bridge (Npcap live capture on Windows & WSL2 -> Windows!)
  3. Offline .pcap / .pcapng import & export
  4. Interactive Multi-Protocol Security Demo Replay
  5. Live Interface Sparkline sampling (/proc/net/dev + live packet rate deltas)
  6. Real-Time Packet Dissection, Stream Reassembly, OS Process Attribution, Security IDS,
     and Network Communication Topology Aggregation
"""
from __future__ import annotations

import asyncio
import ctypes
import os
import platform
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque
from typing import Any, Callable, Dict, List, Optional, Tuple

from .demo_generator import build_demo_dataset
from .direct_pcap import DirectPcapLoader, _PcapPktHdr, _PcapStat
from .dissector.engine import ProtocolDissector
from .dissector.models import PacketRecord
from .filter_engine import compile_filter, validate_filter
from .pcap_io import DLT_EN10MB, RawPacket, iter_capture_stream, read_capture_bytes, write_pcap_bytes
from .process_tracker import OSProcessTracker
from .security_engine import SecurityEngine
from .stream_engine import StreamTracker
from .wireshark_bridge import WiresharkBridge

# --- ctypes Bindings for core/libwirepulse_pcap.so (.dll) ---
class _WPIfaceInfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 256),
        ("description", ctypes.c_char * 256),
        ("ipv4", ctypes.c_char * 64),
        ("ipv6", ctypes.c_char * 128),
        ("flags", ctypes.c_uint32),
    ]


class _WPPacketView(ctypes.Structure):
    _fields_ = [
        ("ts_sec", ctypes.c_int64),
        ("ts_usec", ctypes.c_int32),
        ("caplen", ctypes.c_uint32),
        ("origlen", ctypes.c_uint32),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
    ]


class _WPCaptureStats(ctypes.Structure):
    _fields_ = [
        ("packets_captured", ctypes.c_uint64),
        ("bytes_captured", ctypes.c_uint64),
        ("kernel_recv", ctypes.c_uint32),
        ("kernel_drop", ctypes.c_uint32),
        ("iface_drop", ctypes.c_uint32),
        ("datalink", ctypes.c_int32),
    ]


class NativePcapEngine:
    """Wrapper around our C11 libwirepulse_pcap shared library with direct wpcap/libpcap fallback."""

    def __init__(self, project_root: str) -> None:
        self.lib: Optional[ctypes.CDLL] = None
        self.direct: Optional[DirectPcapLoader] = None
        self.version: str = "unavailable"
        self.load_error: Optional[str] = None
        self._load(project_root)

    def _load(self, root: str) -> None:
        sys_name = platform.system()
        if sys_name == "Windows":
            candidates = [os.path.join(root, "core", "wirepulse_pcap.dll")]
        elif sys_name == "Darwin":
            candidates = [os.path.join(root, "core", "libwirepulse_pcap.dylib")]
        else:
            candidates = [os.path.join(root, "core", "libwirepulse_pcap.so")]

        for path in candidates:
            if not os.path.isfile(path):
                continue
            try:
                lib = ctypes.CDLL(path)
                lib.wp_init.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                lib.wp_init.restype = ctypes.c_int
                lib.wp_lib_version.restype = ctypes.c_char_p
                lib.wp_list_interfaces.argtypes = [ctypes.POINTER(_WPIfaceInfo), ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
                lib.wp_list_interfaces.restype = ctypes.c_int
                lib.wp_validate_bpf.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
                lib.wp_validate_bpf.restype = ctypes.c_int
                lib.wp_open_live.argtypes = [
                    ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                    ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
                ]
                lib.wp_open_live.restype = ctypes.c_void_p
                lib.wp_next_packet.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WPPacketView), ctypes.c_char_p, ctypes.c_size_t]
                lib.wp_next_packet.restype = ctypes.c_int
                lib.wp_get_datalink.argtypes = [ctypes.c_void_p]
                lib.wp_get_datalink.restype = ctypes.c_int
                lib.wp_get_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WPCaptureStats)]
                lib.wp_get_stats.restype = ctypes.c_int
                lib.wp_break.argtypes = [ctypes.c_void_p]
                lib.wp_close.argtypes = [ctypes.c_void_p]

                err = ctypes.create_string_buffer(256)
                if lib.wp_init(err, 256) == 0:
                    self.lib = lib
                    self.version = (lib.wp_lib_version() or b"libpcap").decode("utf-8", errors="replace")
                    return
                self.load_error = err.value.decode("utf-8", errors="replace")
            except Exception as e:
                self.load_error = str(e)

        # Fallback: direct ctypes binding to Npcap wpcap.dll / libpcap.so
        direct = DirectPcapLoader()
        if direct.available:
            self.direct = direct
            self.version = direct.version
            self.load_error = None
        elif not self.load_error:
            self.load_error = direct.error

    @property
    def available(self) -> bool:
        return self.lib is not None or (self.direct is not None and self.direct.available)

    def list_interfaces(self) -> List[Dict[str, Any]]:
        if not self.lib:
            return self.direct.list_interfaces() if self.direct else []
        arr = (_WPIfaceInfo * 64)()
        err = ctypes.create_string_buffer(256)
        n = self.lib.wp_list_interfaces(arr, 64, err, 256)
        if n <= 0:
            return []
        out = []
        for i in range(n):
            item = arr[i]
            name = item.name.decode("utf-8", errors="replace")
            desc = item.description.decode("utf-8", errors="replace")
            ipv4 = item.ipv4.decode("utf-8", errors="replace")
            ipv6 = item.ipv6.decode("utf-8", errors="replace")
            flags = int(item.flags)
            out.append(
                {
                    "id": f"native:{name}",
                    "name": name,
                    "device": name,
                    "description": desc or f"Native libpcap/Npcap interface ({name})",
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "engine": "native_libpcap",
                    "isLoopback": bool(flags & 0x01) or name == "lo",
                    "isUp": bool(flags & 0x02),
                    "isRunning": bool(flags & 0x04),
                    "isWireless": bool(flags & 0x08),
                }
            )
        return out

    def validate_bpf(self, expr: str) -> Dict[str, Any]:
        expr = (expr or "").strip()
        if not expr:
            return {"valid": True, "error": None}
        if not self.lib:
            return self.direct.validate_bpf(expr) if self.direct else {"valid": True, "error": None}
        err = ctypes.create_string_buffer(256)
        rc = self.lib.wp_validate_bpf(expr.encode("utf-8"), DLT_EN10MB, err, 256)
        if rc == 0:
            return {"valid": True, "error": None}
        return {"valid": False, "error": err.value.decode("utf-8", errors="replace")}


class CaptureManager:
    """Central session store & capture orchestrator shared by REST API and WebSockets."""

    MAX_PACKETS = 100_000

    def __init__(self, project_root: str) -> None:
        self.project_root = project_root
        self.native = NativePcapEngine(project_root)
        self.wireshark = WiresharkBridge()
        self.dissector = ProtocolDissector()
        self.streams = StreamTracker()
        self.processes = OSProcessTracker()
        self.security = SecurityEngine()

        self._lock = threading.RLock()
        self.packets: List[PacketRecord] = []

        # Capture runtime state
        self.capturing: bool = False
        self.paused: bool = False
        self.active_engine: str = "idle"
        self.active_interface: str = ""
        self.active_bpf: str = ""
        self.capture_error: Optional[str] = None
        self.kernel_stats: Dict[str, int] = {"recv": 0, "drop": 0, "ifdrop": 0}
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._native_sess: Optional[ctypes.c_void_p] = None
        self._dumpcap_proc: Optional[subprocess.Popen] = None

        # Telemetry & Analytics rolling history
        self.proto_counts: Counter = Counter()
        self.osi_counts: Counter = Counter()
        self.endpoint_stats: Dict[str, Dict[str, Any]] = {}
        self.edge_stats: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.host_hints: Dict[str, str] = {}  # IP -> observed DNS/SNI/Host
        self.timeseries: deque = deque(maxlen=90)
        self._sec_bucket_ts: int = 0
        self._sec_pkts: int = 0
        self._sec_bytes: int = 0

        # Sparkline history per Linux interface (/proc/net/dev)
        self._prev_netdev: Dict[str, Tuple[int, float]] = {}
        self._sparklines: Dict[str, deque] = defaultdict(lambda: deque([0] * 24, maxlen=24))

        # Async event subscribers (WebSocket clients)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ws_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._pending_batch: List[Dict[str, Any]] = []
        self._pending_alerts: List[Dict[str, Any]] = []

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def add_listener(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        self._ws_listeners.append(cb)

    def remove_listener(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        if cb in self._ws_listeners:
            self._ws_listeners.remove(cb)

    def _broadcast(self, msg: Dict[str, Any]) -> None:
        if not self._loop or not self._ws_listeners:
            return
        for cb in list(self._ws_listeners):
            self._loop.call_soon_threadsafe(cb, msg)

    def flush_live_batch(self) -> None:
        """Called periodically (~80ms) by server loop to push coalesced packets & alerts over WS."""
        with self._lock:
            if not self._pending_batch and not self._pending_alerts:
                return
            pkts = self._pending_batch[:500]
            self._pending_batch = self._pending_batch[500:]
            alerts = self._pending_alerts[:100]
            self._pending_alerts = self._pending_alerts[100:]
            status = self.get_status_snapshot()
        self._broadcast({"type": "batch", "packets": pkts, "alerts": alerts, "status": status})

    def reset_session(self) -> None:
        with self._lock:
            self.packets.clear()
            self.dissector.reset()
            self.streams.reset()
            self.processes.reset_stats()
            self.security.reset()
            self.proto_counts.clear()
            self.osi_counts.clear()
            self.endpoint_stats.clear()
            self.edge_stats.clear()
            self.host_hints.clear()
            self.timeseries.clear()
            self._sec_bucket_ts = 0
            self._sec_pkts = 0
            self._sec_bytes = 0
            self.kernel_stats = {"recv": 0, "drop": 0, "ifdrop": 0}
            self.capture_error = None
            self._pending_batch.clear()
            self._pending_alerts.clear()

    def _sample_sparklines(self) -> None:
        """Sample live interface byte deltas from /proc/net/dev for Welcome Screen sparklines."""
        if not os.path.isfile("/proc/net/dev"):
            return
        now = time.monotonic()
        try:
            with open("/proc/net/dev", "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[2:]
            for line in lines:
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                cols = rest.split()
                if len(cols) < 10:
                    continue
                total_bytes = int(cols[0]) + int(cols[8])
                prev = self._prev_netdev.get(iface)
                if prev is not None:
                    dt = max(0.05, now - prev[1])
                    rate = max(0, int((total_bytes - prev[0]) / dt))
                    self._sparklines[iface].append(rate)
                self._prev_netdev[iface] = (total_bytes, now)
        except OSError:
            pass

    def list_interfaces(self) -> Dict[str, Any]:
        self._sample_sparklines()
        native_ifaces = self.native.list_interfaces()
        for iface in native_ifaces:
            iface["sparkline"] = list(self._sparklines[iface["name"]])

        dumpcap_ifaces = self.wireshark.list_dumpcap_interfaces()
        for idx, iface in enumerate(dumpcap_ifaces):
            # Provide clean sparkline baseline (real rates updated during capture)
            key = f"dc_{idx}"
            iface["sparkline"] = list(self._sparklines[key])

        return {
            "nativeEngine": {
                "available": self.native.available,
                "version": self.native.version,
                "error": self.native.load_error,
                "isRoot": (os.geteuid() == 0) if hasattr(os, "geteuid") else True,
            },
            "wireshark": self.wireshark.env.to_dict(),
            "nativeInterfaces": native_ifaces,
            "dumpcapInterfaces": dumpcap_ifaces,
        }

    def get_status_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "capturing": self.capturing,
                "paused": self.paused,
                "engine": self.active_engine,
                "interface": self.active_interface,
                "bpfFilter": self.active_bpf,
                "error": self.capture_error,
                "totalPackets": len(self.packets),
                "totalBytes": sum(p.origlen for p in self.packets),
                "tcpStreams": len(self.streams.tcp_streams),
                "udpStreams": len(self.streams.udp_streams),
                "alerts": self.security.summary_counts(),
                "kernelStats": dict(self.kernel_stats),
                "nativeVersion": self.native.version,
                "wiresharkAvailable": self.wireshark.env.available,
                "wiresharkVersion": self.wireshark.env.version,
                "keylogActive": bool(self.wireshark.keylog_path),
            }

    def _ingest_raw_packet(self, raw_pkt: RawPacket, emit_ws: bool = True) -> Optional[PacketRecord]:
        with self._lock:
            if self.paused and self.capturing:
                return None
            if len(self.packets) >= self.MAX_PACKETS:
                return None

            no = len(self.packets) + 1
            pkt = self.dissector.dissect(
                no=no,
                raw=raw_pkt.data,
                timestamp=raw_pkt.timestamp,
                origlen=raw_pkt.origlen,
                linktype=raw_pkt.linktype,
            )

            # OS Process Attribution lookup
            proto_l4 = "tcp" if "tcp" in pkt.protocols else ("udp" if "udp" in pkt.protocols else "")
            pinfo = None
            if proto_l4:
                pinfo = self.processes.lookup(proto_l4, pkt.src, pkt.src_port, pkt.dst, pkt.dst_port)
                if pinfo:
                    pkt.pid = pinfo.pid
                    pkt.process_name = pinfo.name
                    pkt.add_field_index("proc.pid", pinfo.pid)
                    pkt.add_field_index("proc.name", pinfo.name)

            # Stream Tracking & TCP Expert Analysis
            self.streams.ingest(pkt)

            # Security IDS Inspection
            new_alerts = self.security.inspect(pkt)

            # Record per-process traffic stats
            if pinfo:
                self.processes.record_packet(
                    pinfo,
                    pkt.src,
                    pkt.dst,
                    pkt.src_port,
                    pkt.dst_port,
                    pkt.origlen,
                    pkt.protocol,
                    pkt.stream_id,
                    is_alert=bool(new_alerts),
                )

            self.packets.append(pkt)
            self._update_analytics(pkt, bool(new_alerts))

            if emit_ws:
                self._pending_batch.append(pkt.to_summary())
                for a in new_alerts:
                    self._pending_alerts.append(a.to_dict())

            return pkt

    def _update_analytics(self, pkt: PacketRecord, has_alert: bool) -> None:
        self.proto_counts[pkt.protocol] += 1
        self.osi_counts[f"L{pkt.osi_top_layer}"] += 1

        # Record hostname hints from DNS / SNI / HTTP Host
        sni_vals = pkt.fields_index.get("tls.handshake.sni")
        if sni_vals and pkt.dst:
            self.host_hints[pkt.dst] = str(sni_vals[0])
        host_vals = pkt.fields_index.get("http.host")
        if host_vals and pkt.dst:
            self.host_hints[pkt.dst] = str(host_vals[0])
        if "dns" in pkt.protocols and pkt.fields_index.get("dns.a") and pkt.fields_index.get("dns.qry.name"):
            qname = str(pkt.fields_index["dns.qry.name"][0])
            for ip_a in pkt.fields_index["dns.a"]:
                self.host_hints[str(ip_a)] = qname

        # Endpoints & Topology Edges
        for ep, is_src in ((pkt.src, True), (pkt.dst, False)):
            if not ep or ep in ("Broadcast", "0.0.0.0", "255.255.255.255"):
                continue
            st = self.endpoint_stats.get(ep)
            if st is None:
                st = {"ip": ep, "txPackets": 0, "rxPackets": 0, "txBytes": 0, "rxBytes": 0, "alerts": 0, "protocols": set()}
                self.endpoint_stats[ep] = st
            if is_src:
                st["txPackets"] += 1
                st["txBytes"] += pkt.origlen
            else:
                st["rxPackets"] += 1
                st["rxBytes"] += pkt.origlen
            st["protocols"].add(pkt.protocol)
            if has_alert:
                st["alerts"] += 1

        if pkt.src and pkt.dst and pkt.dst not in ("Broadcast", "255.255.255.255"):
            edge_key = (pkt.src, pkt.dst) if pkt.src <= pkt.dst else (pkt.dst, pkt.src)
            edge = self.edge_stats.get(edge_key)
            if edge is None:
                edge = {"source": edge_key[0], "target": edge_key[1], "packets": 0, "bytes": 0, "protocols": set(), "alerts": 0}
                self.edge_stats[edge_key] = edge
            edge["packets"] += 1
            edge["bytes"] += pkt.origlen
            edge["protocols"].add(pkt.protocol)
            if has_alert:
                edge["alerts"] += 1

        # 1-second time-series bucketing
        sec = int(pkt.timestamp)
        if self._sec_bucket_ts == 0:
            self._sec_bucket_ts = sec
        if sec != self._sec_bucket_ts:
            self.timeseries.append({"ts": self._sec_bucket_ts, "pps": self._sec_pkts, "bps": self._sec_bytes})
            self._sec_bucket_ts = sec
            self._sec_pkts = 0
            self._sec_bytes = 0
        self._sec_pkts += 1
        self._sec_bytes += pkt.origlen

    # --- Capture Lifecycle ---
    def start_capture(
        self,
        interface_id: str,
        bpf_filter: str = "",
        promisc: bool = True,
        snaplen: int = 65535,
        buffer_mb: int = 16,
    ) -> Dict[str, Any]:
        self.stop_capture()
        self.reset_session()
        self._stop_evt.clear()
        self.active_bpf = (bpf_filter or "").strip()

        if interface_id.startswith("dumpcap:"):
            return self._start_dumpcap_capture(interface_id.split(":", 1)[1], self.active_bpf, promisc, snaplen, buffer_mb)

        iface_name = interface_id.split(":", 1)[1] if interface_id.startswith("native:") else interface_id
        return self._start_native_capture(iface_name, self.active_bpf, promisc, snaplen, buffer_mb)

    def _start_native_capture(
        self, iface_name: str, bpf_filter: str, promisc: bool, snaplen: int, buffer_mb: int
    ) -> Dict[str, Any]:
        if not self.native.available:
            return {"ok": False, "error": f"Native libpcap/Npcap engine unavailable: {self.native.load_error}"}

        # Path B: Direct wpcap.dll / libpcap.so fallback (e.g., Windows without compiled DLL)
        if not self.native.lib and self.native.direct and self.native.direct.lib:
            return self._start_direct_pcap_capture(iface_name, bpf_filter, promisc, snaplen, buffer_mb)

        assert self.native.lib is not None
        err = ctypes.create_string_buffer(512)
        sess = self.native.lib.wp_open_live(
            iface_name.encode("utf-8"),
            int(snaplen),
            1 if promisc else 0,
            50,
            int(buffer_mb),
            bpf_filter.encode("utf-8"),
            err,
            512,
        )
        if not sess:
            msg = err.value.decode("utf-8", errors="replace")
            if "permission" in msg.lower() or "operation not permitted" in msg.lower():
                msg += " (Tip: Run with sudo / setcap cap_net_raw,cap_net_admin=eip, OR select a Wireshark dumpcap/Npcap interface!)"
            return {"ok": False, "error": msg}

        self._native_sess = sess
        self.capturing = True
        self.paused = False
        self.active_engine = f"Native C11 libpcap ({self.native.version})"
        self.active_interface = iface_name
        self.processes.set_windows_bridge(False)
        self.processes.start_background_refresh(2.0)

        def _worker() -> None:
            lib = self.native.lib
            assert lib is not None
            dlt = lib.wp_get_datalink(sess)
            view = _WPPacketView()
            st = _WPCaptureStats()
            eb = ctypes.create_string_buffer(256)
            last_stat_t = time.monotonic()

            try:
                while not self._stop_evt.is_set():
                    rc = lib.wp_next_packet(sess, ctypes.byref(view), eb, 256)
                    if rc == 1:
                        data = ctypes.string_at(view.data, view.caplen)
                        ts = float(view.ts_sec) + float(view.ts_usec) / 1_000_000.0
                        self._ingest_raw_packet(
                            RawPacket(timestamp=ts, caplen=view.caplen, origlen=view.origlen, linktype=dlt, data=data)
                        )
                    elif rc == 0:
                        pass
                    elif rc == -2:
                        break
                    else:
                        self.capture_error = eb.value.decode("utf-8", errors="replace")
                        break

                    now = time.monotonic()
                    if now - last_stat_t >= 1.0:
                        last_stat_t = now
                        if lib.wp_get_stats(sess, ctypes.byref(st)) == 0:
                            self.kernel_stats = {
                                "recv": int(st.kernel_recv),
                                "drop": int(st.kernel_drop),
                                "ifdrop": int(st.iface_drop),
                            }
            finally:
                lib.wp_close(sess)
                self._native_sess = None
                self.capturing = False
                self.processes.stop_background_refresh()
                self._broadcast({"type": "status", "status": self.get_status_snapshot()})

        self._capture_thread = threading.Thread(target=_worker, daemon=True, name="wp-native-cap")
        self._capture_thread.start()
        return {"ok": True, "status": self.get_status_snapshot()}

    def _start_direct_pcap_capture(
        self, iface_name: str, bpf_filter: str, promisc: bool, snaplen: int, buffer_mb: int
    ) -> Dict[str, Any]:
        direct = self.native.direct
        assert direct is not None and direct.lib is not None
        handle, err_msg = direct.open_live(iface_name, snaplen, promisc, 50, buffer_mb, bpf_filter)
        if not handle:
            return {"ok": False, "error": err_msg or "Failed to open Npcap/libpcap handle"}

        self._native_sess = handle
        self.capturing = True
        self.paused = False
        self.active_engine = f"Native Npcap/libpcap ({direct.version})"
        self.active_interface = iface_name
        self.processes.set_windows_bridge(False)
        self.processes.start_background_refresh(2.0)

        def _worker() -> None:
            lib = direct.lib
            assert lib is not None
            dlt = lib.pcap_datalink(handle)
            hdr_ptr = ctypes.POINTER(_PcapPktHdr)()
            data_ptr = ctypes.POINTER(ctypes.c_uint8)()
            st = _PcapStat()
            last_stat_t = time.monotonic()
            try:
                while not self._stop_evt.is_set():
                    rc = lib.pcap_next_ex(handle, ctypes.byref(hdr_ptr), ctypes.byref(data_ptr))
                    if rc == 1 and hdr_ptr and data_ptr:
                        h = hdr_ptr.contents
                        raw = ctypes.string_at(data_ptr, h.caplen)
                        ts = float(h.ts.tv_sec) + float(h.ts.tv_usec) / 1_000_000.0
                        self._ingest_raw_packet(
                            RawPacket(timestamp=ts, caplen=h.caplen, origlen=h.len, linktype=dlt, data=raw)
                        )
                    elif rc == 0:
                        pass
                    else:
                        break
                    now = time.monotonic()
                    if now - last_stat_t >= 1.0:
                        last_stat_t = now
                        if lib.pcap_stats(handle, ctypes.byref(st)) == 0:
                            self.kernel_stats = {
                                "recv": int(st.ps_recv),
                                "drop": int(st.ps_drop),
                                "ifdrop": int(st.ps_ifdrop),
                            }
            finally:
                lib.pcap_close(handle)
                self._native_sess = None
                self.capturing = False
                self.processes.stop_background_refresh()
                self._broadcast({"type": "status", "status": self.get_status_snapshot()})

        self._capture_thread = threading.Thread(target=_worker, daemon=True, name="wp-direct-pcap")
        self._capture_thread.start()
        return {"ok": True, "status": self.get_status_snapshot()}

    def _start_dumpcap_capture(
        self, dumpcap_idx: str, bpf_filter: str, promisc: bool, snaplen: int, buffer_mb: int
    ) -> Dict[str, Any]:
        if not self.wireshark.env.dumpcap_path:
            return {"ok": False, "error": "Wireshark dumpcap executable not found."}

        cmd = [
            self.wireshark.env.dumpcap_path,
            "-i", dumpcap_idx,
            "-s", str(snaplen),
            "-B", str(max(2, min(buffer_mb, 64))),
            "-F", "pcap",
            "-q",
            "-w", "-",
        ]
        if not promisc:
            cmd.append("-p")
        if bpf_filter:
            cmd.extend(["-f", bpf_filter])

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        except Exception as e:
            return {"ok": False, "error": f"Failed to launch dumpcap: {e}"}

        self._dumpcap_proc = proc
        self.capturing = True
        self.paused = False
        self.active_engine = "Wireshark dumpcap Bridge (Npcap)"
        self.active_interface = f"NIC #{dumpcap_idx}"
        self.processes.set_windows_bridge(self.wireshark.env.is_wsl_win_exe)
        self.processes.start_background_refresh(3.0)

        def _worker() -> None:
            try:
                assert proc.stdout is not None
                for raw_pkt in iter_capture_stream(proc.stdout):
                    if self._stop_evt.is_set():
                        break
                    self._ingest_raw_packet(raw_pkt)
                    self.kernel_stats["recv"] = len(self.packets)
            except Exception as e:
                if not self._stop_evt.is_set():
                    self.capture_error = str(e)
            finally:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                self._dumpcap_proc = None
                self.capturing = False
                self.processes.stop_background_refresh()
                self._broadcast({"type": "status", "status": self.get_status_snapshot()})

        self._capture_thread = threading.Thread(target=_worker, daemon=True, name="wp-dumpcap")
        self._capture_thread.start()
        return {"ok": True, "status": self.get_status_snapshot()}

    def stop_capture(self) -> Dict[str, Any]:
        self._stop_evt.set()
        if self._native_sess:
            try:
                if self.native.lib:
                    self.native.lib.wp_break(self._native_sess)
                elif self.native.direct and self.native.direct.lib:
                    self.native.direct.lib.pcap_breakloop(self._native_sess)
            except Exception:
                pass
        if self._dumpcap_proc:
            try:
                self._dumpcap_proc.terminate()
            except Exception:
                pass
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)
        self.capturing = False
        self.paused = False
        self.processes.stop_background_refresh()
        self._broadcast({"type": "status", "status": self.get_status_snapshot()})
        return self.get_status_snapshot()

    def toggle_pause(self) -> Dict[str, Any]:
        if self.capturing:
            self.paused = not self.paused
        st = self.get_status_snapshot()
        self._broadcast({"type": "status", "status": st})
        return st

    def load_demo_capture(self, realtime: bool = False) -> Dict[str, Any]:
        """Load or stream the curated multi-protocol + security incident dataset."""
        self.stop_capture()
        self.reset_session()
        pkts, proc_overrides = build_demo_dataset()
        for ip_a, p_a, ip_b, p_b, pid, name, cmdline in proc_overrides:
            self.processes.register_override(ip_a, p_a, ip_b, p_b, pid, name, cmdline)

        self.active_engine = "Interactive Security Lab Dataset"
        self.active_interface = "Demo Scenario (Multi-Protocol + IDS)"

        if not realtime:
            for rp in pkts:
                self._ingest_raw_packet(rp, emit_ws=False)
            self.kernel_stats["recv"] = len(self.packets)
            st = self.get_status_snapshot()
            self._broadcast({"type": "reload", "status": st})
            return {"ok": True, "status": st}

        # Real-time streaming replay (fun for live video demos!)
        self._stop_evt.clear()
        self.capturing = True
        self.paused = False

        def _replay() -> None:
            try:
                for rp in pkts:
                    if self._stop_evt.is_set():
                        break
                    while self.paused and not self._stop_evt.is_set():
                        time.sleep(0.1)
                    self._ingest_raw_packet(rp, emit_ws=True)
                    self.kernel_stats["recv"] = len(self.packets)
                    time.sleep(0.06)
            finally:
                self.capturing = False
                self._broadcast({"type": "status", "status": self.get_status_snapshot()})

        self._capture_thread = threading.Thread(target=_replay, daemon=True, name="wp-demo-replay")
        self._capture_thread.start()
        return {"ok": True, "status": self.get_status_snapshot()}

    def import_pcap_bytes(self, raw_bytes: bytes, filename: str = "uploaded.pcap") -> Dict[str, Any]:
        self.stop_capture()
        self.reset_session()
        try:
            raw_pkts = read_capture_bytes(raw_bytes)
        except Exception as e:
            return {"ok": False, "error": f"Failed to parse capture file: {e}"}

        self.active_engine = "Offline PCAP/PCAPNG Analyzer"
        self.active_interface = filename
        for rp in raw_pkts[: self.MAX_PACKETS]:
            self._ingest_raw_packet(rp, emit_ws=False)
        self.kernel_stats["recv"] = len(self.packets)
        st = self.get_status_snapshot()
        self._broadcast({"type": "reload", "status": st})
        return {"ok": True, "status": st}

    def export_pcap_bytes(self, filter_expr: str = "") -> bytes:
        with self._lock:
            cf = compile_filter(filter_expr) if filter_expr.strip() else None
            selected = [
                RawPacket(p.timestamp, p.caplen, p.origlen, p.linktype, p.raw)
                for p in self.packets
                if (cf is None or cf.matches(p))
            ]
        return write_pcap_bytes(selected)

    # --- Query APIs ---
    def query_packets(self, filter_expr: str = "", offset: int = 0, limit: int = 2000) -> Dict[str, Any]:
        val_res = validate_filter(filter_expr)
        if not val_res["valid"]:
            return {"ok": False, "error": val_res["error"], "pos": val_res["pos"], "packets": [], "totalMatched": 0}
        cf = compile_filter(filter_expr)
        with self._lock:
            matched = [p for p in self.packets if cf.matches(p)]
            total = len(matched)
            page = [p.to_summary() for p in matched[offset : offset + limit]]
        return {
            "ok": True,
            "ast": cf.ast_summary,
            "totalCaptured": len(self.packets),
            "totalMatched": total,
            "offset": offset,
            "packets": page,
        }

    def get_packet_detail(self, packet_no: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            if packet_no < 1 or packet_no > len(self.packets):
                return None
            return self.packets[packet_no - 1].to_detail()

    def get_packet_wireshark_detail(self, packet_no: int) -> Dict[str, Any]:
        with self._lock:
            if packet_no < 1 or packet_no > len(self.packets):
                return {"ok": False, "error": "Packet number out of range"}
            target = self.packets[packet_no - 1]
            # If keylog decryption is active and packet belongs to a TCP stream, feed the full stream context!
            context_pkts: Optional[List[RawPacket]] = None
            target_idx = 1
            if self.wireshark.keylog_path and target.stream_proto == "tcp" and target.stream_id is not None:
                st = self.streams.tcp_streams.get(target.stream_id)
                if st and len(st.packet_nos) <= 400:
                    context_pkts = []
                    for i, pno in enumerate(st.packet_nos, start=1):
                        p = self.packets[pno - 1]
                        context_pkts.append(RawPacket(p.timestamp, p.caplen, p.origlen, p.linktype, p.raw))
                        if pno == packet_no:
                            target_idx = i
            raw_pkt = RawPacket(target.timestamp, target.caplen, target.origlen, target.linktype, target.raw)
        return self.wireshark.dissect_packet_with_wireshark(raw_pkt, context_packets=context_pkts, target_frame_index=target_idx)

    def get_analytics(self) -> Dict[str, Any]:
        with self._lock:
            ts_list = list(self.timeseries)
            if self._sec_bucket_ts > 0 and (not ts_list or ts_list[-1]["ts"] != self._sec_bucket_ts):
                ts_list.append({"ts": self._sec_bucket_ts, "pps": self._sec_pkts, "bps": self._sec_bytes})

            protos = [{"name": k, "count": v} for k, v in self.proto_counts.most_common(16)]
            osi_order = ["L2", "L3", "L4", "L6", "L7"]
            osi_labels = {"L2": "L2 Data Link", "L3": "L3 Network", "L4": "L4 Transport", "L6": "L6 Presentation (TLS)", "L7": "L7 Application"}
            osi = [{"layer": k, "label": osi_labels[k], "count": self.osi_counts.get(k, 0)} for k in osi_order]

            endpoints = sorted(
                self.endpoint_stats.values(),
                key=lambda x: -(x["txBytes"] + x["rxBytes"]),
            )[:25]
            top_endpoints = [
                {
                    "ip": e["ip"],
                    "hostname": self.host_hints.get(e["ip"], ""),
                    "txPackets": e["txPackets"],
                    "rxPackets": e["rxPackets"],
                    "txBytes": e["txBytes"],
                    "rxBytes": e["rxBytes"],
                    "totalBytes": e["txBytes"] + e["rxBytes"],
                    "alerts": e["alerts"],
                    "protocols": sorted(list(e["protocols"]))[:6],
                }
                for e in endpoints
            ]

            top_ip_set = {e["ip"] for e in top_endpoints[:18]}
            nodes = [
                {
                    "id": e["ip"],
                    "label": self.host_hints.get(e["ip"]) or e["ip"],
                    "ip": e["ip"],
                    "bytes": e["txBytes"] + e["rxBytes"],
                    "packets": e["txPackets"] + e["rxPackets"],
                    "alerts": e["alerts"],
                }
                for e in endpoints[:18]
            ]
            edges = [
                {
                    "source": ed["source"],
                    "target": ed["target"],
                    "packets": ed["packets"],
                    "bytes": ed["bytes"],
                    "protocols": sorted(list(ed["protocols"]))[:4],
                    "alerts": ed["alerts"],
                }
                for ed in self.edge_stats.values()
                if ed["source"] in top_ip_set and ed["target"] in top_ip_set
            ]
            edges.sort(key=lambda x: -x["bytes"])

            return {
                "status": self.get_status_snapshot(),
                "timeseries": ts_list[-60:],
                "protocols": protos,
                "osiLayers": osi,
                "topEndpoints": top_endpoints,
                "topology": {"nodes": nodes, "edges": edges[:40]},
            }
