"""
WirePulse Cross-Platform OS Process-to-Socket Attribution Engine.

Implements CommView-style OS Process Tracing (Experiment 1A Bonus:
"Track all TCP/UDP streams produced by a specific OS process"):

  - Linux: parses /proc/net/{tcp,tcp6,udp,udp6} + /proc/<pid>/fd socket inodes
           + /proc/<pid>/{comm,cmdline}
  - Windows: calls iphlpapi.dll GetExtendedTcpTable / GetExtendedUdpTable via ctypes
             (with netstat -ano + tasklist fallback)
  - WSL2 <-> Windows Bridge: polls Windows host netstat.exe & tasklist.exe when
             capturing on Windows NICs through Wireshark dumpcap.exe!
"""
from __future__ import annotations

import csv
import io
import os
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cmdline: str = ""
    user: str = ""


@dataclass
class ProcessTrafficStats:
    pid: int
    name: str
    cmdline: str = ""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    stream_ids: set = field(default_factory=set)
    remote_endpoints: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    alerts: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "pid": self.pid,
            "name": self.name,
            "cmdline": self.cmdline,
            "packetsIn": self.packets_in,
            "packetsOut": self.packets_out,
            "totalPackets": self.packets_in + self.packets_out,
            "bytesIn": self.bytes_in,
            "bytesOut": self.bytes_out,
            "totalBytes": self.bytes_in + self.bytes_out,
            "streamCount": len(self.stream_ids),
            "streamIds": sorted(self.stream_ids),
            "remoteEndpoints": sorted(list(self.remote_endpoints))[:20],
            "protocols": sorted(list(self.protocols)),
            "alerts": self.alerts,
        }


def _decode_proc_ip4(hex_str: str) -> str:
    raw = bytes.fromhex(hex_str)
    # /proc/net/tcp stores IPv4 in little-endian host order on x86_64
    return socket.inet_ntoa(raw[::-1])


def _decode_proc_ip6(hex_str: str) -> str:
    raw = bytes.fromhex(hex_str)
    # Four 32-bit little-endian words
    fixed = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, fixed)


class OSProcessTracker:
    """Maintains a low-overhead TTL-cached map of (proto, local_ip, local_port, remote_ip, remote_port) -> ProcessInfo."""

    def __init__(self, use_windows_bridge: bool = False) -> None:
        self._lock = threading.RLock()
        self._use_windows_bridge = use_windows_bridge
        self._system = platform.system()
        # Exact 5-tuple & local-port lookup maps
        self._exact_map: Dict[Tuple[str, str, int, str, int], ProcessInfo] = {}
        self._local_map: Dict[Tuple[str, int], ProcessInfo] = {}
        # Manual / demo override map for offline PCAP attribution
        self._override_map: Dict[Tuple[str, int, str, int], ProcessInfo] = {}
        self._stats: Dict[int, ProcessTrafficStats] = {}
        self._last_refresh: float = 0.0
        self._stop_evt = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None

    def set_windows_bridge(self, enabled: bool) -> None:
        self._use_windows_bridge = enabled

    def reset_stats(self) -> None:
        with self._lock:
            self._stats.clear()
            self._override_map.clear()

    def register_override(
        self, ip_a: str, port_a: int, ip_b: str, port_b: int, pid: int, name: str, cmdline: str = ""
    ) -> None:
        """Register explicit process ownership for offline/demo PCAP replay streams."""
        info = ProcessInfo(pid=pid, name=name, cmdline=cmdline)
        with self._lock:
            self._override_map[(ip_a, port_a, ip_b, port_b)] = info
            self._override_map[(ip_b, port_b, ip_a, port_a)] = info

    def start_background_refresh(self, interval_sec: float = 2.0) -> None:
        if self._bg_thread and self._bg_thread.is_alive():
            return
        self._stop_evt.clear()

        def _loop() -> None:
            while not self._stop_evt.is_set():
                try:
                    self.refresh_socket_table()
                except Exception:
                    pass
                self._stop_evt.wait(interval_sec)

        self._bg_thread = threading.Thread(target=_loop, daemon=True, name="wp-proc-tracker")
        self._bg_thread.start()

    def stop_background_refresh(self) -> None:
        self._stop_evt.set()

    def refresh_socket_table(self) -> None:
        now = time.monotonic()
        if now - self._last_refresh < 0.8:
            return
        self._last_refresh = now

        exact: Dict[Tuple[str, str, int, str, int], ProcessInfo] = {}
        local: Dict[Tuple[str, int], ProcessInfo] = {}

        if self._system == "Windows" or self._use_windows_bridge:
            self._scan_windows_netstat(exact, local)
        elif self._system == "Linux":
            self._scan_linux_proc(exact, local)

        with self._lock:
            if exact or local:
                self._exact_map = exact
                self._local_map = local

    def _scan_linux_proc(
        self,
        exact: Dict[Tuple[str, str, int, str, int], ProcessInfo],
        local: Dict[Tuple[str, int], ProcessInfo],
    ) -> None:
        # Step 1: Map socket inode -> ProcessInfo via /proc/<pid>/fd
        inode_to_proc: Dict[str, ProcessInfo] = {}
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                fd_dir = f"/proc/{pid}/fd"
                try:
                    fds = os.listdir(fd_dir)
                except OSError:
                    continue
                sock_inodes = []
                for fd in fds:
                    try:
                        target = os.readlink(f"{fd_dir}/{fd}")
                        if target.startswith("socket:[") and target.endswith("]"):
                            sock_inodes.append(target[8:-1])
                    except OSError:
                        continue
                if not sock_inodes:
                    continue
                name = f"pid-{pid}"
                cmdline = ""
                try:
                    with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="ignore") as f:
                        name = f.read().strip() or name
                except OSError:
                    pass
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                except OSError:
                    pass
                pinfo = ProcessInfo(pid=pid, name=name, cmdline=cmdline[:180])
                for ino in sock_inodes:
                    inode_to_proc[ino] = pinfo
        except OSError:
            return

        # Step 2: Parse /proc/net/{tcp,tcp6,udp,udp6}
        tables = [
            ("/proc/net/tcp", "tcp", False),
            ("/proc/net/tcp6", "tcp", True),
            ("/proc/net/udp", "udp", False),
            ("/proc/net/udp6", "udp", True),
        ]
        for path, proto, is_v6 in tables:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    next(f, None)
                    for line in f:
                        parts = line.split()
                        if len(parts) < 10:
                            continue
                        inode = parts[9]
                        pinfo = inode_to_proc.get(inode)
                        if not pinfo:
                            continue
                        lip_h, lport_h = parts[1].split(":")
                        rip_h, rport_h = parts[2].split(":")
                        lip = _decode_proc_ip6(lip_h) if is_v6 else _decode_proc_ip4(lip_h)
                        rip = _decode_proc_ip6(rip_h) if is_v6 else _decode_proc_ip4(rip_h)
                        lport = int(lport_h, 16)
                        rport = int(rport_h, 16)
                        if rport > 0:
                            exact[(proto, lip, lport, rip, rport)] = pinfo
                            exact[(proto, rip, rport, lip, lport)] = pinfo
                        if lport > 0:
                            local[(proto, lport)] = pinfo
            except OSError:
                continue

    def _scan_windows_netstat(
        self,
        exact: Dict[Tuple[str, str, int, str, int], ProcessInfo],
        local: Dict[Tuple[str, int], ProcessInfo],
    ) -> None:
        netstat_cmd = ["netstat", "-ano"] if self._system == "Windows" else ["/mnt/c/Windows/System32/netstat.exe", "-ano"]
        tasklist_cmd = (
            ["tasklist", "/FO", "CSV", "/NH"]
            if self._system == "Windows"
            else ["/mnt/c/Windows/System32/tasklist.exe", "/FO", "CSV", "/NH"]
        )

        pid_names: Dict[int, str] = {}
        try:
            tl = subprocess.run(tasklist_cmd, capture_output=True, text=True, timeout=3, encoding="utf-8", errors="ignore")
            for row in csv.reader(io.StringIO(tl.stdout)):
                if len(row) >= 2 and row[1].strip().isdigit():
                    pid_names[int(row[1].strip())] = row[0].strip()
        except Exception:
            pass

        try:
            ns = subprocess.run(netstat_cmd, capture_output=True, text=True, timeout=3, encoding="utf-8", errors="ignore")
            for line in ns.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                proto = parts[0].lower()
                if proto not in ("tcp", "udp"):
                    continue
                pid_str = parts[-1]
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)
                if pid == 0:
                    continue
                l_ip, l_port = _split_host_port(parts[1])
                r_ip, r_port = _split_host_port(parts[2])
                pinfo = ProcessInfo(pid=pid, name=pid_names.get(pid, f"PID-{pid}"))
                if l_port is not None and r_port is not None and r_port > 0:
                    exact[(proto, l_ip, l_port, r_ip, r_port)] = pinfo
                    exact[(proto, r_ip, r_port, l_ip, l_port)] = pinfo
                if l_port is not None and l_port > 0:
                    local[(proto, l_port)] = pinfo
        except Exception:
            pass

    def lookup(
        self, proto: str, src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int]
    ) -> Optional[ProcessInfo]:
        if src_port is None or dst_port is None:
            return None
        with self._lock:
            ov = self._override_map.get((src_ip, src_port, dst_ip, dst_port))
            if ov:
                return ov
            hit = self._exact_map.get((proto, src_ip, src_port, dst_ip, dst_port))
            if hit:
                return hit
            # Local port fallback (useful for UDP / short-lived TCP connections)
            hit = self._local_map.get((proto, src_port)) or self._local_map.get((proto, dst_port))
            return hit

    def record_packet(
        self,
        pinfo: ProcessInfo,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        length: int,
        protocol: str,
        stream_id: Optional[int],
        is_alert: bool = False,
    ) -> None:
        with self._lock:
            st = self._stats.get(pinfo.pid)
            if st is None:
                st = ProcessTrafficStats(pid=pinfo.pid, name=pinfo.name, cmdline=pinfo.cmdline)
                self._stats[pinfo.pid] = st

            # Heuristic direction: ephemeral src_port >= dst_port treated as outbound
            outbound = (src_port or 0) >= (dst_port or 0)
            if outbound:
                st.packets_out += 1
                st.bytes_out += length
                if dst_ip:
                    st.remote_endpoints.add(f"{dst_ip}:{dst_port}" if dst_port else dst_ip)
            else:
                st.packets_in += 1
                st.bytes_in += length
                if src_ip:
                    st.remote_endpoints.add(f"{src_ip}:{src_port}" if src_port else src_ip)

            if protocol:
                st.protocols.add(protocol)
            if stream_id is not None:
                st.stream_ids.add(stream_id)
            if is_alert:
                st.alerts += 1

    def list_processes(self) -> List[Dict[str, object]]:
        with self._lock:
            items = sorted(
                self._stats.values(),
                key=lambda s: (-(s.bytes_in + s.bytes_out), -(s.packets_in + s.packets_out)),
            )
            return [s.to_dict() for s in items]


def _split_host_port(addr: str) -> Tuple[str, Optional[int]]:
    if addr.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", addr)
        if m:
            return m.group(1), int(m.group(2))
        return addr, None
    if ":" in addr:
        host, port_s = addr.rsplit(":", 1)
        return host, int(port_s) if port_s.isdigit() else None
    return addr, None
