"""
Pure-Python direct Npcap (wpcap.dll) / libpcap ctypes fallback for environments
where core/wirepulse_pcap.dll has not yet been compiled with MSVC/MinGW.
"""
from __future__ import annotations

import ctypes
import os
import platform
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

from .pcap_io import DLT_EN10MB


class _TimeValWin(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _TimeValPosix(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


_TimeVal = _TimeValWin if platform.system() == "Windows" else _TimeValPosix


class _PcapPktHdr(ctypes.Structure):
    _fields_ = [("ts", _TimeVal), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _SockAddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]


class _PcapAddr(ctypes.Structure):
    pass


_PcapAddr._fields_ = [
    ("next", ctypes.POINTER(_PcapAddr)),
    ("addr", ctypes.POINTER(_SockAddr)),
    ("netmask", ctypes.POINTER(_SockAddr)),
    ("broadaddr", ctypes.POINTER(_SockAddr)),
    ("dstaddr", ctypes.POINTER(_SockAddr)),
]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(_PcapAddr)),
    ("flags", ctypes.c_uint32),
]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint32), ("bf_insns", ctypes.c_void_p)]


class _PcapStat(ctypes.Structure):
    _fields_ = [
        ("ps_recv", ctypes.c_uint32),
        ("ps_drop", ctypes.c_uint32),
        ("ps_ifdrop", ctypes.c_uint32),
        ("ps_capt", ctypes.c_uint32),
    ]


class DirectPcapLoader:
    """Directly binds to wpcap.dll (Npcap on Windows) or libpcap.so when C shim isn't compiled."""

    def __init__(self) -> None:
        self.lib: Optional[ctypes.CDLL] = None
        self.version: str = "unavailable"
        self.error: Optional[str] = None
        self._load()

    def _load(self) -> None:
        try:
            if platform.system() == "Windows":
                npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
                if os.path.isdir(npcap_dir) and hasattr(os, "add_dll_directory"):
                    os.add_dll_directory(npcap_dir)
                lib = ctypes.CDLL("wpcap.dll")
            else:
                lib = None
                for cand in ("libpcap.so.1", "libpcap.so.0.8", "libpcap.so", "libpcap.dylib"):
                    try:
                        lib = ctypes.CDLL(cand)
                        break
                    except OSError:
                        continue
                if lib is None:
                    self.error = "libpcap not found"
                    return

            lib.pcap_lib_version.restype = ctypes.c_char_p
            lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), ctypes.c_char_p]
            lib.pcap_findalldevs.restype = ctypes.c_int
            lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
            lib.pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            lib.pcap_create.restype = ctypes.c_void_p
            lib.pcap_set_snaplen.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.pcap_set_promisc.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.pcap_set_timeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.pcap_set_buffer_size.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.pcap_activate.argtypes = [ctypes.c_void_p]
            lib.pcap_activate.restype = ctypes.c_int
            lib.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
            lib.pcap_open_dead.restype = ctypes.c_void_p
            lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
            lib.pcap_compile.restype = ctypes.c_int
            lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
            lib.pcap_setfilter.restype = ctypes.c_int
            lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
            lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_PcapPktHdr)), ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8))]
            lib.pcap_next_ex.restype = ctypes.c_int
            lib.pcap_datalink.argtypes = [ctypes.c_void_p]
            lib.pcap_datalink.restype = ctypes.c_int
            lib.pcap_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PcapStat)]
            lib.pcap_stats.restype = ctypes.c_int
            lib.pcap_breakloop.argtypes = [ctypes.c_void_p]
            lib.pcap_close.argtypes = [ctypes.c_void_p]
            lib.pcap_geterr.argtypes = [ctypes.c_void_p]
            lib.pcap_geterr.restype = ctypes.c_char_p

            self.lib = lib
            self.version = (lib.pcap_lib_version() or b"Npcap/libpcap").decode("utf-8", errors="replace")
        except Exception as e:
            self.error = str(e)

    @property
    def available(self) -> bool:
        return self.lib is not None

    def list_interfaces(self) -> List[Dict[str, Any]]:
        if not self.lib:
            return []
        err = ctypes.create_string_buffer(256)
        devs = ctypes.POINTER(_PcapIf)()
        if self.lib.pcap_findalldevs(ctypes.byref(devs), err) != 0:
            return []
        out: List[Dict[str, Any]] = []
        cur = devs
        while cur:
            d = cur.contents
            name = (d.name or b"").decode("utf-8", errors="replace")
            desc = (d.description or b"").decode("utf-8", errors="replace")
            ipv4 = ""
            addr_ptr = d.addresses
            while addr_ptr:
                a = addr_ptr.contents
                if a.addr and a.addr.contents.sa_family == socket.AF_INET and not ipv4:
                    raw_ip = bytes(a.addr.contents.sa_data[2:6])
                    ipv4 = socket.inet_ntoa(raw_ip)
                addr_ptr = a.next
            flags = int(d.flags)
            out.append(
                {
                    "id": f"native:{name}",
                    "name": desc or name,
                    "device": name,
                    "description": f"Npcap/libpcap direct ({name})",
                    "ipv4": ipv4,
                    "ipv6": "",
                    "engine": "native_libpcap",
                    "isLoopback": bool(flags & 0x01) or "loopback" in (name + desc).lower(),
                    "isUp": bool(flags & 0x02) or True,
                    "isRunning": bool(flags & 0x04),
                    "isWireless": bool(flags & 0x08),
                }
            )
            cur = d.next
        self.lib.pcap_freealldevs(devs)
        return out

    def validate_bpf(self, expr: str) -> Dict[str, Any]:
        expr = (expr or "").strip()
        if not expr or not self.lib:
            return {"valid": True, "error": None}
        dead = self.lib.pcap_open_dead(DLT_EN10MB, 65535)
        if not dead:
            return {"valid": True, "error": None}
        prog = _BpfProgram()
        rc = self.lib.pcap_compile(dead, ctypes.byref(prog), expr.encode("utf-8"), 1, 0xFFFFFFFF)
        if rc != 0:
            err = (self.lib.pcap_geterr(dead) or b"Invalid BPF").decode("utf-8", errors="replace")
            self.lib.pcap_close(dead)
            return {"valid": False, "error": err}
        self.lib.pcap_freecode(ctypes.byref(prog))
        self.lib.pcap_close(dead)
        return {"valid": True, "error": None}

    def open_live(
        self, iface: str, snaplen: int, promisc: bool, timeout_ms: int, buffer_mb: int, bpf_filter: str
    ) -> Tuple[Optional[ctypes.c_void_p], Optional[str]]:
        if not self.lib:
            return None, self.error or "pcap unavailable"
        err = ctypes.create_string_buffer(256)
        h = self.lib.pcap_create(iface.encode("utf-8"), err)
        if not h:
            return None, err.value.decode("utf-8", errors="replace")
        self.lib.pcap_set_snaplen(h, snaplen)
        self.lib.pcap_set_promisc(h, 1 if promisc else 0)
        self.lib.pcap_set_timeout(h, timeout_ms)
        self.lib.pcap_set_buffer_size(h, buffer_mb * 1024 * 1024)
        if hasattr(self.lib, "pcap_set_immediate_mode"):
            try:
                self.lib.pcap_set_immediate_mode(h, 1)
            except Exception:
                pass
        rc = self.lib.pcap_activate(h)
        if rc < 0:
            msg = (self.lib.pcap_geterr(h) or b"pcap_activate failed").decode("utf-8", errors="replace")
            self.lib.pcap_close(h)
            return None, msg
        if bpf_filter:
            prog = _BpfProgram()
            if self.lib.pcap_compile(h, ctypes.byref(prog), bpf_filter.encode("utf-8"), 1, 0xFFFFFFFF) != 0:
                msg = (self.lib.pcap_geterr(h) or b"BPF compile failed").decode("utf-8", errors="replace")
                self.lib.pcap_close(h)
                return None, msg
            if self.lib.pcap_setfilter(h, ctypes.byref(prog)) != 0:
                msg = (self.lib.pcap_geterr(h) or b"BPF setfilter failed").decode("utf-8", errors="replace")
                self.lib.pcap_freecode(ctypes.byref(prog))
                self.lib.pcap_close(h)
                return None, msg
            self.lib.pcap_freecode(ctypes.byref(prog))
        return h, None
