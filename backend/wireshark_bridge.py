"""
WirePulse <-> Wireshark Incremental Integration Bridge.

Provides genuine incremental development on top of Wireshark's ecosystem:
  1. Auto-discovers installed Wireshark tools (sharkd, tshark, dumpcap) across
     Linux, macOS, Windows, and WSL2 -> Windows host installations.
  2. Dual-Engine Dissection: invokes Wireshark's libwireshark engine (via sharkd
     JSON-RPC 2.0 or tshark) to dissect 3,000+ protocols on demand and convert
     libwireshark trees into WirePulse's byte-exact LayerNode/FieldNode format.
  3. TLS Decryption via SSLKEYLOGFILE using Wireshark's TLS dissector.
  4. Custom Wireshark Lua Dissector Plugin Generator (.lua export ready to load
     directly into Wireshark's plugins directory).
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .pcap_io import RawPacket, write_pcap_file


@dataclass
class WiresharkEnvironment:
    available: bool
    version: str = ""
    tshark_path: Optional[str] = None
    sharkd_path: Optional[str] = None
    dumpcap_path: Optional[str] = None
    is_wsl_win_exe: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "version": self.version,
            "tsharkPath": self.tshark_path,
            "sharkdPath": self.sharkd_path,
            "dumpcapPath": self.dumpcap_path,
            "isWslWindowsBridge": self.is_wsl_win_exe,
        }


def _to_tool_path(linux_path: str, is_win_exe: bool) -> str:
    """Convert a WSL /mnt/<drive>/... path to Windows C:\\... path when calling .exe tools."""
    if not is_win_exe or platform.system() == "Windows":
        return linux_path
    try:
        out = subprocess.run(["wslpath", "-w", linux_path], capture_output=True, text=True, timeout=3)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return linux_path


class WiresharkBridge:
    def __init__(self) -> None:
        self.env = self._discover()
        self.keylog_path: Optional[str] = None

    def _discover(self) -> WiresharkEnvironment:
        candidates_dirs = [
            "",  # PATH
            "/usr/bin",
            "/usr/local/bin",
            "/Applications/Wireshark.app/Contents/MacOS",
            r"C:\Program Files\Wireshark",
            r"D:\Wireshark",
            "/mnt/c/Program Files/Wireshark",
            "/mnt/d/Wireshark",
            "/mnt/e/Wireshark",
        ]

        def find_bin(base: str) -> Optional[str]:
            hit = shutil.which(base)
            if hit:
                return hit
            for d in candidates_dirs[1:]:
                for ext in ("", ".exe"):
                    p = os.path.join(d, base + ext)
                    if os.path.isfile(p):
                        return p
            return None

        tshark = find_bin("tshark")
        sharkd = find_bin("sharkd")
        dumpcap = find_bin("dumpcap")
        is_wsl_win = platform.system() != "Windows" and any(
            (p or "").endswith(".exe") for p in (tshark, sharkd, dumpcap)
        )

        version = ""
        probe = tshark or sharkd or dumpcap
        if probe:
            try:
                res = subprocess.run([probe, "--version"], capture_output=True, text=True, timeout=5)
                first = (res.stdout or res.stderr).splitlines()
                if first:
                    version = first[0].strip()
            except Exception:
                version = "Wireshark CLI detected"

        return WiresharkEnvironment(
            available=bool(tshark or sharkd or dumpcap),
            version=version,
            tshark_path=tshark,
            sharkd_path=sharkd,
            dumpcap_path=dumpcap,
            is_wsl_win_exe=is_wsl_win,
        )

    def set_keylog_file(self, path: Optional[str]) -> Dict[str, Any]:
        if not path:
            self.keylog_path = None
            return {"ok": True, "keylogPath": None}
        if not os.path.isfile(path):
            return {"ok": False, "error": f"Keylog file not found: {path}"}
        self.keylog_path = path
        return {"ok": True, "keylogPath": path}

    def list_dumpcap_interfaces(self) -> List[Dict[str, Any]]:
        """Enumerate NICs via Wireshark dumpcap -D (great for Windows/Npcap & WSL bridge)."""
        if not self.env.dumpcap_path:
            return []
        try:
            res = subprocess.run(
                [self.env.dumpcap_path, "-D"],
                capture_output=True,
                timeout=6,
            )
            raw_out = res.stdout.decode("utf-8", errors="replace")
            if not raw_out.strip():
                raw_out = res.stdout.decode("gbk", errors="replace")
            ifaces: List[Dict[str, Any]] = []
            for line in raw_out.splitlines():
                line = line.strip()
                if not line or not line[0].isdigit():
                    continue
                # Format: "7. \Device\NPF_{...} (WLAN)"
                dot = line.find(".")
                if dot == -1:
                    continue
                idx = line[:dot].strip()
                rest = line[dot + 1 :].strip()
                desc = ""
                name = rest
                if rest.endswith(")") and "(" in rest:
                    lp = rest.rfind("(")
                    name = rest[:lp].strip()
                    desc = rest[lp + 1 : -1].strip()
                ifaces.append(
                    {
                        "id": f"dumpcap:{idx}",
                        "dumpcapIndex": idx,
                        "name": desc or name,
                        "device": name,
                        "description": f"Wireshark dumpcap/Npcap #{idx}" + (f" ({desc})" if desc else ""),
                        "engine": "wireshark_dumpcap",
                        "isLoopback": "loopback" in (name + desc).lower(),
                        "isUp": True,
                    }
                )
            return ifaces
        except Exception:
            return []

    def dissect_packet_with_wireshark(
        self,
        raw_pkt: RawPacket,
        context_packets: Optional[List[RawPacket]] = None,
        target_frame_index: int = 1,
    ) -> Dict[str, Any]:
        """
        Dissect a packet using Wireshark's libwireshark engine (preferring sharkd JSON-RPC,
        falling back to tshark -T json). Supports SSLKEYLOGFILE TLS decryption!
        """
        if not self.env.available:
            return {
                "ok": False,
                "error": "Wireshark (sharkd/tshark) not found on this machine. Using WirePulse Native Dissector.",
            }

        pkts_to_write = context_packets if context_packets else [raw_pkt]
        tmp_dir = tempfile.gettempdir()
        # Use a WSL-accessible Windows temp path if invoking .exe from WSL2
        if self.env.is_wsl_win_exe and os.path.isdir("/mnt/c/Windows/Temp"):
            tmp_dir = "/mnt/c/Windows/Temp"

        tmp_fd, tmp_path = tempfile.mkstemp(prefix="wirepulse_ws_", suffix=".pcap", dir=tmp_dir)
        os.close(tmp_fd)
        try:
            write_pcap_file(tmp_path, pkts_to_write, linktype=raw_pkt.linktype)
            tool_pcap_path = _to_tool_path(tmp_path, self.env.is_wsl_win_exe)

            if self.env.sharkd_path:
                result = self._dissect_via_sharkd(tool_pcap_path, target_frame_index)
                if result.get("ok"):
                    return result

            if self.env.tshark_path:
                return self._dissect_via_tshark(tool_pcap_path, target_frame_index)

            return {"ok": False, "error": "Neither sharkd nor tshark succeeded"}
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _dissect_via_sharkd(self, pcap_path: str, frame_no: int) -> Dict[str, Any]:
        reqs = []
        if self.keylog_path:
            kl = _to_tool_path(self.keylog_path, self.env.is_wsl_win_exe)
            reqs.append({"jsonrpc": "2.0", "id": 1, "method": "setconf", "params": {"name": "tls.keylog_file", "value": kl}})
        reqs.append({"jsonrpc": "2.0", "id": 2, "method": "load", "params": {"file": pcap_path}})
        reqs.append({"jsonrpc": "2.0", "id": 3, "method": "frame", "params": {"frame": frame_no, "proto": True, "bytes": True}})
        reqs.append({"jsonrpc": "2.0", "id": 4, "method": "bye"})

        payload = "\n".join(json.dumps(r) for r in reqs) + "\n"
        try:
            proc = subprocess.run(
                [self.env.sharkd_path, "-"],
                input=payload,
                capture_output=True,
                text=True,
                timeout=8,
                encoding="utf-8",
                errors="replace",
            )
            frame_res = None
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                obj = json.loads(line)
                if obj.get("id") == 3 and "result" in obj:
                    frame_res = obj["result"]
                    break
            if not frame_res:
                return {"ok": False, "error": "sharkd returned no frame result"}

            layers = self._convert_sharkd_tree(frame_res.get("tree", []))
            return {
                "ok": True,
                "engine": f"Wireshark libwireshark (sharkd) — {self.env.version}",
                "tlsDecryptionActive": bool(self.keylog_path),
                "layers": layers,
            }
        except Exception as e:
            return {"ok": False, "error": f"sharkd error: {e}"}

    def _convert_sharkd_tree(self, tree: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        layers: List[Dict[str, Any]] = []

        def convert_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            out = []
            for n in nodes:
                pos = n.get("h", [0, 0])
                off = pos[0] if isinstance(pos, list) and len(pos) >= 2 else 0
                ln = pos[1] if isinstance(pos, list) and len(pos) >= 2 else 0
                label = n.get("l", "")
                fkey = n.get("f", "")
                sev = None
                if n.get("s") in ("Error", "Malformed"):
                    sev = "error"
                elif n.get("s") in ("Warning", "Note"):
                    sev = "warn"
                item: Dict[str, Any] = {
                    "key": fkey or "ws.field",
                    "label": label,
                    "value": label,
                    "offset": off,
                    "length": ln,
                }
                if sev:
                    item["severity"] = sev
                if n.get("n"):
                    item["children"] = convert_nodes(n["n"])
                out.append(item)
            return out

        for idx, proto in enumerate(tree):
            pos = proto.get("h", [0, 0])
            off = pos[0] if isinstance(pos, list) and len(pos) >= 2 else 0
            ln = pos[1] if isinstance(pos, list) and len(pos) >= 2 else 0
            title = proto.get("l", f"Protocol {idx}")
            pkey = proto.get("f", title.split(",")[0]).upper()
            osi = 1 if "frame" in pkey.lower() else (2 if any(k in pkey.lower() for k in ("eth", "arp", "vlan", "sll", "null")) else (3 if any(k in pkey.lower() for k in ("ip", "icmp")) else (4 if any(k in pkey.lower() for k in ("tcp", "udp")) else 7)))
            layers.append(
                {
                    "protocol": pkey[:18],
                    "title": title,
                    "osiLayer": osi,
                    "offset": off,
                    "length": ln,
                    "fields": convert_nodes(proto.get("n", [])),
                }
            )
        return layers

    def _dissect_via_tshark(self, pcap_path: str, frame_no: int) -> Dict[str, Any]:
        cmd = [self.env.tshark_path, "-r", pcap_path, "-Y", f"frame.number == {frame_no}", "-T", "json"]
        if self.keylog_path:
            kl = _to_tool_path(self.keylog_path, self.env.is_wsl_win_exe)
            cmd.extend(["-o", f"tls.keylog_file:{kl}"])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8, encoding="utf-8", errors="replace")
            data = json.loads(proc.stdout or "[]")
            if not data:
                return {"ok": False, "error": "tshark returned empty result"}
            raw_layers = data[0].get("_source", {}).get("layers", {})
            layers = []
            for lname, content in raw_layers.items():
                fields = []
                if isinstance(content, dict):
                    for fk, fv in content.items():
                        fields.append({"key": fk, "label": f"{fk}: {fv}", "value": str(fv), "offset": 0, "length": 0})
                layers.append(
                    {
                        "protocol": lname.upper(),
                        "title": f"Wireshark Layer: {lname}",
                        "osiLayer": 7,
                        "offset": 0,
                        "length": 0,
                        "fields": fields[:60],
                    }
                )
            return {
                "ok": True,
                "engine": f"Wireshark tshark — {self.env.version}",
                "tlsDecryptionActive": bool(self.keylog_path),
                "layers": layers,
            }
        except Exception as e:
            return {"ok": False, "error": f"tshark error: {e}"}

    def generate_lua_dissector(
        self,
        proto_name: str,
        description: str,
        transport: str,
        port: int,
        magic_hex: str,
        fields: List[Dict[str, Any]],
    ) -> str:
        """
        Generate a ready-to-install Wireshark Lua Dissector Plugin (.lua).
        Demonstrates bidirectional incremental development with upstream Wireshark!
        """
        safe_id = "".join(ch for ch in proto_name.lower() if ch.isalnum() or ch == "_") or "custom_proto"
        safe_upper = safe_id.upper()
        transport_l = "udp" if transport.lower() == "udp" else "tcp"
        magic_clean = magic_hex.strip().replace("0x", "").replace(" ", "").upper()

        field_decls = []
        field_parses = []
        cursor = 0
        for f in fields:
            fname = "".join(ch for ch in str(f.get("name", "field")).lower() if ch.isalnum() or ch == "_") or "field"
            flabel = str(f.get("label", fname)).replace('"', '\\"')
            ftype = str(f.get("type", "uint16")).lower()
            flen = int(f.get("length", 2))
            if ftype == "uint8":
                lua_t, add_fn, flen = "ProtoField.uint8", "add", 1
            elif ftype == "uint16":
                lua_t, add_fn, flen = "ProtoField.uint16", "add", 2
            elif ftype == "uint32":
                lua_t, add_fn, flen = "ProtoField.uint32", "add", 4
            elif ftype == "string":
                lua_t, add_fn = "ProtoField.string", "add"
            else:
                lua_t, add_fn = "ProtoField.bytes", "add"

            field_decls.append(f'local f_{fname} = {lua_t}("{safe_id}.{fname}", "{flabel}")')
            if flen > 0:
                field_parses.append(
                    f'    if buf_len >= {cursor + flen} then\n'
                    f'        subtree:{add_fn}(f_{fname}, buffer({cursor}, {flen}))\n'
                    f'    end'
                )
                cursor += flen
            else:
                field_parses.append(
                    f'    if buf_len > {cursor} then\n'
                    f'        subtree:{add_fn}(f_{fname}, buffer({cursor}, buf_len - {cursor}))\n'
                    f'    end'
                )

        field_list_str = ", ".join(
            f"f_{(''.join(ch for ch in str(f.get('name', 'field')).lower() if ch.isalnum() or ch == '_') or 'field')}"
            for f in fields
        )
        magic_check = ""
        if magic_clean and len(magic_clean) % 2 == 0:
            magic_bytes = len(magic_clean) // 2
            magic_check = (
                f'    if buf_len >= {magic_bytes} then\n'
                f'        local hdr_hex = tostring(buffer(0, {magic_bytes}):bytes()):upper()\n'
                f'        if hdr_hex ~= "{magic_clean}" then\n'
                f'            return 0 -- Magic bytes mismatch, skip heuristic\n'
                f'        end\n'
                f'    end\n'
            )

        lua_code = f'''-- ============================================================================
-- Wireshark Lua Dissector Plugin — Generated by WirePulse
-- Protocol: {safe_upper} ({description})
-- Install : Copy to Wireshark Personal Lua Plugins folder
--           (Help -> About Wireshark -> Folders -> Personal Lua Plugins)
-- ============================================================================

local p_{safe_id} = Proto("{safe_id}", "{description}")

{chr(10).join(field_decls)}
local f_payload = ProtoField.bytes("{safe_id}.payload", "Remaining Payload")

p_{safe_id}.fields = {{ {field_list_str}{', ' if field_list_str else ''}f_payload }}

function p_{safe_id}.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()
    if buf_len == 0 then return 0 end

{magic_check}    pinfo.cols.protocol = "{safe_upper}"
    local subtree = tree:add(p_{safe_id}, buffer(), "{description} (" .. buf_len .. " bytes)")

{chr(10).join(field_parses)}

    if buf_len > {cursor} then
        subtree:add(f_payload, buffer({cursor}, buf_len - {cursor}))
    end

    pinfo.cols.info = "{safe_upper} Packet (len=" .. buf_len .. ")"
    return buf_len
end

-- Register on {transport_l.upper()} port {port}
local port_table = DissectorTable.get("{transport_l}.port")
port_table:add({port}, p_{safe_id})
'''
        return lua_code
