"""
WirePulse TCP/UDP Stream Reassembly & Interactive Flow Sequence Diagram Engine.

Implements:
  - Bidirectional 5-tuple TCP & UDP stream indexing (tcp.stream / udp.stream)
  - Sequence-ordered TCP payload reassembly (deduplicating retransmissions & sorting out-of-order segments)
  - TCP Expert Analysis (Retransmission, Out-of-Order, Dup ACK, Zero Window, Handshake RTT)
  - Follow Stream payload view (Client -> Server vs Server -> Client colored chunks, UTF-8/Hex/HTTP)
  - Flow Sequence / Ladder Diagram events for graphical timeline visualization
"""
from __future__ import annotations

import base64
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .dissector.models import FieldNode, PacketRecord


def _bytes_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:4096]
    counts: Dict[int, int] = {}
    for b in sample:
        counts[b] = counts.get(b, 0) + 1
    n = float(len(sample))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _to_wireshark_ascii(data: bytes, max_bytes: int = 16384) -> str:
    """Wireshark Follow Stream ASCII mode: printable ASCII + \\r\\n\\t kept, all other bytes rendered as '.'."""
    chunk = data[:max_bytes]
    chars = []
    for b in chunk:
        if 32 <= b <= 126 or b in (9, 10, 13):
            chars.append(chr(b))
        else:
            chars.append(".")
    return "".join(chars)


def _to_clean_utf8(data: bytes, max_bytes: int = 16384) -> str:
    """UTF-8 decoding with raw C0/C1 control chars replaced by '.' so no ugly tofu boxes appear."""
    decoded = data[:max_bytes].decode("utf-8", errors="replace")
    out = []
    for ch in decoded:
        code = ord(ch)
        if ch in ("\n", "\r", "\t") or (code >= 32 and code != 0x7F and code != 0xFFFD):
            out.append(ch)
        else:
            out.append(".")
    return "".join(out)


def _is_binary_payload(data: bytes) -> Tuple[bool, float]:
    if not data:
        return False, 0.0
    sample = data[:2048]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = printable / float(len(sample))
    ent = _bytes_entropy(sample)
    # Check if valid UTF-8 text (e.g., Chinese JSON/HTML) vs true binary/encrypted bytes
    utf8_ok = False
    try:
        dec = sample.decode("utf-8")
        ctrl = sum(1 for ch in dec if ord(ch) < 32 and ch not in ("\n", "\r", "\t"))
        utf8_ok = (ctrl / max(1, len(dec))) < 0.05
    except UnicodeDecodeError:
        utf8_ok = False
    is_bin = (not utf8_ok and ratio < 0.78) or (ratio < 0.65 and ent > 5.8)
    return is_bin, round(ent, 2)


@dataclass
class StreamSegment:
    packet_no: int
    timestamp: float
    rel_time: float
    direction: str  # "c2s" | "s2c"
    seq: int
    ack: int
    flags: int
    flags_str: str
    window: int
    payload: bytes
    info: str
    expert: List[str] = field(default_factory=list)


@dataclass
class FlowStream:
    stream_id: int
    proto: str  # "tcp" | "udp"
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    app_protocol: str = ""
    sni: str = ""
    http_host: str = ""
    pid: Optional[int] = None
    process_name: str = ""

    start_time: float = 0.0
    end_time: float = 0.0
    handshake_rtt_ms: Optional[float] = None
    state: str = "ACTIVE"
    packet_nos: List[int] = field(default_factory=list)
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    segments: List[StreamSegment] = field(default_factory=list)

    # Internal TCP expert state per direction ("c2s", "s2c")
    _max_next_seq: Dict[str, int] = field(default_factory=dict)
    _seen_seq_ranges: Dict[str, List[Tuple[int, int]]] = field(default_factory=lambda: {"c2s": [], "s2c": []})
    _last_ack: Dict[str, Tuple[int, int]] = field(default_factory=dict)  # ack -> repeat count
    _syn_ts: Optional[float] = None
    _synack_ts: Optional[float] = None

    def to_summary(self) -> Dict[str, Any]:
        return {
            "streamId": self.stream_id,
            "proto": self.proto,
            "client": f"{self.client_ip}:{self.client_port}",
            "server": f"{self.server_ip}:{self.server_port}",
            "clientIp": self.client_ip,
            "clientPort": self.client_port,
            "serverIp": self.server_ip,
            "serverPort": self.server_port,
            "appProtocol": self.app_protocol or self.proto.upper(),
            "host": self.sni or self.http_host or "",
            "pid": self.pid,
            "processName": self.process_name,
            "packets": len(self.packet_nos),
            "bytesC2S": self.bytes_c2s,
            "bytesS2C": self.bytes_s2c,
            "totalBytes": self.bytes_c2s + self.bytes_s2c,
            "durationMs": round(max(0.0, (self.end_time - self.start_time) * 1000.0), 2),
            "rttMs": round(self.handshake_rtt_ms, 2) if self.handshake_rtt_ms is not None else None,
            "state": self.state,
            "retransmissions": self.retransmissions,
            "outOfOrder": self.out_of_order,
        }


class StreamTracker:
    def __init__(self) -> None:
        self._tcp_key_to_id: Dict[Tuple[str, int, str, int], int] = {}
        self._udp_key_to_id: Dict[Tuple[str, int, str, int], int] = {}
        self.tcp_streams: Dict[int, FlowStream] = {}
        self.udp_streams: Dict[int, FlowStream] = {}

    def reset(self) -> None:
        self._tcp_key_to_id.clear()
        self._udp_key_to_id.clear()
        self.tcp_streams.clear()
        self.udp_streams.clear()

    def _canonical_key(self, ip1: str, p1: int, ip2: str, p2: int) -> Tuple[str, int, str, int]:
        if (ip1, p1) <= (ip2, p2):
            return (ip1, p1, ip2, p2)
        return (ip2, p2, ip1, p1)

    def ingest(self, pkt: PacketRecord) -> None:
        if pkt.src_port is None or pkt.dst_port is None:
            return
        if "tcp" in pkt.protocols:
            self._ingest_tcp(pkt)
        elif "udp" in pkt.protocols:
            self._ingest_udp(pkt)

    def _ingest_tcp(self, pkt: PacketRecord) -> None:
        ckey = self._canonical_key(pkt.src, pkt.src_port or 0, pkt.dst, pkt.dst_port or 0)
        sid = self._tcp_key_to_id.get(ckey)
        if sid is None:
            sid = len(self.tcp_streams)
            self._tcp_key_to_id[ckey] = sid
            # Heuristic: SYN initiator or higher ephemeral port is client
            is_syn_only = bool(pkt.tcp_flags & 0x0002) and not bool(pkt.tcp_flags & 0x0010)
            if is_syn_only or (pkt.src_port or 0) >= (pkt.dst_port or 0):
                c_ip, c_p, s_ip, s_p = pkt.src, pkt.src_port or 0, pkt.dst, pkt.dst_port or 0
            else:
                c_ip, c_p, s_ip, s_p = pkt.dst, pkt.dst_port or 0, pkt.src, pkt.src_port or 0
            stream = FlowStream(
                stream_id=sid,
                proto="tcp",
                client_ip=c_ip,
                client_port=c_p,
                server_ip=s_ip,
                server_port=s_p,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
                state="SYN_SENT" if is_syn_only else "ESTABLISHED",
            )
            self.tcp_streams[sid] = stream
        else:
            stream = self.tcp_streams[sid]

        pkt.stream_id = sid
        pkt.stream_proto = "tcp"
        pkt.add_field_index("tcp.stream", sid)

        direction = "c2s" if (pkt.src == stream.client_ip and pkt.src_port == stream.client_port) else "s2c"
        stream.end_time = max(stream.end_time, pkt.timestamp)
        stream.packet_nos.append(pkt.no)

        if pkt.protocol not in ("TCP", "IPv4", "IPv6"):
            stream.app_protocol = pkt.protocol
        if not stream.sni and pkt.fields_index.get("tls.handshake.sni"):
            stream.sni = str(pkt.fields_index["tls.handshake.sni"][0])
        if not stream.http_host and pkt.fields_index.get("http.host"):
            stream.http_host = str(pkt.fields_index["http.host"][0])
        if pkt.pid is not None and stream.pid is None:
            stream.pid = pkt.pid
            stream.process_name = pkt.process_name
        elif stream.pid is not None and pkt.pid is None:
            pkt.pid = stream.pid
            pkt.process_name = stream.process_name

        payload = (
            pkt.raw[pkt.tcp_payload_offset : pkt.tcp_payload_offset + pkt.tcp_payload_len]
            if pkt.tcp_payload_len > 0
            else b""
        )
        if direction == "c2s":
            stream.bytes_c2s += len(payload)
        else:
            stream.bytes_s2c += len(payload)

        # TCP State & Handshake RTT tracking
        flags = pkt.tcp_flags
        syn = bool(flags & 0x0002)
        ack = bool(flags & 0x0010)
        fin = bool(flags & 0x0001)
        rst = bool(flags & 0x0004)
        if syn and not ack:
            stream._syn_ts = pkt.timestamp
            stream.state = "SYN_SENT"
        elif syn and ack:
            stream._synack_ts = pkt.timestamp
            if stream._syn_ts is not None and stream.handshake_rtt_ms is None:
                stream.handshake_rtt_ms = max(0.0, (pkt.timestamp - stream._syn_ts) * 1000.0)
            stream.state = "SYN_RECEIVED"
        elif rst:
            stream.state = "RESET"
        elif fin:
            stream.state = "FIN_WAIT" if stream.state != "FIN_WAIT" else "CLOSED"
        elif ack and stream.state in ("SYN_RECEIVED", "SYN_SENT"):
            stream.state = "ESTABLISHED"

        # TCP Expert Analysis (Retransmission, Out-of-Order, Dup ACK, Zero Window)
        expert: List[str] = []
        seq = pkt.tcp_seq or 0
        seq_end = (seq + len(payload) + (1 if syn else 0) + (1 if fin else 0)) & 0xFFFFFFFF

        if pkt.tcp_window == 0 and not rst and not syn:
            expert.append("Zero Window")

        if rst:
            expert.append("Connection Reset (RST)")

        prev_max = stream._max_next_seq.get(direction)
        if len(payload) > 0:
            if prev_max is not None:
                # Signed 32-bit comparison for wrap-around safety
                diff = ((seq - prev_max) + 0x80000000) % 0x100000000 - 0x80000000
                if diff < 0:
                    # Check if already seen (Retransmission) vs newly arrived earlier segment (Out-of-Order)
                    already_seen = any(s0 <= seq < s1 for s0, s1 in stream._seen_seq_ranges[direction])
                    if already_seen:
                        expert.append("Retransmission")
                        stream.retransmissions += 1
                    else:
                        expert.append("Out-of-Order")
                        stream.out_of_order += 1
            if prev_max is None or (((seq_end - prev_max) + 0x80000000) % 0x100000000 - 0x80000000) > 0:
                stream._max_next_seq[direction] = seq_end
            stream._seen_seq_ranges[direction].append((seq, seq + len(payload)))
            if len(stream._seen_seq_ranges[direction]) > 512:
                stream._seen_seq_ranges[direction] = stream._seen_seq_ranges[direction][-256:]
        elif ack and not syn and not fin and not rst:
            # Pure ACK -> check Duplicate ACK
            ack_num = pkt.tcp_ack or 0
            last_a, cnt = stream._last_ack.get(direction, (-1, 0))
            if ack_num == last_a:
                cnt += 1
                stream._last_ack[direction] = (ack_num, cnt)
                if cnt >= 2:
                    expert.append(f"Dup ACK #{cnt - 1}")
            else:
                stream._last_ack[direction] = (ack_num, 1)

        if expert:
            pkt.tcp_expert.extend(expert)
            pkt.info = f"[{' | '.join(expert)}] {pkt.info}"
            # Inject expert annotations into TCP LayerNode
            for layer in pkt.layers:
                if layer.protocol == "TCP":
                    layer.fields.append(
                        FieldNode(
                            "tcp.analysis.flags",
                            f"SEQ/ACK Expert Analysis: {', '.join(expert)}",
                            ", ".join(expert),
                            layer.offset,
                            layer.length,
                            4,
                            severity="warn",
                        )
                    )
                    break

        # Also inject tcp.stream into TCP LayerNode
        for layer in pkt.layers:
            if layer.protocol == "TCP":
                layer.fields.insert(0, FieldNode("tcp.stream", f"Stream index: {sid}", sid, layer.offset, 4, 4))
                break

        stream.segments.append(
            StreamSegment(
                packet_no=pkt.no,
                timestamp=pkt.timestamp,
                rel_time=pkt.rel_time,
                direction=direction,
                seq=seq,
                ack=pkt.tcp_ack or 0,
                flags=flags,
                flags_str=pkt.tcp_flags_str,
                window=pkt.tcp_window or 0,
                payload=payload,
                info=pkt.info,
                expert=expert,
            )
        )

    def _ingest_udp(self, pkt: PacketRecord) -> None:
        ckey = self._canonical_key(pkt.src, pkt.src_port or 0, pkt.dst, pkt.dst_port or 0)
        sid = self._udp_key_to_id.get(ckey)
        if sid is None:
            sid = len(self.udp_streams)
            self._udp_key_to_id[ckey] = sid
            if (pkt.src_port or 0) >= (pkt.dst_port or 0):
                c_ip, c_p, s_ip, s_p = pkt.src, pkt.src_port or 0, pkt.dst, pkt.dst_port or 0
            else:
                c_ip, c_p, s_ip, s_p = pkt.dst, pkt.dst_port or 0, pkt.src, pkt.src_port or 0
            stream = FlowStream(
                stream_id=sid,
                proto="udp",
                client_ip=c_ip,
                client_port=c_p,
                server_ip=s_ip,
                server_port=s_p,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
                state="STATELESS",
            )
            self.udp_streams[sid] = stream
        else:
            stream = self.udp_streams[sid]

        pkt.stream_id = sid
        pkt.stream_proto = "udp"
        pkt.add_field_index("udp.stream", sid)

        direction = "c2s" if (pkt.src == stream.client_ip and pkt.src_port == stream.client_port) else "s2c"
        stream.end_time = max(stream.end_time, pkt.timestamp)
        stream.packet_nos.append(pkt.no)
        if pkt.protocol not in ("UDP", "IPv4", "IPv6"):
            stream.app_protocol = pkt.protocol
        if pkt.pid is not None and stream.pid is None:
            stream.pid = pkt.pid
            stream.process_name = pkt.process_name
        elif stream.pid is not None and pkt.pid is None:
            pkt.pid = stream.pid
            pkt.process_name = stream.process_name

        # Locate UDP payload bytes
        udp_payload = b""
        for layer in pkt.layers:
            if layer.protocol == "UDP":
                layer.fields.insert(0, FieldNode("udp.stream", f"Stream index: {sid}", sid, layer.offset, 4, 4))
                poff = layer.offset + layer.length
                udp_payload = pkt.raw[poff:]
                break

        if direction == "c2s":
            stream.bytes_c2s += len(udp_payload)
        else:
            stream.bytes_s2c += len(udp_payload)

        stream.segments.append(
            StreamSegment(
                packet_no=pkt.no,
                timestamp=pkt.timestamp,
                rel_time=pkt.rel_time,
                direction=direction,
                seq=0,
                ack=0,
                flags=0,
                flags_str="UDP",
                window=0,
                payload=udp_payload,
                info=pkt.info,
            )
        )

    def list_streams(self, proto: Optional[str] = None, pid: Optional[int] = None, process_name: Optional[str] = None) -> List[Dict[str, Any]]:
        result: List[FlowStream] = []
        if proto in (None, "all", "tcp"):
            result.extend(self.tcp_streams.values())
        if proto in (None, "all", "udp"):
            result.extend(self.udp_streams.values())
        if pid is not None:
            result = [s for s in result if s.pid == pid]
        if process_name:
            pn = process_name.lower()
            result = [s for s in result if pn in s.process_name.lower()]
        result.sort(key=lambda s: (-s.bytes_c2s - s.bytes_s2c, s.stream_id))
        return [s.to_summary() for s in result]

    def follow_stream(self, proto: str, stream_id: int) -> Optional[Dict[str, Any]]:
        """
        Reassemble ordered bidirectional conversation chunks + interactive Flow Sequence Diagram.
        Deduplicates TCP retransmissions while preserving conversational turn order.
        """
        store = self.tcp_streams if proto == "tcp" else self.udp_streams
        stream = store.get(stream_id)
        if not stream:
            return None

        # Build conversational turns (skipping pure retransmissions in reassembled text)
        turns: List[Dict[str, Any]] = []
        seen_c2s_seq: set = set()
        seen_s2c_seq: set = set()

        for seg in stream.segments:
            if not seg.payload:
                continue
            if proto == "tcp":
                seen_set = seen_c2s_seq if seg.direction == "c2s" else seen_s2c_seq
                sig = (seg.seq, len(seg.payload))
                if sig in seen_set:
                    continue
                seen_set.add(sig)

            if turns and turns[-1]["direction"] == seg.direction:
                turns[-1]["_raw"] += seg.payload
                turns[-1]["packetNos"].append(seg.packet_no)
            else:
                turns.append(
                    {
                        "direction": seg.direction,
                        "packetNos": [seg.packet_no],
                        "timestamp": round(seg.rel_time, 6),
                        "_raw": bytearray(seg.payload),
                    }
                )

        serialized_turns = []
        for t in turns:
            raw_b = bytes(t["_raw"])
            is_bin, ent = _is_binary_payload(raw_b)
            serialized_turns.append(
                {
                    "direction": t["direction"],
                    "packetNos": t["packetNos"],
                    "timestamp": t["timestamp"],
                    "length": len(raw_b),
                    "isBinary": is_bin,
                    "entropy": ent,
                    "ascii": _to_wireshark_ascii(raw_b, 16384),
                    "text": _to_clean_utf8(raw_b, 16384),
                    "hex": raw_b[:8192].hex(),
                    "truncated": len(raw_b) > 8192,
                    "rawBase64": base64.b64encode(raw_b[:65536]).decode("ascii"),
                }
            )

        # Build Flow Sequence / Ladder Diagram timeline (all control + data frames)
        sequence_events = []
        prev_ts = stream.segments[0].timestamp if stream.segments else 0.0
        for seg in stream.segments[:300]:
            delta_ms = round(max(0.0, (seg.timestamp - prev_ts) * 1000.0), 3)
            prev_ts = seg.timestamp
            sequence_events.append(
                {
                    "packetNo": seg.packet_no,
                    "relTime": round(seg.rel_time, 6),
                    "deltaMs": delta_ms,
                    "direction": seg.direction,
                    "flags": seg.flags_str,
                    "payloadLen": len(seg.payload),
                    "window": seg.window,
                    "info": seg.info[:140],
                    "expert": seg.expert,
                }
            )

        return {
            "summary": stream.to_summary(),
            "turns": serialized_turns,
            "sequence": sequence_events,
        }
