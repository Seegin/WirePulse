"""
Data models for byte-exact OSI 7-layer packet dissection.

Every FieldNode carries absolute frame byte offset and length so the GUI can
perform bidirectional highlighting between the Packet Details tree and the
Hex/ASCII/Binary viewer (matching Wireshark's core UX).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FieldNode:
    key: str
    label: str
    value: Any
    offset: int = 0
    length: int = 0
    osi_layer: int = 0
    severity: Optional[str] = None  # "info" | "warn" | "error"
    children: List["FieldNode"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "offset": self.offset,
            "length": self.length,
        }
        if self.osi_layer:
            d["osiLayer"] = self.osi_layer
        if self.severity:
            d["severity"] = self.severity
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


@dataclass
class LayerNode:
    protocol: str
    title: str
    osi_layer: int
    offset: int
    length: int
    fields: List[FieldNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "title": self.title,
            "osiLayer": self.osi_layer,
            "offset": self.offset,
            "length": self.length,
            "fields": [f.to_dict() for f in self.fields],
        }


@dataclass
class PacketRecord:
    no: int
    timestamp: float
    rel_time: float
    delta_time: float
    caplen: int
    origlen: int
    linktype: int
    raw: bytes

    src: str = ""
    dst: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "RAW"
    protocols: List[str] = field(default_factory=list)
    osi_top_layer: int = 2
    info: str = ""
    dpi_method: str = ""

    # Stream & OS Process attribution
    stream_id: Optional[int] = None
    stream_proto: Optional[str] = None  # "tcp" | "udp"
    pid: Optional[int] = None
    process_name: str = ""

    # TCP metadata for stream & expert analysis
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: int = 0
    tcp_flags_str: str = ""
    tcp_window: Optional[int] = None
    tcp_payload_offset: int = 0
    tcp_payload_len: int = 0
    tcp_expert: List[str] = field(default_factory=list)

    # Security Alerts linked to this packet
    alert_severity: Optional[str] = None
    alert_rules: List[str] = field(default_factory=list)

    # Full OSI layer tree and flat field index for Display Filter AST evaluation
    layers: List[LayerNode] = field(default_factory=list)
    fields_index: Dict[str, List[Any]] = field(default_factory=dict)

    def add_field_index(self, key: str, value: Any) -> None:
        if not key:
            return
        bucket = self.fields_index.get(key)
        if bucket is None:
            self.fields_index[key] = [value]
        else:
            bucket.append(value)

    def to_summary(self) -> Dict[str, Any]:
        """Compact row representation for high-speed Packet List streaming & virtualization."""
        return {
            "no": self.no,
            "timestamp": round(self.timestamp, 6),
            "relTime": round(self.rel_time, 6),
            "deltaTime": round(self.delta_time, 6),
            "src": self.src,
            "dst": self.dst,
            "srcPort": self.src_port,
            "dstPort": self.dst_port,
            "protocol": self.protocol,
            "protocols": self.protocols,
            "osiLayer": self.osi_top_layer,
            "length": self.origlen,
            "caplen": self.caplen,
            "info": self.info,
            "dpiMethod": self.dpi_method,
            "streamId": self.stream_id,
            "streamProto": self.stream_proto,
            "pid": self.pid,
            "processName": self.process_name,
            "tcpFlags": self.tcp_flags_str,
            "tcpExpert": self.tcp_expert,
            "alertSeverity": self.alert_severity,
            "alertRules": self.alert_rules,
        }

    def to_detail(self) -> Dict[str, Any]:
        """Full packet inspection payload including OSI layer tree and hex bytes."""
        return {
            "summary": self.to_summary(),
            "layers": [l.to_dict() for l in self.layers],
            "rawHex": self.raw.hex(),
        }
