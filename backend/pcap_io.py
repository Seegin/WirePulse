"""
WirePulse - Pure-Python Streaming PCAP & PCAPNG Reader / Writer.

Supports:
  - Classic PCAP (little/big endian, microsecond & nanosecond resolution)
  - PCAPNG (Section Header Block, Interface Description Block with if_tsresol,
    Enhanced Packet Block, Simple Packet Block)
  - Incremental streaming from live pipes (e.g., Wireshark dumpcap -w -)
"""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, List, Optional, Tuple

# Classic PCAP magic numbers
PCAP_MAGIC_USEC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_USEC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NSEC_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NSEC_BE = b"\xa1\xb2\x3c\x4d"

# PCAPNG Block Types
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_SPB = 0x00000003
PCAPNG_EPB = 0x00000006

# Standard Link-Layer Types (DLT_*)
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276


@dataclass
class RawPacket:
    timestamp: float
    caplen: int
    origlen: int
    linktype: int
    data: bytes


def _read_exact(stream: BinaryIO, n: int) -> Optional[bytes]:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None if not chunks else b"".join(chunks)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_capture_stream(stream: BinaryIO) -> Iterator[RawPacket]:
    """Auto-detect PCAP or PCAPNG on a binary stream and yield RawPacket objects."""
    magic = _read_exact(stream, 4)
    if not magic or len(magic) < 4:
        return

    if magic in (PCAP_MAGIC_USEC_LE, PCAP_MAGIC_USEC_BE, PCAP_MAGIC_NSEC_LE, PCAP_MAGIC_NSEC_BE):
        yield from _iter_pcap(stream, magic)
    elif struct.unpack("<I", magic)[0] == PCAPNG_SHB:
        yield from _iter_pcapng(stream, magic)
    else:
        raise ValueError(f"Unsupported capture format magic: {magic.hex()}")


def _iter_pcap(stream: BinaryIO, magic: bytes) -> Iterator[RawPacket]:
    is_le = magic in (PCAP_MAGIC_USEC_LE, PCAP_MAGIC_NSEC_LE)
    is_nsec = magic in (PCAP_MAGIC_NSEC_LE, PCAP_MAGIC_NSEC_BE)
    endian = "<" if is_le else ">"

    rest_hdr = _read_exact(stream, 20)
    if not rest_hdr or len(rest_hdr) < 20:
        return
    _ver_maj, _ver_min, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(
        f"{endian}HHiiii", rest_hdr
    )
    linktype = linktype & 0x0FFFFFFF
    ts_div = 1_000_000_000.0 if is_nsec else 1_000_000.0
    pkt_hdr_fmt = f"{endian}IIII"

    while True:
        pkt_hdr = _read_exact(stream, 16)
        if not pkt_hdr or len(pkt_hdr) < 16:
            break
        ts_sec, ts_sub, caplen, origlen = struct.unpack(pkt_hdr_fmt, pkt_hdr)
        if caplen > 10 * 1024 * 1024:
            break
        data = _read_exact(stream, caplen)
        if not data or len(data) < caplen:
            break
        yield RawPacket(
            timestamp=ts_sec + ts_sub / ts_div,
            caplen=caplen,
            origlen=origlen,
            linktype=linktype,
            data=data,
        )


def _parse_idb_tsresol(options_bytes: bytes, endian: str) -> float:
    """Parse PCAPNG IDB option code 9 (if_tsresol). Default is 1e-6 (microseconds)."""
    pos = 0
    n = len(options_bytes)
    while pos + 4 <= n:
        opt_code, opt_len = struct.unpack_from(f"{endian}HH", options_bytes, pos)
        pos += 4
        if opt_code == 0:
            break
        if pos + opt_len > n:
            break
        if opt_code == 9 and opt_len >= 1:
            val = options_bytes[pos]
            if val & 0x80:
                return float(2 ** (-(val & 0x7F)))
            return float(10 ** (-val))
        padded = (opt_len + 3) & ~3
        pos += padded
    return 1e-6


def _iter_pcapng(stream: BinaryIO, first_four: bytes) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: List[Tuple[int, float]] = []  # (linktype, ts_unit_seconds)

    pending_type_bytes: Optional[bytes] = first_four
    while True:
        if pending_type_bytes is not None:
            btype_bytes = pending_type_bytes
            pending_type_bytes = None
        else:
            btype_bytes = _read_exact(stream, 4)
            if not btype_bytes or len(btype_bytes) < 4:
                break

        blen_bytes = _read_exact(stream, 4)
        if not blen_bytes or len(blen_bytes) < 4:
            break

        raw_type_le = struct.unpack("<I", btype_bytes)[0]
        if raw_type_le == PCAPNG_SHB:
            bom_bytes = _read_exact(stream, 4)
            if not bom_bytes or len(bom_bytes) < 4:
                break
            if struct.unpack("<I", bom_bytes)[0] == 0x1A2B3C4D:
                endian = "<"
            else:
                endian = ">"
            blen = struct.unpack(f"{endian}I", blen_bytes)[0]
            remaining = blen - 12
            if remaining > 0:
                _read_exact(stream, remaining)
            interfaces.clear()
            continue

        btype = struct.unpack(f"{endian}I", btype_bytes)[0]
        blen = struct.unpack(f"{endian}I", blen_bytes)[0]
        if blen < 12 or blen > 64 * 1024 * 1024:
            break
        body_and_tail = _read_exact(stream, blen - 8)
        if not body_and_tail or len(body_and_tail) < blen - 8:
            break
        body = body_and_tail[:-4]

        if btype == PCAPNG_IDB and len(body) >= 8:
            linktype, _reserved, _snaplen = struct.unpack_from(f"{endian}HHI", body, 0)
            ts_unit = _parse_idb_tsresol(body[8:], endian)
            interfaces.append((linktype, ts_unit))
        elif btype == PCAPNG_EPB and len(body) >= 20:
            iface_id, ts_high, ts_low, caplen, origlen = struct.unpack_from(f"{endian}IIIII", body, 0)
            if 20 + caplen > len(body):
                continue
            data = body[20 : 20 + caplen]
            linktype, ts_unit = interfaces[iface_id] if iface_id < len(interfaces) else (DLT_EN10MB, 1e-6)
            ts_ticks = (ts_high << 32) | ts_low
            yield RawPacket(
                timestamp=ts_ticks * ts_unit,
                caplen=caplen,
                origlen=origlen,
                linktype=linktype,
                data=data,
            )
        elif btype == PCAPNG_SPB and len(body) >= 4:
            origlen = struct.unpack_from(f"{endian}I", body, 0)[0]
            data = body[4 : 4 + origlen]
            linktype = interfaces[0][0] if interfaces else DLT_EN10MB
            yield RawPacket(
                timestamp=0.0,
                caplen=len(data),
                origlen=origlen,
                linktype=linktype,
                data=data,
            )


def read_capture_file(filepath: str) -> List[RawPacket]:
    """Read all packets from a .pcap or .pcapng file."""
    with open(filepath, "rb") as f:
        return list(iter_capture_stream(f))


def read_capture_bytes(raw_bytes: bytes) -> List[RawPacket]:
    """Parse packets from an in-memory .pcap or .pcapng buffer."""
    return list(iter_capture_stream(io.BytesIO(raw_bytes)))


def write_pcap_bytes(packets: List[RawPacket], linktype: Optional[int] = None) -> bytes:
    """Serialize packets to standard little-endian microsecond PCAP format."""
    lt = linktype if linktype is not None else (packets[0].linktype if packets else DLT_EN10MB)
    buf = io.BytesIO()
    # Global header: magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, network=lt
    buf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, lt))
    for p in packets:
        ts_sec = int(p.timestamp)
        ts_usec = int(round((p.timestamp - ts_sec) * 1_000_000))
        if ts_usec >= 1_000_000:
            ts_sec += 1
            ts_usec -= 1_000_000
        elif ts_usec < 0:
            ts_usec = 0
        buf.write(struct.pack("<IIII", ts_sec, ts_usec, len(p.data), p.origlen))
        buf.write(p.data)
    return buf.getvalue()


def write_pcap_file(filepath: str, packets: List[RawPacket], linktype: Optional[int] = None) -> None:
    data = write_pcap_bytes(packets, linktype=linktype)
    with open(filepath, "wb") as f:
        f.write(data)
