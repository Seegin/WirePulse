"""
WirePulse Display Filter Compiler & Logic Inference Engine.

Hand-written Lexer -> Recursive Descent Parser -> AST -> Evaluator supporting
Wireshark-compatible display filter expressions:

  Logical ops:    and / &&, or / ||, not / !, parentheses (...)
  Relational ops: == / eq, != / ne, > / gt, < / lt, >= / ge, <= / le
  Match ops:      contains, matches (regex), in {v1, v2, ...}
  CIDR matching:  ip.src == 10.0.0.0/8, ip.addr == 192.168.1.0/24
  Bare protocols: http, tcp, udp, ip, ipv4, ipv6, icmp, icmpv6, arp, dns, tls,
                  quic, ssh, ftp, dhcp, websocket, alert
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from .dissector.models import PacketRecord

# Known protocol presence aliases
PROTOCOL_ALIASES = {
    "eth": "eth",
    "vlan": "vlan",
    "arp": "arp",
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ipv6",
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "tcp": "tcp",
    "udp": "udp",
    "http": "http",
    "http2": "http2",
    "tls": "tls",
    "ssl": "tls",
    "dns": "dns",
    "mdns": "mdns",
    "dhcp": "dhcp",
    "quic": "quic",
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "smtp",
    "websocket": "websocket",
    "ntp": "ntp",
    "ssdp": "ssdp",
    "redis": "redis",
    "mysql": "mysql",
    "stun": "stun",
    "alert": "__alert__",
}

# Field catalog used for autocomplete in the GUI filter bar
FILTER_FIELD_CATALOG = [
    {"field": "http", "type": "protocol", "desc": "HTTP/1.x application traffic"},
    {"field": "tls", "type": "protocol", "desc": "TLS/SSL encrypted sessions"},
    {"field": "dns", "type": "protocol", "desc": "DNS / mDNS queries and responses"},
    {"field": "tcp", "type": "protocol", "desc": "TCP transport segments"},
    {"field": "udp", "type": "protocol", "desc": "UDP datagrams"},
    {"field": "ip", "type": "protocol", "desc": "IPv4 network packets"},
    {"field": "ipv6", "type": "protocol", "desc": "IPv6 network packets"},
    {"field": "icmp", "type": "protocol", "desc": "ICMPv4 control messages"},
    {"field": "icmpv6", "type": "protocol", "desc": "ICMPv6 / NDP messages"},
    {"field": "arp", "type": "protocol", "desc": "ARP address resolution"},
    {"field": "quic", "type": "protocol", "desc": "QUIC / HTTP3 UDP transport"},
    {"field": "ssh", "type": "protocol", "desc": "SSH sessions"},
    {"field": "ftp", "type": "protocol", "desc": "FTP control traffic"},
    {"field": "dhcp", "type": "protocol", "desc": "DHCP lease messages"},
    {"field": "alert", "type": "security", "desc": "Packets flagged by Security IDS"},
    {"field": "ip.src", "type": "ipv4", "desc": "IPv4 source address (supports CIDR)"},
    {"field": "ip.dst", "type": "ipv4", "desc": "IPv4 destination address (supports CIDR)"},
    {"field": "ip.addr", "type": "ipv4", "desc": "IPv4 source or destination address"},
    {"field": "ip.ttl", "type": "int", "desc": "IPv4 Time-To-Live"},
    {"field": "ipv6.addr", "type": "ipv6", "desc": "IPv6 source or destination address"},
    {"field": "eth.src", "type": "mac", "desc": "Source MAC address"},
    {"field": "eth.dst", "type": "mac", "desc": "Destination MAC address"},
    {"field": "tcp.port", "type": "int", "desc": "TCP source or destination port"},
    {"field": "tcp.srcport", "type": "int", "desc": "TCP source port"},
    {"field": "tcp.dstport", "type": "int", "desc": "TCP destination port"},
    {"field": "tcp.stream", "type": "int", "desc": "TCP stream index"},
    {"field": "tcp.len", "type": "int", "desc": "TCP payload byte length"},
    {"field": "tcp.window_size", "type": "int", "desc": "TCP receive window size"},
    {"field": "tcp.flags.syn", "type": "bool", "desc": "TCP SYN flag"},
    {"field": "tcp.flags.ack", "type": "bool", "desc": "TCP ACK flag"},
    {"field": "tcp.flags.rst", "type": "bool", "desc": "TCP RST flag"},
    {"field": "tcp.flags.fin", "type": "bool", "desc": "TCP FIN flag"},
    {"field": "tcp.flags.psh", "type": "bool", "desc": "TCP PSH flag"},
    {"field": "tcp.analysis.retransmission", "type": "bool", "desc": "TCP retransmission expert flag"},
    {"field": "udp.port", "type": "int", "desc": "UDP source or destination port"},
    {"field": "udp.stream", "type": "int", "desc": "UDP stream index"},
    {"field": "http.request.method", "type": "string", "desc": "HTTP method (GET, POST, ...)"},
    {"field": "http.request.uri", "type": "string", "desc": "HTTP request URI"},
    {"field": "http.host", "type": "string", "desc": "HTTP Host header"},
    {"field": "http.response.code", "type": "int", "desc": "HTTP status code (200, 404, ...)"},
    {"field": "dns.qry.name", "type": "string", "desc": "DNS queried domain name"},
    {"field": "dns.qry.type", "type": "string", "desc": "DNS query type (A, AAAA, TXT, ...)"},
    {"field": "dns.flags.response", "type": "bool", "desc": "DNS query (false) vs response (true)"},
    {"field": "tls.handshake.sni", "type": "string", "desc": "TLS Server Name Indication (SNI)"},
    {"field": "tls.ja3", "type": "string", "desc": "TLS Client JA3 MD5 fingerprint"},
    {"field": "tls.record.version", "type": "string", "desc": "TLS protocol version"},
    {"field": "frame.len", "type": "int", "desc": "Packet wire length in bytes"},
    {"field": "frame.number", "type": "int", "desc": "Frame sequence number"},
    {"field": "proc.pid", "type": "int", "desc": "Owning OS process ID"},
    {"field": "proc.name", "type": "string", "desc": "Owning OS process name"},
    {"field": "alert.severity", "type": "string", "desc": "IDS severity (CRITICAL, HIGH, MEDIUM, LOW)"},
    {"field": "alert.rule", "type": "string", "desc": "IDS alert rule name"},
    {"field": "info", "type": "string", "desc": "Packet Info summary text"},
]


class FilterSyntaxError(Exception):
    def __init__(self, message: str, pos: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.pos = pos


@dataclass
class Token:
    kind: str
    value: str
    pos: int


_TOKEN_SPEC = [
    ("SKIP", r"[ \t\r\n]+"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("LBRACE", r"\{"),
    ("RBRACE", r"\}"),
    ("COMMA", r","),
    ("AND", r"&&"),
    ("OR", r"\|\|"),
    ("OP", r"==|!=|>=|<=|>|<"),
    ("NOT", r"!"),
    ("STRING", r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''),
    # IPv4 / CIDR / IPv6 / MAC / Hex / Number / Identifiers (dotted)
    ("WORD", r"[A-Za-z0-9_.:/\-]+"),
]
_MASTER_RE = re.compile("|".join(f"(?P<{name}>{pat})" for name, pat in _TOKEN_SPEC))

_OP_KEYWORDS = {
    "and": "AND",
    "or": "OR",
    "not": "NOT",
    "eq": "OP",
    "ne": "OP",
    "gt": "OP",
    "lt": "OP",
    "ge": "OP",
    "le": "OP",
    "contains": "OP",
    "matches": "OP",
    "in": "IN",
}

_OP_NORM = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "lt": "<",
    "ge": ">=",
    "le": "<=",
}


def tokenize(expr: str) -> List[Token]:
    tokens: List[Token] = []
    pos = 0
    n = len(expr)
    while pos < n:
        m = _MASTER_RE.match(expr, pos)
        if not m:
            raise FilterSyntaxError(f"Unexpected character '{expr[pos]}' at column {pos + 1}", pos)
        kind = m.lastgroup or ""
        raw = m.group()
        start = m.start()
        pos = m.end()
        if kind == "SKIP":
            continue
        if kind == "STRING":
            val = raw[1:-1].replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
            tokens.append(Token("STRING", val, start))
        elif kind == "WORD":
            low = raw.lower()
            if low in _OP_KEYWORDS:
                mapped_kind = _OP_KEYWORDS[low]
                mapped_val = _OP_NORM.get(low, low)
                tokens.append(Token(mapped_kind, mapped_val, start))
            else:
                tokens.append(Token("WORD", raw, start))
        else:
            tokens.append(Token(kind, raw, start))
    tokens.append(Token("EOF", "", n))
    return tokens


# --- AST Nodes ---
class ASTNode:
    def evaluate(self, pkt: PacketRecord) -> bool:
        raise NotImplementedError

    def to_expr_str(self) -> str:
        raise NotImplementedError


@dataclass
class LogicalNode(ASTNode):
    op: str  # "AND" | "OR"
    left: ASTNode
    right: ASTNode

    def evaluate(self, pkt: PacketRecord) -> bool:
        if self.op == "AND":
            return self.left.evaluate(pkt) and self.right.evaluate(pkt)
        return self.left.evaluate(pkt) or self.right.evaluate(pkt)

    def to_expr_str(self) -> str:
        return f"({self.left.to_expr_str()} {self.op} {self.right.to_expr_str()})"


@dataclass
class NotNode(ASTNode):
    operand: ASTNode

    def evaluate(self, pkt: PacketRecord) -> bool:
        return not self.operand.evaluate(pkt)

    def to_expr_str(self) -> str:
        return f"(NOT {self.operand.to_expr_str()})"


@dataclass
class ExistsNode(ASTNode):
    field: str

    def evaluate(self, pkt: PacketRecord) -> bool:
        f = self.field.lower()
        if f in PROTOCOL_ALIASES:
            target = PROTOCOL_ALIASES[f]
            if target == "__alert__":
                return bool(pkt.alert_rules)
            return target in pkt.protocols or pkt.protocol.lower() == target
        vals = _get_field_values(pkt, f)
        if not vals:
            return False
        # For boolean fields (like tcp.flags.syn), bare `tcp.flags.syn` checks truthiness
        return any(bool(v) for v in vals)

    def to_expr_str(self) -> str:
        return f"EXISTS({self.field})"


@dataclass
class CompareNode(ASTNode):
    field: str
    op: str
    rhs: Any
    _regex: Optional[re.Pattern] = None
    _net: Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = None

    def __post_init__(self) -> None:
        if self.op == "matches":
            try:
                self._regex = re.compile(str(self.rhs), re.IGNORECASE)
            except re.error as e:
                raise FilterSyntaxError(f"Invalid regular expression '{self.rhs}': {e}")
        elif self.op in ("==", "!=") and isinstance(self.rhs, str) and "/" in self.rhs:
            try:
                self._net = ipaddress.ip_network(self.rhs, strict=False)
            except ValueError:
                self._net = None

    def evaluate(self, pkt: PacketRecord) -> bool:
        vals = _get_field_values(pkt, self.field.lower())
        if not vals:
            return False
        if self.op == "!=":
            return all(not self._match_single(v, "==") for v in vals)
        return any(self._match_single(v, self.op) for v in vals)

    def _match_single(self, val: Any, op: str) -> bool:
        if op == "contains":
            return str(self.rhs).lower() in str(val).lower()
        if op == "matches":
            return bool(self._regex and self._regex.search(str(val)))

        if self._net is not None:
            try:
                ip_obj = ipaddress.ip_address(str(val))
                return ip_obj in self._net
            except ValueError:
                return False

        # Boolean comparison normalization
        if isinstance(val, bool) or str(self.rhs).lower() in ("true", "false"):
            b_val = _to_bool(val)
            b_rhs = _to_bool(self.rhs)
            if op == "==":
                return b_val == b_rhs
            if op == "!=":
                return b_val != b_rhs

        # Numeric comparison
        n_val = _try_num(val)
        n_rhs = _try_num(self.rhs)
        if n_val is not None and n_rhs is not None:
            if op == "==":
                return n_val == n_rhs
            if op == ">":
                return n_val > n_rhs
            if op == "<":
                return n_val < n_rhs
            if op == ">=":
                return n_val >= n_rhs
            if op == "<=":
                return n_val <= n_rhs

        # Case-insensitive string comparison
        s_val = str(val).lower()
        s_rhs = str(self.rhs).lower()
        if op == "==":
            return s_val == s_rhs
        if op == ">":
            return s_val > s_rhs
        if op == "<":
            return s_val < s_rhs
        if op == ">=":
            return s_val >= s_rhs
        if op == "<=":
            return s_val <= s_rhs
        return False

    def to_expr_str(self) -> str:
        return f"({self.field} {self.op} {self.rhs!r})"


@dataclass
class InSetNode(ASTNode):
    field: str
    items: List[Any]

    def evaluate(self, pkt: PacketRecord) -> bool:
        vals = _get_field_values(pkt, self.field.lower())
        if not vals:
            return False
        for v in vals:
            for item in self.items:
                if CompareNode(self.field, "==", item)._match_single(v, "=="):
                    return True
        return False

    def to_expr_str(self) -> str:
        return f"({self.field} IN {{{', '.join(repr(i) for i in self.items)}}})"


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("1", "true", "yes", "set")


def _try_num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(("0x", "0X")):
            try:
                return float(int(s, 16))
            except ValueError:
                return None
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _get_field_values(pkt: PacketRecord, key: str) -> List[Any]:
    # Direct indexed fields
    vals = pkt.fields_index.get(key)
    if vals is not None:
        return vals
    # Dynamic fields attached after dissection (stream, process, security alerts, expert)
    if key == "tcp.stream" and pkt.stream_proto == "tcp" and pkt.stream_id is not None:
        return [pkt.stream_id]
    if key == "udp.stream" and pkt.stream_proto == "udp" and pkt.stream_id is not None:
        return [pkt.stream_id]
    if key == "stream.id" and pkt.stream_id is not None:
        return [pkt.stream_id]
    if key == "proc.pid" and pkt.pid is not None:
        return [pkt.pid]
    if key == "proc.name" and pkt.process_name:
        return [pkt.process_name]
    if key == "alert.severity" and pkt.alert_severity:
        return [pkt.alert_severity]
    if key == "alert.rule" and pkt.alert_rules:
        return pkt.alert_rules
    if key == "tcp.analysis.retransmission":
        return ["Retransmission" in pkt.tcp_expert or "Fast Retransmission" in pkt.tcp_expert]
    if key == "tcp.analysis.out_of_order":
        return ["Out-of-Order" in pkt.tcp_expert]
    if key == "tcp.analysis.zero_window":
        return ["Zero Window" in pkt.tcp_expert]
    if key == "src":
        return [pkt.src]
    if key == "dst":
        return [pkt.dst]
    return []


class RecursiveDescentParser:
    """
    Grammar:
      expr      := or_expr EOF
      or_expr   := and_expr ( ('or' | '||') and_expr )*
      and_expr  := not_expr ( ('and' | '&&') not_expr )*
      not_expr  := ('not' | '!') not_expr | primary
      primary   := '(' or_expr ')'
                 | WORD IN '{' value (','? value)* '}'
                 | WORD OP value
                 | WORD
    """

    def __init__(self, tokens: List[Token]) -> None:
        self.tokens = tokens
        self.idx = 0

    def peek(self, offset: int = 0) -> Token:
        pos = self.idx + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return self.tokens[-1]

    def consume(self, expected_kind: Optional[str] = None) -> Token:
        tok = self.peek()
        if expected_kind and tok.kind != expected_kind:
            raise FilterSyntaxError(
                f"Expected {expected_kind} but got '{tok.value or tok.kind}' at column {tok.pos + 1}",
                tok.pos,
            )
        self.idx += 1
        return tok

    def parse(self) -> ASTNode:
        node = self.parse_or()
        if self.peek().kind != "EOF":
            tok = self.peek()
            raise FilterSyntaxError(
                f"Unexpected token '{tok.value}' at column {tok.pos + 1}",
                tok.pos,
            )
        return node

    def parse_or(self) -> ASTNode:
        node = self.parse_and()
        while self.peek().kind == "OR":
            self.consume("OR")
            right = self.parse_and()
            node = LogicalNode("OR", node, right)
        return node

    def parse_and(self) -> ASTNode:
        node = self.parse_not()
        while self.peek().kind == "AND":
            self.consume("AND")
            right = self.parse_not()
            node = LogicalNode("AND", node, right)
        return node

    def parse_not(self) -> ASTNode:
        if self.peek().kind == "NOT":
            self.consume("NOT")
            return NotNode(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> ASTNode:
        tok = self.peek()
        if tok.kind == "LPAREN":
            self.consume("LPAREN")
            inner = self.parse_or()
            self.consume("RPAREN")
            return inner

        if tok.kind == "WORD":
            field_tok = self.consume("WORD")
            nxt = self.peek()
            if nxt.kind == "OP":
                op_tok = self.consume("OP")
                val_tok = self.peek()
                if val_tok.kind not in ("WORD", "STRING"):
                    raise FilterSyntaxError(
                        f"Expected value after '{op_tok.value}' at column {val_tok.pos + 1}",
                        val_tok.pos,
                    )
                self.consume()
                return CompareNode(field_tok.value, op_tok.value, val_tok.value)
            if nxt.kind == "IN":
                self.consume("IN")
                self.consume("LBRACE")
                items: List[Any] = []
                while self.peek().kind not in ("RBRACE", "EOF"):
                    if self.peek().kind == "COMMA":
                        self.consume("COMMA")
                        continue
                    vtok = self.peek()
                    if vtok.kind not in ("WORD", "STRING"):
                        raise FilterSyntaxError(
                            f"Expected set value at column {vtok.pos + 1}",
                            vtok.pos,
                        )
                    self.consume()
                    items.append(vtok.value)
                self.consume("RBRACE")
                if not items:
                    raise FilterSyntaxError("Set in 'in {...}' cannot be empty", nxt.pos)
                return InSetNode(field_tok.value, items)
            return ExistsNode(field_tok.value)

        raise FilterSyntaxError(
            f"Unexpected token '{tok.value or tok.kind}' at column {tok.pos + 1}",
            tok.pos,
        )


@dataclass
class CompiledFilter:
    source: str
    ast: Optional[ASTNode]

    def matches(self, pkt: PacketRecord) -> bool:
        if self.ast is None:
            return True
        return self.ast.evaluate(pkt)

    @property
    def ast_summary(self) -> str:
        return self.ast.to_expr_str() if self.ast else "ALL"


def compile_filter(expr: str) -> CompiledFilter:
    text = (expr or "").strip()
    if not text:
        return CompiledFilter(source="", ast=None)
    tokens = tokenize(text)
    ast = RecursiveDescentParser(tokens).parse()
    return CompiledFilter(source=text, ast=ast)


def validate_filter(expr: str) -> Dict[str, Any]:
    text = (expr or "").strip()
    if not text:
        return {"valid": True, "ast": "ALL", "error": None, "pos": 0}
    try:
        cf = compile_filter(text)
        return {"valid": True, "ast": cf.ast_summary, "error": None, "pos": 0}
    except FilterSyntaxError as e:
        return {"valid": False, "ast": None, "error": e.message, "pos": e.pos}
