import type { PacketSummary } from '../types'

export interface ProtocolColorStyle {
  rowBg: string
  badgeClass: string
  accentHex: string
  ruleName: string
}

/**
 * Wireshark-inspired semantic coloring rules adapted for both Obsidian Dark and Daylight Light themes.
 */
export function getPacketRowStyle(pkt: PacketSummary): ProtocolColorStyle {
  const proto = pkt.protocol.toUpperCase()

  if (pkt.alertSeverity === 'CRITICAL') {
    return {
      rowBg: 'bg-rose-500/15 dark:bg-rose-500/18 border-l-2 border-l-rose-500',
      badgeClass: 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40',
      accentHex: '#f43f5e',
      ruleName: 'Security Critical Alert',
    }
  }

  if (pkt.alertSeverity === 'HIGH') {
    return {
      rowBg: 'bg-orange-500/12 dark:bg-orange-500/14 border-l-2 border-l-orange-500',
      badgeClass: 'bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/40',
      accentHex: '#f97316',
      ruleName: 'Security High Alert',
    }
  }

  if (pkt.tcpExpert.length > 0 || pkt.tcpFlags.includes('RST')) {
    return {
      rowBg: 'bg-amber-500/10 dark:bg-amber-500/12 border-l-2 border-l-amber-500/80',
      badgeClass: 'bg-amber-500/20 text-amber-800 dark:text-amber-300 border-amber-500/40',
      accentHex: '#f59e0b',
      ruleName: 'Bad TCP / Expert Warning',
    }
  }

  if (proto.startsWith('HTTP') || proto === 'WEBSOCKET') {
    return {
      rowBg: 'bg-emerald-500/[0.06] dark:bg-emerald-500/[0.08] border-l-2 border-l-emerald-500/60',
      badgeClass: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/35',
      accentHex: '#10b981',
      ruleName: 'HTTP / Web Application',
    }
  }

  if (proto.startsWith('TLS') || proto.startsWith('SSL') || proto === 'QUIC') {
    return {
      rowBg: 'bg-violet-500/[0.06] dark:bg-violet-500/[0.08] border-l-2 border-l-violet-500/60',
      badgeClass: 'bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/35',
      accentHex: '#8b5cf6',
      ruleName: 'TLS / QUIC Encrypted',
    }
  }

  if (proto === 'DNS' || proto === 'MDNS') {
    return {
      rowBg: 'bg-sky-500/[0.06] dark:bg-sky-500/[0.08] border-l-2 border-l-sky-500/60',
      badgeClass: 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/35',
      accentHex: '#0ea5e9',
      ruleName: 'DNS / Name Resolution',
    }
  }

  if (proto === 'ARP') {
    return {
      rowBg: 'bg-yellow-500/[0.07] dark:bg-yellow-500/[0.08] border-l-2 border-l-yellow-500/60',
      badgeClass: 'bg-yellow-500/15 text-yellow-800 dark:text-yellow-300 border-yellow-500/35',
      accentHex: '#eab308',
      ruleName: 'ARP Data Link',
    }
  }

  if (proto.startsWith('ICMP')) {
    return {
      rowBg: 'bg-fuchsia-500/[0.06] dark:bg-fuchsia-500/[0.08] border-l-2 border-l-fuchsia-500/60',
      badgeClass: 'bg-fuchsia-500/15 text-fuchsia-700 dark:text-fuchsia-300 border-fuchsia-500/35',
      accentHex: '#d946ef',
      ruleName: 'ICMP / Control',
    }
  }

  if (proto === 'SSH' || proto === 'FTP' || proto === 'SMTP') {
    return {
      rowBg: 'bg-teal-500/[0.06] dark:bg-teal-500/[0.08] border-l-2 border-l-teal-500/60',
      badgeClass: 'bg-teal-500/15 text-teal-700 dark:text-teal-300 border-teal-500/35',
      accentHex: '#14b8a6',
      ruleName: 'SSH / FTP / Remote Ops',
    }
  }

  if (proto === 'TCP') {
    if (pkt.tcpFlags.includes('SYN') || pkt.tcpFlags.includes('FIN')) {
      return {
        rowBg: 'bg-slate-500/[0.07] dark:bg-slate-400/[0.07] border-l-2 border-l-cyan-500/50',
        badgeClass: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/35',
        accentHex: '#06b6d4',
        ruleName: 'TCP SYN / FIN Handshake',
      }
    }
    return {
      rowBg: 'bg-transparent border-l-2 border-l-slate-400/30',
      badgeClass: 'bg-indigo-500/12 text-indigo-700 dark:text-indigo-300 border-indigo-500/30',
      accentHex: '#6366f1',
      ruleName: 'TCP Transport',
    }
  }

  if (proto === 'UDP' || proto === 'DHCP' || proto === 'NTP' || proto === 'SSDP') {
    return {
      rowBg: 'bg-cyan-500/[0.04] dark:bg-cyan-500/[0.05] border-l-2 border-l-cyan-400/50',
      badgeClass: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/35',
      accentHex: '#22d3ee',
      ruleName: 'UDP / Datagram',
    }
  }

  return {
    rowBg: 'bg-transparent border-l-2 border-l-transparent',
    badgeClass: 'bg-slate-500/15 text-slate-700 dark:text-slate-300 border-slate-500/30',
    accentHex: '#94a3b8',
    ruleName: 'Default Frame',
  }
}

export const COLORING_RULES_REFERENCE = [
  { name: 'Security Critical Alert', filter: 'alert.severity == "CRITICAL"', color: '#f43f5e', desc: 'ARP Spoofing, SQLi, Cleartext Basic Auth, SYN Flood' },
  { name: 'Security High Alert', filter: 'alert.severity == "HIGH"', color: '#f97316', desc: 'Port Scan, XSS, Path Traversal, DNS Tunneling, Cred Leak' },
  { name: 'Bad TCP / Expert Warning', filter: 'tcp.analysis.retransmission || tcp.flags.rst', color: '#f59e0b', desc: 'TCP Retransmission, Out-of-Order, Zero Window, RST' },
  { name: 'HTTP / Web Application', filter: 'http || websocket', color: '#10b981', desc: 'HTTP/1.x, HTTP/2 & WebSocket (including DPI non-standard ports)' },
  { name: 'TLS / QUIC Encrypted', filter: 'tls || quic', color: '#8b5cf6', desc: 'TLS 1.0–1.3 Handshakes (JA3/SNI) & QUIC RFC 9000' },
  { name: 'DNS / Name Resolution', filter: 'dns || mdns', color: '#0ea5e9', desc: 'Domain Name System & Multicast DNS' },
  { name: 'TCP SYN / FIN Control', filter: 'tcp.flags.syn || tcp.flags.fin', color: '#06b6d4', desc: 'TCP Connection Setup & Teardown' },
  { name: 'ARP Data Link', filter: 'arp', color: '#eab308', desc: 'Address Resolution Protocol Requests & Replies' },
  { name: 'ICMP / Control', filter: 'icmp || icmpv6', color: '#d946ef', desc: 'ICMPv4 Ping & ICMPv6 Neighbor Discovery' },
]

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

export const OSI_BADGE_META: Record<number, { label: string; cls: string }> = {
  1: { label: 'L1 FRAME', cls: 'bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30' },
  2: { label: 'L2 LINK', cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30' },
  3: { label: 'L3 NET', cls: 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30' },
  4: { label: 'L4 TRANS', cls: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30' },
  6: { label: 'L6 PRES', cls: 'bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30' },
  7: { label: 'L7 APP', cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' },
}
