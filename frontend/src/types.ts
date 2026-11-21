export type NavTab = 'capture' | 'packets' | 'learn' | 'streams' | 'processes' | 'security' | 'analytics' | 'wireshark'

export interface InterfaceInfo {
  id: string
  name: string
  device: string
  description: string
  ipv4?: string
  ipv6?: string
  engine: 'native_libpcap' | 'wireshark_dumpcap'
  dumpcapIndex?: string
  isLoopback?: boolean
  isUp?: boolean
  isRunning?: boolean
  isWireless?: boolean
  sparkline?: number[]
}

export interface InterfacesResponse {
  nativeEngine: {
    available: boolean
    version: string
    error: string | null
    isRoot: boolean
  }
  wireshark: {
    available: boolean
    version: string
    tsharkPath: string | null
    sharkdPath: string | null
    dumpcapPath: string | null
    isWslWindowsBridge: boolean
  }
  nativeInterfaces: InterfaceInfo[]
  dumpcapInterfaces: InterfaceInfo[]
}

export interface AlertCounts {
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
  TOTAL: number
}

export interface SessionStatus {
  capturing: boolean
  paused: boolean
  engine: string
  interface: string
  bpfFilter: string
  error: string | null
  totalPackets: number
  totalBytes: number
  tcpStreams: number
  udpStreams: number
  alerts: AlertCounts
  kernelStats: {
    recv: number
    drop: number
    ifdrop: number
  }
  nativeVersion: string
  wiresharkAvailable: boolean
  wiresharkVersion: string
  keylogActive: boolean
}

export interface PacketSummary {
  no: number
  timestamp: number
  relTime: number
  deltaTime: number
  src: string
  dst: string
  srcPort: number | null
  dstPort: number | null
  protocol: string
  protocols: string[]
  osiLayer: number
  length: number
  caplen: number
  info: string
  dpiMethod: string
  streamId: number | null
  streamProto: 'tcp' | 'udp' | null
  pid: number | null
  processName: string
  tcpFlags: string
  tcpExpert: string[]
  alertSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null
  alertRules: string[]
}

export interface FieldNode {
  key: string
  label: string
  value: unknown
  offset: number
  length: number
  osiLayer?: number
  severity?: 'info' | 'warn' | 'error'
  children?: FieldNode[]
}

export interface LayerNode {
  protocol: string
  title: string
  osiLayer: number
  offset: number
  length: number
  fields: FieldNode[]
}

export interface PacketDetail {
  summary: PacketSummary
  layers: LayerNode[]
  rawHex: string
}

export interface StreamSummary {
  streamId: number
  proto: 'tcp' | 'udp'
  client: string
  server: string
  clientIp: string
  clientPort: number
  serverIp: string
  serverPort: number
  appProtocol: string
  host: string
  pid: number | null
  processName: string
  packets: number
  bytesC2S: number
  bytesS2C: number
  totalBytes: number
  durationMs: number
  rttMs: number | null
  state: string
  retransmissions: number
  outOfOrder: number
}

export interface StreamTurn {
  direction: 'c2s' | 's2c'
  packetNos: number[]
  timestamp: number
  length: number
  text: string
  hex: string
  rawBase64: string
}

export interface SequenceEvent {
  packetNo: number
  relTime: number
  deltaMs: number
  direction: 'c2s' | 's2c'
  flags: string
  payloadLen: number
  window: number
  info: string
  expert: string[]
}

export interface StreamFollowData {
  summary: StreamSummary
  turns: StreamTurn[]
  sequence: SequenceEvent[]
}

export interface ProcessTraffic {
  pid: number
  name: string
  cmdline: string
  packetsIn: number
  packetsOut: number
  totalPackets: number
  bytesIn: number
  bytesOut: number
  totalBytes: number
  streamCount: number
  streamIds: number[]
  remoteEndpoints: string[]
  protocols: string[]
  alerts: number
}

export interface SecurityAlert {
  id: number
  timestamp: number
  relTime: number
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  rule: string
  category: string
  title: string
  description: string
  src: string
  dst: string
  protocol: string
  packetNo: number
  streamId: number | null
  evidence: string
  mitreId: string
}

export interface AnalyticsPayload {
  status: SessionStatus
  timeseries: { ts: number; pps: number; bps: number }[]
  protocols: { name: string; count: number }[]
  osiLayers: { layer: string; label: string; count: number }[]
  topEndpoints: {
    ip: string
    hostname: string
    txPackets: number
    rxPackets: number
    txBytes: number
    rxBytes: number
    totalBytes: number
    alerts: number
    protocols: string[]
  }[]
  topology: {
    nodes: { id: string; label: string; ip: string; bytes: number; packets: number; alerts: number }[]
    edges: { source: string; target: string; packets: number; bytes: number; protocols: string[]; alerts: number }[]
  }
}

export interface FilterFieldCatalogItem {
  field: string
  type: string
  desc: string
}

export interface HighlightRange {
  offset: number
  length: number
  label?: string
}
