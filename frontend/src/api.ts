import type {
  AnalyticsPayload,
  FilterFieldCatalogItem,
  InterfacesResponse,
  LayerNode,
  PacketDetail,
  PacketSummary,
  ProcessTraffic,
  SecurityAlert,
  SessionStatus,
  StreamFollowData,
  StreamSummary,
  AlertCounts,
} from './types'

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  const data = await res.json()
  return data as T
}

export const api = {
  getInterfaces: () => req<InterfacesResponse>('/api/interfaces'),
  getStatus: () => req<SessionStatus>('/api/status'),

  startCapture: (payload: {
    interfaceId: string
    bpfFilter: string
    promisc: boolean
    snaplen: number
    bufferMb: number
  }) =>
    req<{ ok: boolean; error?: string; status?: SessionStatus }>('/api/capture/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),

  stopCapture: () =>
    req<{ ok: boolean; status: SessionStatus }>('/api/capture/stop', { method: 'POST' }),

  pauseCapture: () =>
    req<{ ok: boolean; status: SessionStatus }>('/api/capture/pause', { method: 'POST' }),

  clearCapture: () =>
    req<{ ok: boolean; status: SessionStatus }>('/api/capture/clear', { method: 'POST' }),

  loadDemo: (realtime = false) =>
    req<{ ok: boolean; status: SessionStatus }>('/api/capture/demo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ realtime }),
    }),

  importPcap: async (file: File) => {
    const buf = await file.arrayBuffer()
    return req<{ ok: boolean; error?: string; status?: SessionStatus }>('/api/capture/import', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Filename': file.name,
      },
      body: buf,
    })
  },

  exportPcapUrl: (filterExpr: string) =>
    `/api/capture/export?filter=${encodeURIComponent(filterExpr || '')}`,

  validateBpf: (expr: string) =>
    req<{ valid: boolean; error: string | null }>('/api/bpf/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ expr }),
    }),

  validateFilter: (expr: string) =>
    req<{ valid: boolean; ast: string | null; error: string | null; pos: number }>(
      '/api/filter/validate',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expr }),
      },
    ),

  getFilterFields: () => req<{ fields: FilterFieldCatalogItem[] }>('/api/filter/fields'),

  getPackets: (filterExpr = '', offset = 0, limit = 10000) =>
    req<{
      ok: boolean
      error?: string
      ast?: string
      totalCaptured: number
      totalMatched: number
      packets: PacketSummary[]
    }>(
      `/api/packets?filter=${encodeURIComponent(filterExpr)}&offset=${offset}&limit=${limit}`,
    ),

  getPacketDetail: (no: number) =>
    req<{ ok: boolean } & PacketDetail>(`/api/packets/${no}`),

  getPacketWiresharkDetail: (no: number) =>
    req<{
      ok: boolean
      error?: string
      engine?: string
      tlsDecryptionActive?: boolean
      layers?: LayerNode[]
    }>(`/api/packets/${no}/wireshark`),

  getStreams: (proto = 'all', pid?: number | null, processName?: string) => {
    const params = new URLSearchParams({ proto })
    if (pid) params.set('pid', String(pid))
    if (processName) params.set('process', processName)
    return req<{ streams: StreamSummary[] }>(`/api/streams?${params.toString()}`)
  },

  followStream: (proto: 'tcp' | 'udp', sid: number) =>
    req<{ ok: boolean } & StreamFollowData>(`/api/streams/${proto}/${sid}`),

  getProcesses: () => req<{ processes: ProcessTraffic[] }>('/api/processes'),

  getAlerts: (severity = 'ALL') =>
    req<{ counts: AlertCounts; alerts: SecurityAlert[] }>(
      `/api/alerts?severity=${encodeURIComponent(severity)}`,
    ),

  getAnalytics: () => req<AnalyticsPayload>('/api/analytics'),

  setKeylog: (payload: { path?: string | null; content?: string }) =>
    req<{ ok: boolean; keylogPath?: string | null; error?: string }>('/api/wireshark/keylog', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),

  generateLuaDissector: (payload: {
    protoName: string
    description: string
    transport: string
    port: number
    magicHex: string
    fields: { name: string; label: string; type: string; length: number }[]
  }) =>
    req<{ ok: boolean; lua: string }>('/api/wireshark/lua-generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
}
