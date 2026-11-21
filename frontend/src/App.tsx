import React, { useCallback, useEffect, useRef, useState } from 'react'
import {
  BarChart3,
  Cpu,
  GitBranch,
  Layers,
  Radio,
  ShieldAlert,
  Sparkles,
} from 'lucide-react'
import { api } from './api'
import { AnalyticsView } from './components/AnalyticsView'
import { CaptureWelcome } from './components/CaptureWelcome'
import { HexDumpPane } from './components/HexDumpPane'
import { PacketDetailsPane } from './components/PacketDetailsPane'
import { PacketListPane } from './components/PacketListPane'
import { ProcessView } from './components/ProcessView'
import { SecurityView } from './components/SecurityView'
import { StreamView } from './components/StreamView'
import { TopToolbar } from './components/TopToolbar'
import { WiresharkLabView } from './components/WiresharkLabView'
import type {
  HighlightRange,
  LayerNode,
  NavTab,
  PacketDetail,
  PacketSummary,
  SessionStatus,
} from './types'
import { formatBytes } from './utils/coloring'

const INITIAL_STATUS: SessionStatus = {
  capturing: false,
  paused: false,
  engine: 'idle',
  interface: '',
  bpfFilter: '',
  error: null,
  totalPackets: 0,
  totalBytes: 0,
  tcpStreams: 0,
  udpStreams: 0,
  alerts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, TOTAL: 0 },
  kernelStats: { recv: 0, drop: 0, ifdrop: 0 },
  nativeVersion: '',
  wiresharkAvailable: false,
  wiresharkVersion: '',
  keylogActive: false,
}

export default function App() {
  const [dark, setDark] = useState(true)
  const [activeTab, setActiveTab] = useState<NavTab>('capture')
  const [status, setStatus] = useState<SessionStatus>(INITIAL_STATUS)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  // Packet list & Display Filter state
  const [packets, setPackets] = useState<PacketSummary[]>([])
  const [totalCaptured, setTotalCaptured] = useState(0)
  const [filterExpr, setFilterExpr] = useState('')
  const [appliedFilter, setAppliedFilter] = useState('')
  const [filterAst, setFilterAst] = useState('ALL')
  const [filterError, setFilterError] = useState<string | null>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  // Selected Packet & Dual-Engine Detail state
  const [selectedNo, setSelectedNo] = useState<number | null>(null)
  const [detail, setDetail] = useState<PacketDetail | null>(null)
  const [engineMode, setEngineMode] = useState<'native' | 'wireshark'>('native')
  const [wsLayers, setWsLayers] = useState<LayerNode[] | null>(null)
  const [wsEngineName, setWsEngineName] = useState('')
  const [wsLoading, setWsLoading] = useState(false)
  const [wsError, setWsError] = useState<string | null>(null)
  const [tlsDecrypted, setTlsDecrypted] = useState(false)
  const [highlight, setHighlight] = useState<HighlightRange | null>(null)
  const [selectedByteOffset, setSelectedByteOffset] = useState<number | null>(null)

  // Stream / Process cross-navigation state
  const [streamSelection, setStreamSelection] = useState<{
    proto: 'tcp' | 'udp'
    streamId: number
    tab?: 'stream' | 'sequence'
  } | null>(null)
  const [streamProcFilter, setStreamProcFilter] = useState<{ pid: number | null; name: string } | null>(null)

  // Draggable 3-Pane Splitter proportions
  const [topPanePct, setTopPanePct] = useState(52)
  const [leftBottomPct, setLeftBottomPct] = useState(55)
  const workspaceRef = useRef<HTMLDivElement>(null)
  const bottomPaneRef = useRef<HTMLDivElement>(null)

  const appliedFilterRef = useRef(appliedFilter)
  appliedFilterRef.current = appliedFilter

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
  }, [dark])

  const fetchPackets = useCallback(async (expr = appliedFilterRef.current) => {
    try {
      const res = await api.getPackets(expr, 0, 15000)
      if (!res.ok) {
        setFilterError(res.error || 'Invalid filter')
        return
      }
      setFilterError(null)
      setFilterAst(res.ast || 'ALL')
      setPackets(res.packets || [])
      setTotalCaptured(res.totalCaptured)
    } catch {
      // ignore network jitter
    }
  }, [])

  const refreshStatus = useCallback(() => {
    api
      .getStatus()
      .then((st) => {
        setStatus(st)
        if (st.totalPackets > 0) {
          fetchPackets(appliedFilterRef.current)
        }
      })
      .catch(() => {})
  }, [fetchPackets])

  useEffect(() => {
    refreshStatus()
  }, [refreshStatus])

  // Real-time WebSocket Stream
  useEffect(() => {
    let ws: WebSocket | null = null
    let closed = false
    let retryTimer: ReturnType<typeof setTimeout>

    const connect = () => {
      if (closed) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const url = `${proto}://${window.location.host}/ws`
      ws = new WebSocket(url)

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data)
          if (msg.status) setStatus(msg.status)
          if (msg.type === 'reload') {
            fetchPackets(appliedFilterRef.current)
          } else if (msg.type === 'batch' && Array.isArray(msg.packets)) {
            setTotalCaptured(msg.status?.totalPackets ?? 0)
            if (!appliedFilterRef.current.trim()) {
              setPackets((prev) => {
                const next = [...prev, ...msg.packets]
                return next.length > 20000 ? next.slice(next.length - 20000) : next
              })
            } else {
              // When display filter is active during live capture, re-query server AST filter cleanly
              fetchPackets(appliedFilterRef.current)
            }
          }
        } catch {
          // ignore
        }
      }

      ws.onclose = () => {
        if (!closed) {
          retryTimer = setTimeout(connect, 1500)
        }
      }
    }

    connect()
    return () => {
      closed = true
      clearTimeout(retryTimer)
      ws?.close()
    }
  }, [fetchPackets])

  // Load Packet Detail whenever selectedNo changes
  useEffect(() => {
    if (selectedNo === null) {
      setDetail(null)
      setWsLayers(null)
      return
    }
    setHighlight(null)
    setSelectedByteOffset(null)
    api
      .getPacketDetail(selectedNo)
      .then((res) => {
        if (res.ok) setDetail(res)
      })
      .catch(() => {})

    if (engineMode === 'wireshark') {
      loadWiresharkDetail(selectedNo)
    } else {
      setWsLayers(null)
    }
  }, [selectedNo])

  const loadWiresharkDetail = useCallback(async (no: number) => {
    setWsLoading(true)
    setWsError(null)
    try {
      const res = await api.getPacketWiresharkDetail(no)
      if (res.ok && res.layers) {
        setWsLayers(res.layers)
        setWsEngineName(res.engine || 'Wireshark libwireshark')
        setTlsDecrypted(Boolean(res.tlsDecryptionActive))
      } else {
        setWsError(res.error || 'Wireshark dissection failed')
        setWsLayers(null)
      }
    } catch (e) {
      setWsError(String(e))
    } finally {
      setWsLoading(false)
    }
  }, [])

  const handleEngineChange = (mode: 'native' | 'wireshark') => {
    setEngineMode(mode)
    if (mode === 'wireshark' && selectedNo !== null) {
      loadWiresharkDetail(selectedNo)
    }
  }

  // Keyboard Up/Down navigation in Packet List
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (activeTab !== 'packets' || packets.length === 0) return
      const tag = (e.target as HTMLElement)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault()
        const idx = packets.findIndex((p) => p.no === selectedNo)
        const nextIdx =
          e.key === 'ArrowDown'
            ? Math.min(packets.length - 1, idx === -1 ? 0 : idx + 1)
            : Math.max(0, idx === -1 ? 0 : idx - 1)
        setSelectedNo(packets[nextIdx].no)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [activeTab, packets, selectedNo])

  // Splitter Drag Handlers
  const startVerticalResize = (e: React.MouseEvent) => {
    e.preventDefault()
    const el = workspaceRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const onMove = (ev: MouseEvent) => {
      const pct = ((ev.clientY - rect.top) / rect.height) * 100
      setTopPanePct(Math.min(78, Math.max(22, pct)))
    }
    const onUp = () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  const startHorizontalResize = (e: React.MouseEvent) => {
    e.preventDefault()
    const el = bottomPaneRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const onMove = (ev: MouseEvent) => {
      const pct = ((ev.clientX - rect.left) / rect.width) * 100
      setLeftBottomPct(Math.min(75, Math.max(28, pct)))
    }
    const onUp = () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  // Actions
  const handleStartCapture = async (cfg: {
    interfaceId: string
    bpfFilter: string
    promisc: boolean
    snaplen: number
    bufferMb: number
  }) => {
    setErrorMsg(null)
    const res = await api.startCapture(cfg)
    if (!res.ok) {
      setErrorMsg(res.error || 'Failed to start capture')
      return
    }
    if (res.status) setStatus(res.status)
    setPackets([])
    setSelectedNo(null)
    setDetail(null)
    setFilterExpr('')
    setAppliedFilter('')
    setActiveTab('packets')
  }

  const handleLoadDemo = async (realtime: boolean) => {
    setErrorMsg(null)
    setPackets([])
    setSelectedNo(null)
    setDetail(null)
    setFilterExpr('')
    setAppliedFilter('')
    const res = await api.loadDemo(realtime)
    if (res.status) setStatus(res.status)
    setActiveTab('packets')
    if (!realtime) {
      const list = await api.getPackets('', 0, 15000)
      if (list.ok) {
        setPackets(list.packets)
        setTotalCaptured(list.totalCaptured)
        if (list.packets.length > 0) setSelectedNo(list.packets[0].no)
      }
    }
  }

  const handleImportPcap = async (file: File) => {
    setErrorMsg(null)
    const res = await api.importPcap(file)
    if (!res.ok) {
      setErrorMsg(res.error || 'Failed to import PCAP file')
      return
    }
    if (res.status) setStatus(res.status)
    setFilterExpr('')
    setAppliedFilter('')
    setActiveTab('packets')
    const list = await api.getPackets('', 0, 15000)
    if (list.ok) {
      setPackets(list.packets)
      setTotalCaptured(list.totalCaptured)
      setSelectedNo(list.packets[0]?.no ?? null)
    }
  }

  const handleApplyFilter = (expr?: string) => {
    const target = expr !== undefined ? expr : filterExpr
    setFilterExpr(target)
    setAppliedFilter(target)
    setActiveTab('packets')
    fetchPackets(target)
  }

  const handleJumpToPacket = (packetNo: number) => {
    setFilterExpr('')
    setAppliedFilter('')
    setActiveTab('packets')
    fetchPackets('')
    setSelectedNo(packetNo)
  }

  const handleFollowStream = (
    proto: 'tcp' | 'udp',
    streamId: number,
    tab: 'stream' | 'sequence' = 'stream',
  ) => {
    setStreamProcFilter(null)
    setStreamSelection({ proto, streamId, tab })
    setActiveTab('streams')
  }

  const navItems: { id: NavTab; label: string; icon: React.FC<{ className?: string }>; badge?: number; danger?: boolean }[] = [
    { id: 'capture', label: 'Capture', icon: Radio },
    { id: 'packets', label: 'Packets', icon: Layers, badge: status.totalPackets || undefined },
    { id: 'streams', label: 'Streams', icon: GitBranch, badge: status.tcpStreams + status.udpStreams || undefined },
    { id: 'processes', label: 'Processes', icon: Cpu },
    {
      id: 'security',
      label: 'Security',
      icon: ShieldAlert,
      badge: status.alerts.TOTAL || undefined,
      danger: status.alerts.CRITICAL > 0 || status.alerts.HIGH > 0,
    },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 },
    { id: 'wireshark', label: 'WS Lab', icon: Sparkles },
  ]

  const displayedPct =
    totalCaptured > 0 ? ((packets.length / totalCaptured) * 100).toFixed(1) : '100.0'

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-slate-100 dark:bg-[#090d14] text-slate-900 dark:text-slate-100">
      {/* Top Toolbar + Display Filter Bar */}
      <TopToolbar
        status={status}
        activeTab={activeTab}
        dark={dark}
        onToggleTheme={() => setDark((d) => !d)}
        filterExpr={filterExpr}
        appliedFilter={appliedFilter}
        filterAst={filterAst}
        filterError={filterError}
        onFilterExprChange={setFilterExpr}
        onApplyFilter={handleApplyFilter}
        onStopCapture={() => api.stopCapture().then((r) => setStatus(r.status))}
        onPauseCapture={() => api.pauseCapture().then((r) => setStatus(r.status))}
        onClearCapture={() => {
          api.clearCapture().then((r) => {
            setStatus(r.status)
            setPackets([])
            setTotalCaptured(0)
            setSelectedNo(null)
            setDetail(null)
          })
        }}
        onLoadDemo={handleLoadDemo}
        onImportPcap={handleImportPcap}
        onNavigate={setActiveTab}
      />

      {/* Main Content Area: Left Navigation Rail + Active Workspace */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Slim IDE-style Activity Rail */}
        <aside className="w-[68px] border-r border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#0d131f] flex flex-col items-center py-2.5 gap-1 shrink-0 select-none">
          {navItems.map((item) => {
            const Icon = item.icon
            const active = activeTab === item.id
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`relative w-[56px] py-2 rounded-xl flex flex-col items-center justify-center gap-1 transition-all cursor-pointer ${
                  active
                    ? 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 font-semibold shadow-xs'
                    : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                {active && (
                  <span className="absolute left-0 top-2.5 bottom-2.5 w-[3px] rounded-r-full bg-cyan-500" />
                )}
                <Icon className={`w-[18px] h-[18px] ${item.danger && !active ? 'text-rose-500' : ''}`} />
                <span className="text-[10px] leading-none">{item.label}</span>
                {item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`absolute top-1 right-1 min-w-[16px] h-4 px-1 rounded-full text-[9px] font-mono-code font-bold flex items-center justify-center ${
                      item.danger
                        ? 'bg-rose-500 text-white'
                        : 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                    }`}
                  >
                    {item.badge > 999 ? '999+' : item.badge}
                  </span>
                )}
              </button>
            )
          })}
        </aside>

        {/* Active View Workspace */}
        <main className="flex-1 min-w-0 min-h-0 overflow-hidden relative">
          {activeTab === 'capture' && (
            <CaptureWelcome
              onStartCapture={handleStartCapture}
              onLoadDemo={handleLoadDemo}
              onImportPcap={handleImportPcap}
              errorMsg={errorMsg}
            />
          )}

          {activeTab === 'packets' && (
            <div ref={workspaceRef} className="flex flex-col h-full w-full overflow-hidden">
              {/* Top Pane: Packet List */}
              <div style={{ height: `${topPanePct}%` }} className="min-h-0 overflow-hidden">
                <PacketListPane
                  packets={packets}
                  totalCaptured={totalCaptured}
                  selectedNo={selectedNo}
                  autoScroll={autoScroll}
                  onToggleAutoScroll={() => setAutoScroll((v) => !v)}
                  onSelectPacket={(no) => setSelectedNo(no)}
                  onApplyFilter={handleApplyFilter}
                  onFollowStream={handleFollowStream}
                  onTraceProcess={(pid, name) => {
                    setStreamProcFilter({ pid, name })
                    setStreamSelection(null)
                    setActiveTab('streams')
                  }}
                  onInspectWireshark={(no) => {
                    setSelectedNo(no)
                    setEngineMode('wireshark')
                    loadWiresharkDetail(no)
                  }}
                />
              </div>

              {/* Draggable Horizontal Splitter */}
              <div
                onMouseDown={startVerticalResize}
                className="h-1.5 bg-slate-200 dark:bg-slate-800/90 hover:bg-cyan-500/70 cursor-row-resize transition-colors shrink-0 flex items-center justify-center"
                title="Drag to resize Packet List / Inspector panes"
              >
                <div className="w-10 h-0.5 rounded-full bg-slate-400/60" />
              </div>

              {/* Bottom Split: Packet Details Tree (Left) + Hex/ASCII/Binary Dump (Right) */}
              <div
                ref={bottomPaneRef}
                style={{ height: `calc(${100 - topPanePct}% - 6px)` }}
                className="flex min-h-0 overflow-hidden"
              >
                <div style={{ width: `${leftBottomPct}%` }} className="min-w-0 h-full overflow-hidden">
                  <PacketDetailsPane
                    detail={detail}
                    engineMode={engineMode}
                    wiresharkLayers={wsLayers}
                    wiresharkEngineName={wsEngineName}
                    wiresharkLoading={wsLoading}
                    wiresharkError={wsError}
                    tlsDecrypted={tlsDecrypted}
                    wiresharkAvailable={status.wiresharkAvailable}
                    highlight={highlight}
                    selectedByteOffset={selectedByteOffset}
                    onEngineChange={handleEngineChange}
                    onHighlight={setHighlight}
                    onApplyFilter={handleApplyFilter}
                    onFollowStream={(proto, sid) => handleFollowStream(proto, sid, 'stream')}
                  />
                </div>

                {/* Draggable Vertical Splitter */}
                <div
                  onMouseDown={startHorizontalResize}
                  className="w-1.5 bg-slate-200 dark:bg-slate-800/90 hover:bg-cyan-500/70 cursor-col-resize transition-colors shrink-0 flex items-center justify-center"
                  title="Drag to resize Details / Hex panes"
                >
                  <div className="h-10 w-0.5 rounded-full bg-slate-400/60" />
                </div>

                <div
                  style={{ width: `calc(${100 - leftBottomPct}% - 6px)` }}
                  className="min-w-0 h-full overflow-hidden"
                >
                  <HexDumpPane
                    rawHex={detail?.rawHex || ''}
                    highlight={highlight}
                    selectedByteOffset={selectedByteOffset}
                    onSelectByte={(off) => {
                      setSelectedByteOffset(off)
                      setHighlight({ offset: off, length: 1 })
                    }}
                  />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'streams' && (
            <StreamView
              initialSelection={streamSelection}
              processFilter={streamProcFilter}
              onClearProcessFilter={() => setStreamProcFilter(null)}
              onJumpToPacket={handleJumpToPacket}
              onApplyFilter={handleApplyFilter}
            />
          )}

          {activeTab === 'processes' && (
            <ProcessView
              onTraceProcessStreams={(pid, name) => {
                setStreamProcFilter({ pid, name })
                setStreamSelection(null)
                setActiveTab('streams')
              }}
              onFilterProcessPackets={(pid) => handleApplyFilter(`proc.pid == ${pid}`)}
            />
          )}

          {activeTab === 'security' && (
            <SecurityView
              onJumpToPacket={handleJumpToPacket}
              onFollowStream={(proto, sid) => handleFollowStream(proto, sid, 'stream')}
            />
          )}

          {activeTab === 'analytics' && (
            <AnalyticsView
              onFilterIp={(ip) => handleApplyFilter(`ip.addr == ${ip}`)}
              onFilterProto={(proto) => handleApplyFilter(proto)}
            />
          )}

          {activeTab === 'wireshark' && (
            <WiresharkLabView
              status={status}
              onApplyFilter={handleApplyFilter}
              onStatusRefresh={refreshStatus}
            />
          )}
        </main>
      </div>

      {/* Bottom Wireshark-Style Telemetry Status Bar */}
      <footer className="h-6 px-3 border-t border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#0d131f] flex items-center justify-between text-[11px] font-mono-code text-slate-500 dark:text-slate-400 select-none shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <span className="truncate max-w-[330px]" title={status.engine}>
            Engine: <strong className="text-slate-700 dark:text-slate-200">{status.engine}</strong>
          </span>
          <span className="hidden sm:inline text-slate-300 dark:text-slate-700">|</span>
          <span className="hidden sm:inline">
            Packets: <strong className="text-slate-700 dark:text-slate-200">{totalCaptured}</strong> · Displayed:{' '}
            <strong className="text-cyan-600 dark:text-cyan-400">
              {packets.length} ({displayedPct}%)
            </strong>
          </span>
          <span className="hidden md:inline text-slate-300 dark:text-slate-700">|</span>
          <span className="hidden md:inline">
            Volume: {formatBytes(status.totalBytes)}
          </span>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <span className="hidden lg:inline">
            Kernel Recv/Drop:{' '}
            <strong className="text-emerald-600 dark:text-emerald-400">
              {status.kernelStats.recv}/{status.kernelStats.drop}
            </strong>
          </span>
          {status.alerts.TOTAL > 0 && (
            <button
              onClick={() => setActiveTab('security')}
              className="text-rose-600 dark:text-rose-400 font-semibold hover:underline cursor-pointer"
            >
              IDS Alerts: {status.alerts.TOTAL} ({status.alerts.CRITICAL} Crit)
            </button>
          )}
          <span className="text-violet-600 dark:text-violet-400 hidden xl:inline">
            {status.wiresharkAvailable ? 'libwireshark Ready' : 'Native OSI Mode'}
          </span>
        </div>
      </footer>
    </div>
  )
}
