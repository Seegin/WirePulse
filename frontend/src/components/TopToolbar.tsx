import React, { useEffect, useMemo, useRef, useState } from 'react'
import {
  Download,
  Filter,
  FolderOpen,
  Moon,
  Pause,
  Play,
  Radio,
  ShieldAlert,
  Sparkles,
  Square,
  Sun,
  Trash2,
  X,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react'
import { api } from '../api'
import type { FilterFieldCatalogItem, NavTab, SessionStatus } from '../types'

interface Props {
  status: SessionStatus
  activeTab: NavTab
  dark: boolean
  onToggleTheme: () => void
  filterExpr: string
  appliedFilter: string
  filterAst: string
  filterError: string | null
  onFilterExprChange: (val: string) => void
  onApplyFilter: (expr?: string) => void
  onStopCapture: () => void
  onPauseCapture: () => void
  onClearCapture: () => void
  onLoadDemo: (realtime: boolean) => void
  onImportPcap: (file: File) => void
  onNavigate: (tab: NavTab) => void
}

const QUICK_FILTERS = [
  { label: 'All', expr: '' },
  { label: 'HTTP', expr: 'http' },
  { label: 'TLS', expr: 'tls' },
  { label: 'DNS', expr: 'dns' },
  { label: 'TCP', expr: 'tcp' },
  { label: 'UDP', expr: 'udp' },
  { label: 'ARP', expr: 'arp' },
  { label: 'ICMP', expr: 'icmp || icmpv6' },
  { label: 'Alerts', expr: 'alert', danger: true },
  { label: 'Retrans', expr: 'tcp.analysis.retransmission || tcp.flags.rst' },
]

export const TopToolbar: React.FC<Props> = ({
  status,
  activeTab,
  dark,
  onToggleTheme,
  filterExpr,
  appliedFilter,
  filterAst,
  filterError,
  onFilterExprChange,
  onApplyFilter,
  onStopCapture,
  onPauseCapture,
  onClearCapture,
  onLoadDemo,
  onImportPcap,
  onNavigate,
}) => {
  const fileRef = useRef<HTMLInputElement>(null)
  const [catalog, setCatalog] = useState<FilterFieldCatalogItem[]>([])
  const [showSuggest, setShowSuggest] = useState(false)
  const [liveValid, setLiveValid] = useState<{ valid: boolean; ast: string | null; error: string | null }>({
    valid: true,
    ast: 'ALL',
    error: null,
  })

  useEffect(() => {
    api.getFilterFields().then((r) => setCatalog(r.fields || [])).catch(() => {})
  }, [])

  // Live syntax validation with short debounce
  useEffect(() => {
    const trimmed = filterExpr.trim()
    if (!trimmed) {
      setLiveValid({ valid: true, ast: 'ALL', error: null })
      return
    }
    const timer = setTimeout(() => {
      api
        .validateFilter(trimmed)
        .then((res) => setLiveValid({ valid: res.valid, ast: res.ast, error: res.error }))
        .catch(() => {})
    }, 140)
    return () => clearTimeout(timer)
  }, [filterExpr])

  const suggestions = useMemo(() => {
    const parts = filterExpr.split(/[\s()!&|]+/)
    const token = (parts[parts.length - 1] || '').toLowerCase()
    if (!token) return catalog.slice(0, 8)
    return catalog
      .filter((c) => c.field.toLowerCase().includes(token) || c.desc.toLowerCase().includes(token))
      .slice(0, 8)
  }, [filterExpr, catalog])

  const insertSuggestion = (field: string) => {
    const match = filterExpr.match(/^(.*?)([A-Za-z0-9_.]*)$/)
    const prefix = match ? match[1] : ''
    onFilterExprChange(prefix + field)
    setShowSuggest(false)
  }

  return (
    <header className="flex flex-col border-b border-slate-200 dark:border-slate-800/90 bg-white/95 dark:bg-[#0d131f]/95 backdrop-blur-md z-30 select-none">
      {/* Row 1: Brand + Capture Controls + Theme */}
      <div className="flex items-center justify-between h-12 px-3.5 gap-3">
        {/* Brand Logo */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={() => onNavigate('capture')}
            className="flex items-center gap-2.5 group focus:outline-none"
            title="WirePulse Capture Hub"
          >
            <div className="relative w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 via-sky-500 to-indigo-600 flex items-center justify-center shadow-md shadow-cyan-500/20 group-hover:scale-105 transition-transform">
              {/* Custom Shark Fin + Telemetry Pulse SVG */}
              <svg viewBox="0 0 24 24" className="w-5 h-5 text-white" fill="none">
                <path
                  d="M3 16.5H7.2L9.5 11.5L12.5 17.5L15 6C17.2 8.2 18.8 11.8 19.2 16.5H21"
                  stroke="currentColor"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
            <div className="flex flex-col text-left leading-none">
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-[15px] tracking-tight text-slate-900 dark:text-white">
                  Wire<span className="text-cyan-600 dark:text-cyan-400">Pulse</span>
                </span>
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
                  PRO
                </span>
              </div>
              <span className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">
                Packet Sniffer &amp; Security NPA
              </span>
            </div>
          </button>

          <div className="h-6 w-px bg-slate-200 dark:bg-slate-800 mx-1" />

          {/* Live Capture Status Pill */}
          <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 text-xs">
            <span
              className={`relative w-2 h-2 rounded-full shrink-0 ${
                status.capturing
                  ? status.paused
                    ? 'bg-amber-400'
                    : 'bg-emerald-500 text-emerald-500 live-pulse'
                  : 'bg-slate-400 dark:bg-slate-600'
              }`}
            />
            <span className="font-medium text-slate-700 dark:text-slate-200 max-w-[260px] truncate">
              {status.capturing
                ? status.paused
                  ? `Paused · ${status.interface}`
                  : `Capturing · ${status.interface}`
                : status.interface || 'Ready to Capture'}
            </span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-1.5 shrink-0 whitespace-nowrap">
          {!status.capturing ? (
            <button
              onClick={() => onNavigate('capture')}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm shadow-cyan-500/20 transition-colors cursor-pointer"
              title="Select Network Interface & Start Live Capture"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>New Capture</span>
            </button>
          ) : (
            <>
              <button
                onClick={onPauseCapture}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium border transition-colors cursor-pointer ${
                  status.paused
                    ? 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-500'
                    : 'bg-amber-500/15 hover:bg-amber-500/25 text-amber-700 dark:text-amber-300 border-amber-500/40'
                }`}
                title={status.paused ? 'Resume Capture' : 'Pause Capture'}
              >
                {status.paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                <span>{status.paused ? 'Resume' : 'Pause'}</span>
              </button>
              <button
                onClick={onStopCapture}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-rose-600 hover:bg-rose-500 text-white shadow-sm transition-colors cursor-pointer"
                title="Stop Live Capture"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop</span>
              </button>
            </>
          )}

          <button
            onClick={() => onLoadDemo(false)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-violet-500/12 hover:bg-violet-500/20 text-violet-700 dark:text-violet-300 border border-violet-500/30 transition-colors cursor-pointer"
            title="Load Multi-Protocol & Security Incident Lab Capture"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Security Demo</span>
          </button>

          <div className="h-5 w-px bg-slate-200 dark:bg-slate-800 mx-0.5" />

          <input
            ref={fileRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) onImportPcap(f)
              e.target.value = ''
            }}
          />
          <button
            onClick={() => fileRef.current?.click()}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700/80 transition-colors cursor-pointer"
            title="Import .pcap / .pcapng file"
          >
            <FolderOpen className="w-3.5 h-3.5 text-sky-500" />
            <span className="hidden sm:inline">Open PCAP</span>
          </button>

          <a
            href={api.exportPcapUrl(appliedFilter)}
            download="wirepulse_capture.pcap"
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium border transition-colors ${
              status.totalPackets > 0
                ? 'text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-700/80'
                : 'opacity-40 pointer-events-none border-slate-200 dark:border-slate-800 text-slate-400'
            }`}
            title="Export captured/filtered packets as standard Wireshark .pcap"
          >
            <Download className="w-3.5 h-3.5 text-emerald-500" />
            <span className="hidden sm:inline">Export</span>
          </a>

          <button
            onClick={onClearCapture}
            className="p-1.5 rounded-md text-slate-500 hover:text-rose-500 hover:bg-rose-500/10 transition-colors cursor-pointer"
            title="Clear current capture buffer"
          >
            <Trash2 className="w-4 h-4" />
          </button>

          <button
            onClick={onToggleTheme}
            className="p-1.5 rounded-md text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            title={dark ? 'Switch to Daylight Light Theme' : 'Switch to Obsidian Dark Theme'}
          >
            {dark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-indigo-500" />}
          </button>
        </div>
      </div>

      {/* Row 2: Wireshark Display Filter Bar (visible on Packets tab or whenever filter is active) */}
      {(activeTab === 'packets' || appliedFilter) && (
        <div className="flex flex-wrap items-center gap-2 px-3.5 py-1.5 border-t border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-[#0a0f18]">
          <div className="relative flex-1 min-w-[280px]">
            <div
              className={`flex items-center gap-2 px-2.5 h-8 rounded-md border transition-all bg-white dark:bg-[#111827] ${
                !liveValid.valid || filterError
                  ? 'border-rose-500/80 ring-2 ring-rose-500/20'
                  : filterExpr.trim()
                    ? 'border-emerald-500/70 ring-1 ring-emerald-500/15'
                    : 'border-slate-300 dark:border-slate-700/80 focus-within:border-cyan-500'
              }`}
            >
              <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <input
                type="text"
                value={filterExpr}
                onChange={(e) => onFilterExprChange(e.target.value)}
                onFocus={() => setShowSuggest(true)}
                onBlur={() => setTimeout(() => setShowSuggest(false), 160)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    setShowSuggest(false)
                    onApplyFilter(filterExpr)
                  }
                }}
                placeholder='Apply Display Filter... e.g. (http or dns) && ip.src == 10.212.5.0/24  |  proc.name == "chrome.exe"  |  alert'
                className="flex-1 bg-transparent text-xs font-mono-code text-slate-800 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none"
              />
              {filterExpr && (
                <button
                  onClick={() => {
                    onFilterExprChange('')
                    onApplyFilter('')
                  }}
                  className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                  title="Clear filter"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
              {liveValid.valid ? (
                filterExpr.trim() && (
                  <span
                    className="hidden md:flex items-center gap-1 text-[10px] font-mono-code px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 max-w-[220px] truncate"
                    title={`Parsed AST: ${liveValid.ast}`}
                  >
                    <CheckCircle2 className="w-3 h-3 shrink-0" />
                    <span className="truncate">{liveValid.ast}</span>
                  </span>
                )
              ) : (
                <span
                  className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-600 dark:text-rose-300 max-w-[240px] truncate"
                  title={liveValid.error || ''}
                >
                  <AlertCircle className="w-3 h-3 shrink-0" />
                  <span className="truncate">{liveValid.error}</span>
                </span>
              )}
              <button
                onClick={() => onApplyFilter(filterExpr)}
                disabled={!liveValid.valid}
                className="px-2.5 py-0.5 rounded text-[11px] font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white transition-colors cursor-pointer"
              >
                Apply
              </button>
            </div>

            {/* Autocomplete Dropdown */}
            {showSuggest && suggestions.length > 0 && (
              <div className="absolute left-0 right-0 top-9 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#121a2b] shadow-xl overflow-hidden z-50">
                <div className="px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-slate-800 flex justify-between">
                  <span>Display Filter Fields (Logical ops: &amp;&amp;, ||, !, ==, !=, contains, matches, in &#123;...&#125;)</span>
                  <span>Click to insert</span>
                </div>
                {suggestions.map((s) => (
                  <button
                    key={s.field}
                    onMouseDown={(e) => {
                      e.preventDefault()
                      insertSuggestion(s.field)
                    }}
                    className="w-full flex items-center justify-between px-2.5 py-1.5 text-xs hover:bg-cyan-500/10 text-left transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono-code font-semibold text-cyan-600 dark:text-cyan-400">
                        {s.field}
                      </span>
                      <span className="text-[10px] px-1.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500">
                        {s.type}
                      </span>
                    </div>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-[300px]">
                      {s.desc}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Quick Filter Chips */}
          <div className="flex items-center gap-1 overflow-x-auto">
            {QUICK_FILTERS.map((qf) => {
              const active = appliedFilter === qf.expr
              return (
                <button
                  key={qf.label}
                  onClick={() => {
                    onFilterExprChange(qf.expr)
                    onApplyFilter(qf.expr)
                  }}
                  className={`px-2 py-1 rounded text-[11px] font-medium border transition-all cursor-pointer shrink-0 ${
                    active
                      ? qf.danger
                        ? 'bg-rose-600 text-white border-rose-500 shadow-sm'
                        : 'bg-cyan-600 text-white border-cyan-500 shadow-sm'
                      : qf.danger
                        ? 'bg-rose-500/10 text-rose-600 dark:text-rose-300 border-rose-500/30 hover:bg-rose-500/20'
                        : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:border-cyan-500/50'
                  }`}
                >
                  {qf.danger && <ShieldAlert className="w-3 h-3 inline mr-1 -mt-0.5" />}
                  {qf.label}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </header>
  )
}
