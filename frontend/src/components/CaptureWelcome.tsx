import React, { useEffect, useState } from 'react'
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Cpu,
  FolderOpen,
  GraduationCap,
  Layers,
  Network,
  Play,
  Radio,
  RefreshCw,
  Shield,
  Sliders,
  Sparkles,
  Wifi,
} from 'lucide-react'
import { api } from '../api'
import type { InterfaceInfo, InterfacesResponse } from '../types'
import type { Lang } from '../utils/i18n'

interface Props {
  lang: Lang
  onStartCapture: (cfg: {
    interfaceId: string
    bpfFilter: string
    promisc: boolean
    snaplen: number
    bufferMb: number
  }) => Promise<void>
  onLoadDemo: (realtime: boolean) => Promise<void>
  onLoadDemoAndLearn: () => Promise<void>
  onImportPcap: (file: File) => Promise<void>
  errorMsg: string | null
}

const Sparkline: React.FC<{ values: number[]; active?: boolean }> = ({ values, active }) => {
  const pts = values && values.length >= 2 ? values : Array(20).fill(0)
  const max = Math.max(100, ...pts)
  const w = 136
  const h = 26
  const step = w / Math.max(1, pts.length - 1)
  const coords = pts.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 5)).toFixed(1)}`)
  const hasTraffic = pts.some((v) => v > 0)
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="overflow-visible shrink-0">
      <polyline
        fill="none"
        stroke={active ? '#06b6d4' : hasTraffic ? '#10b981' : '#64748b'}
        strokeOpacity={hasTraffic || active ? 0.9 : 0.35}
        strokeWidth={hasTraffic ? 1.8 : 1.2}
        strokeLinejoin="round"
        strokeLinecap="round"
        points={coords.join(' ')}
      />
    </svg>
  )
}

export const CaptureWelcome: React.FC<Props> = ({
  lang,
  onStartCapture,
  onLoadDemo,
  onLoadDemoAndLearn,
  onImportPcap,
  errorMsg,
}) => {
  const isZh = lang === 'zh'
  const [data, setData] = useState<InterfacesResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedId, setSelectedId] = useState<string>('')
  const [bpfFilter, setBpfFilter] = useState('')
  const [bpfValid, setBpfValid] = useState<{ valid: boolean; error: string | null }>({ valid: true, error: null })
  const [promisc, setPromisc] = useState(true)
  const [snaplen, setSnaplen] = useState(65535)
  const [bufferMb, setBufferMb] = useState(16)
  const [starting, setStarting] = useState(false)
  const [dragOver, setDragOver] = useState(false)

  const bpfPresets = [
    { label: isZh ? 'All Traffic' : 'All Traffic', expr: '' },
    { label: 'HTTP / HTTPS', expr: 'tcp port 80 or tcp port 443' },
    { label: 'DNS (53)', expr: 'udp port 53 or tcp port 53' },
    { label: 'ICMP & ARP', expr: 'icmp or icmp6 or arp' },
    { label: 'No SSH (!22)', expr: 'not port 22' },
  ]

  const fetchIfaces = () => {
    api
      .getInterfaces()
      .then((res) => {
        setData(res)
        setLoading(false)
        if (!selectedId) {
          const dcPref =
            res.dumpcapInterfaces.find((i) => /^以太网$|^ethernet$/i.test(i.name)) ||
            res.dumpcapInterfaces.find((i) => /wlan|wi-fi|以太网|ethernet/i.test(i.name) && !/2|4|蓝牙/i.test(i.name)) ||
            res.dumpcapInterfaces.find((i) => i.isLoopback) ||
            res.dumpcapInterfaces[0]
          const natPref =
            res.nativeInterfaces.find((i) => i.isUp && !i.isLoopback && i.ipv4) || res.nativeInterfaces[0]
          if (!res.nativeEngine.isRoot && dcPref) {
            setSelectedId(dcPref.id)
          } else if (natPref) {
            setSelectedId(natPref.id)
          } else if (dcPref) {
            setSelectedId(dcPref.id)
          }
        }
      })
      .catch(() => setLoading(false))
  }

  useEffect(() => {
    fetchIfaces()
    const timer = setInterval(fetchIfaces, 2000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    const expr = bpfFilter.trim()
    if (!expr) {
      setBpfValid({ valid: true, error: null })
      return
    }
    const t = setTimeout(() => {
      api.validateBpf(expr).then(setBpfValid).catch(() => {})
    }, 200)
    return () => clearTimeout(t)
  }, [bpfFilter])

  const handleLaunch = async (ifaceId?: string) => {
    const id = ifaceId || selectedId
    if (!id || !bpfValid.valid) return
    setStarting(true)
    try {
      await onStartCapture({ interfaceId: id, bpfFilter, promisc, snaplen, bufferMb })
    } finally {
      setStarting(false)
    }
  }

  const renderIfaceRow = (iface: InterfaceInfo) => {
    const isSelected = selectedId === iface.id
    return (
      <div
        key={iface.id}
        onClick={() => setSelectedId(iface.id)}
        onDoubleClick={() => handleLaunch(iface.id)}
        className={`group flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-lg border transition-all cursor-pointer ${
          isSelected
            ? 'bg-cyan-500/10 dark:bg-cyan-500/12 border-cyan-500/70 shadow-sm shadow-cyan-500/10'
            : 'bg-white dark:bg-[#111827]/90 border-slate-200 dark:border-slate-800 hover:border-cyan-500/40'
        }`}
      >
        <div className="flex items-center gap-3 min-w-0">
          <div
            className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
              isSelected
                ? 'bg-cyan-500 text-white'
                : 'bg-slate-100 dark:bg-slate-800/90 text-slate-500 dark:text-slate-400'
            }`}
          >
            {iface.isWireless || /wlan|wi-fi/i.test(iface.name) ? (
              <Wifi className="w-4 h-4" />
            ) : (
              <Network className="w-4 h-4" />
            )}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-xs text-slate-900 dark:text-slate-100 truncate">
                {iface.name}
              </span>
              {iface.isLoopback && (
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                  Loopback
                </span>
              )}
              {iface.ipv4 && (
                <span className="text-[11px] font-mono-code text-cyan-700 dark:text-cyan-400">
                  {iface.ipv4}
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-[340px]">
              {iface.description}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <Sparkline values={iface.sparkline || []} active={isSelected} />
          <button
            onClick={(e) => {
              e.stopPropagation()
              handleLaunch(iface.id)
            }}
            className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-all cursor-pointer ${
              isSelected
                ? 'bg-cyan-600 hover:bg-cyan-500 text-white'
                : 'opacity-0 group-hover:opacity-100 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-cyan-600 hover:text-white'
            }`}
          >
            Capture
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto p-6 bg-slate-50 dark:bg-[#090d14]">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Hero Banner */}
        <div className="relative overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-800 bg-gradient-to-br from-white via-slate-50 to-cyan-50/60 dark:from-[#0f172a] dark:via-[#0d1424] dark:to-[#0c1d2e] p-6 shadow-sm">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="space-y-2 max-w-2xl">
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-cyan-700 dark:text-cyan-300 text-[11px] font-semibold">
                <Activity className="w-3.5 h-3.5" />
                <span>
                  {isZh
                    ? 'UCAS Software & System Security · Experiment 1A'
                    : 'UCAS Software & System Security · Experiment 1A'}
                </span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                {isZh ? 'WirePulse Capture Studio' : 'Welcome to WirePulse Capture Studio'}
              </h1>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                {isZh ? (
                  <>
                    融合 <span className="font-mono-code text-cyan-600 dark:text-cyan-400">C11 libpcap / Npcap</span> 与{' '}
                    <span className="font-semibold text-violet-600 dark:text-violet-400">Wireshark libwireshark</span> 双引擎：支持经典 3-Pane 抓包、Display Filter 逻辑求值、Follow Stream、OS Process 归因、Security IDS，并内置面向《计算机网络》学习的 <strong>32-bit Header 位图与 OSI 封装动画</strong>。
                  </>
                ) : (
                  <>
                    High-performance <span className="font-mono-code text-cyan-600 dark:text-cyan-400">C11 libpcap / Npcap</span>{' '}
                    packet sniffer with OSI 7-layer DPI dissection, Recursive-Descent Display Filter engine, TCP stream reassembly &amp; sequence diagrams, OS process tracing, real-time Security IDS, and live{' '}
                    <span className="font-semibold text-violet-600 dark:text-violet-400">Wireshark libwireshark (sharkd)</span> integration.
                  </>
                )}
              </p>
            </div>

            {/* Quick Launch Action Cards */}
            <div className="flex flex-wrap gap-2.5 shrink-0">
              <button
                onClick={onLoadDemoAndLearn}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-semibold shadow-lg shadow-emerald-500/20 transition-all cursor-pointer"
              >
                <GraduationCap className="w-4 h-4" />
                <span>{isZh ? '计网学习工坊 (NetLearn)' : 'Open NetLearn Studio'}</span>
              </button>
              <button
                onClick={() => onLoadDemo(false)}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500 text-white text-xs font-semibold shadow-lg shadow-violet-500/20 transition-all cursor-pointer"
              >
                <Sparkles className="w-4 h-4" />
                <span>{isZh ? '加载 Demo Capture' : 'Instant Security Demo'}</span>
              </button>
              <button
                onClick={() => onLoadDemo(true)}
                className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
              >
                <Play className="w-4 h-4" />
                <span>{isZh ? 'Live Replay' : 'Live Replay'}</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-5 pt-4 border-t border-slate-200/70 dark:border-slate-800/80">
            <div className="flex items-center gap-2.5 text-xs">
              <Cpu className="w-4 h-4 text-cyan-500 shrink-0" />
              <div className="min-w-0">
                <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">Native C11 Engine</div>
                <div className="font-mono-code text-slate-800 dark:text-slate-200 truncate">
                  {data?.nativeEngine.version || 'Detecting...'}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2.5 text-xs">
              <Layers className="w-4 h-4 text-violet-500 shrink-0" />
              <div className="min-w-0">
                <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">Wireshark Dual-Engine</div>
                <div className="font-mono-code text-slate-800 dark:text-slate-200 truncate">
                  {data?.wireshark.available ? data.wireshark.version : 'Standalone Native Mode'}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2.5 text-xs">
              <Shield className="w-4 h-4 text-emerald-500 shrink-0" />
              <div className="min-w-0">
                <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">IDS · Process · NetLearn</div>
                <div className="text-slate-800 dark:text-slate-200 truncate">
                  {isZh
                    ? '13 IDS Rules · OS PID 归因 · 32-bit Header 位图'
                    : '13 Threat Rules · OS PID Attribution · 32-bit RFC Headers'}
                </div>
              </div>
            </div>
          </div>
        </div>

        {errorMsg && (
          <div className="flex items-start gap-2.5 p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/35 text-rose-700 dark:text-rose-300 text-xs">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Capture Filter (Kernel BPF) */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-500" />
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
                Capture Filter (Kernel BPF) &amp; Options
              </h2>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-600 dark:text-slate-400">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={promisc}
                  onChange={(e) => setPromisc(e.target.checked)}
                  className="accent-cyan-500 rounded"
                />
                <span>Promiscuous</span>
              </label>
              <label className="flex items-center gap-1.5">
                <span>Ring Buffer:</span>
                <select
                  value={bufferMb}
                  onChange={(e) => setBufferMb(Number(e.target.value))}
                  className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 font-mono-code text-xs"
                >
                  {[4, 8, 16, 32, 64].map((mb) => (
                    <option key={mb} value={mb}>{mb} MB</option>
                  ))}
                </select>
              </label>
              <label className="flex items-center gap-1.5">
                <span>Snaplen:</span>
                <select
                  value={snaplen}
                  onChange={(e) => setSnaplen(Number(e.target.value))}
                  className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 font-mono-code text-xs"
                >
                  <option value={65535}>65535 (Full)</option>
                  <option value={1518}>1518 (MTU)</option>
                  <option value={256}>256 (Headers)</option>
                </select>
              </label>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-2">
            <div
              className={`flex-1 flex items-center gap-2 px-3 h-9 rounded-lg border bg-slate-50 dark:bg-[#090d14] ${
                !bpfValid.valid
                  ? 'border-rose-500 ring-2 ring-rose-500/20'
                  : bpfFilter.trim()
                    ? 'border-emerald-500/70'
                    : 'border-slate-200 dark:border-slate-700/80'
              }`}
            >
              <span className="text-[11px] font-mono-code font-semibold text-cyan-600 dark:text-cyan-400">BPF</span>
              <input
                type="text"
                value={bpfFilter}
                onChange={(e) => setBpfFilter(e.target.value)}
                placeholder={
                  isZh
                    ? 'Enter Capture Filter (pcap_compile)... 例如: tcp port 80 or udp port 53'
                    : 'Enter kernel BPF capture filter (compiled via pcap_compile)... e.g. tcp port 80 or udp port 53'
                }
                className="flex-1 bg-transparent text-xs font-mono-code text-slate-800 dark:text-slate-100 focus:outline-none"
              />
              {bpfFilter.trim() &&
                (bpfValid.valid ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                ) : (
                  <span className="text-[11px] text-rose-500 truncate max-w-[220px]">{bpfValid.error}</span>
                ))}
            </div>
            <button
              onClick={() => handleLaunch()}
              disabled={!selectedId || !bpfValid.valid || starting}
              className="flex items-center justify-center gap-2 px-5 h-9 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-semibold shadow-sm transition-colors cursor-pointer shrink-0"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>{starting ? 'Starting...' : 'Start Capture'}</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-slate-400 mr-1">Presets:</span>
            {bpfPresets.map((p) => (
              <button
                key={p.label}
                onClick={() => setBpfFilter(p.expr)}
                className="px-2 py-0.5 rounded text-[11px] font-mono-code bg-slate-100 dark:bg-slate-800/80 hover:bg-cyan-500/15 text-slate-600 dark:text-slate-300 transition-colors cursor-pointer"
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Network Interface Lists + Offline PCAP Dropzone */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="lg:col-span-2 space-y-4">
            {data && data.dumpcapInterfaces.length > 0 && (
              <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4 space-y-2.5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-violet-600 dark:text-violet-400">
                      Host Physical NICs — Wireshark dumpcap / Npcap Bridge
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      {isZh
                        ? '双击任意网卡即可实时捕获本机流量，抓完后可切到「计网学习」逐包可视化剖析'
                        : 'Double-click any interface to sniff live traffic immediately via Npcap bridge'}
                    </p>
                  </div>
                  <button
                    onClick={fetchIfaces}
                    className="p-1.5 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 cursor-pointer"
                    title="Refresh interfaces"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="space-y-1.5 max-h-[290px] overflow-y-auto pr-1">
                  {data.dumpcapInterfaces.map(renderIfaceRow)}
                </div>
              </div>
            )}

            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4 space-y-2.5">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
                  Native C11 libpcap / TPACKET_V3 Interfaces
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  {isZh ? (
                    <>
                      直接调用 C11 <code className="font-mono-code">libwirepulse_pcap</code> 引擎与实时 Sparkline 采样
                      {data && !data.nativeEngine.isRoot && ' (Linux requires sudo / CAP_NET_RAW)'}
                    </>
                  ) : (
                    <>
                      Direct C11 <code className="font-mono-code">libwirepulse_pcap</code> ring-buffer capture with live sparklines
                      {data && !data.nativeEngine.isRoot && ' (Requires sudo / CAP_NET_RAW on Linux)'}
                    </>
                  )}
                </p>
              </div>
              {loading ? (
                <div className="text-xs text-slate-400 py-6 text-center">Enumerating interfaces via pcap_findalldevs()...</div>
              ) : (
                <div className="space-y-1.5 max-h-[250px] overflow-y-auto pr-1">
                  {(data?.nativeInterfaces || []).map(renderIfaceRow)}
                </div>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <label
              onDragOver={(e) => {
                e.preventDefault()
                setDragOver(true)
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragOver(false)
                const f = e.dataTransfer.files?.[0]
                if (f) onImportPcap(f)
              }}
              className={`flex flex-col items-center justify-center gap-3 p-6 rounded-xl border-2 border-dashed transition-all cursor-pointer text-center ${
                dragOver
                  ? 'border-cyan-500 bg-cyan-500/10'
                  : 'border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f1520] hover:border-cyan-500/60'
              }`}
            >
              <input
                type="file"
                accept=".pcap,.pcapng,.cap"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  if (f) onImportPcap(f)
                  e.target.value = ''
                }}
              />
              <div className="w-11 h-11 rounded-xl bg-sky-500/15 text-sky-500 flex items-center justify-center">
                <FolderOpen className="w-5 h-5" />
              </div>
              <div>
                <div className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                  Open PCAP / PCAPNG
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                  {isZh
                    ? '拖拽或点击导入 Wireshark .pcap / .pcapng 捕获文件'
                    : 'Drag & drop any Wireshark .pcap or .pcapng capture file here, or click to browse.'}
                </p>
              </div>
            </label>

            <div className="rounded-xl border border-emerald-500/30 bg-white dark:bg-[#0f1520] p-4 space-y-3">
              <h3 className="text-xs font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                <GraduationCap className="w-4 h-4" />
                <span>{isZh ? 'Quick Start 上手路径' : 'Quick Start Workflow'}</span>
              </h3>
              <ol className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
                <li className="flex items-start gap-2">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 font-bold text-[11px] flex items-center justify-center shrink-0">
                    1
                  </span>
                  <span>
                    {isZh
                      ? '双击左侧网卡实时抓包（或点击加载 Demo Capture）。'
                      : 'Double-click any NIC to capture live packets (or load Demo Capture).'}
                  </span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-5 h-5 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-bold text-[11px] flex items-center justify-center shrink-0">
                    2
                  </span>
                  <span>
                    {isZh
                      ? '进入「计网学习」交互查看 OSI 套娃封装动画与 32-bit RFC Header 位图。'
                      : 'Open NetLearn Studio to explore OSI encapsulation & live 32-bit RFC header diagrams.'}
                  </span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-5 h-5 rounded-full bg-violet-500/15 text-violet-600 dark:text-violet-400 font-bold text-[11px] flex items-center justify-center shrink-0">
                    3
                  </span>
                  <span>
                    {isZh
                      ? '在 Streams / Processes / Security 视图排查重传、进程连接与安全告警。'
                      : 'Inspect TCP flows, OS processes, and real-time IDS alerts across workspace tabs.'}
                  </span>
                </li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
