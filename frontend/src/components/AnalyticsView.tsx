import React, { useEffect, useState } from 'react'
import { Activity, BarChart3, Cpu, Gauge, Globe, Network, ShieldAlert } from 'lucide-react'
import { api } from '../api'
import type { AnalyticsPayload } from '../types'
import { formatBytes } from '../utils/coloring'
import type { Lang } from '../utils/i18n'

interface Props {
  lang: Lang
  onFilterIp: (ip: string) => void
  onFilterProto: (proto: string) => void
}

const CHART_PALETTE = [
  '#06b6d4', '#8b5cf6', '#10b981', '#f59e0b', '#f43f5e', '#0ea5e9', '#14b8a6', '#ec4899', '#6366f1',
]

export const AnalyticsView: React.FC<Props> = ({ lang, onFilterIp, onFilterProto }) => {
  const isZh = lang === 'zh'
  const [data, setData] = useState<AnalyticsPayload | null>(null)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)

  useEffect(() => {
    const load = () => {
      api.getAnalytics().then(setData).catch(() => {})
    }
    load()
    const t = setInterval(load, 2000)
    return () => clearInterval(t)
  }, [])

  if (!data) {
    return (
      <div className="h-full flex items-center justify-center text-xs text-slate-400">
        Loading telemetry &amp; topology analytics...
      </div>
    )
  }

  const totalPkts = Math.max(1, data.status.totalPackets)
  const dropRate =
    data.status.kernelStats.recv > 0
      ? ((data.status.kernelStats.drop / data.status.kernelStats.recv) * 100).toFixed(2)
      : '0.00'

  // Compute radial layout for interactive network communication topology
  const nodes = data.topology.nodes
  const cx = 310
  const cy = 195
  const rx = 215
  const ry = 140
  const nodePos: Record<string, { x: number; y: number }> = {}
  nodes.forEach((n, idx) => {
    const angle = (idx / Math.max(1, nodes.length)) * Math.PI * 2 - Math.PI / 2
    nodePos[n.id] = {
      x: nodes.length === 1 ? cx : cx + Math.cos(angle) * rx,
      y: nodes.length === 1 ? cy : cy + Math.sin(angle) * ry,
    }
  })

  // Time-series SVG calculations
  const ts = data.timeseries
  const maxPps = Math.max(5, ...ts.map((p) => p.pps))
  const maxBps = Math.max(1024, ...ts.map((p) => p.bps))

  return (
    <div className="h-full overflow-y-auto p-6 bg-slate-50 dark:bg-[#090d14]">
      <div className="max-w-7xl mx-auto space-y-5">
        {/* KPI Telemetry Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Captured Frames</span>
              <Activity className="w-4 h-4 text-cyan-500" />
            </div>
            <div className="text-2xl font-bold font-mono-code text-slate-900 dark:text-white mt-1.5">
              {data.status.totalPackets.toLocaleString()}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono-code">
              Volume: {formatBytes(data.status.totalBytes)}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Tracked Streams</span>
              <Network className="w-4 h-4 text-violet-500" />
            </div>
            <div className="text-2xl font-bold font-mono-code text-slate-900 dark:text-white mt-1.5">
              {data.status.tcpStreams + data.status.udpStreams}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono-code">
              TCP: {data.status.tcpStreams} · UDP: {data.status.udpStreams}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Kernel Drop Rate</span>
              <Gauge className="w-4 h-4 text-emerald-500" />
            </div>
            <div className="text-2xl font-bold font-mono-code text-emerald-600 dark:text-emerald-400 mt-1.5">
              {dropRate}%
            </div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono-code">
              Recv: {data.status.kernelStats.recv} · Drop: {data.status.kernelStats.drop}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>IDS Security Alerts</span>
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            </div>
            <div className="text-2xl font-bold font-mono-code text-rose-600 dark:text-rose-400 mt-1.5">
              {data.status.alerts.TOTAL}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono-code">
              {data.status.alerts.CRITICAL} Crit · {data.status.alerts.HIGH} High · {data.status.alerts.MEDIUM} Med
            </div>
          </div>
        </div>

        {/* Row 2: Network Communication Topology Graph + Protocol/OSI Distribution */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
          {/* Interactive Network Topology Graph */}
          <div className="lg:col-span-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4 flex flex-col">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-500" />
                  Network Topology
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  {isZh
                    ? '点击任意节点按 IP 筛选；红色虚线外环代表触发了 Security IDS 告警的主机'
                    : 'Click any host node to filter its traffic; red-ringed hosts triggered Security IDS alerts'}
                </p>
              </div>
              <span className="text-[11px] font-mono-code text-slate-400">
                {nodes.length} hosts · {data.topology.edges.length} links
              </span>
            </div>

            {nodes.length === 0 ? (
              <div className="h-[370px] flex items-center justify-center text-xs text-slate-400">
                No host communications captured yet.
              </div>
            ) : (
              <svg viewBox="0 0 620 390" className="w-full h-[370px]">
                {/* Edges */}
                {data.topology.edges.map((ed, idx) => {
                  const p1 = nodePos[ed.source]
                  const p2 = nodePos[ed.target]
                  if (!p1 || !p2) return null
                  const isFocus = hoveredNode === ed.source || hoveredNode === ed.target
                  const strokeW = Math.min(5, Math.max(1.2, Math.log2(ed.bytes + 1) / 3.5))
                  return (
                    <g key={idx}>
                      <line
                        x1={p1.x}
                        y1={p1.y}
                        x2={p2.x}
                        y2={p2.y}
                        stroke={ed.alerts > 0 ? '#f43f5e' : isFocus ? '#06b6d4' : '#64748b'}
                        strokeOpacity={hoveredNode ? (isFocus ? 0.9 : 0.15) : ed.alerts > 0 ? 0.7 : 0.35}
                        strokeWidth={strokeW}
                      />
                      {isFocus && (
                        <text
                          x={(p1.x + p2.x) / 2}
                          y={(p1.y + p2.y) / 2 - 4}
                          textAnchor="middle"
                          className="fill-cyan-500 dark:fill-cyan-300 font-mono-code text-[9.5px] font-semibold"
                        >
                          {ed.protocols.join('/')} ({formatBytes(ed.bytes)})
                        </text>
                      )}
                    </g>
                  )
                })}

                {/* Host Nodes */}
                {nodes.map((n) => {
                  const pos = nodePos[n.id]
                  const r = Math.min(22, Math.max(10, 8 + Math.log10(n.bytes + 10) * 2.5))
                  const hasAlert = n.alerts > 0
                  return (
                    <g
                      key={n.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onMouseEnter={() => setHoveredNode(n.id)}
                      onMouseLeave={() => setHoveredNode(null)}
                      onClick={() => onFilterIp(n.ip)}
                      className="cursor-pointer"
                    >
                      {hasAlert && (
                        <circle r={r + 5} fill="none" stroke="#f43f5e" strokeWidth={1.6} strokeDasharray="3 2" opacity={0.85} />
                      )}
                      <circle
                        r={r}
                        fill={hasAlert ? '#f43f5e' : '#06b6d4'}
                        fillOpacity={hoveredNode === n.id ? 0.95 : 0.78}
                        stroke="#ffffff"
                        strokeOpacity={0.25}
                        strokeWidth={1.5}
                      />
                      <text
                        y={3}
                        textAnchor="middle"
                        className="fill-white font-mono-code text-[9px] font-bold pointer-events-none"
                      >
                        {n.packets}
                      </text>
                      <text
                        y={r + 13}
                        textAnchor="middle"
                        className="fill-slate-700 dark:fill-slate-300 font-mono-code text-[10px] font-medium"
                      >
                        {n.label.length > 22 ? n.label.slice(0, 20) + '…' : n.label}
                      </text>
                    </g>
                  )
                })}
              </svg>
            )}
          </div>

          {/* Protocol & OSI Layer Breakdown */}
          <div className="lg:col-span-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-violet-500" />
                Protocol Distribution
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {isZh ? '点击任意协议条自动过滤 Packet List' : 'Click any protocol bar to filter Packet List'}
              </p>
            </div>

            <div className="space-y-2 max-h-[210px] overflow-y-auto pr-1">
              {data.protocols.map((p, idx) => {
                const pct = ((p.count / totalPkts) * 100).toFixed(1)
                const col = CHART_PALETTE[idx % CHART_PALETTE.length]
                return (
                  <button
                    key={p.name}
                    onClick={() => onFilterProto(p.name.toLowerCase().replace(/^tlsv.*/, 'tls'))}
                    className="w-full text-left group cursor-pointer"
                  >
                    <div className="flex justify-between text-xs mb-0.5">
                      <span className="font-mono-code font-semibold text-slate-800 dark:text-slate-200 group-hover:text-cyan-500">
                        {p.name}
                      </span>
                      <span className="font-mono-code text-slate-500 text-[11px]">
                        {p.count} ({pct}%)
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${Math.max(2, Number(pct))}%`, backgroundColor: col }}
                      />
                    </div>
                  </button>
                )
              })}
            </div>

            {/* OSI 7-Layer Stack Breakdown */}
            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                OSI Top-Layer Classification
              </h4>
              <div className="grid grid-cols-5 gap-1.5">
                {data.osiLayers.map((o) => (
                  <div
                    key={o.layer}
                    className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900/80 border border-slate-200/80 dark:border-slate-800 text-center"
                  >
                    <div className="text-[10px] font-bold text-cyan-600 dark:text-cyan-400">{o.layer}</div>
                    <div className="text-sm font-bold font-mono-code text-slate-800 dark:text-slate-100 mt-0.5">
                      {o.count}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Row 3: Throughput Time-Series Chart + Top Talkers Table */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* PPS / BPS Chart */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-500" />
                Packet Rate (PPS) &amp; Throughput (B/s)
              </h3>
              <div className="flex items-center gap-3 text-[10.5px]">
                <span className="text-cyan-500 font-semibold">— PPS (max {maxPps})</span>
                <span className="text-violet-500 font-semibold">— Bytes/s (max {formatBytes(maxBps)})</span>
              </div>
            </div>

            {ts.length < 2 ? (
              <div className="h-44 flex items-center justify-center text-xs text-slate-400">
                Capture spanning ≥ 2 seconds needed for time-series plot (currently {ts.length} bucket).
              </div>
            ) : (
              <svg viewBox="0 0 540 175" className="w-full h-44">
                {[0.25, 0.5, 0.75, 1].map((g) => (
                  <line
                    key={g}
                    x1={10}
                    y1={160 - g * 140}
                    x2={530}
                    y2={160 - g * 140}
                    stroke="#475569"
                    strokeOpacity={0.18}
                    strokeDasharray="3 3"
                  />
                ))}
                {/* PPS Area + Line */}
                <polyline
                  fill="none"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  points={ts
                    .map((p, i) => {
                      const x = 10 + (i / Math.max(1, ts.length - 1)) * 520
                      const y = 160 - (p.pps / maxPps) * 140
                      return `${x.toFixed(1)},${y.toFixed(1)}`
                    })
                    .join(' ')}
                />
                {/* BPS Line */}
                <polyline
                  fill="none"
                  stroke="#8b5cf6"
                  strokeWidth={1.8}
                  strokeDasharray="4 2"
                  points={ts
                    .map((p, i) => {
                      const x = 10 + (i / Math.max(1, ts.length - 1)) * 520
                      const y = 160 - (p.bps / maxBps) * 140
                      return `${x.toFixed(1)},${y.toFixed(1)}`
                    })
                    .join(' ')}
                />
              </svg>
            )}
          </div>

          {/* Top Talkers Table */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4 flex flex-col">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-3">
              Top Endpoints &amp; Talkers
            </h3>
            <div className="overflow-y-auto max-h-52">
              <table className="w-full text-left text-xs font-mono-code">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-[10.5px] text-slate-500">
                    <th className="pb-2">Endpoint / Hostname</th>
                    <th className="pb-2 text-right">TX / RX Pkts</th>
                    <th className="pb-2 text-right">Volume</th>
                    <th className="pb-2 text-right">Alerts</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                  {data.topEndpoints.slice(0, 12).map((ep) => (
                    <tr
                      key={ep.ip}
                      onClick={() => onFilterIp(ep.ip)}
                      className="hover:bg-cyan-500/10 cursor-pointer"
                    >
                      <td className="py-1.5 pr-2">
                        <div className="text-slate-800 dark:text-slate-200 font-semibold">{ep.ip}</div>
                        {ep.hostname && (
                          <div className="text-[10px] text-cyan-600 dark:text-cyan-400 truncate max-w-[180px]">
                            {ep.hostname}
                          </div>
                        )}
                      </td>
                      <td className="py-1.5 text-right text-slate-500">
                        {ep.txPackets} / {ep.rxPackets}
                      </td>
                      <td className="py-1.5 text-right font-semibold text-slate-800 dark:text-slate-100">
                        {formatBytes(ep.totalBytes)}
                      </td>
                      <td className="py-1.5 text-right">
                        {ep.alerts > 0 ? (
                          <span className="px-1.5 py-0.2 rounded bg-rose-500/15 text-rose-500 font-bold">
                            {ep.alerts}
                          </span>
                        ) : (
                          <span className="text-slate-400">0</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
