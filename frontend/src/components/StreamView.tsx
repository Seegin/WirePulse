import React, { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Cpu,
  Download,
  Filter,
  GitBranch,
  Search,
  Workflow,
  ArrowRight,
  ArrowLeft,
} from 'lucide-react'
import { api } from '../api'
import type { StreamFollowData, StreamSummary } from '../types'
import { formatBytes } from '../utils/coloring'

interface Props {
  initialSelection: { proto: 'tcp' | 'udp'; streamId: number; tab?: 'stream' | 'sequence' } | null
  processFilter: { pid: number | null; name: string } | null
  onClearProcessFilter: () => void
  onJumpToPacket: (packetNo: number) => void
  onApplyFilter: (expr: string) => void
}

export const StreamView: React.FC<Props> = ({
  initialSelection,
  processFilter,
  onClearProcessFilter,
  onJumpToPacket,
  onApplyFilter,
}) => {
  const [protoFilter, setProtoFilter] = useState<'all' | 'tcp' | 'udp'>('all')
  const [streams, setStreams] = useState<StreamSummary[]>([])
  const [selected, setSelected] = useState<{ proto: 'tcp' | 'udp'; streamId: number } | null>(null)
  const [followData, setFollowData] = useState<StreamFollowData | null>(null)
  const [subTab, setSubTab] = useState<'stream' | 'sequence'>('stream')
  const [viewFmt, setViewFmt] = useState<'text' | 'hex'>('text')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    api
      .getStreams(protoFilter, processFilter?.pid, processFilter?.name)
      .then((res) => {
        setStreams(res.streams || [])
        if (initialSelection) {
          setSelected({ proto: initialSelection.proto, streamId: initialSelection.streamId })
          if (initialSelection.tab) setSubTab(initialSelection.tab)
        } else if (!selected && res.streams && res.streams.length > 0) {
          setSelected({ proto: res.streams[0].proto, streamId: res.streams[0].streamId })
        }
      })
      .catch(() => {})
  }, [protoFilter, processFilter?.pid, processFilter?.name, initialSelection?.streamId, initialSelection?.proto])

  useEffect(() => {
    if (!selected) {
      setFollowData(null)
      return
    }
    api
      .followStream(selected.proto, selected.streamId)
      .then((res) => {
        if (res.ok) setFollowData(res)
      })
      .catch(() => {})
  }, [selected?.proto, selected?.streamId])

  const filteredTurns = useMemo(() => {
    if (!followData) return []
    const q = searchTerm.trim().toLowerCase()
    if (!q) return followData.turns
    return followData.turns.filter(
      (t) => t.text.toLowerCase().includes(q) || t.hex.toLowerCase().includes(q),
    )
  }, [followData, searchTerm])

  const downloadStream = () => {
    if (!followData) return
    const content = followData.turns
      .map(
        (t) =>
          `=== ${t.direction === 'c2s' ? 'CLIENT -> SERVER' : 'SERVER -> CLIENT'} (${t.length} bytes, pkts: ${t.packetNos.join(',')}) ===\n${t.text}\n`,
      )
      .join('\n')
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `wirepulse_${followData.summary.proto}_stream_${followData.summary.streamId}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex h-full bg-slate-50 dark:bg-[#090d14] overflow-hidden">
      {/* Left Stream List Sidebar */}
      <div className="w-[360px] xl:w-[400px] border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0d131f] flex flex-col shrink-0">
        <div className="p-3 border-b border-slate-200 dark:border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-cyan-500" />
              <h2 className="text-xs font-bold text-slate-700 dark:text-slate-200">
                TCP / UDP 通信流 ({streams.length})
              </h2>
            </div>
            <div className="flex rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-900 p-0.5 text-[10.5px]">
              {(['all', 'tcp', 'udp'] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => setProtoFilter(p)}
                  className={`px-2 py-0.5 rounded uppercase font-semibold cursor-pointer ${
                    protoFilter === p
                      ? 'bg-white dark:bg-cyan-600 text-cyan-700 dark:text-white'
                      : 'text-slate-500'
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>

          {processFilter && (
            <div className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-amber-500/12 border border-amber-500/30 text-[11px] text-amber-800 dark:text-amber-300">
              <span className="flex items-center gap-1.5 truncate">
                <Cpu className="w-3.5 h-3.5 shrink-0" />
                Tracing Process: <strong>{processFilter.name}</strong>
                {processFilter.pid ? ` (PID ${processFilter.pid})` : ''}
              </span>
              <button
                onClick={onClearProcessFilter}
                className="underline font-semibold ml-2 cursor-pointer"
              >
                Clear
              </button>
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/60">
          {streams.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-400">
              No TCP/UDP streams captured yet.
            </div>
          ) : (
            streams.map((s) => {
              const active = selected?.proto === s.proto && selected?.streamId === s.streamId
              return (
                <div
                  key={`${s.proto}_${s.streamId}`}
                  onClick={() => setSelected({ proto: s.proto, streamId: s.streamId })}
                  className={`p-3 cursor-pointer transition-colors ${
                    active
                      ? 'bg-cyan-500/12 border-l-2 border-l-cyan-500'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono-code font-bold px-1.5 py-0.2 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300">
                        {s.proto.toUpperCase()} #{s.streamId}
                      </span>
                      <span className="text-[10px] font-semibold px-1.5 py-0.2 rounded bg-violet-500/15 text-violet-700 dark:text-violet-300">
                        {s.appProtocol}
                      </span>
                      {s.retransmissions > 0 && (
                        <span className="flex items-center gap-0.5 text-[10px] px-1 rounded bg-amber-500/15 text-amber-600 dark:text-amber-300">
                          <AlertTriangle className="w-2.5 h-2.5" /> {s.retransmissions} Retr
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] font-mono-code text-slate-400">
                      {s.packets} pkts · {formatBytes(s.totalBytes)}
                    </span>
                  </div>

                  <div className="font-mono-code text-[11px] text-slate-800 dark:text-slate-200 truncate">
                    {s.client} <span className="text-cyan-500">↔</span> {s.server}
                  </div>

                  <div className="flex items-center justify-between mt-1.5 text-[10.5px] text-slate-500 dark:text-slate-400">
                    <span className="truncate max-w-[180px]">
                      {s.host || (s.processName ? `Proc: ${s.processName}` : s.state)}
                    </span>
                    <div className="flex items-center gap-2 font-mono-code">
                      {s.rttMs !== null && <span>RTT {s.rttMs}ms</span>}
                      <span
                        className={`px-1.5 rounded text-[9.5px] font-semibold ${
                          s.state === 'RESET'
                            ? 'bg-rose-500/15 text-rose-500'
                            : s.state === 'CLOSED'
                              ? 'bg-slate-200 dark:bg-slate-800 text-slate-500'
                              : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                        }`}
                      >
                        {s.state}
                      </span>
                    </div>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>

      {/* Right Stream Inspector & Sequence Diagram */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {!followData ? (
          <div className="flex-1 flex flex-col items-center justify-center text-xs text-slate-400 gap-2">
            <Workflow className="w-8 h-8 opacity-30" />
            <span>Select a TCP or UDP stream to reassemble payload &amp; plot its flow sequence diagram</span>
          </div>
        ) : (
          <>
            {/* Stream Detail Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520]">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono-code">
                    {followData.summary.client} ↔ {followData.summary.server}
                  </h3>
                  <span className="text-[10.5px] px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 font-semibold">
                    {followData.summary.appProtocol}
                  </span>
                  {followData.summary.processName && (
                    <span className="text-[10.5px] px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-300 font-mono-code">
                      {followData.summary.processName} (PID {followData.summary.pid})
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono-code mt-0.5 flex flex-wrap gap-3">
                  <span>C→S: {formatBytes(followData.summary.bytesC2S)}</span>
                  <span>S→C: {formatBytes(followData.summary.bytesS2C)}</span>
                  <span>Duration: {followData.summary.durationMs}ms</span>
                  {followData.summary.rttMs !== null && <span>Handshake RTT: {followData.summary.rttMs}ms</span>}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="flex rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-900 p-0.5 text-xs">
                  <button
                    onClick={() => setSubTab('stream')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded-md font-medium cursor-pointer ${
                      subTab === 'stream'
                        ? 'bg-white dark:bg-cyan-600 text-cyan-700 dark:text-white shadow-xs'
                        : 'text-slate-500'
                    }`}
                  >
                    <GitBranch className="w-3.5 h-3.5" />
                    <span>流内容重组 (Follow)</span>
                  </button>
                  <button
                    onClick={() => setSubTab('sequence')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded-md font-medium cursor-pointer ${
                      subTab === 'sequence'
                        ? 'bg-white dark:bg-cyan-600 text-cyan-700 dark:text-white shadow-xs'
                        : 'text-slate-500'
                    }`}
                  >
                    <Workflow className="w-3.5 h-3.5" />
                    <span>交互式流时序图</span>
                  </button>
                </div>

                <button
                  onClick={() =>
                    onApplyFilter(`${followData.summary.proto}.stream == ${followData.summary.streamId}`)
                  }
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                  title="在报文三栏中只看该流"
                >
                  <Filter className="w-3.5 h-3.5 text-cyan-500" />
                  <span>过滤此流</span>
                </button>
              </div>
            </div>

            {/* Sub-tab 1: Follow Stream Conversation */}
            {subTab === 'stream' ? (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 border-b border-slate-200/80 dark:border-slate-800/80 bg-slate-50 dark:bg-[#0b101b] text-xs gap-3">
                  <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1.5 text-rose-600 dark:text-rose-400 font-medium">
                      <ArrowRight className="w-3.5 h-3.5" /> Client → Server
                    </span>
                    <span className="flex items-center gap-1.5 text-cyan-600 dark:text-cyan-400 font-medium">
                      <ArrowLeft className="w-3.5 h-3.5" /> Server → Client
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5 px-2 h-7 rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900">
                      <Search className="w-3 h-3 text-slate-400" />
                      <input
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        placeholder="Search stream..."
                        className="bg-transparent text-xs focus:outline-none w-36 text-slate-800 dark:text-slate-100"
                      />
                    </div>
                    <div className="flex rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-0.5 text-[11px]">
                      <button
                        onClick={() => setViewFmt('text')}
                        className={`px-2 py-0.5 rounded cursor-pointer ${
                          viewFmt === 'text' ? 'bg-cyan-600 text-white' : 'text-slate-500'
                        }`}
                      >
                        UTF-8 / ASCII
                      </button>
                      <button
                        onClick={() => setViewFmt('hex')}
                        className={`px-2 py-0.5 rounded cursor-pointer ${
                          viewFmt === 'hex' ? 'bg-cyan-600 text-white' : 'text-slate-500'
                        }`}
                      >
                        Hex
                      </button>
                    </div>
                    <button
                      onClick={downloadStream}
                      className="flex items-center gap-1 px-2 py-1 rounded border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" /> Save
                    </button>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto p-4 space-y-3">
                  {filteredTurns.length === 0 ? (
                    <div className="text-center text-xs text-slate-400 py-10">
                      No application payload bytes in this stream (control handshake / port scan only).
                    </div>
                  ) : (
                    filteredTurns.map((turn, idx) => {
                      const isC2S = turn.direction === 'c2s'
                      return (
                        <div
                          key={idx}
                          className={`rounded-xl border overflow-hidden ${
                            isC2S
                              ? 'border-rose-500/30 bg-rose-500/[0.04] dark:bg-rose-500/[0.06]'
                              : 'border-cyan-500/30 bg-cyan-500/[0.04] dark:bg-cyan-500/[0.06]'
                          }`}
                        >
                          <div
                            className={`flex items-center justify-between px-3 py-1.5 text-[11px] font-mono-code border-b ${
                              isC2S
                                ? 'border-rose-500/20 text-rose-700 dark:text-rose-300'
                                : 'border-cyan-500/20 text-cyan-700 dark:text-cyan-300'
                            }`}
                          >
                            <span className="font-semibold">
                              {isC2S ? 'CLIENT → SERVER' : 'SERVER → CLIENT'} ({turn.length} bytes)
                            </span>
                            <div className="flex items-center gap-2">
                              <span>t={turn.timestamp.toFixed(4)}s</span>
                              <button
                                onClick={() => onJumpToPacket(turn.packetNos[0])}
                                className="underline hover:opacity-80 cursor-pointer"
                              >
                                Frame #{turn.packetNos[0]}
                              </button>
                            </div>
                          </div>
                          <pre className="p-3 text-[11.5px] font-mono-code whitespace-pre-wrap break-all text-slate-800 dark:text-slate-200 max-h-96 overflow-y-auto">
                            {viewFmt === 'text'
                              ? turn.text
                              : (turn.hex.match(/.{1,32}/g) || [])
                                  .map((line, i) => `${(i * 16).toString(16).padStart(4, '0')}  ${line.match(/.{1,2}/g)?.join(' ')}`)
                                  .join('\n')}
                          </pre>
                        </div>
                      )
                    })
                  )}
                </div>
              </div>
            ) : (
              /* Sub-tab 2: Interactive SVG Flow Sequence Ladder Diagram */
              <div className="flex-1 overflow-auto p-5 bg-slate-50 dark:bg-[#090d14]">
                <div className="max-w-4xl mx-auto rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0e1422] p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                        交互式网络流时序图（Flow Sequence Ladder Diagram）
                      </h4>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">
                        直观展示客户端与服务端之间的三次握手、数据交互、RTT 往返延迟、超时重传与四次挥手；点击任意箭头直达该帧
                      </p>
                    </div>
                    <div className="flex items-center gap-3 text-[10.5px]">
                      <span className="flex items-center gap-1 text-cyan-500">● 握手/挥手</span>
                      <span className="flex items-center gap-1 text-emerald-500">● 业务数据</span>
                      <span className="flex items-center gap-1 text-amber-500">● 重传/乱序</span>
                      <span className="flex items-center gap-1 text-rose-500">● RST重置</span>
                    </div>
                  </div>

                  {/* SVG Ladder */}
                  {(() => {
                    const evs = followData.sequence
                    const rowH = 44
                    const topPad = 56
                    const svgW = 780
                    const svgH = topPad + evs.length * rowH + 30
                    const leftX = 180
                    const rightX = 620
                    return (
                      <svg viewBox={`0 0 ${svgW} ${svgH}`} className="w-full h-auto">
                        <defs>
                          <marker id="arr-cyan" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 1 L 10 5 L 0 9 z" fill="#06b6d4" />
                          </marker>
                          <marker id="arr-emerald" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
                          </marker>
                          <marker id="arr-amber" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b" />
                          </marker>
                          <marker id="arr-rose" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" />
                          </marker>
                          <marker id="arr-slate" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
                          </marker>
                        </defs>

                        {/* Endpoint Header Boxes */}
                        <rect x={leftX - 110} y={8} width={220} height={32} rx={8} fill="#06b6d4" fillOpacity={0.14} stroke="#06b6d4" strokeWidth={1.2} />
                        <text x={leftX} y={28} textAnchor="middle" className="fill-cyan-600 dark:fill-cyan-300 font-mono-code text-[11px] font-semibold">
                          Client: {followData.summary.client}
                        </text>

                        <rect x={rightX - 110} y={8} width={220} height={32} rx={8} fill="#8b5cf6" fillOpacity={0.14} stroke="#8b5cf6" strokeWidth={1.2} />
                        <text x={rightX} y={28} textAnchor="middle" className="fill-violet-600 dark:fill-violet-300 font-mono-code text-[11px] font-semibold">
                          Server: {followData.summary.server}
                        </text>

                        {/* Vertical Lifelines */}
                        <line x1={leftX} y1={42} x2={leftX} y2={svgH - 14} stroke="#475569" strokeOpacity={0.4} strokeWidth={1.5} strokeDasharray="4 4" />
                        <line x1={rightX} y1={42} x2={rightX} y2={svgH - 14} stroke="#475569" strokeOpacity={0.4} strokeWidth={1.5} strokeDasharray="4 4" />

                        {/* Arrows */}
                        {evs.map((ev, i) => {
                          const y = topPad + i * rowH + 22
                          const isC2S = ev.direction === 'c2s'
                          const x1 = isC2S ? leftX + 4 : rightX - 4
                          const x2 = isC2S ? rightX - 6 : leftX + 6
                          const isRetr = ev.expert.some((x) => x.includes('Retrans') || x.includes('Out-of-Order'))
                          const isRst = ev.flags.includes('RST')
                          const isSynFin = ev.flags.includes('SYN') || ev.flags.includes('FIN')
                          const color = isRst
                            ? '#f43f5e'
                            : isRetr
                              ? '#f59e0b'
                              : ev.payloadLen > 0
                                ? '#10b981'
                                : isSynFin
                                  ? '#06b6d4'
                                  : '#64748b'
                          const marker = isRst
                            ? 'url(#arr-rose)'
                            : isRetr
                              ? 'url(#arr-amber)'
                              : ev.payloadLen > 0
                                ? 'url(#arr-emerald)'
                                : isSynFin
                                  ? 'url(#arr-cyan)'
                                  : 'url(#arr-slate)'

                          return (
                            <g
                              key={ev.packetNo}
                              onClick={() => onJumpToPacket(ev.packetNo)}
                              className="cursor-pointer group"
                            >
                              <rect x={4} y={y - 18} width={svgW - 8} height={34} rx={6} className="fill-transparent group-hover:fill-cyan-500/8 transition-colors" />
                              {/* Timestamp & Delta on left */}
                              <text x={14} y={y - 2} className="fill-slate-400 font-mono-code text-[10px]">
                                #{ev.packetNo}
                              </text>
                              <text x={14} y={y + 11} className="fill-slate-500 font-mono-code text-[9.5px]">
                                +{ev.deltaMs.toFixed(1)}ms
                              </text>

                              {/* Arrow line */}
                              <line
                                x1={x1}
                                y1={y + 4}
                                x2={x2}
                                y2={y + 4}
                                stroke={color}
                                strokeWidth={ev.payloadLen > 0 || isRetr ? 2.2 : 1.5}
                                strokeDasharray={isRetr ? '5 3' : undefined}
                                markerEnd={marker}
                              />

                              {/* Label above arrow */}
                              <text
                                x={(leftX + rightX) / 2}
                                y={y - 3}
                                textAnchor="middle"
                                fill={color}
                                className="font-mono-code text-[10.5px] font-semibold"
                              >
                                {ev.info.slice(0, 62)}
                              </text>

                              {/* Payload badge on right */}
                              <text x={rightX + 18} y={y + 7} className="fill-slate-500 font-mono-code text-[10px]">
                                {ev.payloadLen > 0 ? `${ev.payloadLen} B` : `[${ev.flags}]`}
                              </text>
                            </g>
                          )
                        })}
                      </svg>
                    )
                  })()}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
