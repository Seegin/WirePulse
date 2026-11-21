import React, { useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowDownToLine,
  Clock,
  Cpu,
  Filter,
  GitBranch,
  Layers,
  ShieldAlert,
  Workflow,
} from 'lucide-react'
import type { PacketSummary } from '../types'
import { getPacketRowStyle } from '../utils/coloring'

interface Props {
  packets: PacketSummary[]
  totalCaptured: number
  selectedNo: number | null
  autoScroll: boolean
  onToggleAutoScroll: () => void
  onSelectPacket: (no: number) => void
  onApplyFilter: (expr: string) => void
  onFollowStream: (proto: 'tcp' | 'udp', streamId: number, initialTab?: 'stream' | 'sequence') => void
  onTraceProcess: (pid: number, name: string) => void
  onInspectWireshark: (no: number) => void
}

const ROW_HEIGHT = 27
const OVERSCAN = 14

export const PacketListPane: React.FC<Props> = ({
  packets,
  totalCaptured,
  selectedNo,
  autoScroll,
  onToggleAutoScroll,
  onSelectPacket,
  onApplyFilter,
  onFollowStream,
  onTraceProcess,
  onInspectWireshark,
}) => {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportH, setViewportH] = useState(320)
  const [timeMode, setTimeMode] = useState<'rel' | 'delta'>('rel')
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; pkt: PacketSummary } | null>(null)

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const ro = new ResizeObserver(() => setViewportH(el.clientHeight))
    ro.observe(el)
    setViewportH(el.clientHeight)
    return () => ro.disconnect()
  }, [])

  // Auto-scroll to bottom when live packets stream in (only when capturing / growing)
  const prevCountRef = useRef(0)
  useEffect(() => {
    if (autoScroll && scrollRef.current && packets.length > prevCountRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
    prevCountRef.current = packets.length
  }, [packets.length, autoScroll])

  // Keep selected packet scrolled into view when jumping from Security / Streams / keyboard
  useEffect(() => {
    if (selectedNo === null || !scrollRef.current) return
    const idx = packets.findIndex((p) => p.no === selectedNo)
    if (idx === -1) return
    const rowTop = idx * ROW_HEIGHT
    const rowBottom = rowTop + ROW_HEIGHT
    const el = scrollRef.current
    if (rowTop < el.scrollTop || rowBottom > el.scrollTop + el.clientHeight) {
      el.scrollTop = Math.max(0, rowTop - el.clientHeight / 3)
    }
  }, [selectedNo])

  // Close context menu on click elsewhere
  useEffect(() => {
    const close = () => setCtxMenu(null)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [])

  const totalH = packets.length * ROW_HEIGHT
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const endIdx = Math.min(packets.length, Math.ceil((scrollTop + viewportH) / ROW_HEIGHT) + OVERSCAN)
  const visible = packets.slice(startIdx, endIdx)

  return (
    <div className="flex flex-col h-full bg-white dark:bg-[#0b101b] select-none overflow-hidden">
      {/* Pane Sub-Header */}
      <div className="flex items-center justify-between px-3 h-7 border-b border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#0f1520] text-[11px]">
        <div className="flex items-center gap-2 text-slate-600 dark:text-slate-300 font-semibold">
          <span>Packet List</span>
          <span className="font-mono-code font-normal text-slate-400">
            {packets.length.toLocaleString()} / {totalCaptured.toLocaleString()} frames
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setTimeMode((m) => (m === 'rel' ? 'delta' : 'rel'))}
            className="flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-slate-200/70 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 cursor-pointer"
            title="Toggle Relative Time vs Delta Time"
          >
            <Clock className="w-3 h-3" />
            <span>{timeMode === 'rel' ? 'Relative (s)' : 'Delta (ms)'}</span>
          </button>
          <button
            onClick={onToggleAutoScroll}
            className={`flex items-center gap-1 px-1.5 py-0.5 rounded cursor-pointer transition-colors ${
              autoScroll
                ? 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300'
                : 'text-slate-500 hover:bg-slate-200/70 dark:hover:bg-slate-800'
            }`}
            title="Auto-scroll on live capture"
          >
            <ArrowDownToLine className="w-3 h-3" />
            <span>Auto-scroll</span>
          </button>
        </div>
      </div>

      {/* Column Headers */}
      <div className="grid grid-cols-[58px_82px_145px_145px_76px_58px_118px_1fr] items-center px-2 h-7 border-b border-slate-200 dark:border-slate-800 bg-slate-100/80 dark:bg-[#111827] text-[11px] font-semibold text-slate-500 dark:text-slate-400 shrink-0">
        <div className="px-1">No.</div>
        <div className="px-1">{timeMode === 'rel' ? 'Time' : 'Delta'}</div>
        <div className="px-1">Source</div>
        <div className="px-1">Destination</div>
        <div className="px-1">Protocol</div>
        <div className="px-1 text-right pr-2">Len</div>
        <div className="px-1">Process</div>
        <div className="px-1">Info</div>
      </div>

      {/* Virtualized Table Viewport */}
      <div
        ref={scrollRef}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
        className="flex-1 overflow-y-auto overflow-x-auto relative"
      >
        {packets.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-400 dark:text-slate-500 text-xs gap-2 p-6">
            <Layers className="w-7 h-7 opacity-40" />
            <span>No packets match the current display filter or capture is empty.</span>
          </div>
        ) : (
          <div style={{ height: totalH, position: 'relative' }}>
            <div style={{ transform: `translateY(${startIdx * ROW_HEIGHT}px)` }}>
              {visible.map((pkt) => {
                const isSelected = selectedNo === pkt.no
                const style = getPacketRowStyle(pkt)
                return (
                  <div
                    key={pkt.no}
                    onClick={() => onSelectPacket(pkt.no)}
                    onContextMenu={(e) => {
                      e.preventDefault()
                      onSelectPacket(pkt.no)
                      setCtxMenu({ x: e.clientX, y: e.clientY, pkt })
                    }}
                    style={{ height: ROW_HEIGHT }}
                    className={`grid grid-cols-[58px_82px_145px_145px_76px_58px_118px_1fr] items-center px-2 text-[11.5px] font-mono-code border-b border-slate-100/80 dark:border-slate-800/40 cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-600 text-white dark:bg-cyan-600/90 dark:text-white border-l-2 border-l-cyan-300'
                        : `${style.rowBg} text-slate-800 dark:text-slate-200 hover:bg-slate-200/60 dark:hover:bg-slate-800/70`
                    }`}
                  >
                    <div className="px-1 flex items-center gap-1 truncate">
                      {pkt.alertSeverity && (
                        <span
                          title={pkt.alertRules.join(', ')}
                          className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                            pkt.alertSeverity === 'CRITICAL'
                              ? 'bg-rose-500'
                              : pkt.alertSeverity === 'HIGH'
                                ? 'bg-orange-500'
                                : 'bg-amber-400'
                          }`}
                        />
                      )}
                      <span>{pkt.no}</span>
                    </div>
                    <div className="px-1 truncate opacity-80">
                      {timeMode === 'rel'
                        ? pkt.relTime.toFixed(4)
                        : `${(pkt.deltaTime * 1000).toFixed(2)}ms`}
                    </div>
                    <div className="px-1 truncate" title={pkt.src}>
                      {pkt.src}
                    </div>
                    <div className="px-1 truncate" title={pkt.dst}>
                      {pkt.dst}
                    </div>
                    <div className="px-1 truncate">
                      <span
                        className={`inline-block px-1.5 py-0 rounded text-[10px] font-semibold border ${
                          isSelected
                            ? 'bg-white/20 text-white border-white/30'
                            : style.badgeClass
                        }`}
                      >
                        {pkt.protocol}
                      </span>
                    </div>
                    <div className="px-1 text-right pr-2 opacity-80">{pkt.length}</div>
                    <div className="px-1 truncate">
                      {pkt.processName ? (
                        <span
                          className={`inline-flex items-center gap-1 px-1.5 rounded text-[10px] truncate max-w-full ${
                            isSelected
                              ? 'bg-white/20 text-white'
                              : 'bg-slate-200/70 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                          }`}
                          title={`${pkt.processName} (PID ${pkt.pid})`}
                        >
                          <span className="truncate">{pkt.processName}</span>
                        </span>
                      ) : (
                        <span className="opacity-30">—</span>
                      )}
                    </div>
                    <div className="px-1 truncate flex items-center gap-1.5" title={pkt.info}>
                      {pkt.tcpExpert.length > 0 && (
                        <AlertTriangle
                          className={`w-3 h-3 shrink-0 ${isSelected ? 'text-amber-200' : 'text-amber-500'}`}
                        />
                      )}
                      {pkt.alertSeverity && (
                        <ShieldAlert
                          className={`w-3 h-3 shrink-0 ${isSelected ? 'text-rose-200' : 'text-rose-500'}`}
                        />
                      )}
                      <span className="truncate">{pkt.info}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Wireshark-Style Context Menu */}
      {ctxMenu && (
        <div
          style={{
            position: 'fixed',
            left: Math.min(ctxMenu.x, window.innerWidth - 260),
            top: Math.min(ctxMenu.y, window.innerHeight - 280),
          }}
          className="w-60 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#131b2e] shadow-2xl py-1.5 text-xs z-50"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-slate-800">
            Frame #{ctxMenu.pkt.no} · {ctxMenu.pkt.protocol}
          </div>

          {ctxMenu.pkt.streamId !== null && ctxMenu.pkt.streamProto && (
            <>
              <button
                onClick={() => {
                  onFollowStream(ctxMenu.pkt.streamProto!, ctxMenu.pkt.streamId!, 'stream')
                  setCtxMenu(null)
                }}
                className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-cyan-500/15 text-slate-800 dark:text-slate-100 cursor-pointer"
              >
                <GitBranch className="w-3.5 h-3.5 text-cyan-500" />
                <span>Follow {ctxMenu.pkt.streamProto.toUpperCase()} Stream #{ctxMenu.pkt.streamId}</span>
              </button>
              <button
                onClick={() => {
                  onFollowStream(ctxMenu.pkt.streamProto!, ctxMenu.pkt.streamId!, 'sequence')
                  setCtxMenu(null)
                }}
                className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-cyan-500/15 text-slate-800 dark:text-slate-100 cursor-pointer"
              >
                <Workflow className="w-3.5 h-3.5 text-emerald-500" />
                <span>View Flow Sequence Diagram</span>
              </button>
            </>
          )}

          {ctxMenu.pkt.pid !== null && (
            <button
              onClick={() => {
                onTraceProcess(ctxMenu.pkt.pid!, ctxMenu.pkt.processName)
                setCtxMenu(null)
              }}
              className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-cyan-500/15 text-slate-800 dark:text-slate-100 cursor-pointer"
            >
              <Cpu className="w-3.5 h-3.5 text-amber-500" />
              <span>Trace Process: {ctxMenu.pkt.processName}</span>
            </button>
          )}

          <button
            onClick={() => {
              onInspectWireshark(ctxMenu.pkt.no)
              setCtxMenu(null)
            }}
            className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-violet-500/15 text-violet-700 dark:text-violet-300 cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Dissect via Wireshark libwireshark</span>
          </button>

          <div className="my-1 border-t border-slate-100 dark:border-slate-800" />

          <button
            onClick={() => {
              onApplyFilter(`ip.addr == ${ctxMenu.pkt.src}`)
              setCtxMenu(null)
            }}
            className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5 text-sky-500" />
            <span className="truncate">Filter: ip.addr == {ctxMenu.pkt.src}</span>
          </button>
          <button
            onClick={() => {
              onApplyFilter(`not (ip.src == ${ctxMenu.pkt.src})`)
              setCtxMenu(null)
            }}
            className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5 text-rose-500" />
            <span className="truncate">Exclude: not (ip.src == {ctxMenu.pkt.src})</span>
          </button>
        </div>
      )}
    </div>
  )
}
