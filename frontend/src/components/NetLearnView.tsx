import React, { useEffect, useMemo, useState } from 'react'
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  BookOpen,
  Box,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  GraduationCap,
  Grid3X3,
  Layers,
  Lock,
  LockOpen,
  Play,
  Pause,
  Radio,
  ShieldAlert,
  Sparkles,
  Workflow,
  Lightbulb,
} from 'lucide-react'
import { api } from '../api'
import type { PacketDetail, PacketSummary, StreamSummary } from '../types'
import {
  discoverLearningLessons,
  extractHeaderDiagrams,
  lookupFieldKnowledge,
  narratePacketZh,
  type HeaderBitCell,
} from '../utils/cnKnowledge'

interface Props {
  packets: PacketSummary[]
  selectedNo: number | null
  onSelectPacket: (no: number) => void
  onJumpTo3Pane: (no: number) => void
  onOpenStreamSequence: (proto: 'tcp' | 'udp', streamId: number) => void
  onGoCapture: () => void
  onLoadDemo: () => void
}

type LearnSubTab = 'encap' | 'bitfield' | 'lessons'

const OSI_LAYER_META: Record<
  number,
  { pdu: string; name: string; addr: string; role: string; colorCls: string; barHex: string }
> = {
  2: {
    pdu: '帧 (Frame)',
    name: 'L2 数据链路层',
    addr: 'MAC 物理地址 (48位)',
    role: '负责同一个局域网内相邻节点（如电脑 ↔ 路由器网关）之间的可靠成帧与寻址转发。',
    colorCls: 'border-amber-500/45 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    barHex: '#f59e0b',
  },
  3: {
    pdu: '分组 / 数据报 (Packet)',
    name: 'L3 网络层',
    addr: 'IP 逻辑地址 (IPv4 32位 / IPv6 128位)',
    role: '负责跨网络、跨路由器的端到端路径选择（路由转发）与防环路控制（TTL）。',
    colorCls: 'border-sky-500/45 bg-sky-500/10 text-sky-700 dark:text-sky-300',
    barHex: '#0ea5e9',
  },
  4: {
    pdu: '报文段 / 用户数据报 (Segment / Datagram)',
    name: 'L4 传输层',
    addr: '端口号 Port (16位)',
    role: '负责主机上具体进程间的端到端通信：TCP 提供可靠字节流与流量控制，UDP 提供极速无连接交付。',
    colorCls: 'border-indigo-500/45 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
    barHex: '#6366f1',
  },
  6: {
    pdu: '安全加密记录 (TLS Record)',
    name: 'L6 表示层 / 安全会话层',
    addr: 'SNI 域名 + 会话密钥 / 证书',
    role: '负责数据加密解密、身份证书校验与防篡改（HTTPS 的核心安全防线）。',
    colorCls: 'border-violet-500/45 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    barHex: '#8b5cf6',
  },
  7: {
    pdu: '应用消息 (Message)',
    name: 'L7 应用层',
    addr: 'URL / 域名 / 业务指令',
    role: '直接面向用户软件提供服务语义（网页 HTTP、域名解析 DNS、远程登录 SSH、自动联网 DHCP 等）。',
    colorCls: 'border-emerald-500/45 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    barHex: '#10b981',
  },
}

const CELL_TONE: Record<string, string> = {
  cyan: 'border-cyan-500/45 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-800 dark:text-cyan-200',
  emerald: 'border-emerald-500/45 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-800 dark:text-emerald-200',
  violet: 'border-violet-500/45 bg-violet-500/10 hover:bg-violet-500/20 text-violet-800 dark:text-violet-200',
  amber: 'border-amber-500/45 bg-amber-500/10 hover:bg-amber-500/20 text-amber-800 dark:text-amber-200',
  rose: 'border-rose-500/50 bg-rose-500/12 hover:bg-rose-500/22 text-rose-800 dark:text-rose-200',
  slate: 'border-slate-300 dark:border-slate-700 bg-slate-100/80 dark:bg-slate-800/70 hover:bg-slate-200/80 dark:hover:bg-slate-700/80 text-slate-800 dark:text-slate-200',
}

export const NetLearnView: React.FC<Props> = ({
  packets,
  selectedNo,
  onSelectPacket,
  onJumpTo3Pane,
  onOpenStreamSequence,
  onGoCapture,
  onLoadDemo,
}) => {
  const [subTab, setSubTab] = useState<LearnSubTab>('encap')
  const [catFilter, setCatFilter] = useState<string>('ALL')
  const [detail, setDetail] = useState<PacketDetail | null>(null)
  const [streams, setStreams] = useState<StreamSummary[]>([])

  // Encapsulation / Decapsulation stepper state
  const [direction, setDirection] = useState<'encap' | 'decap'>('encap')
  const [animStep, setAnimStep] = useState<number>(99) // show all layers initially
  const [playing, setPlaying] = useState(false)

  // 32-bit Header Bitfield state
  const [activeProtoIdx, setActiveProtoIdx] = useState(0)
  const [selectedCell, setSelectedCell] = useState<HeaderBitCell | null>(null)

  useEffect(() => {
    api.getStreams('all').then((r) => setStreams(r.streams || [])).catch(() => {})
  }, [packets.length])

  const filteredPackets = useMemo(() => {
    if (catFilter === 'ALL') return packets
    if (catFilter === 'ARP') return packets.filter((p) => p.protocol === 'ARP')
    if (catFilter === 'DNS') return packets.filter((p) => p.protocol === 'DNS' || p.protocol === 'mDNS')
    if (catFilter === 'SYN') return packets.filter((p) => p.tcpFlags.includes('SYN') || p.tcpFlags.includes('FIN'))
    if (catFilter === 'HTTP') return packets.filter((p) => p.protocol.startsWith('HTTP'))
    if (catFilter === 'TLS') return packets.filter((p) => p.protocol.startsWith('TLS') || p.protocol === 'QUIC')
    if (catFilter === 'ICMP') return packets.filter((p) => p.protocol.startsWith('ICMP') || p.protocol === 'DHCP')
    if (catFilter === 'ALERT') return packets.filter((p) => Boolean(p.alertSeverity))
    return packets
  }, [packets, catFilter])

  const currentNo = useMemo(() => {
    if (selectedNo !== null && filteredPackets.some((p) => p.no === selectedNo)) return selectedNo
    return filteredPackets[0]?.no ?? packets[0]?.no ?? null
  }, [selectedNo, filteredPackets, packets])

  useEffect(() => {
    if (currentNo === null) {
      setDetail(null)
      return
    }
    api
      .getPacketDetail(currentNo)
      .then((res) => {
        if (res.ok) setDetail(res)
      })
      .catch(() => {})
  }, [currentNo])

  // Extract OSI layers (exclude L1 Frame wrapper for encapsulation diagram)
  const osiLayers = useMemo(() => {
    if (!detail) return []
    return detail.layers.filter((l) => l.osiLayer >= 2)
  }, [detail])

  // Reset stepper when packet changes
  useEffect(() => {
    setPlaying(false)
    setAnimStep(Math.max(1, osiLayers.length))
  }, [detail?.summary.no, osiLayers.length])

  // Auto-play encapsulation animation
  useEffect(() => {
    if (!playing || osiLayers.length === 0) return
    const t = setInterval(() => {
      setAnimStep((prev) => {
        if (prev >= osiLayers.length) {
          setPlaying(false)
          return osiLayers.length
        }
        return prev + 1
      })
    }, 1150)
    return () => clearInterval(t)
  }, [playing, osiLayers.length])

  const narration = useMemo(() => (detail ? narratePacketZh(detail) : null), [detail])
  const headerDiagrams = useMemo(() => (detail ? extractHeaderDiagrams(detail) : []), [detail])
  const lessons = useMemo(() => discoverLearningLessons(packets, streams), [packets, streams])

  // Keep selected header diagram & bitfield cell synced
  useEffect(() => {
    if (headerDiagrams.length === 0) {
      setSelectedCell(null)
      return
    }
    // Prefer IPv4 or TCP as default showcase when present
    const preferred = headerDiagrams.findIndex((d) => d.protocol === 'TCP' || d.protocol === 'IPv4')
    const idx = preferred >= 0 ? preferred : 0
    setActiveProtoIdx(idx)
    setSelectedCell(headerDiagrams[idx]?.rows[0]?.[0] ?? null)
  }, [detail?.summary.no])

  const activeDiagram = headerDiagrams[activeProtoIdx] || headerDiagrams[0] || null
  const cellKnowledge = selectedCell ? lookupFieldKnowledge(selectedCell.fieldKey, selectedCell.zhName) : null

  // Compute visible layers according to encapsulation / decapsulation step
  const steppedLayers = useMemo(() => {
    if (osiLayers.length === 0) return []
    const k = Math.min(osiLayers.length, Math.max(1, animStep))
    if (direction === 'encap') {
      // Encapsulation adds layers from top (L7) down to L2: take last k layers
      return osiLayers.slice(osiLayers.length - k)
    }
    // Decapsulation peels from outer L2 inward to L7: show remaining layers from index (k - 1)
    return osiLayers.slice(Math.min(k - 1, osiLayers.length - 1))
  }, [osiLayers, animStep, direction])

  const activeStepLayer = useMemo(() => {
    if (osiLayers.length === 0) return null
    const k = Math.min(osiLayers.length, Math.max(1, animStep))
    return direction === 'encap' ? osiLayers[osiLayers.length - k] : osiLayers[k - 1]
  }, [osiLayers, animStep, direction])

  const currentIdxInFiltered = filteredPackets.findIndex((p) => p.no === currentNo)

  if (packets.length === 0) {
    return (
      <div className="h-full flex items-center justify-center p-6 bg-slate-50 dark:bg-[#090d14]">
        <div className="max-w-lg w-full rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-8 text-center space-y-4 shadow-sm">
          <div className="w-14 h-14 mx-auto rounded-2xl bg-gradient-to-br from-cyan-500 to-violet-600 text-white flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <GraduationCap className="w-7 h-7" />
          </div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white">
            欢迎来到「计网可视化学习工坊」
          </h2>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
            你可以直接抓取自己电脑上的真实网络流量（浏览器访问网页、Ping、DNS 查询等），也可以一键加载教学演示包。WirePulse 会把每一个真实数据包变成<strong>可交互的 OSI 套娃封装动画、教科书 32 位首部位图和 TCP 状态机课堂</strong>！
          </p>
          <div className="flex flex-wrap justify-center gap-3 pt-2">
            <button
              onClick={onGoCapture}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer shadow-sm"
            >
              <Radio className="w-4 h-4" /> 去抓取我的真实流量
            </button>
            <button
              onClick={onLoadDemo}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold cursor-pointer shadow-sm"
            >
              <Sparkles className="w-4 h-4" /> 一键加载计网教学示范包
            </button>
          </div>
        </div>
      </div>
    )
  }

  // Recursive renderer for Nested Russian-Doll Encapsulation Visual
  const renderRussianDoll = (layers: typeof osiLayers, depth = 0): React.ReactNode => {
    if (depth >= layers.length) return null
    const l = layers[depth]
    const meta = OSI_LAYER_META[l.osiLayer] || OSI_LAYER_META[7]
    const isHighlight = activeStepLayer && l.protocol === activeStepLayer.protocol && l.offset === activeStepLayer.offset
    const inner = renderRussianDoll(layers, depth + 1)

    return (
      <div
        onClick={(e) => {
          e.stopPropagation()
          const fullIdx = osiLayers.findIndex((x) => x === l)
          if (fullIdx !== -1) {
            setAnimStep(direction === 'encap' ? osiLayers.length - fullIdx : fullIdx + 1)
          }
        }}
        className={`rounded-xl border-2 p-3 transition-all cursor-pointer ${
          isHighlight
            ? 'border-cyan-500 bg-cyan-500/[0.08] shadow-md shadow-cyan-500/15'
            : `${meta.colorCls} opacity-90 hover:opacity-100`
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded-md text-[10.5px] font-bold bg-white/80 dark:bg-slate-900/80 border border-current/25">
              {meta.name} · {l.protocol}
            </span>
            <span className="text-[11px] font-medium opacity-85">{meta.pdu}</span>
          </div>
          <span className="text-[11px] font-mono-code font-semibold">
            首部/区段: {l.length} B（偏移 {l.offset}..{l.offset + Math.max(0, l.length - 1)}）
          </span>
        </div>

        <div className="text-[11.5px] font-mono-code opacity-90 mb-2 truncate" title={l.title}>
          {l.title}
        </div>

        {inner ? (
          <div className="pl-2 sm:pl-4 pt-1">{inner}</div>
        ) : (
          <div className="mt-1 px-3 py-2 rounded-lg bg-white/70 dark:bg-slate-950/60 border border-dashed border-current/30 text-[11px] font-mono-code">
            <span className="font-semibold">最内层业务数据 / 协议内容：</span>
            {detail?.summary.info}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto bg-slate-50 dark:bg-[#090d14] p-4 sm:p-6">
      <div className="max-w-7xl mx-auto space-y-5">
        {/* Top Real-Packet Picker Bar */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-3.5 space-y-3 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-violet-600 text-white flex items-center justify-center shrink-0">
                <GraduationCap className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  计网可视化学习工坊（基于当前真实抓包实时生成）
                </h2>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  任选你自己抓到的任意数据包，亲眼看懂 OSI 封装套娃、教科书 32 位首部位图与协议交互过程
                </p>
              </div>
            </div>

            {/* Packet Prev / Dropdown / Next */}
            <div className="flex items-center gap-1.5">
              <button
                disabled={currentIdxInFiltered <= 0}
                onClick={() => onSelectPacket(filteredPackets[currentIdxInFiltered - 1].no)}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 disabled:opacity-35 cursor-pointer"
                title="上一帧"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <select
                value={currentNo ?? ''}
                onChange={(e) => onSelectPacket(Number(e.target.value))}
                className="h-8 px-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-xs font-mono-code text-slate-800 dark:text-slate-100 max-w-[330px]"
              >
                {filteredPackets.slice(0, 300).map((p) => (
                  <option key={p.no} value={p.no}>
                    #{p.no} [{p.protocol}] {p.src} → {p.dst} | {p.info.slice(0, 38)}
                  </option>
                ))}
              </select>
              <button
                disabled={currentIdxInFiltered < 0 || currentIdxInFiltered >= filteredPackets.length - 1}
                onClick={() => onSelectPacket(filteredPackets[currentIdxInFiltered + 1].no)}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 disabled:opacity-35 cursor-pointer"
                title="下一帧"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Quick Protocol Learning Filter Chips */}
          <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-100 dark:border-slate-800/80">
            <span className="text-[11px] text-slate-400 mr-1">快速挑一个经典协议包：</span>
            {[
              { id: 'ALL', label: `全部 (${packets.length})` },
              { id: 'ARP', label: 'ARP 寻址' },
              { id: 'DNS', label: 'DNS 域名解析' },
              { id: 'SYN', label: 'TCP 握手/挥手' },
              { id: 'HTTP', label: 'HTTP 明文' },
              { id: 'TLS', label: 'TLS/QUIC 加密' },
              { id: 'ICMP', label: 'ICMP / DHCP' },
              { id: 'ALERT', label: '⚠️ 攻击/告警包' },
            ].map((chip) => (
              <button
                key={chip.id}
                onClick={() => setCatFilter(chip.id)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium border transition-colors cursor-pointer ${
                  catFilter === chip.id
                    ? 'bg-cyan-600 text-white border-cyan-500'
                    : 'bg-slate-50 dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:border-cyan-500/50'
                }`}
              >
                {chip.label}
              </button>
            ))}
          </div>
        </div>

        {/* Hero Plain-Chinese Story Card */}
        {detail && narration && (
          <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-br from-white via-cyan-50/40 to-violet-50/40 dark:from-[#0f172a] dark:via-[#0d1929] dark:to-[#151329] p-5 shadow-xs space-y-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="space-y-1.5 flex-1 min-w-[260px]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-mono-code font-bold px-2 py-0.5 rounded-md bg-cyan-600 text-white">
                    帧 #{detail.summary.no}
                  </span>
                  <span className="text-[11px] font-semibold px-2 py-0.5 rounded-md bg-violet-500/15 text-violet-700 dark:text-violet-300 border border-violet-500/30">
                    OSI 最高第 {detail.summary.osiLayer} 层 · {detail.summary.protocol}
                  </span>
                  <span className="text-[11px] font-mono-code text-slate-500 dark:text-slate-400">
                    {detail.summary.src}
                    {detail.summary.srcPort ? `:${detail.summary.srcPort}` : ''} → {detail.summary.dst}
                    {detail.summary.dstPort ? `:${detail.summary.dstPort}` : ''}（共 {detail.summary.length} 字节）
                  </span>
                </div>
                <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
                  {narration.headline}
                </h3>
                <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
                  {narration.story}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  onClick={() => onJumpTo3Pane(detail.summary.no)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 hover:border-cyan-500 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-cyan-500" />
                  <span>在三栏视图看十六进制</span>
                </button>
                {detail.summary.streamId !== null && detail.summary.streamProto && (
                  <button
                    onClick={() => onOpenStreamSequence(detail.summary.streamProto!, detail.summary.streamId!)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
                  >
                    <Workflow className="w-3.5 h-3.5" />
                    <span>查看该流时序图</span>
                  </button>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-start gap-2 pt-2 border-t border-slate-200/70 dark:border-slate-800/80 text-xs">
              <div className="flex items-center gap-1.5 text-amber-700 dark:text-amber-300 font-semibold shrink-0">
                <Lightbulb className="w-4 h-4" />
                <span>核心原理：</span>
              </div>
              <span className="text-slate-700 dark:text-slate-300">{narration.keyConcept}</span>
            </div>

            <div className="flex flex-wrap gap-2">
              {narration.takeaways.map((tk, i) => (
                <span
                  key={i}
                  className="text-[11px] px-2.5 py-1 rounded-lg bg-white/80 dark:bg-slate-900/70 border border-slate-200 dark:border-slate-700/80 text-slate-700 dark:text-slate-300"
                >
                  • {tk}
                </span>
              ))}
            </div>

            {narration.securityNote && (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-500/12 border border-rose-500/35 text-xs text-rose-700 dark:text-rose-300">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                <span>{narration.securityNote}</span>
              </div>
            )}
          </div>
        )}

        {/* Sub-navigation Tabs */}
        <div className="flex flex-wrap items-center gap-2">
          {[
            { id: 'encap' as const, icon: Box, label: '1. OSI 封装/解封装套娃动画' },
            { id: 'bitfield' as const, icon: Grid3X3, label: '2. 教科书 32 位首部位图（实时填值）' },
            { id: 'lessons' as const, icon: BookOpen, label: `3. 真实流量互动课堂（发现 ${lessons.length} 个场景）` },
          ].map((t) => {
            const Icon = t.icon
            const active = subTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setSubTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold border transition-all cursor-pointer ${
                  active
                    ? 'bg-cyan-600 text-white border-cyan-500 shadow-sm shadow-cyan-500/20'
                    : 'bg-white dark:bg-[#0f1520] text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:border-cyan-500/50'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{t.label}</span>
              </button>
            )
          })}
        </div>

        {/* SUB-TAB 1: OSI ENCAPSULATION RUSSIAN-DOLL ANIMATOR */}
        {subTab === 'encap' && detail && (
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
            <div className="lg:col-span-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-5 space-y-4">
              {/* Animation Controls */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-900 p-0.5 text-xs">
                  <button
                    onClick={() => {
                      setDirection('encap')
                      setAnimStep(1)
                      setPlaying(true)
                    }}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded-md font-semibold cursor-pointer ${
                      direction === 'encap' ? 'bg-white dark:bg-cyan-600 text-cyan-700 dark:text-white' : 'text-slate-500'
                    }`}
                  >
                    <ArrowDown className="w-3.5 h-3.5" /> 发送端封装 (L7→L2)
                  </button>
                  <button
                    onClick={() => {
                      setDirection('decap')
                      setAnimStep(1)
                      setPlaying(true)
                    }}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded-md font-semibold cursor-pointer ${
                      direction === 'decap' ? 'bg-white dark:bg-violet-600 text-violet-700 dark:text-white' : 'text-slate-500'
                    }`}
                  >
                    <ArrowUp className="w-3.5 h-3.5" /> 接收端解封装 (L2→L7)
                  </button>
                </div>

                <div className="flex items-center gap-1.5 text-xs">
                  <button
                    onClick={() => {
                      if (!playing && animStep >= osiLayers.length) setAnimStep(1)
                      setPlaying((p) => !p)
                    }}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold cursor-pointer"
                  >
                    {playing ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    <span>{playing ? '暂停' : '动画演示'}</span>
                  </button>
                  <button
                    onClick={() => {
                      setPlaying(false)
                      setAnimStep((s) => Math.max(1, s - 1))
                    }}
                    className="px-2 py-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 cursor-pointer"
                  >
                    上一步
                  </button>
                  <button
                    onClick={() => {
                      setPlaying(false)
                      setAnimStep((s) => Math.min(osiLayers.length, s + 1))
                    }}
                    className="px-2 py-1 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500 cursor-pointer"
                  >
                    下一步
                  </button>
                  <span className="font-mono-code text-slate-400 ml-1">
                    {Math.min(animStep, osiLayers.length)}/{osiLayers.length}
                  </span>
                </div>
              </div>

              {/* Proportional Wire Byte Layout Bar */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  物理线路真实字节切分比例（总长 {detail.summary.length} 字节）
                </div>
                <div className="flex h-8 rounded-lg overflow-hidden border border-slate-200 dark:border-slate-700">
                  {osiLayers.map((l, idx) => {
                    const pct = Math.max(8, (l.length / Math.max(1, detail.summary.length)) * 100)
                    const meta = OSI_LAYER_META[l.osiLayer] || OSI_LAYER_META[7]
                    const isCur = activeStepLayer === l
                    return (
                      <button
                        key={idx}
                        onClick={() => {
                          setPlaying(false)
                          setAnimStep(direction === 'encap' ? osiLayers.length - idx : idx + 1)
                        }}
                        style={{ width: `${pct}%`, backgroundColor: meta.barHex }}
                        className={`flex items-center justify-center text-[10.5px] font-mono-code font-bold text-white px-1 truncate cursor-pointer transition-all ${
                          isCur ? 'ring-2 ring-inset ring-white brightness-110' : 'opacity-80 hover:opacity-100'
                        }`}
                        title={`${l.protocol}: ${l.length} 字节`}
                      >
                        {l.protocol} ({l.length}B)
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Nested Russian Doll Diagram */}
              <div className="pt-1">
                {renderRussianDoll(steppedLayers, 0)}
              </div>
            </div>

            {/* Right Active Layer Textbook Card */}
            <div className="lg:col-span-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-5 space-y-4">
              {activeStepLayer ? (
                <>
                  {(() => {
                    const meta = OSI_LAYER_META[activeStepLayer.osiLayer] || OSI_LAYER_META[7]
                    return (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className={`px-2.5 py-1 rounded-lg text-xs font-bold border ${meta.colorCls}`}>
                            {meta.name} · {activeStepLayer.protocol}
                          </span>
                          <span className="text-xs font-mono-code text-slate-400">
                            {direction === 'encap' ? '正在封装此层首部' : '正在拆解此层首部'}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2.5 text-xs">
                          <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800">
                            <div className="text-[10px] text-slate-400">协议数据单元 (PDU)</div>
                            <div className="font-semibold text-slate-800 dark:text-slate-100 mt-0.5">{meta.pdu}</div>
                          </div>
                          <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800">
                            <div className="text-[10px] text-slate-400">核心寻址方式</div>
                            <div className="font-semibold text-slate-800 dark:text-slate-100 mt-0.5">{meta.addr}</div>
                          </div>
                        </div>

                        <div className="p-3 rounded-lg bg-cyan-500/[0.06] border border-cyan-500/25 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                          <strong className="text-cyan-700 dark:text-cyan-300">为什么需要这一层？</strong>
                          <p className="mt-1">{meta.role}</p>
                        </div>

                        <div>
                          <div className="text-[11px] font-semibold text-slate-500 mb-1.5">
                            当前真实数据包在这一层携带的关键字段：
                          </div>
                          <div className="space-y-1 max-h-52 overflow-y-auto pr-1">
                            {activeStepLayer.fields.slice(0, 12).map((f, i) => (
                              <div
                                key={i}
                                className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-md bg-slate-50 dark:bg-slate-900/90 border border-slate-100 dark:border-slate-800 text-[11px] font-mono-code"
                              >
                                <span className="truncate text-slate-800 dark:text-slate-200">{f.label}</span>
                                {f.length > 0 && (
                                  <span className="text-[10px] text-slate-400 shrink-0">{f.length}B</span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>

                        {headerDiagrams.some((d) => d.osiLayer === activeStepLayer.osiLayer) && (
                          <button
                            onClick={() => {
                              const idx = headerDiagrams.findIndex((d) => d.osiLayer === activeStepLayer.osiLayer)
                              if (idx >= 0) {
                                setActiveProtoIdx(idx)
                                setSelectedCell(headerDiagrams[idx].rows[0]?.[0] ?? null)
                              }
                              setSubTab('bitfield')
                            }}
                            className="w-full flex items-center justify-center gap-2 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold cursor-pointer"
                          >
                            <Grid3X3 className="w-3.5 h-3.5" />
                            <span>查看该层教科书 32 位首部位图 →</span>
                          </button>
                        )}
                      </div>
                    )
                  })()}
                </>
              ) : (
                <div className="text-xs text-slate-400">暂无可展示的协议层</div>
              )}
            </div>
          </div>
        )}

        {/* SUB-TAB 2: TEXTBOOK 32-BIT RFC HEADER BITFIELD DIAGRAM */}
        {subTab === 'bitfield' && (
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
            <div className="lg:col-span-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-5 space-y-4">
              {/* Layer Selector Pills */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap gap-1.5">
                  {headerDiagrams.map((d, idx) => (
                    <button
                      key={d.protocol}
                      onClick={() => {
                        setActiveProtoIdx(idx)
                        setSelectedCell(d.rows[0]?.[0] ?? null)
                      }}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                        activeProtoIdx === idx
                          ? 'bg-cyan-600 text-white border-cyan-500 shadow-xs'
                          : 'bg-slate-50 dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:border-cyan-500/60'
                      }`}
                    >
                      L{d.osiLayer} · {d.protocol} ({d.totalBytes}B)
                    </button>
                  ))}
                </div>
                <span className="text-[11px] text-slate-400">点击任意字段格子查看计网百科与二进制位</span>
              </div>

              {activeDiagram ? (
                <div className="space-y-3">
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-white">{activeDiagram.titleZh}</h4>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">{activeDiagram.subtitle}</p>
                  </div>

                  {/* Classic 0..31 Bit Ruler */}
                  <div className="border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden">
                    <div
                      className="grid bg-slate-100 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 text-[9.5px] font-mono-code text-slate-400 select-none"
                      style={{ gridTemplateColumns: 'repeat(32, minmax(0, 1fr))' }}
                    >
                      <div className="col-span-8 px-1.5 py-1 border-r border-slate-200 dark:border-slate-800 flex justify-between">
                        <span>0</span>
                        <span>Bit 0..7 (1B)</span>
                        <span>7</span>
                      </div>
                      <div className="col-span-8 px-1.5 py-1 border-r border-slate-200 dark:border-slate-800 flex justify-between">
                        <span>8</span>
                        <span>8..15 (2B)</span>
                        <span>15</span>
                      </div>
                      <div className="col-span-8 px-1.5 py-1 border-r border-slate-200 dark:border-slate-800 flex justify-between">
                        <span>16</span>
                        <span>16..23 (3B)</span>
                        <span>23</span>
                      </div>
                      <div className="col-span-8 px-1.5 py-1 flex justify-between">
                        <span>24</span>
                        <span>24..31 (4B)</span>
                        <span>31</span>
                      </div>
                    </div>

                    {/* 32-Bit Rows */}
                    <div className="divide-y divide-slate-200 dark:divide-slate-800">
                      {activeDiagram.rows.map((row, rIdx) => (
                        <div
                          key={rIdx}
                          className="grid"
                          style={{ gridTemplateColumns: 'repeat(32, minmax(0, 1fr))' }}
                        >
                          {row.map((cell) => {
                            const isSel = selectedCell?.id === cell.id
                            const tone = CELL_TONE[cell.highlightTone || 'slate']
                            return (
                              <button
                                key={cell.id}
                                onClick={() => setSelectedCell(cell)}
                                style={{ gridColumn: `span ${cell.bitSpan} / span ${cell.bitSpan}` }}
                                className={`p-2 text-left border-r last:border-r-0 transition-all cursor-pointer min-h-[58px] flex flex-col justify-between ${tone} ${
                                  isSel ? 'ring-2 ring-inset ring-cyan-500 brightness-105 z-10' : ''
                                }`}
                              >
                                <div className="text-[10px] font-semibold opacity-80 truncate" title={cell.zhName}>
                                  {cell.zhName}
                                </div>
                                <div
                                  className="text-[11.5px] font-mono-code font-bold truncate mt-0.5"
                                  title={cell.valueText}
                                >
                                  {cell.valueText}
                                </div>
                              </button>
                            )
                          })}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-xs text-slate-400">
                  当前帧不含标准以太网/IPv4/TCP/UDP/ARP/DNS/ICMP 固定首部。
                </div>
              )}
            </div>

            {/* Right Interactive Knowledge & Binary Inspector Card */}
            <div className="lg:col-span-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-5 space-y-4">
              {selectedCell ? (
                <>
                  <div className="space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10.5px] font-mono-code px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 font-semibold">
                        {selectedCell.fieldKey}
                      </span>
                      <span className="text-[11px] font-mono-code text-slate-400">
                        帧偏移 [{selectedCell.byteOffset}..{selectedCell.byteOffset + selectedCell.byteLength - 1}]
                      </span>
                    </div>
                    <h4 className="text-base font-bold text-slate-900 dark:text-white">
                      {cellKnowledge?.zhTitle || selectedCell.zhName}
                    </h4>
                    <div className="text-xs text-slate-400 font-mono-code">
                      {cellKnowledge?.enName || selectedCell.enShort}
                    </div>
                  </div>

                  {/* Live Real Value + Hex + Binary */}
                  <div className="rounded-xl bg-slate-900 text-slate-100 p-3.5 space-y-2 font-mono-code text-xs border border-slate-800">
                    <div className="flex justify-between gap-2">
                      <span className="text-slate-400">当前真实取值</span>
                      <span className="text-cyan-300 font-bold text-right">{selectedCell.valueText}</span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-slate-400">原始十六进制</span>
                      <span className="text-emerald-300">{selectedCell.rawHex}</span>
                    </div>
                    <div className="pt-1 border-t border-slate-800">
                      <div className="text-[10px] text-slate-400 mb-1">二进制比特流 (Network Byte Order / 大端序)</div>
                      <div className="text-[11px] text-amber-300 break-all">{selectedCell.rawBin}</div>
                    </div>
                  </div>

                  {/* Plain Chinese Explanation */}
                  {cellKnowledge && (
                    <div className="space-y-2.5 text-xs leading-relaxed">
                      <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/90 border border-slate-200/80 dark:border-slate-800 text-slate-700 dark:text-slate-200">
                        <div className="font-bold text-cyan-600 dark:text-cyan-400 mb-1">💡 大白话原理解析</div>
                        <p>{cellKnowledge.plainExplain}</p>
                      </div>

                      {cellKnowledge.examTip && (
                        <div className="p-3 rounded-lg bg-violet-500/10 border border-violet-500/30 text-violet-900 dark:text-violet-200">
                          <div className="font-bold mb-1">🎓 计网考研 / 面试高频考点</div>
                          <p>{cellKnowledge.examTip}</p>
                        </div>
                      )}

                      {cellKnowledge.securityTip && (
                        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-900 dark:text-rose-200">
                          <div className="font-bold mb-1">🛡️ 软件与系统安全视角</div>
                          <p>{cellKnowledge.securityTip}</p>
                        </div>
                      )}
                    </div>
                  )}
                </>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-slate-400">
                  请点击左侧 32 位首部位图中的任意字段
                </div>
              )}
            </div>
          </div>
        )}

        {/* SUB-TAB 3: AUTO-DISCOVERED REAL CAPTURE LESSONS */}
        {subTab === 'lessons' && (
          <div className="space-y-5">
            {/* TCP State Machine Visual Cheat Sheet */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                <div className="text-xs font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-500" />
                  <span>TCP 连接状态机速查图（对照下方真实抓包步步印证）</span>
                </div>
                <span className="text-[11px] text-slate-400">三次握手建连 → 双向可靠传输 → 四次挥手释放</span>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono-code">
                {[
                  { st: 'CLOSED', desc: '初始关闭', cls: 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300' },
                  { st: 'SYN_SENT', desc: '发 SYN (Seq=0)', cls: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/40' },
                  { st: 'SYN_RCVD', desc: '收 SYN+ACK', cls: 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/40' },
                  { st: 'ESTABLISHED', desc: '稳定传输数据', cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/40' },
                  { st: 'FIN_WAIT / CLOSE_WAIT', desc: '发/收 FIN 挥手', cls: 'bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/40' },
                  { st: 'TIME_WAIT → CLOSED', desc: '等待 2MSL 关闭', cls: 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300' },
                ].map((node, i, arr) => (
                  <React.Fragment key={node.st}>
                    <div className={`px-2.5 py-1.5 rounded-lg border border-transparent text-center ${node.cls}`}>
                      <div className="font-bold">{node.st}</div>
                      <div className="text-[10px] opacity-80">{node.desc}</div>
                    </div>
                    {i < arr.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0 hidden sm:block" />}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Discovered Interactive Lesson Cards */}
            {lessons.length === 0 ? (
              <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-10 text-center text-xs text-slate-400">
                当前抓包尚未发现多步协议场景，尝试多浏览几个网页或加载教学示范包！
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {lessons.map((lesson) => (
                  <div
                    key={lesson.id}
                    className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-4 flex flex-col gap-3 shadow-xs"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10.5px] font-bold px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300">
                            {lesson.badge}
                          </span>
                          {lesson.id === 'http-vs-tls' && (
                            <span className="flex items-center gap-1 text-[10.5px] text-violet-500 font-semibold">
                              <LockOpen className="w-3 h-3" /> vs <Lock className="w-3 h-3" />
                            </span>
                          )}
                        </div>
                        <h4 className="text-sm font-bold text-slate-900 dark:text-white">{lesson.title}</h4>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{lesson.subtitle}</p>
                      </div>
                      {lesson.streamRef && (
                        <button
                          onClick={() => onOpenStreamSequence(lesson.streamRef!.proto, lesson.streamRef!.streamId)}
                          className="px-2.5 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-semibold shrink-0 cursor-pointer"
                        >
                          打开时序图
                        </button>
                      )}
                    </div>

                    <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                      {lesson.steps.map((st, idx) => (
                        <button
                          key={`${st.packetNo}_${idx}`}
                          onClick={() => {
                            onSelectPacket(st.packetNo)
                            setSubTab('bitfield')
                          }}
                          className={`w-full text-left p-2.5 rounded-lg border transition-all cursor-pointer ${
                            currentNo === st.packetNo
                              ? 'border-cyan-500 bg-cyan-500/10'
                              : 'border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0b101b] hover:border-cyan-500/50'
                          }`}
                        >
                          <div className="flex items-center justify-between text-[11px] font-mono-code font-semibold text-cyan-700 dark:text-cyan-300">
                            <span>{st.label}</span>
                            <span className="text-[10px] text-slate-400">点击解剖首部位图 →</span>
                          </div>
                          <div className="text-xs text-slate-700 dark:text-slate-300 mt-0.5 leading-snug">
                            {st.explain}
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
