import React, { useEffect, useState } from 'react'
import {
  AlertTriangle,
  BookOpen,
  ChevronDown,
  ChevronRight,
  Copy,
  Filter,
  GitBranch,
  GraduationCap,
  Layers,
  Loader2,
  LockOpen,
  Sparkles,
} from 'lucide-react'
import type { FieldNode, HighlightRange, LayerNode, PacketDetail } from '../types'
import { OSI_BADGE_META } from '../utils/coloring'
import { lookupFieldKnowledge } from '../utils/cnKnowledge'
import { UI_TEXT, type Lang } from '../utils/i18n'

interface Props {
  lang: Lang
  detail: PacketDetail | null
  engineMode: 'native' | 'wireshark'
  wiresharkLayers: LayerNode[] | null
  wiresharkEngineName: string
  wiresharkLoading: boolean
  wiresharkError: string | null
  tlsDecrypted: boolean
  wiresharkAvailable: boolean
  highlight: HighlightRange | null
  selectedByteOffset: number | null
  onEngineChange: (mode: 'native' | 'wireshark') => void
  onHighlight: (range: HighlightRange | null) => void
  onApplyFilter: (expr: string) => void
  onFollowStream: (proto: 'tcp' | 'udp', streamId: number) => void
  onOpenLearn: (no: number) => void
}

function formatFilterExpr(key: string, val: unknown): string {
  if (typeof val === 'boolean') return `${key} == ${val ? 'true' : 'false'}`
  if (typeof val === 'number') return `${key} == ${val}`
  const s = String(val)
  if (/^[0-9.:a-fA-Fx]+$/.test(s) && !s.includes(' ')) return `${key} == ${s}`
  return `${key} == "${s.replace(/"/g, '\\"')}"`
}

export const PacketDetailsPane: React.FC<Props> = ({
  lang,
  detail,
  engineMode,
  wiresharkLayers,
  wiresharkEngineName,
  wiresharkLoading,
  wiresharkError,
  tlsDecrypted,
  wiresharkAvailable,
  highlight,
  selectedByteOffset,
  onEngineChange,
  onHighlight,
  onApplyFilter,
  onFollowStream,
  onOpenLearn,
}) => {
  const t = UI_TEXT[lang]
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({})
  const [expandedFields, setExpandedFields] = useState<Record<string, boolean>>({})
  const [eduMode, setEduMode] = useState(true)
  const [activeFieldKey, setActiveFieldKey] = useState<{ key: string; label: string } | null>(null)

  const activeLayers = engineMode === 'wireshark' ? wiresharkLayers || [] : detail?.layers || []

  useEffect(() => {
    if (!detail) return
    const next: Record<string, boolean> = {}
    activeLayers.forEach((l, i) => {
      next[`${i}_${l.protocol}`] = l.osiLayer >= 3 || i === activeLayers.length - 1
    })
    setExpandedLayers(next)
    setExpandedFields({})
    setActiveFieldKey(null)
  }, [detail?.summary.no, engineMode, wiresharkLayers?.length])

  useEffect(() => {
    if (selectedByteOffset === null) return
    const nextLayers: Record<string, boolean> = { ...expandedLayers }
    activeLayers.forEach((l, i) => {
      if (l.length > 0 && selectedByteOffset >= l.offset && selectedByteOffset < l.offset + l.length) {
        nextLayers[`${i}_${l.protocol}`] = true
      }
    })
    setExpandedLayers(nextLayers)
  }, [selectedByteOffset])

  const expandAll = (open: boolean) => {
    const next: Record<string, boolean> = {}
    activeLayers.forEach((l, i) => {
      next[`${i}_${l.protocol}`] = open
    })
    setExpandedLayers(next)
  }

  const fieldKnowledge = activeFieldKey
    ? lookupFieldKnowledge(activeFieldKey.key, activeFieldKey.label)
    : null

  const renderField = (node: FieldNode, path: string, depth: number) => {
    const hasKids = Boolean(node.children && node.children.length > 0)
    const byteHit =
      selectedByteOffset !== null &&
      node.length > 0 &&
      selectedByteOffset >= node.offset &&
      selectedByteOffset < node.offset + node.length
    const isExpanded = expandedFields[path] ?? (byteHit && hasKids)
    const isHighlighted =
      highlight !== null &&
      node.length > 0 &&
      highlight.offset === node.offset &&
      highlight.length === node.length &&
      highlight.label === node.label

    return (
      <div key={path}>
        <div
          onClick={(e) => {
            e.stopPropagation()
            if (hasKids) {
              setExpandedFields((prev) => ({ ...prev, [path]: !isExpanded }))
            }
            if (node.length > 0) {
              onHighlight({ offset: node.offset, length: node.length, label: node.label })
            }
            if (node.key) {
              setActiveFieldKey({ key: node.key, label: node.label })
            }
          }}
          style={{ paddingLeft: `${12 + depth * 16}px` }}
          className={`group flex items-center justify-between gap-2 pr-2 py-0.5 text-[11.5px] font-mono-code cursor-pointer transition-colors ${
            isHighlighted || (byteHit && !hasKids)
              ? 'bg-cyan-500/20 text-cyan-900 dark:text-cyan-200'
              : node.severity === 'error'
                ? 'bg-rose-500/12 text-rose-700 dark:text-rose-300'
                : node.severity === 'warn'
                  ? 'bg-amber-500/10 text-amber-800 dark:text-amber-300'
                  : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/70'
          }`}
        >
          <div className="flex items-center gap-1.5 min-w-0">
            {hasKids ? (
              isExpanded ? (
                <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              )
            ) : (
              <span className="w-3.5 shrink-0 inline-block" />
            )}
            {(node.severity === 'warn' || node.severity === 'error') && (
              <AlertTriangle
                className={`w-3 h-3 shrink-0 ${node.severity === 'error' ? 'text-rose-500' : 'text-amber-500'}`}
              />
            )}
            <span className="truncate" title={node.label}>
              {node.label}
            </span>
            {node.length > 0 && (
              <span className="text-[10px] text-slate-400 dark:text-slate-500 shrink-0">
                [{node.offset}..{node.offset + node.length - 1}]
              </span>
            )}
          </div>

          <div className="hidden group-hover:flex items-center gap-1 shrink-0">
            {node.key && !node.key.startsWith('ws.') && (
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onApplyFilter(formatFilterExpr(node.key, node.value))
                }}
                className="flex items-center gap-0.5 px-1.5 py-0.2 rounded text-[10px] bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 hover:bg-cyan-500/25 cursor-pointer"
                title={`Filter: ${formatFilterExpr(node.key, node.value)}`}
              >
                <Filter className="w-2.5 h-2.5" />
                <span>{t.filterAction}</span>
              </button>
            )}
            <button
              onClick={(e) => {
                e.stopPropagation()
                navigator.clipboard?.writeText(String(node.value ?? node.label))
              }}
              className="p-0.5 rounded hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-400 hover:text-slate-700 dark:hover:text-slate-100 cursor-pointer"
              title={t.copyValue}
            >
              <Copy className="w-3 h-3" />
            </button>
          </div>
        </div>

        {hasKids && isExpanded && (
          <div>
            {node.children!.map((child, idx) => renderField(child, `${path}.${idx}`, depth + 1))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full bg-white dark:bg-[#0b101b] overflow-hidden select-none">
      {/* Header with Dual-Engine + Beginner Knowledge Guide Toggle */}
      <div className="flex items-center justify-between px-3 h-8 border-b border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#0f1520] text-[11px] gap-2 shrink-0 overflow-hidden">
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-semibold text-slate-700 dark:text-slate-200 shrink-0">{t.packetDetails}</span>
          {detail && (
            <span
              className="font-mono-code text-slate-400 truncate hidden xl:inline"
              title={`Frame #${detail.summary.no}${detail.summary.dpiMethod ? ` · ${detail.summary.dpiMethod}` : ''}`}
            >
              #{detail.summary.no}
              {detail.summary.dpiMethod ? ` · ${detail.summary.dpiMethod}` : ''}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0 whitespace-nowrap">
          {detail && (
            <button
              onClick={() => onOpenLearn(detail.summary.no)}
              className="flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/12 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 text-[10.5px] font-semibold cursor-pointer"
              title={lang === 'zh' ? '在计网学习工坊中用 32 位首部位图与 OSI 套娃图解此帧' : 'Visualize in NetLearn Studio (32-bit header & OSI encapsulation)'}
            >
              <GraduationCap className="w-3 h-3" />
              <span>{t.learnPacketBtn}</span>
            </button>
          )}

          {detail?.summary.streamId !== null && detail?.summary.streamProto && (
            <button
              onClick={() => onFollowStream(detail.summary.streamProto!, detail.summary.streamId!)}
              className="hidden sm:flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/12 hover:bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 text-[10.5px] font-medium cursor-pointer"
            >
              <GitBranch className="w-3 h-3" />
              <span>
                {t.followStream} #{detail.summary.streamId}
              </span>
            </button>
          )}

          {/* Edu Guide Toggle */}
          <button
            onClick={() => setEduMode((v) => !v)}
            className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-[10.5px] font-medium border cursor-pointer transition-colors ${
              eduMode
                ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/35'
                : 'text-slate-500 border-slate-200 dark:border-slate-700'
            }`}
            title={lang === 'zh' ? '开启/关闭点击字段时底部的新手百科解释' : 'Toggle protocol field explanation card'}
          >
            <BookOpen className="w-3 h-3" />
            <span>{t.learnCompanion}</span>
          </button>

          {/* Dual Engine Switcher */}
          <div className="flex items-center rounded-md border border-slate-200 dark:border-slate-700/80 bg-slate-100 dark:bg-slate-900 p-0.5">
            <button
              onClick={() => onEngineChange('native')}
              className={`px-2 py-0.5 rounded text-[10.5px] font-medium transition-colors cursor-pointer ${
                engineMode === 'native'
                  ? 'bg-white dark:bg-cyan-600 text-cyan-700 dark:text-white shadow-xs'
                  : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              {t.nativeEngine}
            </button>
            <button
              onClick={() => onEngineChange('wireshark')}
              disabled={!wiresharkAvailable}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-medium transition-colors cursor-pointer disabled:opacity-40 ${
                engineMode === 'wireshark'
                  ? 'bg-violet-600 text-white shadow-xs'
                  : 'text-slate-500 hover:text-violet-600 dark:hover:text-violet-300'
              }`}
            >
              <Sparkles className="w-3 h-3" />
              <span>{t.wiresharkEngine}</span>
            </button>
          </div>

          <button
            onClick={() => expandAll(true)}
            className="px-1 py-0.5 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 cursor-pointer"
            title={t.expandAll}
          >
            +
          </button>
          <button
            onClick={() => expandAll(false)}
            className="px-1 py-0.5 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 cursor-pointer"
            title={t.collapseAll}
          >
            -
          </button>
        </div>
      </div>

      {/* Tree Content */}
      <div className="flex-1 overflow-y-auto py-1 min-h-0">
        {!detail ? (
          <div className="h-full flex flex-col items-center justify-center text-xs text-slate-400 gap-1.5">
            <Layers className="w-6 h-6 opacity-40" />
            <span>{t.detailsEmpty}</span>
          </div>
        ) : engineMode === 'wireshark' && wiresharkLoading ? (
          <div className="h-full flex items-center justify-center gap-2 text-xs text-violet-500">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>
              {lang === 'zh'
                ? '正在调用 Wireshark libwireshark (sharkd JSON-RPC)...'
                : 'Querying Wireshark libwireshark (sharkd JSON-RPC)...'}
            </span>
          </div>
        ) : engineMode === 'wireshark' && wiresharkError ? (
          <div className="p-4 text-xs text-rose-500">{wiresharkError}</div>
        ) : (
          <div className="space-y-0.5">
            {engineMode === 'wireshark' && (
              <div className="mx-2 mb-1.5 px-2.5 py-1 rounded-md bg-violet-500/10 border border-violet-500/30 flex items-center justify-between text-[11px] text-violet-700 dark:text-violet-300">
                <span className="truncate font-medium">{wiresharkEngineName || 'Wireshark libwireshark'}</span>
                {tlsDecrypted && (
                  <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400 font-semibold shrink-0">
                    <LockOpen className="w-3 h-3" /> SSLKEYLOG Active
                  </span>
                )}
              </div>
            )}

            {activeLayers.map((layer, idx) => {
              const lkey = `${idx}_${layer.protocol}`
              const isOpen = expandedLayers[lkey] ?? false
              const osiMeta = OSI_BADGE_META[layer.osiLayer] || OSI_BADGE_META[7]
              return (
                <div key={lkey} className="border-b border-slate-100/80 dark:border-slate-800/50 last:border-b-0">
                  <div
                    onClick={() => {
                      setExpandedLayers((prev) => ({ ...prev, [lkey]: !isOpen }))
                      if (layer.length > 0) {
                        onHighlight({ offset: layer.offset, length: layer.length, label: layer.title })
                      }
                    }}
                    className="flex items-center gap-2 px-2 py-1 text-xs font-medium text-slate-800 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800/70 cursor-pointer"
                  >
                    {isOpen ? (
                      <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    )}
                    <span className={`text-[9.5px] font-bold px-1.5 py-0 rounded border shrink-0 ${osiMeta.cls}`}>
                      {osiMeta.label}
                    </span>
                    <span className="truncate font-mono-code text-[11.5px]">{layer.title}</span>
                    {layer.length > 0 && (
                      <span className="ml-auto text-[10px] font-mono-code text-slate-400 shrink-0">
                        {layer.length}B
                      </span>
                    )}
                  </div>

                  {isOpen && (
                    <div className="pb-1">
                      {layer.fields.map((f, fi) => renderField(f, `${lkey}.${fi}`, 0))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Inline Beginner Knowledge Companion Card */}
      {eduMode && detail && (
        <div className="border-t border-amber-500/30 bg-amber-500/[0.06] dark:bg-[#121928] px-3 py-2 text-[11.5px] shrink-0">
          {fieldKnowledge ? (
            <div className="space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  <BookOpen className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                  <span className="font-bold text-slate-900 dark:text-white truncate">
                    {lang === 'zh' ? fieldKnowledge.zhTitle : fieldKnowledge.enName}
                  </span>
                  <span className="text-[10px] font-mono-code text-slate-400 truncate hidden sm:inline">
                    ({fieldKnowledge.key} · OSI L{fieldKnowledge.osiLayer})
                  </span>
                </div>
                <button
                  onClick={() => onOpenLearn(detail.summary.no)}
                  className="text-[10.5px] font-semibold text-cyan-600 dark:text-cyan-400 hover:underline shrink-0 cursor-pointer"
                >
                  {lang === 'zh' ? '32-bit Header 位图 →' : '32-bit Header Diagram →'}
                </button>
              </div>
              {lang === 'zh' ? (
                <>
                  <p className="text-slate-700 dark:text-slate-300 leading-snug">{fieldKnowledge.plainExplain}</p>
                  {fieldKnowledge.examTip && (
                    <p className="text-[11px] text-violet-700 dark:text-violet-300">
                      🎓 <strong>考点：</strong>
                      {fieldKnowledge.examTip}
                    </p>
                  )}
                  {fieldKnowledge.securityTip && (
                    <p className="text-[11px] text-rose-700 dark:text-rose-300">
                      🛡️ <strong>Security：</strong>
                      {fieldKnowledge.securityTip}
                    </p>
                  )}
                </>
              ) : (
                <p className="text-slate-700 dark:text-slate-300 leading-snug font-mono-code text-[11px]">
                  Filter key: <code className="text-cyan-500">{fieldKnowledge.key}</code> · OSI Layer {fieldKnowledge.osiLayer} ({fieldKnowledge.enName}). Click &quot;32-bit Header Diagram&quot; for bit-level RFC structure.
                </p>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                <span>
                  {lang === 'zh'
                    ? '点击上方任意协议字段（如 TTL、SYN、Window、SNI），此处立即显示原理与考点解析'
                    : 'Click any protocol field above (e.g. TTL, SYN, Window, SNI) to inspect its filter key and RFC role'}
                </span>
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
