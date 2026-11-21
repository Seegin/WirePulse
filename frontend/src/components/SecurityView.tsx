import React, { useEffect, useState } from 'react'
import {
  AlertOctagon,
  AlertTriangle,
  ExternalLink,
  GitBranch,
  Info,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { api } from '../api'
import type { AlertCounts, SecurityAlert } from '../types'

interface Props {
  onJumpToPacket: (packetNo: number) => void
  onFollowStream: (proto: 'tcp' | 'udp', streamId: number) => void
}

const SEV_META = {
  CRITICAL: {
    badge: 'bg-rose-500 text-white',
    border: 'border-rose-500/40 bg-rose-500/[0.05] dark:bg-rose-500/[0.08]',
    text: 'text-rose-600 dark:text-rose-400',
    icon: AlertOctagon,
  },
  HIGH: {
    badge: 'bg-orange-500 text-white',
    border: 'border-orange-500/40 bg-orange-500/[0.05] dark:bg-orange-500/[0.07]',
    text: 'text-orange-600 dark:text-orange-400',
    icon: ShieldAlert,
  },
  MEDIUM: {
    badge: 'bg-amber-500 text-white',
    border: 'border-amber-500/35 bg-amber-500/[0.05] dark:bg-amber-500/[0.07]',
    text: 'text-amber-600 dark:text-amber-400',
    icon: AlertTriangle,
  },
  LOW: {
    badge: 'bg-sky-500 text-white',
    border: 'border-sky-500/30 bg-sky-500/[0.04] dark:bg-sky-500/[0.06]',
    text: 'text-sky-600 dark:text-sky-400',
    icon: Info,
  },
}

export const SecurityView: React.FC<Props> = ({ onJumpToPacket, onFollowStream }) => {
  const [severity, setSeverity] = useState<string>('ALL')
  const [counts, setCounts] = useState<AlertCounts>({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, TOTAL: 0 })
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])

  const load = (sev = severity) => {
    api
      .getAlerts(sev)
      .then((res) => {
        setCounts(res.counts)
        setAlerts(res.alerts || [])
      })
      .catch(() => {})
  }

  useEffect(() => {
    load(severity)
    const t = setInterval(() => load(severity), 2000)
    return () => clearInterval(t)
  }, [severity])

  return (
    <div className="h-full overflow-y-auto p-6 bg-slate-50 dark:bg-[#090d14]">
      <div className="max-w-7xl mx-auto space-y-5">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-500" />
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                实时网络安全 IDS 威胁雷达
              </h2>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              有状态检测 ARP 欺骗、TCP 端口/隐蔽扫描、SYN 泛洪、明文账号密码泄露、SQL 注入/XSS/路径穿越、高熵 DNS 隧道与弱 TLS 加密套件；点击任意告警直达取证帧。
            </p>
          </div>
        </div>

        {/* Severity KPI Filter Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {([
            { key: 'ALL', label: '全部告警', val: counts.TOTAL, accent: 'border-cyan-500/40 text-cyan-600 dark:text-cyan-400' },
            { key: 'CRITICAL', label: '严重 (Critical)', val: counts.CRITICAL, accent: 'border-rose-500/40 text-rose-600 dark:text-rose-400' },
            { key: 'HIGH', label: '高危 (High)', val: counts.HIGH, accent: 'border-orange-500/40 text-orange-600 dark:text-orange-400' },
            { key: 'MEDIUM', label: '中危 (Medium)', val: counts.MEDIUM, accent: 'border-amber-500/40 text-amber-600 dark:text-amber-400' },
            { key: 'LOW', label: '低危 (Low)', val: counts.LOW, accent: 'border-sky-500/40 text-sky-600 dark:text-sky-400' },
          ] as const).map((card) => (
            <button
              key={card.key}
              onClick={() => setSeverity(card.key)}
              className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer bg-white dark:bg-[#0f1520] ${
                severity === card.key
                  ? `${card.accent} ring-2 ring-current/20 shadow-sm`
                  : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
              }`}
            >
              <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">
                {card.label}
              </div>
              <div className={`text-2xl font-bold font-mono-code mt-1 ${card.accent.split(' ').slice(1).join(' ')}`}>
                {card.val}
              </div>
            </button>
          ))}
        </div>

        {/* Alert Cards List */}
        {alerts.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-12 text-center space-y-2">
            <ShieldCheck className="w-10 h-10 mx-auto text-emerald-500 opacity-70" />
            <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">
              No security threats detected in current filter
            </div>
            <p className="text-xs text-slate-400">
              Try loading the Security Lab Demo to witness all 13 IDS rules trigger across realistic attack streams.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {alerts.map((a) => {
              const meta = SEV_META[a.severity] || SEV_META.LOW
              const Icon = meta.icon
              return (
                <div
                  key={a.id}
                  className={`rounded-xl border p-4 transition-all ${meta.border}`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1.5 min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${meta.badge}`}>
                          <Icon className="w-3 h-3" />
                          {a.severity}
                        </span>
                        <span className="text-[11px] font-mono-code font-semibold px-2 py-0.5 rounded bg-slate-200/70 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                          {a.rule}
                        </span>
                        <span className="text-[11px] px-2 py-0.5 rounded bg-white/70 dark:bg-slate-900/70 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300">
                          {a.category}
                        </span>
                        {a.mitreId && (
                          <span className="text-[10.5px] font-mono-code px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-700 dark:text-violet-300">
                            MITRE {a.mitreId}
                          </span>
                        )}
                      </div>

                      <h3 className="text-sm font-bold text-slate-900 dark:text-white">{a.title}</h3>
                      <p className="text-xs text-slate-600 dark:text-slate-300">{a.description}</p>

                      {a.evidence && (
                        <div className="mt-2 px-3 py-1.5 rounded-lg bg-slate-900/90 text-emerald-300 font-mono-code text-[11px] overflow-x-auto border border-slate-800">
                          <span className="text-slate-500 mr-2">EVIDENCE &gt;</span>
                          {a.evidence}
                        </div>
                      )}

                      <div className="flex flex-wrap items-center gap-4 pt-1 text-[11px] font-mono-code text-slate-500 dark:text-slate-400">
                        <span>Flow: {a.src} → {a.dst}</span>
                        <span>Proto: {a.protocol}</span>
                        <span>Frame #{a.packetNo}</span>
                        <span>t={a.relTime.toFixed(4)}s</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => onJumpToPacket(a.packetNo)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer shadow-xs"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span>Inspect Frame #{a.packetNo}</span>
                      </button>
                      {a.streamId !== null && (
                        <button
                          onClick={() => onFollowStream('tcp', a.streamId!)}
                          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 hover:border-cyan-500 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer"
                        >
                          <GitBranch className="w-3.5 h-3.5 text-cyan-500" />
                          <span>Stream #{a.streamId}</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
