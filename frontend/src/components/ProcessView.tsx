import React, { useEffect, useState } from 'react'
import { Cpu, Filter, GitBranch, RefreshCw, ShieldAlert, Terminal } from 'lucide-react'
import { api } from '../api'
import type { ProcessTraffic } from '../types'
import { formatBytes } from '../utils/coloring'

interface Props {
  onTraceProcessStreams: (pid: number, name: string) => void
  onFilterProcessPackets: (pid: number, name: string) => void
}

export const ProcessView: React.FC<Props> = ({
  onTraceProcessStreams,
  onFilterProcessPackets,
}) => {
  const [processes, setProcesses] = useState<ProcessTraffic[]>([])
  const [search, setSearch] = useState('')

  const load = () => {
    api
      .getProcesses()
      .then((r) => setProcesses(r.processes || []))
      .catch(() => {})
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 2500)
    return () => clearInterval(t)
  }, [])

  const filtered = processes.filter(
    (p) =>
      !search.trim() ||
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      String(p.pid).includes(search) ||
      p.cmdline.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="h-full overflow-y-auto p-6 bg-slate-50 dark:bg-[#090d14]">
      <div className="max-w-7xl mx-auto space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-amber-500" />
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                OS Process Traffic Tracing
              </h2>
              <span className="text-[11px] font-mono-code px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                {processes.length} active processes
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Maps live TCP/UDP 5-tuple sockets to OS PIDs via Linux <code className="font-mono-code">/proc/net/*</code> + inode tables &amp; Windows <code className="font-mono-code">iphlpapi / netstat</code> — solving a classic Wireshark gap.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search process name, PID, cmdline..."
              className="h-8 px-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#111827] text-xs text-slate-800 dark:text-slate-100 focus:outline-none focus:border-cyan-500 w-64"
            />
            <button
              onClick={load}
              className="flex items-center gap-1.5 px-3 h-8 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#111827] hover:border-cyan-500 text-xs text-slate-600 dark:text-slate-300 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Refresh
            </button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-12 text-center text-xs text-slate-400 space-y-2">
            <Terminal className="w-8 h-8 mx-auto opacity-30" />
            <p>No OS process-attributed connections recorded yet. Start a live capture or load the Security Lab Demo.</p>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] overflow-hidden shadow-xs">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#111827] text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                    <th className="py-2.5 px-3.5">Process &amp; PID</th>
                    <th className="py-2.5 px-3">Protocols</th>
                    <th className="py-2.5 px-3 text-right">Streams</th>
                    <th className="py-2.5 px-3 text-right">Packets (Out / In)</th>
                    <th className="py-2.5 px-3 text-right">Volume (Out / In)</th>
                    <th className="py-2.5 px-3">Remote Endpoints</th>
                    <th className="py-2.5 px-3.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
                  {filtered.map((p) => (
                    <tr
                      key={p.pid}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                    >
                      <td className="py-3 px-3.5">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-900 dark:text-white font-mono-code">
                            {p.name}
                          </span>
                          <span className="text-[10px] font-mono-code px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-800 text-slate-500">
                            PID {p.pid}
                          </span>
                          {p.alerts > 0 && (
                            <span className="flex items-center gap-0.5 text-[10px] px-1.5 rounded bg-rose-500/15 text-rose-600 dark:text-rose-400 font-semibold">
                              <ShieldAlert className="w-3 h-3" /> {p.alerts}
                            </span>
                          )}
                        </div>
                        {p.cmdline && (
                          <div className="text-[10.5px] font-mono-code text-slate-400 truncate max-w-[300px] mt-0.5" title={p.cmdline}>
                            {p.cmdline}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex flex-wrap gap-1">
                          {p.protocols.map((pr) => (
                            <span
                              key={pr}
                              className="px-1.5 py-0.2 rounded text-[10px] font-mono-code font-semibold bg-cyan-500/12 text-cyan-700 dark:text-cyan-300 border border-cyan-500/25"
                            >
                              {pr}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-right font-mono-code font-semibold text-slate-700 dark:text-slate-200">
                        {p.streamCount}
                      </td>
                      <td className="py-3 px-3 text-right font-mono-code">
                        <span className="text-rose-600 dark:text-rose-400">↑{p.packetsOut}</span>
                        <span className="mx-1 text-slate-400">/</span>
                        <span className="text-cyan-600 dark:text-cyan-400">↓{p.packetsIn}</span>
                      </td>
                      <td className="py-3 px-3 text-right font-mono-code whitespace-nowrap">
                        <div className="font-semibold text-slate-800 dark:text-slate-100">
                          {formatBytes(p.totalBytes)}
                        </div>
                        <div className="text-[10px] text-slate-400">
                          ↑{formatBytes(p.bytesOut)} · ↓{formatBytes(p.bytesIn)}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex flex-wrap gap-1 max-w-[260px]">
                          {p.remoteEndpoints.slice(0, 3).map((ep) => (
                            <span
                              key={ep}
                              className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800/90 text-[10.5px] font-mono-code text-slate-600 dark:text-slate-300"
                            >
                              {ep}
                            </span>
                          ))}
                          {p.remoteEndpoints.length > 3 && (
                            <span className="text-[10px] text-slate-400 self-center">
                              +{p.remoteEndpoints.length - 3} more
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-3.5 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            onClick={() => onTraceProcessStreams(p.pid, p.name)}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-medium cursor-pointer whitespace-nowrap"
                          >
                            <GitBranch className="w-3 h-3 shrink-0" />
                            <span>All Streams</span>
                          </button>
                          <button
                            onClick={() => onFilterProcessPackets(p.pid, p.name)}
                            className="flex items-center gap-1 px-2 py-1 rounded-md border border-slate-200 dark:border-slate-700 hover:border-cyan-500 text-slate-700 dark:text-slate-200 text-[11px] font-medium cursor-pointer whitespace-nowrap"
                          >
                            <Filter className="w-3 h-3 shrink-0" />
                            <span>Packets</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
