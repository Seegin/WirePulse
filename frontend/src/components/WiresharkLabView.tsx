import React, { useEffect, useState } from 'react'
import {
  Check,
  Code2,
  Copy,
  Download,
  KeyRound,
  Layers,
  Palette,
  Plus,
  Sparkles,
  Trash2,
} from 'lucide-react'
import { api } from '../api'
import type { SessionStatus } from '../types'
import { COLORING_RULES_REFERENCE } from '../utils/coloring'

interface Props {
  status: SessionStatus
  onApplyFilter: (expr: string) => void
  onStatusRefresh: () => void
}

interface LuaFieldDraft {
  name: string
  label: string
  type: 'uint8' | 'uint16' | 'uint32' | 'string' | 'bytes'
  length: number
}

export const WiresharkLabView: React.FC<Props> = ({
  status,
  onApplyFilter,
  onStatusRefresh,
}) => {
  // TLS SSLKEYLOGFILE state
  const [keylogPath, setKeylogPath] = useState('')
  const [keylogContent, setKeylogContent] = useState('')
  const [keylogMsg, setKeylogMsg] = useState<string | null>(null)

  // Lua Dissector Generator state
  const [protoName, setProtoName] = useState('ucas_sft')
  const [description, setDescription] = useState('UCAS Secure File Transfer Protocol')
  const [transport, setTransport] = useState<'tcp' | 'udp'>('tcp')
  const [port, setPort] = useState(9090)
  const [magicHex, setMagicHex] = useState('55434153')
  const [fields, setFields] = useState<LuaFieldDraft[]>([
    { name: 'magic', label: 'Protocol Magic', type: 'uint32', length: 4 },
    { name: 'msg_type', label: 'Packet Type Opcode', type: 'uint8', length: 1 },
    { name: 'flags', label: 'Security Flags', type: 'uint8', length: 1 },
    { name: 'payload_len', label: 'Payload Length', type: 'uint32', length: 4 },
  ])
  const [luaCode, setLuaCode] = useState('')
  const [copiedLua, setCopiedLua] = useState(false)

  const regenerateLua = () => {
    api
      .generateLuaDissector({ protoName, description, transport, port, magicHex, fields })
      .then((res) => {
        if (res.ok) setLuaCode(res.lua)
      })
      .catch(() => {})
  }

  useEffect(() => {
    regenerateLua()
  }, [protoName, description, transport, port, magicHex, fields])

  const applyKeylog = async () => {
    const payload = keylogContent.trim() ? { content: keylogContent } : { path: keylogPath.trim() || null }
    const res = await api.setKeylog(payload)
    if (res.ok) {
      setKeylogMsg(res.keylogPath ? `SSLKEYLOGFILE active: ${res.keylogPath}` : 'SSLKEYLOGFILE cleared.')
      onStatusRefresh()
    } else {
      setKeylogMsg(`Error: ${res.error}`)
    }
  }

  const downloadLua = () => {
    const blob = new Blob([luaCode], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${protoName || 'custom'}_dissector.lua`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="h-full overflow-y-auto p-6 bg-slate-50 dark:bg-[#090d14]">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header Card */}
        <div className="rounded-2xl border border-violet-500/30 bg-gradient-to-r from-violet-500/10 via-indigo-500/8 to-cyan-500/10 p-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-violet-500" />
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                  Wireshark 增量扩展实验室
                </h2>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 max-w-3xl">
                深度复用并扩展 Wireshark 生态：支持 <code className="font-mono-code">libwireshark (sharkd)</code> 3,000+ 协议双引擎解码、
                <code className="font-mono-code">SSLKEYLOGFILE</code> 解密 HTTPS/TLS 1.2 &amp; 1.3，以及可视化设计自定义二进制协议并一键导出上游 Wireshark <code className="font-mono-code">.lua</code> 插件。
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono-code">
              <span
                className={`px-3 py-1.5 rounded-lg border font-semibold ${
                  status.wiresharkAvailable
                    ? 'bg-emerald-500/15 border-emerald-500/35 text-emerald-700 dark:text-emerald-300'
                    : 'bg-amber-500/15 border-amber-500/35 text-amber-700 dark:text-amber-300'
                }`}
              >
                {status.wiresharkAvailable ? `Connected: ${status.wiresharkVersion}` : 'Wireshark CLI Not Installed'}
              </span>
            </div>
          </div>
        </div>

        {/* Grid: TLS Keylog Decryption + Coloring Rules */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* TLS SSLKEYLOGFILE Decryption Manager */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-5 space-y-3.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-emerald-500" />
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  HTTPS / TLS 1.2 &amp; 1.3 Decryption (SSLKEYLOGFILE)
                </h3>
              </div>
              {status.keylogActive && (
                <span className="text-[10.5px] font-semibold px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                  ACTIVE
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Set the <code className="font-mono-code">SSLKEYLOGFILE</code> environment variable in Chrome/Firefox/curl, then load the keylog below. Switch any TLS packet in Packet Details to <strong>Wireshark</strong> mode to view decrypted HTTP/1.1 &amp; HTTP/2 plaintext!
            </p>

            <div className="space-y-2">
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-300 block">
                Local Keylog File Path
              </label>
              <input
                value={keylogPath}
                onChange={(e) => setKeylogPath(e.target.value)}
                placeholder="/path/to/sslkeylog.txt or C:\Users\...\sslkeylog.txt"
                className="w-full h-8 px-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-xs font-mono-code text-slate-800 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-2">
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-300 block">
                Or Paste CLIENT_HANDSHAKE_TRAFFIC_SECRET Lines Directly
              </label>
              <textarea
                rows={4}
                value={keylogContent}
                onChange={(e) => setKeylogContent(e.target.value)}
                placeholder="CLIENT_RANDOM <32-byte-hex> <48-byte-master-secret>..."
                className="w-full p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-[11px] font-mono-code text-slate-800 dark:text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center justify-between gap-2">
              <div className="text-xs text-emerald-600 dark:text-emerald-400 truncate">{keylogMsg}</div>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setKeylogPath('')
                    setKeylogContent('')
                    api.setKeylog({ path: null }).then(() => {
                      setKeylogMsg('Cleared.')
                      onStatusRefresh()
                    })
                  }}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-300 cursor-pointer"
                >
                  Clear
                </button>
                <button
                  onClick={applyKeylog}
                  className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold cursor-pointer"
                >
                  Apply Keylog to sharkd
                </button>
              </div>
            </div>
          </div>

          {/* Wireshark Coloring Rules Reference */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Palette className="w-4 h-4 text-cyan-500" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                Wireshark-Compatible Coloring Rules
              </h3>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Click any rule to immediately filter matching packets in the 3-Pane Packet Browser.
            </p>
            <div className="space-y-1.5 max-h-[260px] overflow-y-auto pr-1">
              {COLORING_RULES_REFERENCE.map((rule) => (
                <div
                  key={rule.name}
                  onClick={() => onApplyFilter(rule.filter)}
                  className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-slate-100 dark:border-slate-800 hover:border-cyan-500/50 bg-slate-50/70 dark:bg-[#0b101b] cursor-pointer transition-colors"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: rule.color }} />
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-slate-800 dark:text-slate-100 truncate">
                        {rule.name}
                      </div>
                      <div className="text-[10.5px] text-slate-500 truncate">{rule.desc}</div>
                    </div>
                  </div>
                  <code className="text-[10.5px] font-mono-code px-2 py-0.5 rounded bg-slate-200/70 dark:bg-slate-800 text-cyan-700 dark:text-cyan-300 shrink-0">
                    {rule.filter}
                  </code>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Custom Wireshark Lua Dissector Plugin Generator */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f1520] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Code2 className="w-4 h-4 text-violet-500" />
                Wireshark Custom Lua Dissector Plugin Generator
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Visually define any custom binary application protocol and export a ready-to-load upstream Wireshark <code className="font-mono-code">.lua</code> dissector plugin.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  navigator.clipboard?.writeText(luaCode)
                  setCopiedLua(true)
                  setTimeout(() => setCopiedLua(false), 1500)
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:border-cyan-500 cursor-pointer"
              >
                {copiedLua ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy Lua</span>
              </button>
              <button
                onClick={downloadLua}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .lua Plugin</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Form Builder */}
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-semibold text-slate-500 block mb-1">Protocol ID</label>
                  <input
                    value={protoName}
                    onChange={(e) => setProtoName(e.target.value)}
                    className="w-full h-8 px-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-xs font-mono-code text-slate-800 dark:text-slate-100"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold text-slate-500 block mb-1">Magic Bytes (Hex)</label>
                  <input
                    value={magicHex}
                    onChange={(e) => setMagicHex(e.target.value)}
                    placeholder="e.g. 55434153"
                    className="w-full h-8 px-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-xs font-mono-code text-slate-800 dark:text-slate-100"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="text-[11px] font-semibold text-slate-500 block mb-1">Description</label>
                  <input
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="w-full h-8 px-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-xs text-slate-800 dark:text-slate-100"
                  />
                </div>
                <div className="grid grid-cols-2 gap-1.5">
                  <div>
                    <label className="text-[11px] font-semibold text-slate-500 block mb-1">L4</label>
                    <select
                      value={transport}
                      onChange={(e) => setTransport(e.target.value as 'tcp' | 'udp')}
                      className="w-full h-8 px-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-xs font-mono-code text-slate-800 dark:text-slate-100"
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[11px] font-semibold text-slate-500 block mb-1">Port</label>
                    <input
                      type="number"
                      value={port}
                      onChange={(e) => setPort(Number(e.target.value))}
                      className="w-full h-8 px-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-xs font-mono-code text-slate-800 dark:text-slate-100"
                    />
                  </div>
                </div>
              </div>

              {/* Header Fields */}
              <div className="space-y-2 pt-1">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-500">Header Fields</span>
                  <button
                    onClick={() =>
                      setFields((prev) => [
                        ...prev,
                        { name: `field_${prev.length + 1}`, label: `Field ${prev.length + 1}`, type: 'uint16', length: 2 },
                      ])
                    }
                    className="flex items-center gap-1 text-[11px] text-cyan-600 dark:text-cyan-400 font-semibold cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" /> Add Field
                  </button>
                </div>

                {fields.map((f, idx) => (
                  <div key={idx} className="grid grid-cols-[1fr_1.2fr_92px_54px_28px] gap-1.5 items-center">
                    <input
                      value={f.name}
                      onChange={(e) =>
                        setFields((prev) => prev.map((x, i) => (i === idx ? { ...x, name: e.target.value } : x)))
                      }
                      placeholder="key"
                      className="h-7 px-2 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-[11px] font-mono-code text-slate-800 dark:text-slate-100"
                    />
                    <input
                      value={f.label}
                      onChange={(e) =>
                        setFields((prev) => prev.map((x, i) => (i === idx ? { ...x, label: e.target.value } : x)))
                      }
                      placeholder="Label"
                      className="h-7 px-2 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-[11px] text-slate-800 dark:text-slate-100"
                    />
                    <select
                      value={f.type}
                      onChange={(e) => {
                        const t = e.target.value as LuaFieldDraft['type']
                        const autoLen = t === 'uint8' ? 1 : t === 'uint16' ? 2 : t === 'uint32' ? 4 : f.length
                        setFields((prev) => prev.map((x, i) => (i === idx ? { ...x, type: t, length: autoLen } : x)))
                      }}
                      className="h-7 px-1 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-[11px] font-mono-code text-slate-800 dark:text-slate-100"
                    >
                      <option value="uint8">uint8</option>
                      <option value="uint16">uint16</option>
                      <option value="uint32">uint32</option>
                      <option value="string">string</option>
                      <option value="bytes">bytes</option>
                    </select>
                    <input
                      type="number"
                      min={1}
                      value={f.length}
                      onChange={(e) =>
                        setFields((prev) =>
                          prev.map((x, i) => (i === idx ? { ...x, length: Number(e.target.value) } : x)),
                        )
                      }
                      className="h-7 px-1.5 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#090d14] text-[11px] font-mono-code text-slate-800 dark:text-slate-100"
                    />
                    <button
                      onClick={() => setFields((prev) => prev.filter((_, i) => i !== idx))}
                      className="p-1 text-slate-400 hover:text-rose-500 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Generated Lua Preview */}
            <pre className="p-3.5 rounded-xl bg-[#090d14] border border-slate-800 text-cyan-200 text-[11px] font-mono-code overflow-auto max-h-[340px] leading-relaxed">
              {luaCode || '-- Generating Lua dissector...'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}
