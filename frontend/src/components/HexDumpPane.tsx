import React, { useMemo, useState } from 'react'
import { Binary, Check, Code2, Copy } from 'lucide-react'
import type { HighlightRange } from '../types'

interface Props {
  rawHex: string
  highlight: HighlightRange | null
  selectedByteOffset: number | null
  onSelectByte: (offset: number) => void
}

export const HexDumpPane: React.FC<Props> = ({
  rawHex,
  highlight,
  selectedByteOffset,
  onSelectByte,
}) => {
  const [mode, setMode] = useState<'hex' | 'bin'>('hex')
  const [copied, setCopied] = useState<string | null>(null)

  const bytes = useMemo(() => {
    if (!rawHex) return new Uint8Array(0)
    const len = Math.floor(rawHex.length / 2)
    const arr = new Uint8Array(len)
    for (let i = 0; i < len; i++) {
      arr[i] = parseInt(rawHex.slice(i * 2, i * 2 + 2), 16)
    }
    return arr
  }, [rawHex])

  const bytesPerRow = mode === 'hex' ? 16 : 8
  const rows = useMemo(() => {
    const out: number[] = []
    for (let off = 0; off < bytes.length; off += bytesPerRow) {
      out.push(off)
    }
    return out
  }, [bytes.length, bytesPerRow])

  const isHighlighted = (idx: number) => {
    if (!highlight || highlight.length <= 0) return false
    return idx >= highlight.offset && idx < highlight.offset + highlight.length
  }

  const doCopy = (kind: 'hex' | 'ascii' | 'c') => {
    let text = ''
    if (kind === 'hex') {
      text = rawHex.match(/.{1,2}/g)?.join(' ') || ''
    } else if (kind === 'ascii') {
      text = Array.from(bytes)
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('')
    } else {
      const items = Array.from(bytes).map((b) => `0x${b.toString(16).padStart(2, '0')}`)
      text = `const uint8_t packet[${bytes.length}] = {\n  ${items.join(', ')}\n};`
    }
    navigator.clipboard?.writeText(text)
    setCopied(kind)
    setTimeout(() => setCopied(null), 1500)
  }

  const selByte = selectedByteOffset !== null && selectedByteOffset < bytes.length ? bytes[selectedByteOffset] : null

  return (
    <div className="flex flex-col h-full bg-white dark:bg-[#0b101b] overflow-hidden select-none">
      {/* Header */}
      <div className="flex items-center justify-between px-3 h-8 border-b border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#0f1520] text-[11px] shrink-0 gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Binary className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
          <span className="font-semibold text-slate-700 dark:text-slate-200 shrink-0">Packet Bytes</span>
          <span className="font-mono-code text-slate-400 shrink-0">{bytes.length} bytes</span>
          {highlight && highlight.length > 0 && (
            <span className="hidden md:inline-block px-1.5 py-0 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 font-mono-code text-[10px] truncate">
              Selected: 0x{highlight.offset.toString(16).padStart(4, '0')} ({highlight.length}B)
            </span>
          )}
          {selByte !== null && selectedByteOffset !== null && (
            <span className="hidden lg:inline-block font-mono-code text-[10px] text-slate-500 dark:text-slate-400">
              Byte[{selectedByteOffset}] = 0x{selByte.toString(16).padStart(2, '0')} ({selByte}) 0b
              {selByte.toString(2).padStart(8, '0')}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <div className="flex items-center rounded border border-slate-200 dark:border-slate-700/80 bg-slate-100 dark:bg-slate-900 p-0.5">
            <button
              onClick={() => setMode('hex')}
              className={`px-1.5 py-0.5 rounded text-[10px] font-semibold cursor-pointer ${
                mode === 'hex'
                  ? 'bg-white dark:bg-cyan-600 text-cyan-700 dark:text-white'
                  : 'text-slate-500'
              }`}
            >
              Hex + ASCII
            </button>
            <button
              onClick={() => setMode('bin')}
              className={`px-1.5 py-0.5 rounded text-[10px] font-semibold cursor-pointer ${
                mode === 'bin'
                  ? 'bg-white dark:bg-cyan-600 text-cyan-700 dark:text-white'
                  : 'text-slate-500'
              }`}
            >
              Binary
            </button>
          </div>

          <button
            onClick={() => doCopy('hex')}
            disabled={bytes.length === 0}
            className="flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 disabled:opacity-30 cursor-pointer"
            title="Copy raw Hex"
          >
            {copied === 'hex' ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
            <span>Hex</span>
          </button>
          <button
            onClick={() => doCopy('c')}
            disabled={bytes.length === 0}
            className="flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 disabled:opacity-30 cursor-pointer"
            title="Copy as C uint8_t array"
          >
            {copied === 'c' ? <Check className="w-3 h-3 text-emerald-500" /> : <Code2 className="w-3 h-3" />}
            <span>C Array</span>
          </button>
        </div>
      </div>

      {/* Byte Matrix */}
      <div className="flex-1 overflow-auto p-2.5 font-mono-code text-[11.5px] leading-[1.65]">
        {bytes.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-400">
            No packet selected
          </div>
        ) : (
          <div className="min-w-max space-y-0.5">
            {rows.map((rowOff) => {
              const sliceEnd = Math.min(rowOff + bytesPerRow, bytes.length)
              return (
                <div key={rowOff} className="flex items-center gap-3">
                  {/* Offset column */}
                  <span className="text-slate-400 dark:text-slate-500 w-11 shrink-0 select-none">
                    {rowOff.toString(16).padStart(4, '0')}
                  </span>

                  {/* Hex or Binary bytes */}
                  <div className="flex items-center gap-1">
                    {Array.from({ length: bytesPerRow }).map((_, col) => {
                      const idx = rowOff + col
                      const gap = mode === 'hex' && col === 8 ? 'ml-2' : ''
                      if (idx >= sliceEnd) {
                        return (
                          <span key={col} className={`${gap} ${mode === 'hex' ? 'w-5' : 'w-16'} inline-block`} />
                        )
                      }
                      const b = bytes[idx]
                      const hi = isHighlighted(idx)
                      const exact = selectedByteOffset === idx
                      return (
                        <span
                          key={col}
                          onClick={() => onSelectByte(idx)}
                          className={`${gap} px-0.5 rounded cursor-pointer transition-colors ${
                            exact
                              ? 'bg-cyan-500 text-white font-bold ring-1 ring-cyan-300'
                              : hi
                                ? 'bg-cyan-500/25 text-cyan-800 dark:text-cyan-200 font-semibold'
                                : 'text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800'
                          }`}
                        >
                          {mode === 'hex'
                            ? b.toString(16).padStart(2, '0')
                            : b.toString(2).padStart(8, '0')}
                        </span>
                      )
                    })}
                  </div>

                  {/* ASCII column */}
                  <div className="flex items-center pl-2 border-l border-slate-200 dark:border-slate-800">
                    {Array.from({ length: sliceEnd - rowOff }).map((_, col) => {
                      const idx = rowOff + col
                      const b = bytes[idx]
                      const ch = b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'
                      const hi = isHighlighted(idx)
                      const exact = selectedByteOffset === idx
                      return (
                        <span
                          key={col}
                          onClick={() => onSelectByte(idx)}
                          className={`w-[8.5px] text-center cursor-pointer rounded-xs ${
                            exact
                              ? 'bg-cyan-500 text-white font-bold'
                              : hi
                                ? 'bg-cyan-500/25 text-cyan-700 dark:text-cyan-200 font-semibold'
                                : b >= 32 && b <= 126
                                  ? 'text-emerald-700 dark:text-emerald-400/90'
                                  : 'text-slate-400 dark:text-slate-600'
                          }`}
                        >
                          {ch}
                        </span>
                      )
                    })}
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
