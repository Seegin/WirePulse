#!/usr/bin/env python3
"""
Build publication-grade PDF (via WeasyPrint) and editable DOCX (via python-docx)
for the WirePulse UCAS Software & System Security Experiment 1A Report.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from docx import Document
from docx.shared import Inches, Pt, RGBColor
from weasyprint import HTML

DOCS_DIR = Path(__file__).resolve().parent
REPORT_MD = DOCS_DIR / "report.md"
IMG_3PANE = DOCS_DIR / "assets" / "wirepulse_3pane.png"
OUT_PDF = DOCS_DIR / "WirePulse_实验1A报告.pdf"
OUT_DOCX = DOCS_DIR / "WirePulse_实验1A报告.docx"

ARCH_SVG = """
<svg viewBox="0 0 760 275" width="100%" xmlns="http://www.w3.org/2000/svg" style="font-family: 'Noto Sans CJK SC', sans-serif;">
  <defs>
    <marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569"/>
    </marker>
  </defs>
  <!-- Layer 3: GUI -->
  <rect x="18" y="10" width="724" height="64" rx="10" fill="#ecfeff" stroke="#0891b2" stroke-width="1.5"/>
  <text x="34" y="30" font-size="12" font-weight="700" fill="#0e7490">表现层：WirePulse 现代化桌面级 GUI（React 18 + TypeScript + Tailwind + 虚拟滚动）</text>
  <rect x="34" y="39" width="110" height="25" rx="5" fill="#ffffff" stroke="#06b6d4"/>
  <text x="89" y="55" text-anchor="middle" font-size="10" fill="#0f172a">网卡 Sparkline</text>
  <rect x="154" y="39" width="128" height="25" rx="5" fill="#ffffff" stroke="#06b6d4"/>
  <text x="218" y="55" text-anchor="middle" font-size="10" fill="#0f172a">三栏检视 &amp; 双向高亮</text>
  <rect x="292" y="39" width="116" height="25" rx="5" fill="#ffffff" stroke="#06b6d4"/>
  <text x="350" y="55" text-anchor="middle" font-size="10" fill="#0f172a">流重组 &amp; SVG时序</text>
  <rect x="418" y="39" width="98" height="25" rx="5" fill="#ffffff" stroke="#06b6d4"/>
  <text x="467" y="55" text-anchor="middle" font-size="10" fill="#0f172a">OS 进程追踪</text>
  <rect x="526" y="39" width="102" height="25" rx="5" fill="#ffffff" stroke="#e11d48"/>
  <text x="577" y="55" text-anchor="middle" font-size="10" fill="#9f1239">安全 IDS 雷达</text>
  <rect x="638" y="39" width="92" height="25" rx="5" fill="#ffffff" stroke="#7c3aed"/>
  <text x="684" y="55" text-anchor="middle" font-size="10" fill="#5b21b6">WS 增量实验室</text>

  <!-- Arrows -->
  <line x1="250" y1="74" x2="250" y2="96" stroke="#475569" stroke-width="1.4" marker-end="url(#ar)" marker-start="url(#ar)"/>
  <text x="260" y="89" font-size="9.5" fill="#475569">REST API + WebSocket (80ms 批合并实时推流)</text>

  <!-- Layer 2: Analysis Engine -->
  <rect x="18" y="100" width="724" height="74" rx="10" fill="#f5f3ff" stroke="#7c3aed" stroke-width="1.5"/>
  <text x="34" y="120" font-size="12" font-weight="700" fill="#5b21b6">核心分析引擎层：Python aiohttp 异步分析中枢</text>
  <rect x="34" y="130" width="132" height="32" rx="5" fill="#ffffff" stroke="#8b5cf6"/>
  <text x="100" y="144" text-anchor="middle" font-size="10" font-weight="600" fill="#0f172a">OSI L1-L7 解剖器</text>
  <text x="100" y="157" text-anchor="middle" font-size="8.5" fill="#64748b">DPI / DNS / TLS JA3</text>

  <rect x="176" y="130" width="128" height="32" rx="5" fill="#ffffff" stroke="#8b5cf6"/>
  <text x="240" y="144" text-anchor="middle" font-size="10" font-weight="600" fill="#0f172a">显示过滤 AST 引擎</text>
  <text x="240" y="157" text-anchor="middle" font-size="8.5" fill="#64748b">词法 + 递归下降求值</text>

  <rect x="314" y="130" width="130" height="32" rx="5" fill="#ffffff" stroke="#8b5cf6"/>
  <text x="379" y="144" text-anchor="middle" font-size="10" font-weight="600" fill="#0f172a">流重组 &amp; 进程归因</text>
  <text x="379" y="157" text-anchor="middle" font-size="8.5" fill="#64748b">TCP重传去重 / /proc</text>

  <rect x="454" y="130" width="130" height="32" rx="5" fill="#ffffff" stroke="#e11d48"/>
  <text x="519" y="144" text-anchor="middle" font-size="10" font-weight="600" fill="#9f1239">有状态安全 IDS</text>
  <text x="519" y="157" text-anchor="middle" font-size="8.5" fill="#64748b">13 条攻击与泄露规则</text>

  <rect x="594" y="130" width="136" height="32" rx="5" fill="#ffffff" stroke="#7c3aed"/>
  <text x="662" y="144" text-anchor="middle" font-size="10" font-weight="600" fill="#5b21b6">Wireshark 增量桥接</text>
  <text x="662" y="157" text-anchor="middle" font-size="8.5" fill="#64748b">sharkd / Keylog / Lua</text>

  <!-- Arrows -->
  <line x1="200" y1="174" x2="200" y2="198" stroke="#475569" stroke-width="1.4" marker-start="url(#ar)"/>
  <line x1="560" y1="174" x2="560" y2="198" stroke="#475569" stroke-width="1.4" marker-start="url(#ar)"/>
  <text x="210" y="191" font-size="9.5" fill="#475569">ctypes FFI</text>
  <text x="570" y="191" font-size="9.5" fill="#475569">PCAP流 / JSON-RPC</text>

  <!-- Layer 1: Native Capture & Kernel -->
  <rect x="18" y="202" width="354" height="62" rx="10" fill="#ecfdf5" stroke="#059669" stroke-width="1.5"/>
  <text x="34" y="223" font-size="11.5" font-weight="700" fill="#065f46">原生 C11 捕获引擎（libwirepulse_pcap）</text>
  <text x="34" y="241" font-size="9.5" fill="#334155">Linux libpcap (AF_PACKET TPACKET_V3) · Windows Npcap wpcap.dll</text>
  <text x="34" y="255" font-size="9.5" fill="#334155">内核态 BPF 过滤 (pcap_compile) · 配套 eBPF/XDP 驱动层探针</text>

  <rect x="388" y="202" width="354" height="62" rx="10" fill="#fffbeb" stroke="#d97706" stroke-width="1.5"/>
  <text x="404" y="223" font-size="11.5" font-weight="700" fill="#92400e">Wireshark 4.x 生态协同层</text>
  <text x="404" y="241" font-size="9.5" fill="#334155">dumpcap 权限分离实时捕获桥 · sharkd libwireshark 3000+ 协议</text>
  <text x="404" y="255" font-size="9.5" fill="#334155">标准 PCAP/PCAPNG 互通 · SSLKEYLOGFILE 解密 · Lua 插件导出</text>
</svg>
"""


def md_inline_to_html(text: str) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Protect inline code spans first so *, _, | inside backticks never interfere with bold/italic
    code_spans = []

    def _stash_code(m: re.Match) -> str:
        code_spans.append(f"<code>{m.group(1)}</code>")
        return f"\x00CODE{len(code_spans) - 1}\x00"

    text = re.sub(r"`([^`]+)`", _stash_code, text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", text)
    for i, span in enumerate(code_spans):
        text = text.replace(f"\x00CODE{i}\x00", span)
    return text


def _split_md_table_row(row: str) -> list[str]:
    """Split a markdown table row on unescaped '|' outside backtick code spans."""
    inner = row.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    cells = []
    buf = []
    in_code = False
    for ch in inner:
        if ch == "`":
            in_code = not in_code
            buf.append(ch)
        elif ch == "|" and not in_code:
            cells.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    cells.append("".join(buf).strip())
    return cells


def build_html(md_text: str) -> str:
    lines = md_text.splitlines()
    html_parts = []
    in_code = False
    code_buf = []
    in_ul = False
    in_ol = False
    in_table = False
    table_rows = []
    inserted_arch = False

    def flush_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            html_parts.append("</ul>")
            in_ul = False
        if in_ol:
            html_parts.append("</ol>")
            in_ol = False

    def flush_table():
        nonlocal in_table, table_rows
        if not in_table:
            return
        html_parts.append("<table>")
        for idx, row in enumerate(table_rows):
            cells = _split_md_table_row(row)
            if idx == 1 and all(set(c) <= set("-: ") for c in cells):
                continue
            tag = "th" if idx == 0 else "td"
            html_parts.append("<tr>" + "".join(f"<{tag}>{md_inline_to_html(c)}</{tag}>" for c in cells) + "</tr>")
        html_parts.append("</table>")
        table_rows = []
        in_table = False

    for line in lines:
        if line.strip().startswith("```"):
            flush_lists()
            flush_table()
            if in_code:
                code_html = "\n".join(code_buf).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html_parts.append(f"<pre><code>{code_html}</code></pre>")
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue

        stripped = line.strip()
        if not stripped:
            flush_lists()
            flush_table()
            continue

        if stripped == "---":
            flush_lists()
            flush_table()
            html_parts.append("<hr/>")
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            flush_lists()
            in_table = True
            table_rows.append(stripped)
            continue
        else:
            flush_table()

        img_m = re.match(r"^!\[([^\]]*)\]\(([^)]+)\)$", stripped)
        if img_m:
            flush_lists()
            alt, rel = img_m.group(1), img_m.group(2)
            abs_img = (DOCS_DIR / rel).resolve()
            if not inserted_arch:
                html_parts.append(f'<figure class="fig">{ARCH_SVG}<figcaption>图 1：WirePulse 三层混合架构与 Wireshark 增量协同数据流图</figcaption></figure>')
                inserted_arch = True
                fig_num = 2
            else:
                fig_num = 3
            html_parts.append(
                f'<figure class="fig"><img src="file://{abs_img}" alt="{alt}"/><figcaption>图 {fig_num}：{alt}</figcaption></figure>'
            )
            continue

        if stripped.startswith("# "):
            flush_lists()
            html_parts.append(f'<div class="title-banner"><h1>{md_inline_to_html(stripped[2:])}</h1><div class="subtitle">中国科学院大学 · UCAS · Software and System Security (2026)</div></div>')
        elif stripped.startswith("## "):
            flush_lists()
            html_parts.append(f"<h2>{md_inline_to_html(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            flush_lists()
            html_parts.append(f"<h3>{md_inline_to_html(stripped[4:])}</h3>")
        elif stripped.startswith("> "):
            flush_lists()
            html_parts.append(f"<blockquote>{md_inline_to_html(stripped[2:])}</blockquote>")
        elif stripped.startswith("- "):
            if in_ol:
                html_parts.append("</ol>")
                in_ol = False
            if not in_ul:
                html_parts.append("<ul>")
                in_ul = True
            html_parts.append(f"<li>{md_inline_to_html(stripped[2:])}</li>")
        elif re.match(r"^\d+\.\s+", stripped):
            flush_lists()
            num_m = re.match(r"^(\d+)\.\s+(.*)$", stripped)
            assert num_m is not None
            num_val = num_m.group(1)
            item_txt = num_m.group(2)
            html_parts.append(f'<p class="num-item"><strong>{num_val}.</strong> {md_inline_to_html(item_txt)}</p>')
        else:
            flush_lists()
            html_parts.append(f"<p>{md_inline_to_html(stripped)}</p>")

    flush_lists()
    flush_table()

    body = "\n".join(html_parts)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<style>
  @page {{
    size: A4;
    margin: 18mm 16mm 18mm 16mm;
    @bottom-center {{
      content: "WirePulse — 《软件与系统安全》实验 1A 报告  ·  第 " counter(page) " / " counter(pages) " 页";
      font-family: "Noto Sans CJK SC", sans-serif;
      font-size: 8.5pt;
      color: #64748b;
    }}
  }}
  body {{
    font-family: "Noto Sans CJK SC", "Microsoft YaHei", sans-serif;
    font-size: 9.8pt;
    line-height: 1.62;
    color: #1e293b;
  }}
  .title-banner {{
    background: linear-gradient(135deg, #581c87 0%, #3b0764 55%, #0e7490 100%);
    color: #ffffff;
    padding: 18px 22px;
    border-radius: 10px;
    margin-bottom: 14px;
  }}
  .title-banner h1 {{
    margin: 0;
    font-size: 18pt;
    letter-spacing: 0.5px;
    border: none;
    color: #ffffff;
  }}
  .title-banner .subtitle {{
    margin-top: 5px;
    font-size: 9.5pt;
    color: #e0f2fe;
  }}
  h2 {{
    font-size: 13pt;
    color: #581c87;
    border-bottom: 1.8px solid #e2e8f0;
    padding-bottom: 4px;
    margin-top: 18px;
    margin-bottom: 8px;
    page-break-after: avoid;
  }}
  h3 {{
    font-size: 10.8pt;
    color: #0e7490;
    margin-top: 12px;
    margin-bottom: 5px;
    page-break-after: avoid;
  }}
  p {{ margin: 5px 0 7px 0; text-align: justify; }}
  p.num-item {{ margin: 6px 0 4px 0; padding-left: 16px; text-indent: -16px; }}
  ul, ol {{ margin: 4px 0 8px 0; padding-left: 20px; }}
  li {{ margin-bottom: 3.5px; }}
  code {{
    font-family: "Noto Sans Mono CJK SC", monospace;
    font-size: 8.6pt;
    background: #f1f5f9;
    color: #0f172a;
    padding: 1px 4px;
    border-radius: 3px;
  }}
  pre {{
    background: #0f172a;
    color: #e2e8f0;
    padding: 10px 12px;
    border-radius: 7px;
    overflow-x: auto;
    font-size: 8.4pt;
    line-height: 1.48;
    page-break-inside: avoid;
  }}
  pre code {{
    background: transparent;
    color: #e2e8f0;
    padding: 0;
  }}
  blockquote {{
    margin: 8px 0;
    padding: 8px 12px;
    border-left: 3.5px solid #7c3aed;
    background: #f5f3ff;
    color: #3b0764;
    border-radius: 0 6px 6px 0;
    font-size: 9.3pt;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0 12px 0;
    font-size: 8.6pt;
    page-break-inside: avoid;
  }}
  th {{
    background: #f1f5f9;
    color: #0f172a;
    font-weight: 700;
    text-align: left;
    padding: 6px 8px;
    border: 1px solid #cbd5e1;
  }}
  td {{
    padding: 5.5px 8px;
    border: 1px solid #cbd5e1;
    vertical-align: top;
  }}
  tr:nth-child(even) td {{ background: #fafafa; }}
  hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 12px 0; }}
  .fig {{
    margin: 12px 0;
    text-align: center;
    page-break-inside: avoid;
  }}
  .fig img {{
    width: 100%;
    border-radius: 8px;
    border: 1px solid #cbd5e1;
    box-shadow: 0 3px 10px rgba(15, 23, 42, 0.12);
  }}
  figcaption {{
    margin-top: 5px;
    font-size: 8.5pt;
    color: #475569;
  }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def build_docx(md_text: str) -> None:
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Microsoft YaHei"
    style.font.size = Pt(10.5)

    lines = md_text.splitlines()
    in_code = False
    code_buf = []
    table_buf = []

    def flush_table():
        nonlocal table_buf
        if not table_buf:
            return
        parsed = []
        for idx, r in enumerate(table_buf):
            cells = [re.sub(r"[`*]", "", c) for c in _split_md_table_row(r)]
            if idx == 1 and all(set(c) <= set("-: ") for c in cells):
                continue
            parsed.append(cells)
        if parsed:
            t = doc.add_table(rows=len(parsed), cols=len(parsed[0]))
            t.style = "Light Grid Accent 1"
            for r_i, row in enumerate(parsed):
                for c_i, val in enumerate(row[: len(parsed[0])]):
                    t.cell(r_i, c_i).text = val
        table_buf = []

    for line in lines:
        if line.strip().startswith("```"):
            flush_table()
            if in_code:
                p = doc.add_paragraph("\n".join(code_buf))
                for run in p.runs:
                    run.font.name = "Consolas"
                    run.font.size = Pt(8.5)
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        st = line.strip()
        if not st or st == "---":
            flush_table()
            continue
        if st.startswith("|") and st.endswith("|"):
            table_buf.append(st)
            continue
        flush_table()

        img_m = re.match(r"^!\[([^\]]*)\]\(([^)]+)\)$", st)
        if img_m:
            abs_img = (DOCS_DIR / img_m.group(2)).resolve()
            if abs_img.is_file():
                doc.add_picture(str(abs_img), width=Inches(6.2))
                cap = doc.add_paragraph(f"图：{img_m.group(1)}")
                cap.runs[0].font.size = Pt(9)
                cap.runs[0].font.color.rgb = RGBColor(0x47, 0x55, 0x69)
            continue

        clean = re.sub(r"\*\*([^*]+)\*\*", r"\1", st)
        clean = re.sub(r"`([^`]+)`", r"\1", clean)
        if st.startswith("# "):
            doc.add_heading(clean[2:], level=0)
        elif st.startswith("## "):
            doc.add_heading(clean[3:], level=1)
        elif st.startswith("### "):
            doc.add_heading(clean[4:], level=2)
        elif st.startswith("- "):
            doc.add_paragraph(clean[2:], style="List Bullet")
        elif re.match(r"^\d+\.\s+", st):
            doc.add_paragraph(re.sub(r"^\d+\.\s+", "", clean), style="List Number")
        else:
            doc.add_paragraph(clean)

    flush_table()
    doc.save(str(OUT_DOCX))


def main() -> None:
    md_text = REPORT_MD.read_text(encoding="utf-8")
    html_str = build_html(md_text)
    HTML(string=html_str, base_url=str(DOCS_DIR)).write_pdf(str(OUT_PDF))
    build_docx(md_text)
    print(f"[OK] Built PDF : {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")
    print(f"[OK] Built DOCX: {OUT_DOCX} ({OUT_DOCX.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
