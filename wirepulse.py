#!/usr/bin/env python3
"""
WirePulse — Next-Gen Network Packet Sniffer & Security Protocol Analyzer
Single-command cross-platform launcher (Linux / Windows / macOS).

Usage:
  python3 wirepulse.py                  # Start server & launch GUI app window
  python3 wirepulse.py --port 8765      # Custom port
  python3 wirepulse.py --no-browser     # Headless / server-only mode
  python3 wirepulse.py --demo           # Pre-load interactive security demo dataset
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import webbrowser

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from aiohttp import web
from backend.demo_generator import ensure_sample_pcap
from backend.server import WirePulseServer


def _open_desktop_app_window(url: str) -> None:
    """Try launching in chromeless Desktop App Window mode (Edge/Chrome --app), fallback to browser."""
    time.sleep(0.8)
    sys_name = platform.system()
    candidates = []
    if sys_name == "Windows":
        candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ]
    elif sys_name == "Darwin":
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
    else:
        for b in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge"):
            p = shutil.which(b)
            if p:
                candidates.append(p)

    for exe in candidates:
        if os.path.isfile(exe):
            try:
                subprocess.Popen(
                    [exe, f"--app={url}", "--window-size=1480,920"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except Exception:
                pass
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="WirePulse Network Packet Sniffer & Security Protocol Analyzer")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open GUI window")
    parser.add_argument("--demo", action="store_true", help="Preload interactive security demo dataset on startup")
    args = parser.parse_args()

    # Ensure sample PCAP exists in samples/
    sample_path = os.path.join(PROJECT_ROOT, "samples", "wirepulse_security_lab.pcap")
    if not os.path.isfile(sample_path):
        try:
            ensure_sample_pcap(sample_path)
        except Exception:
            pass

    srv = WirePulseServer(PROJECT_ROOT)
    if args.demo:
        srv.manager.load_demo_capture(realtime=False)

    url = f"http://{args.host}:{args.port}"
    print("=" * 68)
    print("  WirePulse — Next-Gen Network Sniffer & Security Protocol Analyzer")
    print("=" * 68)
    print(f"  GUI URL        : {url}")
    print(f"  Native Capture : {srv.manager.native.version} ({'READY' if srv.manager.native.available else 'fallback'})")
    print(f"  Wireshark Core : {srv.manager.wireshark.env.version or 'Not installed (Native Dissector active)'}")
    print("=" * 68)

    if not args.no_browser:
        threading.Thread(target=_open_desktop_app_window, args=(url,), daemon=True).start()

    app = srv.create_app()
    web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
