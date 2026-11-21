"""
WirePulse Async HTTP + WebSocket Server (aiohttp).

Serves the REST API, real-time WebSocket packet/alert stream, and compiled React SPA.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from typing import Any, Dict, Set

from aiohttp import WSMsgType, web

from .capture_manager import CaptureManager
from .filter_engine import FILTER_FIELD_CATALOG, validate_filter


class WirePulseServer:
    def __init__(self, project_root: str) -> None:
        self.project_root = project_root
        self.dist_dir = os.path.join(project_root, "frontend", "dist")
        self.manager = CaptureManager(project_root)
        self.ws_clients: Set[web.WebSocketResponse] = set()
        self._flush_task: asyncio.Task | None = None

    def create_app(self) -> web.Application:
        app = web.Application(client_max_size=128 * 1024 * 1024)
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)

        # CORS middleware for dev server (Vite on :5173 -> backend on :8765)
        @web.middleware
        async def cors_mw(request: web.Request, handler: Any) -> web.StreamResponse:
            if request.method == "OPTIONS":
                resp = web.Response(status=204)
            else:
                resp = await handler(request)
            resp.headers["Access-Control-Allow-Origin"] = "*"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Filename"
            return resp

        app.middlewares.append(cors_mw)

        # API routes
        app.router.add_get("/api/interfaces", self.api_interfaces)
        app.router.add_get("/api/status", self.api_status)
        app.router.add_post("/api/capture/start", self.api_capture_start)
        app.router.add_post("/api/capture/stop", self.api_capture_stop)
        app.router.add_post("/api/capture/pause", self.api_capture_pause)
        app.router.add_post("/api/capture/clear", self.api_capture_clear)
        app.router.add_post("/api/capture/demo", self.api_capture_demo)
        app.router.add_post("/api/capture/import", self.api_capture_import)
        app.router.add_get("/api/capture/export", self.api_capture_export)
        app.router.add_post("/api/bpf/validate", self.api_bpf_validate)
        app.router.add_post("/api/filter/validate", self.api_filter_validate)
        app.router.add_get("/api/filter/fields", self.api_filter_fields)
        app.router.add_get("/api/packets", self.api_packets)
        app.router.add_get("/api/packets/{no}", self.api_packet_detail)
        app.router.add_get("/api/packets/{no}/wireshark", self.api_packet_wireshark)
        app.router.add_get("/api/streams", self.api_streams)
        app.router.add_get("/api/streams/{proto}/{sid}", self.api_stream_follow)
        app.router.add_get("/api/processes", self.api_processes)
        app.router.add_get("/api/alerts", self.api_alerts)
        app.router.add_get("/api/analytics", self.api_analytics)
        app.router.add_post("/api/wireshark/keylog", self.api_wireshark_keylog)
        app.router.add_post("/api/wireshark/lua-generate", self.api_wireshark_lua)
        app.router.add_get("/ws", self.ws_handler)

        # Static Frontend SPA hosting
        assets_dir = os.path.join(self.dist_dir, "assets")
        if os.path.isdir(assets_dir):
            app.router.add_static("/assets", assets_dir, show_index=False)
        app.router.add_get("/", self.serve_index)
        app.router.add_get("/{tail:.*}", self.serve_spa_fallback)

        return app

    async def _on_startup(self, _app: web.Application) -> None:
        loop = asyncio.get_running_loop()
        self.manager.bind_loop(loop)
        self.manager.add_listener(self._on_manager_event)

        async def _flusher() -> None:
            while True:
                await asyncio.sleep(0.08)
                self.manager.flush_live_batch()

        self._flush_task = asyncio.create_task(_flusher())

    async def _on_cleanup(self, _app: web.Application) -> None:
        self.manager.stop_capture()
        if self._flush_task:
            self._flush_task.cancel()
        for ws in list(self.ws_clients):
            await ws.close()

    def _on_manager_event(self, payload: Dict[str, Any]) -> None:
        if not self.ws_clients:
            return
        text = json.dumps(payload, ensure_ascii=False)
        for ws in list(self.ws_clients):
            if not ws.closed:
                asyncio.create_task(self._safe_ws_send(ws, text))

    async def _safe_ws_send(self, ws: web.WebSocketResponse, text: str) -> None:
        try:
            await ws.send_str(text)
        except Exception:
            self.ws_clients.discard(ws)

    # --- WebSocket ---
    async def ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=20.0)
        await ws.prepare(request)
        self.ws_clients.add(ws)
        try:
            await ws.send_str(json.dumps({"type": "status", "status": self.manager.get_status_snapshot()}))
            async for msg in ws:
                if msg.type == WSMsgType.TEXT and msg.data == "ping":
                    await ws.send_str("pong")
        finally:
            self.ws_clients.discard(ws)
        return ws

    # --- REST Handlers ---
    async def api_interfaces(self, _request: web.Request) -> web.Response:
        data = await asyncio.to_thread(self.manager.list_interfaces)
        return web.json_response(data)

    async def api_status(self, _request: web.Request) -> web.Response:
        return web.json_response(self.manager.get_status_snapshot())

    async def api_capture_start(self, request: web.Request) -> web.Response:
        body = await request.json()
        res = await asyncio.to_thread(
            self.manager.start_capture,
            str(body.get("interfaceId", "")),
            str(body.get("bpfFilter", "")),
            bool(body.get("promisc", True)),
            int(body.get("snaplen", 65535)),
            int(body.get("bufferMb", 16)),
        )
        return web.json_response(res, status=200 if res.get("ok") else 400)

    async def api_capture_stop(self, _request: web.Request) -> web.Response:
        st = await asyncio.to_thread(self.manager.stop_capture)
        return web.json_response({"ok": True, "status": st})

    async def api_capture_pause(self, _request: web.Request) -> web.Response:
        st = self.manager.toggle_pause()
        return web.json_response({"ok": True, "status": st})

    async def api_capture_clear(self, _request: web.Request) -> web.Response:
        self.manager.stop_capture()
        self.manager.reset_session()
        st = self.manager.get_status_snapshot()
        return web.json_response({"ok": True, "status": st})

    async def api_capture_demo(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            body = {}
        realtime = bool(body.get("realtime", False))
        res = await asyncio.to_thread(self.manager.load_demo_capture, realtime)
        return web.json_response(res)

    async def api_capture_import(self, request: web.Request) -> web.Response:
        ctype = request.headers.get("Content-Type", "")
        filename = request.headers.get("X-Filename", "uploaded.pcap")
        if "multipart/form-data" in ctype:
            reader = await request.multipart()
            part = await reader.next()
            if part is None:
                return web.json_response({"ok": False, "error": "No file part uploaded"}, status=400)
            filename = part.filename or filename
            raw = await part.read(decode=False)
        else:
            raw = await request.read()
        res = await asyncio.to_thread(self.manager.import_pcap_bytes, raw, filename)
        return web.json_response(res, status=200 if res.get("ok") else 400)

    async def api_capture_export(self, request: web.Request) -> web.Response:
        flt = request.query.get("filter", "")
        raw = await asyncio.to_thread(self.manager.export_pcap_bytes, flt)
        return web.Response(
            body=raw,
            content_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": 'attachment; filename="wirepulse_capture.pcap"'},
        )

    async def api_bpf_validate(self, request: web.Request) -> web.Response:
        body = await request.json()
        res = self.manager.native.validate_bpf(str(body.get("expr", "")))
        return web.json_response(res)

    async def api_filter_validate(self, request: web.Request) -> web.Response:
        body = await request.json()
        res = validate_filter(str(body.get("expr", "")))
        return web.json_response(res)

    async def api_filter_fields(self, _request: web.Request) -> web.Response:
        return web.json_response({"fields": FILTER_FIELD_CATALOG})

    async def api_packets(self, request: web.Request) -> web.Response:
        flt = request.query.get("filter", "")
        offset = int(request.query.get("offset", "0"))
        limit = min(int(request.query.get("limit", "5000")), 20000)
        res = await asyncio.to_thread(self.manager.query_packets, flt, offset, limit)
        return web.json_response(res, status=200 if res.get("ok") else 400)

    async def api_packet_detail(self, request: web.Request) -> web.Response:
        no = int(request.match_info["no"])
        detail = self.manager.get_packet_detail(no)
        if not detail:
            return web.json_response({"ok": False, "error": "Packet not found"}, status=404)
        return web.json_response({"ok": True, **detail})

    async def api_packet_wireshark(self, request: web.Request) -> web.Response:
        no = int(request.match_info["no"])
        res = await asyncio.to_thread(self.manager.get_packet_wireshark_detail, no)
        return web.json_response(res)

    async def api_streams(self, request: web.Request) -> web.Response:
        proto = request.query.get("proto", "all")
        pid_s = request.query.get("pid", "")
        pid = int(pid_s) if pid_s.isdigit() else None
        proc_name = request.query.get("process", "") or None
        items = self.manager.streams.list_streams(proto=proto, pid=pid, process_name=proc_name)
        return web.json_response({"streams": items})

    async def api_stream_follow(self, request: web.Request) -> web.Response:
        proto = request.match_info["proto"]
        sid = int(request.match_info["sid"])
        data = self.manager.streams.follow_stream(proto, sid)
        if not data:
            return web.json_response({"ok": False, "error": "Stream not found"}, status=404)
        return web.json_response({"ok": True, **data})

    async def api_processes(self, _request: web.Request) -> web.Response:
        return web.json_response({"processes": self.manager.processes.list_processes()})

    async def api_alerts(self, request: web.Request) -> web.Response:
        sev = request.query.get("severity", "").upper()
        alerts = self.manager.security.alerts
        if sev and sev != "ALL":
            alerts = [a for a in alerts if a.severity == sev]
        return web.json_response({
            "counts": self.manager.security.summary_counts(),
            "alerts": [a.to_dict() for a in reversed(alerts)],
        })

    async def api_analytics(self, _request: web.Request) -> web.Response:
        return web.json_response(self.manager.get_analytics())

    async def api_wireshark_keylog(self, request: web.Request) -> web.Response:
        ctype = request.headers.get("Content-Type", "")
        if "application/json" in ctype:
            body = await request.json()
            path = body.get("path")
            content = body.get("content")
            if content is not None:
                tmp_dir = "/mnt/c/Windows/Temp" if (self.manager.wireshark.env.is_wsl_win_exe and os.path.isdir("/mnt/c/Windows/Temp")) else tempfile.gettempdir()
                kl_path = os.path.join(tmp_dir, "wirepulse_sslkeylog.txt")
                with open(kl_path, "w", encoding="utf-8") as f:
                    f.write(str(content))
                return web.json_response(self.manager.wireshark.set_keylog_file(kl_path))
            return web.json_response(self.manager.wireshark.set_keylog_file(path))
        return web.json_response({"ok": False, "error": "Expected JSON body"}, status=400)

    async def api_wireshark_lua(self, request: web.Request) -> web.Response:
        body = await request.json()
        lua = self.manager.wireshark.generate_lua_dissector(
            proto_name=str(body.get("protoName", "ucas_sec")),
            description=str(body.get("description", "UCAS Custom Security Protocol")),
            transport=str(body.get("transport", "tcp")),
            port=int(body.get("port", 9000)),
            magic_hex=str(body.get("magicHex", "55434153")),
            fields=list(body.get("fields", [])),
        )
        return web.json_response({"ok": True, "lua": lua})

    # --- Frontend Static Hosting ---
    async def serve_index(self, _request: web.Request) -> web.StreamResponse:
        idx = os.path.join(self.dist_dir, "index.html")
        if os.path.isfile(idx):
            return web.FileResponse(idx)
        return web.Response(
            text="WirePulse API server is running. Build frontend (`cd frontend && npm run build`) or open Vite dev server.",
            content_type="text/plain",
        )

    async def serve_spa_fallback(self, request: web.Request) -> web.StreamResponse:
        rel = request.match_info["tail"]
        candidate = os.path.join(self.dist_dir, rel)
        if os.path.isfile(candidate):
            return web.FileResponse(candidate)
        return await self.serve_index(request)


def run_server(project_root: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    srv = WirePulseServer(project_root)
    app = srv.create_app()
    web.run_app(app, host=host, port=port, print=lambda msg: print(f"[WirePulse] {msg}"))
