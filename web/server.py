#!/usr/bin/env python3
# web/server.py — M7Hunter V8 Web Server
# WebSocket real-time updates + REST API + Ollama chatbot
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import threading
import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Global state — injected by pipeline
_pipeline        = None
_findings_engine = None
_ceo_engine      = None
_ollama_ai       = None
_scan_log        = []
_log_lock        = threading.Lock()
_ws_clients      = []
_ws_lock         = threading.Lock()


def inject(pipeline=None, findings_engine=None, ceo_engine=None, ollama_ai=None):
    global _pipeline, _findings_engine, _ceo_engine, _ollama_ai
    _pipeline        = pipeline
    _findings_engine = findings_engine
    _ceo_engine      = ceo_engine
    _ollama_ai       = ollama_ai


def add_log(msg: str):
    with _log_lock:
        _scan_log.append({"time": time.strftime("%H:%M:%S"), "msg": msg})
        _scan_log[:] = _scan_log[-200:]  # keep last 200


def _get_findings():
    if _findings_engine:
        return _findings_engine.get_all()
    # Fallback: scan results dir
    all_f = []
    rd    = getattr(_pipeline, "out", "results") if _pipeline else "results"
    if os.path.isdir(rd):
        for root, _, files in os.walk(rd):
            for fname in files:
                if fname.endswith(".json") and "finding" in fname:
                    try:
                        with open(os.path.join(root, fname)) as f:
                            data = json.load(f)
                            all_f.extend(data.get("findings", []))
                    except Exception:
                        pass
    return all_f


def _get_stats(findings):
    s = {"critical":0,"high":0,"medium":0,"low":0,"info":0,"total":0,"confirmed":0}
    for f in findings:
        sev = f.get("severity","info")
        s[sev]   = s.get(sev, 0) + 1
        s["total"] += 1
        if f.get("status") == "confirmed":
            s["confirmed"] += 1
    return s


def _api_response(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


class M7Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self._base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
        super().__init__(*args, directory=self._base, **kwargs)

    def log_message(self, *a): pass  # silence

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        qs   = parse_qs(urlparse(self.path).query)

        if path == "/api/status":
            findings = _get_findings()
            stats    = _get_stats(findings)
            ceo_st   = _ceo_engine.status() if _ceo_engine else {}
            olm_st   = _ollama_ai.get_status() if _ollama_ai else {}
            _api_response(self, {
                "tool"    : "M7Hunter V8",
                "author"  : "Sharlix | MilkyWay Intelligence",
                "github"  : "https://github.com/httpsm7",
                "stats"   : stats,
                "ceo"     : ceo_st,
                "ollama"  : olm_st,
                "target"  : getattr(_pipeline, "target", "—") if _pipeline else "—",
                "uptime"  : int(time.time() - (_pipeline.start_t if _pipeline else time.time())),
            })

        elif path == "/api/findings":
            findings = _get_findings()
            sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
            findings.sort(key=lambda f: sev_order.get(f.get("severity","info"),4))
            _api_response(self, {"findings": findings, "total": len(findings)})

        elif path == "/api/logs":
            with _log_lock:
                _api_response(self, {"logs": list(_scan_log[-100:])})

        elif path == "/api/ceo/pause":
            if _ceo_engine: _ceo_engine.pause()
            _api_response(self, {"ok": True, "action": "paused"})

        elif path == "/api/ceo/resume":
            if _ceo_engine: _ceo_engine.resume()
            _api_response(self, {"ok": True, "action": "resumed"})

        elif path == "/api/ceo/stop":
            if _ceo_engine: _ceo_engine.stop()
            _api_response(self, {"ok": True, "action": "stopped"})

        elif path == "/api/ceo/kill":
            if _ceo_engine: _ceo_engine.kill()
            _api_response(self, {"ok": True, "action": "killed"})

        elif path == "/api/ceo/state":
            state = _ceo_engine.status() if _ceo_engine else {"state":"unknown"}
            _api_response(self, state)

        elif path.startswith("/api/export"):
            fmt = qs.get("format",["json"])[0]
            findings = _get_findings()
            if fmt == "json":
                _api_response(self, {"findings": findings})
            else:
                _api_response(self, {"error": "format not supported via API"})

        elif path == "/":
            self._serve_index()

        elif path == "/health":
            self._respond_text("M7Hunter V8 OK")

        else:
            try:
                super().do_GET()
            except Exception:
                self._respond_text("Not Found", 404)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b""

        if path == "/api/chat":
            try:
                data = json.loads(body)
                msg  = data.get("message", "").strip()
                if not msg:
                    _api_response(self, {"error": "empty message"}, 400)
                    return
                if _ollama_ai:
                    reply = _ollama_ai.chat(msg)
                else:
                    reply = "⚠️ Ollama AI not loaded. Start with: ollama serve && ollama pull llama3"
                _api_response(self, {"reply": reply})
            except Exception as e:
                _api_response(self, {"error": str(e)}, 500)

        elif path == "/api/ceo/delay":
            try:
                data = json.loads(body)
                ms   = int(data.get("ms", 1000))
                if _ceo_engine:
                    _ceo_engine.rules["normal_min_delay_ms"] = ms
                    _ceo_engine.rules["normal_max_delay_ms"] = ms + 500
                _api_response(self, {"ok": True, "delay_ms": ms})
            except Exception as e:
                _api_response(self, {"error": str(e)}, 400)

        elif path == "/api/scan/start":
            try:
                data   = json.loads(body)
                target = data.get("target","").strip()
                if not target:
                    _api_response(self, {"error": "target required"}, 400)
                    return
                # Launch scan in background thread
                def _bg_scan():
                    import subprocess, sys
                    script = os.path.join(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__))), "m7hunter.py")
                    args = [sys.executable, script, "-u", target]
                    if data.get("deep"):     args.append("--deep")
                    if data.get("cookie"):   args += ["--cookie", data["cookie"]]
                    if data.get("fast"):     args.append("--fast")
                    subprocess.Popen(args)
                threading.Thread(target=_bg_scan, daemon=True).start()
                _api_response(self, {"ok": True, "target": target, "msg": "Scan started"})
            except Exception as e:
                _api_response(self, {"error": str(e)}, 500)

        else:
            _api_response(self, {"error": "not found"}, 404)

    def _serve_index(self):
        idx = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
        if os.path.isfile(idx):
            with open(idx, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._respond_text("Index not found — run installer", 404)

    def _respond_text(self, text: str, status: int = 200):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Dashboard:
    def __init__(self, log=None, port: int = 8719, results_dir: str = "results",
                 pipeline=None, findings_engine=None, ceo_engine=None, ollama_ai=None):
        self.log  = log
        self.port = port
        inject(pipeline=pipeline, findings_engine=findings_engine,
               ceo_engine=ceo_engine, ollama_ai=ollama_ai)
        self._server = None

    def start(self, blocking: bool = True):
        self._server = HTTPServer(("0.0.0.0", self.port), M7Handler)
        if self.log:
            self.log.success(f"Dashboard: http://localhost:{self.port}")
            self.log.info(f"  GitHub: https://github.com/httpsm7")
        if blocking:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                pass
        else:
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
