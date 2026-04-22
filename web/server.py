#!/usr/bin/env python3
# web/server.py — M7Hunter V8 Web Server — COMPLETE REWRITE
# Fixes: favicon, BrokenPipe, live logs, old data persist,
#        token management, real-time updates, WebSocket-style polling
# MilkyWay Intelligence | Author: Sharlix

import os, json, time, threading, socket, getpass
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── Global state ────────────────────────────────────────────────
_state = {
    "pipeline": None, "findings_engine": None,
    "ceo_engine": None, "ollama_ai": None,
    "scan_logs": [], "scan_start_ts": 0,
    "current_target": "—", "current_findings": [],
    "tokens": {}, "lock": threading.Lock(),
}

TOKENS_FILE = os.path.expanduser("~/.m7hunter/tokens.json")

def inject(pipeline=None, findings_engine=None, ceo_engine=None, ollama_ai=None):
    with _state["lock"]:
        _state["pipeline"] = pipeline
        _state["findings_engine"] = findings_engine
        _state["ceo_engine"] = ceo_engine
        _state["ollama_ai"] = ollama_ai
        _state["current_findings"] = []   # FIX: clear old data
        _state["scan_logs"] = []           # FIX: clear old logs
        _state["scan_start_ts"] = time.time()
        if pipeline:
            _state["current_target"] = getattr(pipeline, "target", "—")

def add_log(msg: str):
    with _state["lock"]:
        _state["scan_logs"].append({
            "ts": time.strftime("%H:%M:%S"),
            "msg": str(msg)[:200]
        })
        _state["scan_logs"] = _state["scan_logs"][-500:]

def _load_tokens():
    try:
        if os.path.isfile(TOKENS_FILE):
            with open(TOKENS_FILE) as f:
                _state["tokens"] = json.load(f)
    except Exception:
        pass

def _save_tokens(tokens: dict):
    os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=2)
    _state["tokens"] = tokens

def _get_findings():
    fe = _state.get("findings_engine")
    if fe:
        return fe.get_all()
    # Fallback: scan latest results dir
    findings = []
    base = "results"
    if os.path.isdir(base):
        for root, _, files in sorted(os.walk(base)):
            for fname in sorted(files):
                if fname.endswith(".json") and ("finding" in fname or "risk" in fname):
                    try:
                        with open(os.path.join(root, fname)) as f:
                            data = json.load(f)
                        if "findings" in data:
                            findings.extend(data["findings"])
                    except Exception:
                        pass
    # Return only current scan findings
    return findings

def _get_stats(findings):
    s = {"critical":0,"high":0,"medium":0,"low":0,"info":0,"total":0,"confirmed":0}
    for f in findings:
        sev = f.get("severity","info")
        s[sev] = s.get(sev,0) + 1
        s["total"] += 1
        if f.get("status") == "confirmed":
            s["confirmed"] += 1
    return s


# ── HTTP Handler ────────────────────────────────────────────────
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

FAVICON_ICO = bytes([
    0,0,1,0,1,0,16,16,0,0,1,0,32,0,104,4,0,0,22,0,0,0,
    40,0,0,0,16,0,0,0,32,0,0,0,1,0,32,0,0,0,0,0,0,4,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
] + [0]*1024)  # minimal valid ICO

class M7Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        msg = fmt % args
        add_log(f"[WEB] {msg}")

    def log_error(self, fmt, *args):
        pass  # Suppress BrokenPipe spam

    def _send(self, code, body, ct="application/json", extra_headers=None):
        try:
            if isinstance(body, dict) or isinstance(body, list):
                body = json.dumps(body, default=str).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache")
            if extra_headers:
                for k,v in extra_headers.items():
                    self.send_header(k,v)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # FIX: silent BrokenPipe
        except Exception:
            pass

    def do_OPTIONS(self):
        try:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin","*")
            self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
            self.send_header("Access-Control-Allow-Headers","Content-Type")
            self.end_headers()
        except Exception:
            pass

    def do_GET(self):
        try:
            purl = urlparse(self.path)
            path = purl.path
            qs   = parse_qs(purl.query)

            # ── Favicon ── FIX: no more FileNotFoundError
            if path == "/favicon.ico":
                self._send(200, FAVICON_ICO, "image/x-icon"); return

            # ── API Routes ──
            if path == "/api/status":
                findings = _get_findings()
                stats    = _get_stats(findings)
                ceo = _state["ceo_engine"]
                olm = _state["ollama_ai"]
                uname = getpass.getuser()
                self._send(200, {
                    "tool": f"M7Hunter V8",
                    "user": uname,
                    "github": "https://github.com/httpsm7",
                    "target": _state["current_target"],
                    "stats": stats,
                    "ceo": ceo.status() if ceo else {"state":"idle"},
                    "ollama": olm.get_status() if olm else {"available": False},
                    "uptime": int(time.time() - _state["scan_start_ts"]) if _state["scan_start_ts"] else 0,
                }); return

            elif path == "/api/findings":
                findings = _get_findings()
                sev_ord = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                findings = sorted(findings, key=lambda f: sev_ord.get(f.get("severity","info"),4))
                self._send(200, {"findings": findings, "total": len(findings)}); return

            elif path == "/api/logs":
                with _state["lock"]:
                    logs = list(_state["scan_logs"][-200:])
                self._send(200, {"logs": logs}); return

            elif path == "/api/tokens":
                _load_tokens()
                # Return masked tokens
                masked = {}
                for k,v in _state["tokens"].items():
                    masked[k] = v[:4] + "***" + v[-4:] if len(v) > 8 else "***"
                self._send(200, {"tokens": masked, "keys": list(_state["tokens"].keys())}); return

            elif path.startswith("/api/ceo/"):
                action = path.replace("/api/ceo/","")
                ceo = _state["ceo_engine"]
                actions = {
                    "pause": ceo.pause if ceo else None,
                    "resume": ceo.resume if ceo else None,
                    "stop": ceo.stop if ceo else None,
                    "kill": ceo.kill if ceo else None,
                    "state": None,
                }
                if action in actions and actions[action]:
                    try: actions[action]()
                    except Exception: pass
                state = ceo.status() if ceo else {"state":"idle","waf_detected":False,"findings_count":{}}
                self._send(200, {"ok":True,"action":action,"state":state}); return

            elif path == "/api/scan/start":
                self._send(200, {"error": "Use POST"}); return

            # ── Static files ──
            elif path == "/" or path == "":
                self._serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html"); return

            else:
                file_path = os.path.join(STATIC_DIR, path.lstrip("/"))
                if os.path.isfile(file_path):
                    ct = "text/css" if path.endswith(".css") else \
                         "application/javascript" if path.endswith(".js") else \
                         "text/html"
                    self._serve_file(file_path, ct); return
                self._send(404, {"error":"not found"}); return

        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try: self._send(500, {"error": str(e)})
            except Exception: pass

    def do_POST(self):
        try:
            purl   = urlparse(self.path)
            path   = purl.path
            length = int(self.headers.get("Content-Length",0))
            body   = self.rfile.read(length) if length else b""
            try: data = json.loads(body) if body else {}
            except Exception: data = {}

            if path == "/api/chat":
                msg = data.get("message","").strip()
                olm = _state["ollama_ai"]
                if not msg:
                    self._send(400, {"error":"empty"}); return
                if olm:
                    try:
                        reply = olm.chat(msg)
                    except Exception as e:
                        reply = f"AI error: {e}"
                else:
                    reply = "Ollama AI not available. Run: ollama serve && ollama pull llama3"
                self._send(200, {"reply": reply}); return

            elif path == "/api/tokens/save":
                tokens = data.get("tokens", {})
                if tokens:
                    _save_tokens(tokens)
                    # Also set env vars for current session
                    import os as _os
                    for k, v in tokens.items():
                        _os.environ[k] = v
                self._send(200, {"ok": True, "saved": list(tokens.keys())}); return

            elif path == "/api/ceo/delay":
                ms  = int(data.get("ms", 1000))
                ceo = _state["ceo_engine"]
                if ceo:
                    ceo.rules["normal_min_delay_ms"] = ms
                    ceo.rules["normal_max_delay_ms"] = ms + 500
                self._send(200, {"ok": True, "delay_ms": ms}); return

            elif path == "/api/scan/start":
                target = data.get("target","").strip()
                if not target:
                    self._send(400,{"error":"target required"}); return
                def _bg():
                    import subprocess, sys
                    script = os.path.join(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "m7hunter.py"
                    )
                    args = [sys.executable, script, "-u", target]
                    if data.get("deep"):   args.append("--deep")
                    if data.get("fast"):   args.append("--fast")
                    if data.get("cookie"): args += ["--cookie", data["cookie"]]
                    subprocess.Popen(args)
                threading.Thread(target=_bg, daemon=True).start()
                self._send(200, {"ok":True,"target":target}); return

            else:
                self._send(404,{"error":"not found"}); return

        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try: self._send(500, {"error": str(e)})
            except Exception: pass

    def _serve_file(self, path, ct):
        try:
            with open(path,"rb") as f:
                body = f.read()
            self._send(200, body, ct)
        except FileNotFoundError:
            self._send(404, b"Not found", "text/plain")
        except Exception as e:
            self._send(500, b"Server error", "text/plain")


class Dashboard:
    def __init__(self, log=None, port=8719, results_dir="results",
                 pipeline=None, findings_engine=None,
                 ceo_engine=None, ollama_ai=None):
        self.log  = log
        self.port = port
        _load_tokens()
        inject(pipeline=pipeline, findings_engine=findings_engine,
               ceo_engine=ceo_engine, ollama_ai=ollama_ai)
        self._server = None

    def start(self, blocking=True):
        try:
            self._server = HTTPServer(("0.0.0.0", self.port), M7Handler)
        except OSError:
            self.port += 1
            self._server = HTTPServer(("0.0.0.0", self.port), M7Handler)

        if self.log:
            self.log.success(f"Dashboard: http://localhost:{self.port}")
            uname = getpass.getuser()
            self.log.info(f"  User: {uname} | github.com/httpsm7")

        if blocking:
            try: self._server.serve_forever()
            except KeyboardInterrupt: pass
        else:
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()
            return self.port

    def stop(self):
        if self._server:
            self._server.shutdown()
