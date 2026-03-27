#!/usr/bin/env python3
# web/dashboard.py — M7Hunter Localhost Web Dashboard
# Pure stdlib — no Flask/Django needed
# Access: http://localhost:8719
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import time
import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DASHBOARD_PORT = 8719
RESULTS_DIR    = "results"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="10">
<title>M7Hunter Dashboard</title>
<style>
:root{--bg:#07070f;--card:#0f0f1c;--card2:#13131f;--border:#1e1e30;
  --red:#ff3860;--blue:#2563eb;--cyan:#00d4ff;--green:#00e676;
  --yellow:#ffd600;--text:#e0e0e0;--dim:#555;--white:#fff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;
  display:flex;min-height:100vh}
.sidebar{width:220px;background:var(--card);border-right:1px solid var(--border);
  padding:20px;flex-shrink:0;position:fixed;height:100vh;overflow-y:auto}
.main{margin-left:220px;padding:24px;flex:1}
.logo{color:var(--cyan);font-size:1.2em;font-weight:900;letter-spacing:3px;
  margin-bottom:4px}
.logo-sub{color:var(--dim);font-size:.7em;margin-bottom:24px}
.nav-item{display:block;padding:8px 12px;color:var(--dim);text-decoration:none;
  border-radius:6px;font-size:.82em;margin-bottom:4px;transition:all .15s}
.nav-item:hover,.nav-item.active{background:var(--card2);color:var(--cyan)}
.nav-sep{color:var(--dim);font-size:.65em;padding:12px 0 4px;text-transform:uppercase;
  letter-spacing:2px}
.live-dot{width:8px;height:8px;background:var(--green);border-radius:50%;
  display:inline-block;margin-right:6px;animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
h1{font-size:1.4em;color:var(--white);margin-bottom:4px;font-weight:700}
.subtitle{color:var(--dim);font-size:.8em;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:16px;text-align:center;transition:transform .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--cyan)}
.stat-num{font-size:2em;font-weight:900;line-height:1}
.stat-lbl{font-size:.7em;color:var(--dim);margin-top:4px;text-transform:uppercase;letter-spacing:1px}
.c-r{color:var(--red)}.c-g{color:var(--green)}.c-c{color:var(--cyan)}
.c-y{color:var(--yellow)}.c-w{color:var(--white)}
.section{background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:20px;margin-bottom:20px}
.section h2{color:var(--cyan);font-size:.9em;letter-spacing:2px;text-transform:uppercase;
  margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.8em}
th{background:var(--card2);color:var(--cyan);padding:8px;text-align:left;
  border:1px solid var(--border)}
td{padding:7px 8px;border:1px solid var(--border);vertical-align:top;max-width:300px;word-break:break-all}
tr:nth-child(even) td{background:#0b0b15}
tr:hover td{background:#10101d}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.68em;font-weight:700}
.badge-critical{background:#500;color:#ff8080;border:1px solid #ff3860}
.badge-high{background:#3d1500;color:#ff6b35;border:1px solid #ff6b35}
.badge-medium{background:#2d2600;color:#ffd600;border:1px solid #ffd600}
.badge-low{background:#002d10;color:#00e676;border:1px solid #00e676}
.badge-confirmed{background:#500;color:#ff8080;border:1px solid #ff3860}
.badge-potential{background:#2d2600;color:#ffd600;border:1px solid #ffd600}
.scan-card{background:var(--card2);border:1px solid var(--border);border-radius:8px;
  padding:14px;margin-bottom:10px}
.scan-target{color:var(--cyan);font-size:.9em;font-weight:700}
.scan-meta{color:var(--dim);font-size:.72em;margin-top:4px}
.progress-bar{background:#1e1e30;border-radius:4px;height:6px;margin-top:8px}
.progress-fill{background:var(--cyan);height:6px;border-radius:4px;transition:width .5s}
.empty{color:var(--dim);font-size:.82em;padding:20px;text-align:center}
.tag{background:var(--card2);border:1px solid var(--border);border-radius:20px;
  padding:3px 10px;font-size:.72em;color:var(--cyan);display:inline-block;margin:2px}
.refresh-note{color:var(--dim);font-size:.7em;text-align:right;margin-bottom:8px}
</style>
</head>
<body>
<div class="sidebar">
  <div class="logo">M7HUNTER</div>
  <div class="logo-sub">v3.0 Dashboard</div>
  <span class="live-dot"></span><span style="font-size:.72em;color:var(--green)">LIVE</span>
  <br><br>
  <div class="nav-sep">Navigation</div>
  <a href="/" class="nav-item active">Overview</a>
  <a href="/scans" class="nav-item">Active Scans</a>
  <a href="/findings" class="nav-item">All Findings</a>
  <a href="/exploits" class="nav-item">Auto-Exploit</a>
  <a href="/ai" class="nav-item">AI Chat</a>
  <div class="nav-sep">Actions</div>
  <a href="/api/stats" class="nav-item">API Stats</a>
</div>

<div class="main">
  <div class="refresh-note">Auto-refresh: 10s</div>
  CONTENT_PLACEHOLDER
</div>
</body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    results_dir = RESULTS_DIR

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        routes = {
            "/"          : self._page_overview,
            "/scans"     : self._page_scans,
            "/findings"  : self._page_findings,
            "/exploits"  : self._page_exploits,
            "/ai"        : self._page_ai,
            "/api/stats" : self._api_stats,
        }

        handler = routes.get(path, self._page_404)
        handler()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/ai/chat":
            length  = int(self.headers.get("Content-Length", 0))
            body    = self.rfile.read(length).decode()
            try:
                data    = json.loads(body)
                message = data.get("message","")
                reply   = self._ai_chat(message)
                self._json({"reply": reply})
            except Exception:
                self._json({"reply": "AI not available"})
        else:
            self._page_404()

    # ── Pages ──────────────────────────────────────────────────────

    def _page_overview(self):
        stats   = self._gather_stats()
        content = f"""
<h1>Dashboard Overview</h1>
<p class="subtitle">MilkyWay Intelligence | M7Hunter v3.0</p>

<div class="grid">
  <div class="stat-card"><div class="stat-num c-c">{stats['total_scans']}</div>
    <div class="stat-lbl">Total Scans</div></div>
  <div class="stat-card"><div class="stat-num c-r">{stats['critical']}</div>
    <div class="stat-lbl">Critical</div></div>
  <div class="stat-card"><div class="stat-num c-r">{stats['high']}</div>
    <div class="stat-lbl">High</div></div>
  <div class="stat-card"><div class="stat-num c-y">{stats['medium']}</div>
    <div class="stat-lbl">Medium</div></div>
  <div class="stat-card"><div class="stat-num c-g">{stats['low']}</div>
    <div class="stat-lbl">Low</div></div>
  <div class="stat-card"><div class="stat-num c-w">{stats['total_findings']}</div>
    <div class="stat-lbl">Findings</div></div>
</div>

<div class="section">
  <h2>Recent Scans</h2>
  {self._render_recent_scans(stats['scans'][:5])}
</div>

<div class="section">
  <h2>Top Findings</h2>
  {self._render_findings_table(stats['findings'][:10])}
</div>"""
        self._html(content)

    def _page_findings(self):
        stats   = self._gather_stats()
        content = f"""
<h1>All Findings</h1>
<p class="subtitle">{len(stats['findings'])} total findings across all scans</p>
<div class="section">
  {self._render_findings_table(stats['findings'])}
</div>"""
        self._html(content)

    def _page_scans(self):
        stats   = self._gather_stats()
        content = f"""
<h1>Scan History</h1>
<p class="subtitle">{len(stats['scans'])} scans completed</p>
<div class="section">
  {''.join(self._render_scan_card(s) for s in stats['scans'])}
</div>"""
        self._html(content)

    def _page_exploits(self):
        exploits = self._gather_exploits()
        content  = f"""
<h1>Auto-Exploit Results</h1>
<p class="subtitle">{len(exploits)} exploit findings</p>
<div class="section">
  {self._render_exploit_table(exploits)}
</div>"""
        self._html(content)

    def _page_ai(self):
        content = """
<h1>AI Security Chat</h1>
<p class="subtitle">Offline AI powered by Ollama (mistral)</p>
<div class="section">
  <div id="chat-log" style="height:400px;overflow-y:auto;padding:10px;
       background:#0b0b15;border-radius:6px;margin-bottom:12px;font-size:.82em;">
    <div style="color:var(--dim)">AI ready. Ask about vulnerabilities, payloads, bypass techniques...</div>
  </div>
  <div style="display:flex;gap:8px">
    <input id="chat-input" type="text" placeholder="Ask AI..."
      style="flex:1;background:var(--card2);border:1px solid var(--border);
             border-radius:6px;padding:8px 12px;color:var(--text);font-size:.82em;outline:none">
    <button onclick="sendChat()" style="background:var(--blue);border:none;border-radius:6px;
      padding:8px 16px;color:white;cursor:pointer;font-size:.82em">Send</button>
  </div>
</div>
<script>
async function sendChat(){
  const inp=document.getElementById('chat-input');
  const log=document.getElementById('chat-log');
  const msg=inp.value.trim(); if(!msg) return;
  log.innerHTML+=`<div style="color:var(--cyan);margin:8px 0"><b>You:</b> ${msg}</div>`;
  inp.value='';
  const r=await fetch('/api/ai/chat',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})});
  const d=await r.json();
  log.innerHTML+=`<div style="color:var(--text);margin:8px 0"><b>AI:</b> ${d.reply}</div>`;
  log.scrollTop=log.scrollHeight;
}
document.getElementById('chat-input').addEventListener('keypress',e=>{if(e.key==='Enter')sendChat()});
</script>"""
        self._html(content)

    def _page_404(self):
        self._html("<h1>404</h1><p class='subtitle'>Page not found</p>")

    def _api_stats(self):
        self._json(self._gather_stats())

    # ── Renderers ──────────────────────────────────────────────────

    def _render_findings_table(self, findings):
        if not findings:
            return "<div class='empty'>No findings yet. Run a scan first.</div>"
        rows = ""
        for f in findings:
            sev = f.get("severity","info")
            rows += f"""<tr>
              <td><span class="badge badge-{sev}">{sev.upper()}</span></td>
              <td>{f.get('type','')}</td>
              <td>{str(f.get('url',''))[:60]}</td>
              <td>{str(f.get('detail',''))[:80]}</td>
              <td>{f.get('tool','')}</td>
            </tr>"""
        return f"""<table>
          <tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Tool</th></tr>
          {rows}</table>"""

    def _render_exploit_table(self, exploits):
        if not exploits:
            return "<div class='empty'>No exploit results yet.</div>"
        rows = ""
        for f in exploits:
            rows += f"""<tr>
              <td><span class="badge badge-{f.get('status','info')}">{f.get('status','').upper()}</span></td>
              <td>{f.get('type','')}</td>
              <td>{str(f.get('url',''))[:60]}</td>
              <td>{str(f.get('reason',''))[:80]}</td>
            </tr>"""
        return f"""<table>
          <tr><th>Status</th><th>Type</th><th>URL</th><th>Reason</th></tr>
          {rows}</table>"""

    def _render_recent_scans(self, scans):
        if not scans:
            return "<div class='empty'>No scans yet.</div>"
        return "".join(self._render_scan_card(s) for s in scans)

    def _render_scan_card(self, scan):
        target   = scan.get("target","unknown")
        findings = scan.get("findings_count", 0)
        elapsed  = scan.get("elapsed","?")
        mode     = scan.get("mode","?")
        return f"""<div class="scan-card">
          <div class="scan-target">{target}</div>
          <div class="scan-meta">
            Mode: {mode} | Findings: {findings} | Time: {elapsed}s
          </div>
        </div>"""

    # ── Data gathering ─────────────────────────────────────────────

    def _gather_stats(self) -> dict:
        stats = {
            "total_scans"   : 0,
            "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "findings"      : [],
            "scans"         : [],
        }
        rd = self.results_dir
        if not os.path.isdir(rd):
            return stats

        for scan_dir in sorted(os.listdir(rd), reverse=True)[:20]:
            scan_path = os.path.join(rd, scan_dir)
            if not os.path.isdir(scan_path):
                continue
            stats["total_scans"] += 1

            # Load JSON findings
            for fname in os.listdir(scan_path):
                if fname.endswith("_findings.json"):
                    try:
                        with open(os.path.join(scan_path, fname)) as f:
                            data = json.load(f)
                        findings = data.get("findings", [])
                        stats["findings"].extend(findings)
                        stats["total_findings"] += len(findings)
                        for f in findings:
                            sev = f.get("severity","info")
                            if sev in stats:
                                stats[sev] += 1
                        stats["scans"].append({
                            "target"        : data.get("target","?"),
                            "findings_count": len(findings),
                            "elapsed"       : data.get("elapsed","?"),
                            "mode"          : "scan",
                        })
                    except Exception:
                        pass

        return stats

    def _gather_exploits(self) -> list:
        exploits = []
        rd = self.results_dir
        if not os.path.isdir(rd):
            return exploits
        for scan_dir in os.listdir(rd):
            scan_path = os.path.join(rd, scan_dir)
            if not os.path.isdir(scan_path):
                continue
            for fname in os.listdir(scan_path):
                if fname.endswith("_exploit_results.json"):
                    try:
                        with open(os.path.join(scan_path, fname)) as f:
                            data = json.load(f)
                        exploits.extend(data.get("findings", []))
                    except Exception:
                        pass
        return exploits

    def _ai_chat(self, message: str) -> str:
        try:
            from ai.offline.ollama_engine import OfflineAI
            ai = OfflineAI()
            if ai.is_available():
                return ai.chat(message)
        except Exception:
            pass
        return "AI not available. Install Ollama: curl -fsSL https://ollama.ai/install.sh | sh"

    # ── HTTP helpers ───────────────────────────────────────────────

    def _html(self, content: str):
        html = HTML_TEMPLATE.replace("CONTENT_PLACEHOLDER", content)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def _json(self, data: dict):
        body = json.dumps(data, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class Dashboard:
    """M7Hunter localhost web dashboard."""

    def __init__(self, log=None, port=DASHBOARD_PORT, results_dir=RESULTS_DIR):
        self.log        = log
        self.port       = port
        self.results_dir= results_dir
        self._server    = None
        self._thread    = None

    def start(self, blocking=True):
        """Start dashboard server."""
        DashboardHandler.results_dir = self.results_dir
        self._server = HTTPServer(("127.0.0.1", self.port), DashboardHandler)
        if self.log:
            self.log.success(f"Dashboard: http://localhost:{self.port}")
        else:
            print(f"\033[92m[✓]\033[0m Dashboard: http://localhost:{self.port}")

        if blocking:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                pass
        else:
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True)
            self._thread.start()

    def start_background(self):
        """Start dashboard in background thread."""
        self.start(blocking=False)

    def stop(self):
        if self._server:
            self._server.shutdown()

    @staticmethod
    def is_port_free(port=DASHBOARD_PORT) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", port))
            s.close()
            return True
        except Exception:
            return False


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DASHBOARD_PORT
    results = sys.argv[2] if len(sys.argv) > 2 else "results"
    print(f"Starting M7Hunter Dashboard on http://localhost:{port}")
    Dashboard(port=port, results_dir=results).start(blocking=True)
