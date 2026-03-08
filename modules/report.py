#!/usr/bin/env python3
# modules/report.py — Full HTML + JSON Report Generator

import os, json, time
from core.utils import count_lines, safe_read

class ReportGenerator:
    def __init__(self, pipeline):
        self.p    = pipeline
        self.f    = pipeline.files
        self.out  = pipeline.out
        self.pfx  = pipeline.prefix

    def generate(self) -> str:
        target    = self.p.target
        findings  = self.p.findings
        elapsed   = time.time() - self.p.start_t
        scan_date = time.strftime("%Y-%m-%d %H:%M:%S")

        # ── Stats ─────────────────────────────────────────────────────
        subs  = count_lines(self.f["subdomains"])
        live  = count_lines(self.f["live_hosts"])
        urls  = count_lines(self.f["urls"])
        ports = count_lines(self.f["open_ports"])
        js_s  = count_lines(self.f["js_secrets"])
        crit  = sum(1 for f in findings if f["severity"]=="critical")
        high  = sum(1 for f in findings if f["severity"]=="high")
        med   = sum(1 for f in findings if f["severity"]=="medium")
        low   = sum(1 for f in findings if f["severity"]=="low")

        # ── Build HTML ────────────────────────────────────────────────
        html = self._html(target, scan_date, elapsed,
                          subs, live, urls, ports, js_s,
                          crit, high, med, low, findings)

        # Save files
        html_path = os.path.join(self.out, f"{self.pfx}_report.html")
        json_path = os.path.join(self.out, f"{self.pfx}_findings.json")

        with open(html_path, "w") as f: f.write(html)

        with open(json_path, "w") as f:
            json.dump({
                "tool": "M7Hunter v2.0",
                "author": "Sharlix | MilkyWay Intelligence",
                "target": target,
                "scan_date": scan_date,
                "elapsed_seconds": round(elapsed, 1),
                "stats": {
                    "subdomains": subs, "live_hosts": live,
                    "urls": urls, "open_ports": ports, "js_secrets": js_s
                },
                "findings": findings
            }, f, indent=2)

        self.p.log.success(f"HTML Report : {html_path}")
        self.p.log.success(f"JSON Report : {json_path}")
        return html_path

    # ─────────────────────────────────────────────────────────────────
    def _html(self, target, scan_date, elapsed,
              subs, live, urls, ports, js_s,
              crit, high, med, low, findings):

        steps_run = " → ".join(s.upper() for s in self.p.steps_to_run)
        mode      = "STEALTH" if self.p.args.stealth else \
                    "DEEP"    if self.p.args.deep    else \
                    "QUICK"   if self.p.args.quick   else "CUSTOM"
        tor_status= f"✅ ON (rotate/25 req) | Exit IP: {self.p.tor.current_ip}" \
                    if self.p.tor and self.p.tor.is_running() else "❌ OFF"

        findings_rows = ""
        for f in findings:
            sev   = f["severity"]
            badge = f"<span class='badge badge-{sev}'>{sev.upper()}</span>"
            detail_safe = str(f.get("detail",""))[:120]
            url_safe    = str(f.get("url",""))[:100]
            findings_rows += f"""
            <tr>
              <td>{badge}</td>
              <td>{f.get('type','')}</td>
              <td class='url-cell'>{url_safe}</td>
              <td>{detail_safe}</td>
              <td>{f.get('tool','')}</td>
              <td>{f.get('time','')}</td>
            </tr>"""

        no_findings = "<tr><td colspan='6' style='text-align:center;color:var(--dim)'>No findings recorded.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M7Hunter Report — {target}</title>
<style>
:root{{
  --bg:#080810; --card:#0f0f1a; --card2:#13131f;
  --border:#1e1e30; --red:#ff3860; --blue:#2563eb;
  --cyan:#00d4ff; --green:#00e676; --yellow:#ffd600;
  --text:#e0e0e0; --dim:#666; --white:#fff;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:20px;min-height:100vh}}

/* ── Banner ─── */
.banner{{text-align:center;padding:40px 0 30px;position:relative}}
.triangle-wrap{{display:inline-block;position:relative;margin-bottom:15px}}
.tri{{
  width:0;height:0;
  border-left:90px solid transparent;
  border-right:90px solid transparent;
  border-bottom:156px solid #1e3a8a;
  filter:drop-shadow(0 0 25px #2563eb);
}}
.eye{{
  position:absolute;top:78px;left:50%;
  transform:translate(-50%,-50%);
  font-size:42px;
  filter:drop-shadow(0 0 18px #ff3860);
  animation:eyepulse 2.5s ease-in-out infinite;
}}
@keyframes eyepulse{{0%,100%{{filter:drop-shadow(0 0 18px #ff3860);opacity:1}}
  50%{{filter:drop-shadow(0 0 35px #ff3860);opacity:0.7}}}}
.lines{{color:#2563eb;font-size:0.75em;letter-spacing:1px;margin:6px 0}}
h1{{
  font-size:2.6em;letter-spacing:5px;
  background:linear-gradient(135deg,#fff,#00d4ff,#fff);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  margin:8px 0;font-weight:900;
}}
.tagline{{color:#00d4ff;font-size:0.9em;letter-spacing:2px;margin:4px 0}}
.author{{color:#ff3860;font-size:0.82em;margin-top:6px}}

/* ── Stats grid ─── */
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:28px 0}}
.stat{{
  background:var(--card);border:1px solid var(--border);
  border-radius:10px;padding:18px 12px;text-align:center;
  transition:transform .2s;
}}
.stat:hover{{transform:translateY(-3px);border-color:var(--cyan)}}
.stat .num{{font-size:2.4em;font-weight:900;line-height:1}}
.stat .lbl{{font-size:0.75em;color:var(--dim);margin-top:6px;text-transform:uppercase;letter-spacing:1px}}
.c-red{{color:var(--red)}} .c-grn{{color:var(--green)}}
.c-cyn{{color:var(--cyan)}} .c-ylw{{color:var(--yellow)}}
.c-wht{{color:var(--white)}}

/* ── Section ─── */
.section{{margin:24px 0}}
.section h2{{
  color:var(--cyan);border-bottom:1px solid var(--border);
  padding-bottom:8px;margin-bottom:14px;
  font-size:1em;letter-spacing:2px;text-transform:uppercase;
}}

/* ── Tables ─── */
table{{width:100%;border-collapse:collapse;font-size:0.82em}}
th{{background:var(--card2);color:var(--cyan);padding:10px 8px;
    text-align:left;border:1px solid var(--border);font-size:0.9em}}
td{{padding:7px 8px;border:1px solid var(--border);vertical-align:top}}
tr:nth-child(even) td{{background:#0b0b14}}
tr:hover td{{background:#10101c}}
.url-cell{{word-break:break-all;max-width:300px;font-size:0.8em}}

/* ── Badges ─── */
.badge{{display:inline-block;padding:2px 7px;border-radius:4px;
        font-size:0.72em;font-weight:700;text-transform:uppercase;letter-spacing:1px}}
.badge-critical{{background:#500;color:#ff8080;border:1px solid #ff3860}}
.badge-high    {{background:#3d1500;color:#ff6b35;border:1px solid #ff6b35}}
.badge-medium  {{background:#2d2600;color:#ffd600;border:1px solid #ffd600}}
.badge-low     {{background:#002d10;color:#00e676;border:1px solid #00e676}}
.badge-info    {{background:#001a2d;color:#00d4ff;border:1px solid #00d4ff}}

/* ── Pipeline steps ─── */
.pipeline{{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}}
.pstep{{
  background:var(--card2);border:1px solid var(--blue);
  border-radius:20px;padding:4px 12px;font-size:0.78em;color:var(--cyan);
}}

/* ── File list ─── */
.file-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px;margin:10px 0}}
.file-item{{
  background:var(--card);border:1px solid var(--border);
  border-radius:6px;padding:8px 12px;font-size:0.78em;
  display:flex;justify-content:space-between;align-items:center;
}}
.file-item .fname{{color:var(--cyan)}}
.file-item .fcount{{color:var(--dim)}}

/* ── Footer ─── */
.footer{{
  text-align:center;color:var(--dim);font-size:0.72em;
  margin-top:40px;padding-top:20px;
  border-top:1px solid var(--border);
}}
</style>
</head>
<body>

<div class="banner">
  <div class="triangle-wrap">
    <div class="tri"></div>
    <div class="eye">👁</div>
  </div>
  <div class="lines">═══════════════════════════════════════════════</div>
  <h1>M7HUNTER</h1>
  <div class="tagline">Bug Bounty &amp; Pentest Pipeline Framework</div>
  <div class="author">Made by MilkyWay Intelligence &nbsp;|&nbsp; Author: Sharlix &nbsp;|&nbsp; v2.0.0</div>
  <div class="lines">═══════════════════════════════════════════════</div>
</div>

<div class="stats">
  <div class="stat"><div class="num c-cyn">{subs}</div><div class="lbl">Subdomains</div></div>
  <div class="stat"><div class="num c-grn">{live}</div><div class="lbl">Live Hosts</div></div>
  <div class="stat"><div class="num c-ylw">{urls}</div><div class="lbl">URLs</div></div>
  <div class="stat"><div class="num c-wht">{ports}</div><div class="lbl">Open Ports</div></div>
  <div class="stat"><div class="num c-ylw">{js_s}</div><div class="lbl">JS Secrets</div></div>
  <div class="stat"><div class="num c-red">{crit}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num c-red">{high}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="num c-ylw">{med}</div><div class="lbl">Medium</div></div>
  <div class="stat"><div class="num c-grn">{low}</div><div class="lbl">Low</div></div>
  <div class="stat"><div class="num c-cyn">{int(elapsed//60)}</div><div class="lbl">Minutes</div></div>
</div>

<div class="section">
  <h2>📋 Scan Information</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Target</td><td>{target}</td></tr>
    <tr><td>Scan Date</td><td>{scan_date}</td></tr>
    <tr><td>Mode</td><td>{mode}</td></tr>
    <tr><td>Threads</td><td>{self.p.args.threads}</td></tr>
    <tr><td>Tor / IP Rotation</td><td>{tor_status}</td></tr>
    <tr><td>Duration</td><td>{elapsed:.1f}s ({elapsed/60:.1f} min)</td></tr>
    <tr><td>Output Dir</td><td>{self.out}</td></tr>
  </table>
</div>

<div class="section">
  <h2>🔗 Pipeline Executed</h2>
  <div class="pipeline">
    {''.join(f'<span class="pstep">{s}</span>' for s in self.p.steps_to_run)}
  </div>
</div>

<div class="section">
  <h2>📁 Output Files</h2>
  <div class="file-grid">
    {self._file_grid()}
  </div>
</div>

<div class="section">
  <h2>🚨 Findings ({len(findings)})</h2>
  <table>
    <tr><th>Severity</th><th>Type</th><th>URL / Location</th><th>Detail</th><th>Tool</th><th>Time</th></tr>
    {findings_rows if findings else no_findings}
  </table>
</div>

<div class="footer">
  M7Hunter v2.0.0 &nbsp;|&nbsp; Made by MilkyWay Intelligence &nbsp;|&nbsp; Author: Sharlix<br>
  Use responsibly. Only test systems you own or have explicit written permission to test.<br>
  Generated: {scan_date}
</div>
</body></html>"""

    def _file_grid(self):
        items = []
        for key, path in self.f.items():
            if "dir" in key or not path.endswith(".txt"):
                continue
            if os.path.isfile(path):
                n = count_lines(path)
                name = os.path.basename(path)
                items.append(
                    f"<div class='file-item'>"
                    f"<span class='fname'>{name}</span>"
                    f"<span class='fcount'>{n} lines</span>"
                    f"</div>"
                )
        return "\n".join(items) if items else "<p style='color:var(--dim)'>No files generated yet.</p>"
