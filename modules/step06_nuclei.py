#!/usr/bin/env python3
# modules/step06_nuclei.py — Nuclei Template Scanning
# FIX BUG-01: Removed broken pipe/tee, fixed output handling
# FIX BUG-09: nuclei-update only when --update flag passed
# MilkyWay Intelligence | Author: Sharlix

import os, json
from core.utils import count_lines, safe_read


class Step06Nuclei:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        p    = self.p
        live = p.files["live_hosts"]
        out  = p.files["nuclei_results"]
        t    = p.tmgr.get

        if not os.path.isfile(live) or count_lines(live) == 0:
            p.log.warn("Nuclei: no live hosts"); return

        p.log.info(f"Nuclei scanning {count_lines(live)} hosts")

        cookie_flag = f'-H "Cookie: {p.args.cookie}"' if getattr(p.args,"cookie",None) else ""

        # FIX BUG-09: Only update templates when explicitly requested
        if getattr(p.args, 'update', False):
            p.shell("nuclei -update-templates -silent", timeout=90,
                    label="update nuclei templates")

        json_out = out.replace(".txt", ".json")

        # FIX BUG-01: Use -o for file output; no pipe/tee inside command string
        # shell() will capture stdout separately; file output via -o is reliable
        p.shell(
            f"nuclei -l {live} -silent "
            f"-severity critical,high,medium "
            f"-etags dos,fuzz "
            f"-t cves,exposures,misconfigurations,vulnerabilities,default-logins "
            f"-rl {getattr(p.args,'rate',300)} "
            f"-c 50 "
            f"{cookie_flag} "
            f"-jsonl -o {json_out}",
            label="nuclei main scan", tool_name="nuclei", timeout=t("nuclei")
        )

        # Custom M7 templates if exist
        custom_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "templates", "nuclei", "m7-custom")
        yaml_files = [f for f in os.listdir(custom_dir) if f.endswith(".yaml")] if os.path.isdir(custom_dir) else []
        if yaml_files:
            custom_json = out.replace(".txt", "_custom.json")
            p.shell(
                f"nuclei -l {live} -silent -t {custom_dir} "
                f"-rl 100 {cookie_flag} -jsonl -o {custom_json}",
                label="nuclei custom templates", tool_name="nuclei",
                timeout=600
            )
            if os.path.isfile(custom_json):
                self._parse_nuclei_jsonl(custom_json, out)

        # Parse main results
        if os.path.isfile(json_out):
            self._parse_nuclei_jsonl(json_out, out)
        else:
            # Fallback: re-run with text output only
            p.shell(
                f"nuclei -l {live} -silent "
                f"-severity critical,high,medium "
                f"-etags dos,fuzz "
                f"-rl {getattr(p.args,'rate',300)} "
                f"{cookie_flag}",
                label="nuclei fallback", tool_name="nuclei",
                append_file=out, timeout=t("nuclei")
            )
            self._parse_nuclei_text(out)

        n = count_lines(out)
        p.log.success(f"Nuclei: {n} findings")

    def _parse_nuclei_jsonl(self, json_path: str, txt_out: str):
        """Parse JSONL output from nuclei -o flag and register findings."""
        SEV_MAP = {"critical":"critical","high":"high","medium":"medium",
                   "low":"low","info":"info"}
        lines_written = []
        try:
            with open(json_path) as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        r    = json.loads(line)
                        sev  = SEV_MAP.get(r.get("info",{}).get("severity","info"),"info")
                        url  = r.get("matched-at","") or r.get("host","")
                        name = r.get("info",{}).get("name","Nuclei Finding")
                        tmpl = r.get("template-id","")
                        if url:
                            self.p.add_finding(sev, f"NUCLEI_{tmpl.upper()[:30]}",
                                               url, name, "nuclei")
                            lines_written.append(f"[{sev}] {tmpl} {url} — {name}")
                    except json.JSONDecodeError:
                        pass
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step06_nuclei", _e)
        # Write human-readable txt alongside
        if lines_written:
            with open(txt_out, "a") as f:
                f.write("\n".join(lines_written) + "\n")

    def _parse_nuclei_text(self, out: str):
        import re
        try:
            with open(out) as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    m = re.search(r'\[(critical|high|medium|low)\]', line, re.I)
                    sev = m.group(1).lower() if m else "info"
                    urls = re.findall(r'https?://\S+', line)
                    if urls:
                        self.p.add_finding(sev, "NUCLEI", urls[0],
                                           line[:100], "nuclei")
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step06_nuclei", _e)
