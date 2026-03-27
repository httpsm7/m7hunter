#!/usr/bin/env python3
# modules/step22_idor.py — IDOR (Insecure Direct Object Reference) Detection
import os, re
from core.utils import safe_read, count_lines

class IDORStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    # Patterns that indicate IDOR-prone parameters
    IDOR_PARAMS = [
        r'[?&](id|user_id|uid|account_id|account|profile_id|order_id|'
        r'invoice_id|document_id|file_id|record_id|item_id|pid|cid|'
        r'eid|tid|rid|bid|vid|sid|object_id|resource_id|ref|ref_id)=(\d+)',
    ]

    def run(self):
        urls = self.f.get("urls","")
        out  = os.path.join(self.p.out, f"{self.p.prefix}_idor.txt")
        found = 0

        if not os.path.isfile(urls):
            self.log.warn("IDOR: no URLs file"); return

        all_urls = safe_read(urls)
        idor_candidates = []

        for url in all_urls:
            for pattern in self.IDOR_PARAMS:
                matches = re.findall(pattern, url, re.IGNORECASE)
                if matches:
                    idor_candidates.append((url, matches[0]))
                    break

        self.log.info(f"IDOR candidates: {len(idor_candidates)}")

        for url, (param, value) in idor_candidates[:50]:
            if not value.isdigit():
                continue

            orig_val = int(value)
            test_vals = [
                str(orig_val + 1),
                str(orig_val - 1),
                str(orig_val + 100),
                "1",
                "0",
                "-1",
            ]

            # Get baseline response
            baseline = self.p.shell(
                f"curl -sk --connect-timeout 5 -o /dev/null -w '%{{http_code}}|%{{size_download}}' '{url}'")

            try:
                base_code, base_size = baseline.split("|")
                base_code = int(base_code)
                base_size = int(base_size)
            except Exception:
                continue

            for test_val in test_vals:
                test_url = re.sub(
                    rf'([?&]{re.escape(param)}=){re.escape(value)}',
                    rf'\g<1>{test_val}',
                    url, flags=re.IGNORECASE
                )
                if test_url == url:
                    continue

                auth_flag = f"-H 'Cookie: {self.p.args.cookie}'" if getattr(self.p.args,"cookie",None) else ""
                result = self.p.shell(
                    f"curl -sk --connect-timeout 5 {auth_flag} "
                    f"-o /dev/null -w '%{{http_code}}|%{{size_download}}' '{test_url}'")

                try:
                    code, size = result.split("|")
                    code = int(code)
                    size = int(size)
                except Exception:
                    continue

                # IDOR signals
                signals = []
                if code == 200 and base_code == 200:
                    if abs(size - base_size) < 100:
                        signals.append(f"same response size ({size}b) — may access different resource")
                    elif size > 100:
                        signals.append(f"200 response with content ({size}b) for ID={test_val}")
                if code != base_code and code == 200:
                    signals.append(f"status changed {base_code}→{code} with ID={test_val}")

                if signals:
                    line = f"IDOR_CANDIDATE: {test_url} | {' | '.join(signals)}"
                    with open(out,"a") as f: f.write(line+"\n")
                    self.p.add_finding("high","IDOR_CANDIDATE",test_url,
                                       ' | '.join(signals),"idor-engine")
                    found += 1

        self.log.success(f"IDOR: {found} candidates → {os.path.basename(out)}")
