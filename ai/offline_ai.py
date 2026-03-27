#!/usr/bin/env python3
# ai/offline_ai.py — M7Hunter Offline AI Engine
# 100% local — no API key, no internet required for AI features
# Uses pattern matching, heuristics, and learned rules
# MilkyWay Intelligence | Author: Sharlix

import os
import re
import json
import time
import hashlib
from datetime import datetime

RULES_FILE    = os.path.expanduser("~/.m7hunter/ai_rules.json")
LEARNED_FILE  = os.path.expanduser("~/.m7hunter/learned_patterns.json")

R="\033[91m"; B="\033[34m"; C="\033[96m"; Y="\033[93m"
G="\033[92m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"


# ── Built-in detection rules (no ML needed) ──────────────────────────

FALSE_POSITIVE_PATTERNS = {
    "SSRF": [
        r"connection refused",
        r"invalid url",
        r"connection timed out",
        r"no route to host",
        r"network unreachable",
    ],
    "XSS": [
        r"&lt;script&gt;",       # HTML encoded — sanitized
        r"&amp;",               # Encoded amp
        r"\\u003c",             # Unicode encoded
        r"content.security.policy",  # CSP header present
    ],
    "LFI": [
        r"file not found",
        r"no such file",
        r"permission denied",
        r"access denied",
    ],
    "SQLI": [
        r"syntax error",         # Might be legit error, not injection
        r"you have an error in your sql",  # Only if NOT in response
    ],
}

CONFIRMED_PATTERNS = {
    "SSRF_AWS": [r"ami-id", r"instance-id", r"local-ipv4", r"security-credentials"],
    "SSRF_GCP": [r"computeMetadata", r"instance/zone", r"service-accounts"],
    "SSRF_INTERNAL": [r"127\.0\.0\.1", r"localhost", r"internal"],
    "XSS_REFLECTED": [r"<script>alert", r"<svg/onload", r"onerror=alert", r"javascript:alert"],
    "LFI_UNIX": [r"root:x:0:0", r"daemon:", r"bin/bash", r"bin/sh", r"/etc/passwd"],
    "LFI_WIN": [r"\[boot loader\]", r"windows\\system32", r"autoexec.bat"],
    "SQLI_ERROR": [r"mysql error", r"ora-\d{5}", r"postgresql", r"mssql"],
}

SEVERITY_MAP = {
    "SSRF_AWS"       : "critical",
    "SSRF_GCP"       : "critical",
    "SSRF_INTERNAL"  : "high",
    "XSS_REFLECTED"  : "high",
    "LFI_UNIX"       : "critical",
    "LFI_WIN"        : "high",
    "SQLI_ERROR"     : "critical",
}

WAF_SIGNATURES = [
    r"cloudflare",
    r"access denied.*firewall",
    r"mod_security",
    r"request blocked",
    r"403 forbidden.*nginx",
    r"akamai.*web application",
    r"imperva",
    r"sucuri",
    r"wordfence",
    r"aws waf",
]

INTERESTING_HEADERS = [
    "x-powered-by",
    "server",
    "x-aspnet-version",
    "x-generator",
    "x-drupal",
    "x-wordpress",
    "x-frame-options",
    "content-security-policy",
    "x-xss-protection",
]


class OfflineAI:
    """
    M7Hunter ka built-in offline AI.
    
    Kya karta hai:
    1. Response analyze karta hai — false positive ya confirmed?
    2. WAF detect karta hai
    3. Technology fingerprint karta hai
    4. Payload suggest karta hai based on context
    5. Findings ko automatically rate karta hai
    6. Scan se seekhta hai (rules update karta hai)
    
    100% offline — koi API key nahi chahiye.
    """

    def __init__(self, log=None):
        self.log     = log
        self.rules   = self._load_rules()
        self.learned = self._load_learned()
        self._session_stats = {
            "analyzed" : 0,
            "confirmed": 0,
            "fp_caught": 0,
            "wafs"     : set(),
            "techs"    : set(),
        }

    def _load_rules(self) -> dict:
        if os.path.isfile(RULES_FILE):
            try:
                with open(RULES_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "custom_fp_patterns"       : [],
            "custom_confirm_patterns"  : [],
            "target_specific"          : {},
        }

    def _load_learned(self) -> dict:
        if os.path.isfile(LEARNED_FILE):
            try:
                with open(LEARNED_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "payload_success_rates" : {},
            "target_waf_map"        : {},
            "fp_signatures"         : [],
            "confirmed_signatures"  : [],
            "total_analyzed"        : 0,
        }

    def _save_learned(self):
        os.makedirs(os.path.expanduser("~/.m7hunter/"), exist_ok=True)
        with open(LEARNED_FILE, "w") as f:
            json.dump(self.learned, f, indent=2)

    # ── Core Analysis ────────────────────────────────────────────────

    def analyze_response(self, vuln_type: str, url: str,
                          response: str, payload: str = "",
                          baseline_len: int = 0) -> dict:
        """
        Main analysis function.
        Returns verdict: confirmed / potential / false_positive
        """
        self._session_stats["analyzed"] += 1
        self.learned["total_analyzed"] = self.learned.get("total_analyzed", 0) + 1

        result = {
            "verdict"         : "potential",
            "confidence"      : 0.5,
            "reason"          : [],
            "is_false_positive": False,
            "severity"        : "medium",
            "waf_detected"    : False,
            "tech_hints"      : [],
        }

        resp_lower = response.lower()

        # 1. WAF detection
        waf = self._detect_waf(resp_lower)
        if waf:
            result["waf_detected"] = True
            result["reason"].append(f"WAF detected: {waf}")
            self._session_stats["wafs"].add(waf)

        # 2. False positive check
        fp = self._check_false_positive(vuln_type, resp_lower)
        if fp:
            result["verdict"]          = "false_positive"
            result["is_false_positive"]= True
            result["confidence"]       = 0.9
            result["reason"].append(f"FP pattern: {fp}")
            self._session_stats["fp_caught"] += 1
            return result

        # 3. Confirmed pattern check
        confirmed, pattern_name = self._check_confirmed(vuln_type, resp_lower)
        if confirmed:
            result["verdict"]    = "confirmed"
            result["confidence"] = 0.95
            result["severity"]   = SEVERITY_MAP.get(pattern_name, "high")
            result["reason"].append(f"Confirmed: {pattern_name}")
            self._session_stats["confirmed"] += 1
            self._learn_signature(response[:200], "confirmed")
            return result

        # 4. Content-length diff analysis
        if baseline_len > 0 and response:
            diff = abs(len(response) - baseline_len)
            if diff > 500:
                result["confidence"] += 0.3
                result["reason"].append(f"Large response diff: {diff} bytes")
            elif diff > 100:
                result["confidence"] += 0.15
                result["reason"].append(f"Response diff: {diff} bytes")
            elif diff < 10:
                result["confidence"] -= 0.2
                result["reason"].append("Minimal response change")

        # 5. Reflection check (XSS specific)
        if vuln_type in ("XSS", "SSTI") and payload:
            # Check if payload reflected unencoded
            if payload.lower() in resp_lower:
                result["confidence"] += 0.25
                result["reason"].append("Payload reflected in response")
            # Check if critical chars preserved
            for char in ["<", ">", "\"", "'"]:
                if char in payload and char in response:
                    result["confidence"] += 0.1
                    result["reason"].append(f"Special char unescaped: {char}")

        # 6. Error message analysis
        error_signals = ["exception", "stacktrace", "syntax error",
                         "undefined variable", "fatal error", "warning:"]
        for sig in error_signals:
            if sig in resp_lower:
                result["confidence"] += 0.2
                result["reason"].append(f"Error signal: {sig}")
                break

        # 7. Payload in learned FP signatures?
        resp_hash = hashlib.md5(response[:200].encode()).hexdigest()[:8]
        if resp_hash in self.learned.get("fp_signatures", []):
            result["verdict"]          = "false_positive"
            result["is_false_positive"]= True
            result["reason"].append("Matches learned FP pattern")
            self._session_stats["fp_caught"] += 1
            return result

        # 8. Final verdict by confidence
        if result["confidence"] >= 0.8:
            result["verdict"] = "confirmed"
        elif result["confidence"] >= 0.5:
            result["verdict"] = "potential"
        else:
            result["verdict"] = "false_positive"
            result["is_false_positive"] = True

        return result

    def _detect_waf(self, resp_lower: str) -> str:
        for sig in WAF_SIGNATURES:
            if re.search(sig, resp_lower):
                return sig.split(r"\.")[0].replace("\\", "")
        return ""

    def _check_false_positive(self, vuln_type: str, resp_lower: str) -> str:
        patterns = FALSE_POSITIVE_PATTERNS.get(vuln_type, [])
        # Add learned FP patterns
        patterns += self.rules.get("custom_fp_patterns", [])
        for pattern in patterns:
            if re.search(pattern, resp_lower):
                return pattern
        return ""

    def _check_confirmed(self, vuln_type: str, resp_lower: str) -> tuple:
        vuln_prefix = vuln_type.split("_")[0]
        for pattern_name, patterns in CONFIRMED_PATTERNS.items():
            if not pattern_name.startswith(vuln_prefix):
                continue
            for pattern in patterns:
                if re.search(pattern, resp_lower, re.IGNORECASE):
                    return True, pattern_name
        # Check custom confirmed patterns
        for pattern in self.rules.get("custom_confirm_patterns", []):
            if re.search(pattern, resp_lower):
                return True, "CUSTOM"
        return False, ""

    def _learn_signature(self, response_snippet: str, verdict: str):
        """Learn from confirmed/FP responses for future scans."""
        sig = hashlib.md5(response_snippet.encode()).hexdigest()[:8]
        if verdict == "false_positive":
            sigs = self.learned.setdefault("fp_signatures", [])
            if sig not in sigs:
                sigs.append(sig)
                sigs = sigs[-100:]  # Keep last 100
                self.learned["fp_signatures"] = sigs
        elif verdict == "confirmed":
            sigs = self.learned.setdefault("confirmed_signatures", [])
            if sig not in sigs:
                sigs.append(sig)
        self._save_learned()

    # ── Fingerprinting ────────────────────────────────────────────────

    def fingerprint_response(self, headers: str, body: str) -> dict:
        """Detect tech stack from response."""
        tech = {
            "server"    : None,
            "framework" : None,
            "language"  : None,
            "cms"       : None,
            "cdn"       : None,
            "waf"       : None,
        }
        combined = (headers + body).lower()

        TECH_PATTERNS = {
            "server": {
                "nginx"  : r"nginx",
                "apache" : r"apache",
                "iis"    : r"microsoft-iis",
                "caddy"  : r"caddy",
            },
            "framework": {
                "express"    : r"express",
                "laravel"    : r"laravel|l5-debug",
                "rails"      : r"ruby on rails|x-rails",
                "django"     : r"csrftoken|django",
                "spring"     : r"x-application-context",
                "wordpress"  : r"wp-content|wordpress",
                "drupal"     : r"drupal|x-drupal",
                "joomla"     : r"joomla|joomla!",
            },
            "language": {
                "php"    : r"\.php|x-powered-by: php",
                "java"   : r"jsessionid|\.jsp|j_spring",
                "python" : r"python|wsgi",
                "ruby"   : r"\.rb|rack",
                "dotnet" : r"aspnet|\.aspx|x-aspnet",
                "node"   : r"node\.js|x-powered-by: express",
            },
            "cdn": {
                "cloudflare"  : r"cloudflare|cf-ray",
                "akamai"      : r"akamai|x-check-cacheable",
                "fastly"      : r"fastly",
                "cloudfront"  : r"cloudfront|x-amz-cf",
            },
        }

        for category, patterns in TECH_PATTERNS.items():
            for name, pattern in patterns.items():
                if re.search(pattern, combined):
                    tech[category] = name
                    self._session_stats["techs"].add(f"{category}:{name}")
                    break

        waf = self._detect_waf(combined)
        if waf:
            tech["waf"] = waf

        return tech

    # ── Payload Suggestion ────────────────────────────────────────────

    def suggest_payloads(self, vuln_type: str, context: dict) -> list:
        """
        Context-aware payload suggestions.
        context = {"waf": bool, "tech": dict, "encoding": str}
        """
        waf     = context.get("waf", False)
        tech    = context.get("tech", {})
        enc     = context.get("encoding", "none")
        lang    = tech.get("language", "")
        fw      = tech.get("framework", "")

        base_payloads = {
            "XSS": [
                '"><svg/onload=alert(1)>',
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
                "'><script>alert(1)</script>",
            ],
            "SSRF": [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:80/",
                "http://localhost/",
                "http://[::1]/",
            ],
            "LFI": [
                "../../../../etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "....//....//etc/passwd",
            ],
            "SSTI": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
            ],
        }

        payloads = list(base_payloads.get(vuln_type, []))

        # Tech-specific additions
        if vuln_type == "SSTI":
            if fw == "django" or lang == "python":
                payloads.insert(0, "{{config}}")
                payloads.insert(1, "{{self.__dict__}}")
            elif fw == "laravel" or lang == "php":
                payloads.insert(0, "{{system('id')}}")

        if vuln_type == "XSS" and waf:
            # WAF bypass variants
            payloads += [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<IMG SRC=x OnErRoR=alert(1)>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "';alert(1)//",
                "<iframe src=javascript:alert(1)>",
            ]

        # Check learned payload success rates
        rated = []
        for p in payloads:
            rate = self.learned.get("payload_success_rates", {}).get(
                hashlib.md5(p.encode()).hexdigest()[:8], 0.5)
            rated.append((p, rate))

        # Sort by success rate
        rated.sort(key=lambda x: x[1], reverse=True)
        return [p for p, _ in rated]

    def record_payload_result(self, payload: str, success: bool):
        """Learn which payloads work."""
        key = hashlib.md5(payload.encode()).hexdigest()[:8]
        rates = self.learned.setdefault("payload_success_rates", {})
        current = rates.get(key, 0.5)
        # Exponential moving average
        rates[key] = current * 0.7 + (1.0 if success else 0.0) * 0.3
        self._save_learned()

    # ── Target Intelligence ────────────────────────────────────────────

    def analyze_target_scope(self, subdomains: list, live_hosts: list) -> dict:
        """Quick analysis of target attack surface."""
        report = {
            "total_subdomains" : len(subdomains),
            "live_hosts"       : len(live_hosts),
            "api_endpoints"    : [],
            "admin_panels"     : [],
            "dev_environments" : [],
            "interesting"      : [],
        }

        API_PATTERNS     = [r"/api/", r"/v\d+/", r"/rest/", r"/graphql", r"/gql"]
        ADMIN_PATTERNS   = [r"admin\.", r"/admin", r"/dashboard", r"/panel", r"/manage"]
        DEV_PATTERNS     = [r"dev\.", r"staging\.", r"test\.", r"beta\.", r"uat\."]
        INTERESTING      = [r"vpn\.", r"mail\.", r"git\.", r"jenkins\.", r"kibana\.", r"elastic\."]

        for host in live_hosts:
            for pattern in API_PATTERNS:
                if re.search(pattern, host, re.IGNORECASE):
                    report["api_endpoints"].append(host)
                    break
            for pattern in ADMIN_PATTERNS:
                if re.search(pattern, host, re.IGNORECASE):
                    report["admin_panels"].append(host)
                    break
            for pattern in DEV_PATTERNS:
                if re.search(pattern, host, re.IGNORECASE):
                    report["dev_environments"].append(host)
                    break
            for pattern in INTERESTING:
                if re.search(pattern, host, re.IGNORECASE):
                    report["interesting"].append(host)
                    break

        return report

    def get_session_stats(self) -> dict:
        return {
            "analyzed"  : self._session_stats["analyzed"],
            "confirmed" : self._session_stats["confirmed"],
            "fp_caught" : self._session_stats["fp_caught"],
            "wafs"      : list(self._session_stats["wafs"]),
            "techs"     : list(self._session_stats["techs"]),
            "total_learned": self.learned.get("total_analyzed", 0),
        }

    def is_available(self) -> bool:
        """Always True — offline AI is always available."""
        return True

    def get_status(self) -> str:
        return f"Offline AI | {self.learned.get('total_analyzed', 0)} patterns learned"
