#!/usr/bin/env python3
# confirm/confidence.py — M7Hunter v5.0 Confidence Engine
# Multi-signal vulnerability confirmation with 0.0-1.0 scoring
# MilkyWay Intelligence | Author: Sharlix

import re
import hashlib

# ── Confirmed indicators per vuln type ───────────────────────────────
CONFIRMED_INDICATORS = {
    "SSRF": [
        (r"ami-id",                                0.95),
        (r"instance-id",                           0.95),
        (r"local-ipv4",                            0.95),
        (r"security-credentials",                  0.95),
        (r"AccessKeyId",                           0.95),
        (r"computeMetadata",                       0.90),
        (r"service-accounts",                      0.90),
        (r"subscriptionId",                        0.90),
        (r"169\.254\.169\.254",                    0.70),
    ],
    "XSS": [
        (r"<script[^>]*>alert\(1\)",              0.95),
        (r"<svg[^>]*(onload|onerror)=['\"]?alert",0.90),
        (r"<img[^>]*onerror=['\"]?alert",         0.90),
        (r"javascript:alert\(1\)",                0.85),
        (r"on(mouseover|focus|load)=['\"]?alert", 0.80),
    ],
    "LFI": [
        (r"root:x?:\d+:\d+:",                     0.99),
        (r"daemon:[^:]+:\d+:\d+:",               0.95),
        (r"\[boot loader\]",                      0.99),
        (r"\[fonts\].*\[extensions\]",            0.95),
        (r"Linux version \d+\.\d+",              0.90),
        (r"BEGIN RSA PRIVATE KEY",               0.99),
    ],
    "SQLI": [
        (r"SQL syntax.*MySQL",                    0.95),
        (r"Warning.*mysql_",                      0.90),
        (r"ORA-\d{4,5}:",                         0.95),
        (r"PostgreSQL.*ERROR",                    0.90),
        (r"Unclosed quotation mark",             0.90),
        (r"SQLSTATE\[",                           0.85),
    ],
    "SSTI": [
        (r"\b49\b",                               0.80),
        (r"\b7777777\b",                          0.95),
        (r"uid=\d+\(",                            0.99),
        (r"Twig_Environment",                     0.90),
    ],
    "XXE": [
        (r"root:x?:\d+:\d+:",                     0.99),
        (r"\[boot loader\]",                      0.99),
        (r"BEGIN RSA PRIVATE KEY",               0.99),
    ],
    "JWT": [
        (r"uid=\d+\(",                            0.99),
        (r"\"role\":\s*\"admin\"",               0.85),
        (r"\"admin\":\s*true",                   0.85),
    ],
    "CMDI": [
        (r"uid=\d+\(",                            0.99),
        (r"root:x?:\d+:\d+:",                     0.95),
    ],
    "IDOR": [
        (r"\"email\":\s*\"[^\"]+@",              0.75),
        (r"\"phone\":\s*\"[\d\+\-\s]+\"",        0.75),
    ],
}

# ── False positive patterns ───────────────────────────────────────────
FP_PATTERNS = {
    "SSRF": [
        r"connection refused",
        r"no route to host",
        r"network unreachable",
        r"invalid url",
        r"connection timed out",
        r"connection reset",
    ],
    "XSS": [
        r"&lt;script",
        r"&lt;svg",
        r"&#x3c;script",
        r"\\u003cscript",
        r"X-XSS-Protection: 1",
        r"Content-Security-Policy:.*script-src.*'none'",
    ],
    "LFI": [
        r"file not found",
        r"no such file",
        r"permission denied",
        r"access denied",
        r"invalid path",
    ],
    "SQLI": [
        r"please enter a valid",
        r"invalid input",
        r"bad request",
    ],
}


class ConfidenceEngine:
    """
    V5 Multi-Signal Confidence Scoring Engine.

    Combines:
    1. Response pattern matching (confirmed indicators)
    2. Content-length differential
    3. Reflection analysis
    4. Error signal detection
    5. Offline AI verdict
    6. OOB callback (if applicable)
    7. Timing anomaly

    Output:
      score  : 0.0–1.0
      status : confirmed | potential | false_positive
      signals: list of matched signals with weights
    """

    THRESHOLDS = {
        "confirmed"      : 0.85,
        "potential"      : 0.50,
        "false_positive" : 0.50,   # below this = discard
    }

    def __init__(self, offline_ai=None, threshold: float = 0.8):
        self.offline_ai = offline_ai
        self.threshold  = threshold

    def score(self, vuln_type: str, url: str, detail: str = "",
              response: str = "", payload: str = "",
              ai_analysis: dict = None, tool: str = "",
              baseline_len: int = 0, response_time: float = 0.0,
              oob_hit: bool = False) -> dict:
        """
        Score a potential finding.

        Returns:
          {
            "score"  : float,
            "status" : str,
            "signals": list[dict]
          }
        """
        signals = []
        score   = 0.0
        resp_lower = response.lower() if response else ""

        # ── 1. Confirmed indicator pattern matching ────────────────
        vtype_upper = vuln_type.split("_")[0].upper()
        indicators  = CONFIRMED_INDICATORS.get(vtype_upper, [])
        for pattern, weight in indicators:
            if re.search(pattern, response, re.IGNORECASE):
                score = max(score, weight)
                signals.append({
                    "type"   : "confirmed_pattern",
                    "pattern": pattern[:60],
                    "weight" : weight,
                })
                if weight >= 0.95:
                    # Strong confirmed signal — stop here
                    return self._result(min(score, 1.0), signals, vuln_type)

        # ── 2. False positive filter ───────────────────────────────
        fp_patterns = FP_PATTERNS.get(vtype_upper, [])
        for pattern in fp_patterns:
            if re.search(pattern, resp_lower):
                signals.append({
                    "type"   : "false_positive_pattern",
                    "pattern": pattern[:60],
                    "weight" : -0.9,
                })
                score = max(0.0, score - 0.5)
                if score < 0.2:
                    return {
                        "score"  : score,
                        "status" : "false_positive",
                        "signals": signals,
                    }

        # ── 3. Content-length differential ────────────────────────
        if baseline_len > 0 and response:
            diff = abs(len(response) - baseline_len)
            if diff > 500:
                w = 0.30
                signals.append({"type": "len_diff_large", "diff": diff, "weight": w})
                score += w
            elif diff > 100:
                w = 0.15
                signals.append({"type": "len_diff_medium", "diff": diff, "weight": w})
                score += w
            elif diff < 10:
                w = -0.15
                signals.append({"type": "len_diff_minimal", "diff": diff, "weight": w})
                score += w

        # ── 4. Payload reflection (XSS/SSTI/IDOR) ─────────────────
        if payload and vtype_upper in ("XSS", "SSTI", "IDOR", "CORS"):
            if payload.lower() in resp_lower:
                # Check if encoded
                if ("&lt;" in resp_lower or "&amp;" in resp_lower
                        or "\\u003c" in resp_lower):
                    signals.append({"type": "encoded_reflection", "weight": -0.2})
                    score -= 0.2
                else:
                    w = 0.35
                    signals.append({"type": "unencoded_reflection", "weight": w})
                    score += w
                    # Special chars unescaped?
                    for ch in ["<", ">", '"', "'"]:
                        if ch in payload and ch in response:
                            signals.append({"type": f"special_char_{ch}", "weight": 0.10})
                            score += 0.10

        # ── 5. Error signals ──────────────────────────────────────
        error_signals = [
            ("exception",          0.15),
            ("stacktrace",         0.15),
            ("stack trace",        0.15),
            ("internal server error", 0.10),
            ("syntax error",       0.10),
            ("fatal error",        0.15),
            ("undefined variable", 0.10),
            ("unhandled exception",0.20),
        ]
        for sig, w in error_signals:
            if sig in resp_lower:
                signals.append({"type": "error_signal", "signal": sig, "weight": w})
                score += w
                break

        # ── 6. Timing anomaly (blind vulns) ───────────────────────
        if response_time > 5.0 and vtype_upper in ("SQLI", "SSRF", "CMDI"):
            w = 0.40
            signals.append({"type": "timing_delay", "seconds": response_time, "weight": w})
            score += w

        # ── 7. OOB callback ───────────────────────────────────────
        if oob_hit:
            score = max(score, 0.95)
            signals.append({"type": "oob_callback", "weight": 0.95})
            return self._result(min(score, 1.0), signals, vuln_type)

        # ── 8. AI analysis result ─────────────────────────────────
        if ai_analysis:
            ai_verdict = ai_analysis.get("verdict", "potential")
            ai_conf    = ai_analysis.get("confidence", 0.5)
            if ai_verdict == "confirmed":
                score += 0.20
                signals.append({"type": "ai_confirmed", "confidence": ai_conf, "weight": 0.20})
            elif ai_verdict == "false_positive":
                score -= 0.30
                signals.append({"type": "ai_fp", "confidence": ai_conf, "weight": -0.30})

        # ── 9. Base score from severity ───────────────────────────
        if score == 0.0:
            score = 0.30  # Base potential

        return self._result(min(score, 1.0), signals, vuln_type)

    def _result(self, score: float, signals: list, vuln_type: str) -> dict:
        if score >= self.THRESHOLDS["confirmed"] or score >= self.threshold:
            status = "confirmed"
        elif score >= self.THRESHOLDS["potential"]:
            status = "potential"
        else:
            status = "false_positive"

        return {
            "score"    : round(score, 3),
            "status"   : status,
            "signals"  : signals,
            "vuln_type": vuln_type,
        }
