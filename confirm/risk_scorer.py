#!/usr/bin/env python3
# confirm/risk_scorer.py — M7Hunter v5.0 Risk Scoring Engine
# CVSS-like risk scoring with confidence + automation factors
# MilkyWay Intelligence | Author: Sharlix


class RiskScorer:
    """
    V5 CVSS-like Risk Scoring Engine.

    Score = (Exploitability × Impact × Confidence × Automation) / 4
    Each dimension: 0.0 - 10.0
    Final score:    0.0 - 10.0

    Severity bands:
      9.0-10.0 → Critical
      7.0-8.9  → High
      4.0-6.9  → Medium
      0.1-3.9  → Low
      0.0      → Info
    """

    EXPLOITABILITY = {
        "SQLI"    : 9.5, "CMDI"    : 9.5, "SSTI"    : 9.5,
        "SSRF"    : 8.6, "XXE"     : 8.0, "LFI"     : 8.0,
        "XSS"     : 8.2, "IDOR"    : 7.8, "TAKEOVER": 8.5,
        "JWT"     : 7.5, "CORS"    : 6.8, "REDIRECT": 6.1,
        "SMUGGLING":8.0, "GRAPHQL" : 7.0, "HOST_HEADER":7.0,
        "SSTI"    : 9.5, "DEFAULT" : 5.0,
    }

    IMPACT = {
        "SQLI"    : 9.8, "CMDI"    : 9.8, "SSTI"    : 9.8,
        "SSRF"    : 8.6, "XXE"     : 7.5, "LFI"     : 7.5,
        "XSS"     : 8.2, "IDOR"    : 8.1, "TAKEOVER": 9.1,
        "JWT"     : 7.4, "CORS"    : 7.1, "REDIRECT": 6.1,
        "SMUGGLING":8.0, "GRAPHQL" : 6.5, "HOST_HEADER":7.0,
        "DEFAULT" : 5.0,
    }

    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high"    : 0.8,
        "medium"  : 0.6,
        "low"     : 0.4,
        "info"    : 0.2,
    }

    def score(self, finding: dict) -> dict:
        """Calculate risk score for a finding."""
        vt         = finding.get("type", "DEFAULT").split("_")[0].upper()
        severity   = finding.get("severity", "medium").lower()
        confidence = finding.get("confidence", 0.5)
        status     = finding.get("status", "potential")
        tool       = finding.get("tool", "")

        # Exploitability
        exploit = self.EXPLOITABILITY.get(vt, self.EXPLOITABILITY["DEFAULT"])

        # Impact
        impact = self.IMPACT.get(vt, self.IMPACT["DEFAULT"])

        # Confidence factor (0.0–1.0)
        conf_factor = confidence

        # Automation factor — how easy to auto-exploit?
        auto_map = {
            "sqlmap"    : 0.95, "dalfox"    : 0.90,
            "nuclei"    : 0.80, "subzy"     : 0.90,
            "interactsh": 0.85, "ssrf_engine": 0.70,
            "ssti-engine":0.70, "jwt-engine": 0.75,
            "cloud-enum": 0.80, "graphql"   : 0.70,
        }
        auto = auto_map.get(tool, 0.60)

        # Status multiplier
        status_mult = 1.0 if status == "confirmed" else 0.7

        # Severity baseline
        sev_weight = self.SEVERITY_WEIGHTS.get(severity, 0.6)

        # Calculate dimensions
        d_exploitability = exploit * sev_weight
        d_impact         = impact  * sev_weight
        d_confidence     = conf_factor * 10.0
        d_automation     = auto * 10.0

        # Final score
        total = (
            d_exploitability * 0.30 +
            d_impact         * 0.35 +
            d_confidence     * 0.20 +
            d_automation     * 0.15
        ) * status_mult

        total = min(round(total, 2), 10.0)

        # Severity band
        if total >= 9.0:     band = "Critical"
        elif total >= 7.0:   band = "High"
        elif total >= 4.0:   band = "Medium"
        elif total > 0.0:    band = "Low"
        else:                band = "Info"

        return {
            "total"           : total,
            "band"            : band,
            "dimensions"      : {
                "exploitability": round(d_exploitability, 2),
                "impact"        : round(d_impact, 2),
                "confidence"    : round(d_confidence, 2),
                "automation"    : round(d_automation, 2),
            },
            "factors"         : {
                "base_exploitability": exploit,
                "base_impact"        : impact,
                "confidence_score"   : confidence,
                "automation_score"   : auto,
                "status_multiplier"  : status_mult,
                "severity_weight"    : sev_weight,
            }
        }
