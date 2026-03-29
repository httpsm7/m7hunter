#!/usr/bin/env python3
# ai/offline/ollama_engine.py — 100% Offline AI using Ollama
# No API key needed. Runs locally on Kali.
# Install: curl -fsSL https://ollama.ai/install.sh | sh && ollama pull mistral
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import urllib.request
import urllib.error
import subprocess
import time
import threading

OLLAMA_URL  = "http://localhost:11434"
MODELS      = ["mistral", "llama3", "codellama", "phi3", "gemma2"]
FAST_MODEL  = "mistral"   # default fast model

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"
W="\033[97m"; DIM="\033[2m"; RST="\033[0m"


class OfflineAI:
    """
    100% Offline AI engine using Ollama.
    No internet needed after model download.
    No API keys needed ever.

    Capabilities:
    1. Analyze scan findings — rate severity, suggest exploits
    2. Generate custom nuclei templates from endpoints
    3. Analyze HTTP responses for hidden vulnerabilities
    4. Suggest bypass techniques for WAF/filters
    5. Generate bug bounty report text
    6. Classify false positives
    """

    def __init__(self, model=None, log=None):
        self.log       = log
        self.model     = model or self._detect_best_model()
        self._available = False
        self._check_thread = threading.Thread(
            target=self._check_availability, daemon=True)
        self._check_thread.start()

    def _check_availability(self):
        """Check if Ollama is running."""
        try:
            req  = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
            resp = urllib.request.urlopen(req, timeout=3)
            data = json.loads(resp.read())
            available_models = [m["name"].split(":")[0] for m in data.get("models", [])]
            if available_models:
                self._available = True
                if self.log:
                    self.log.info(f"[AI] Offline AI ready — model: {self.model}")
            else:
                if self.log:
                    self.log.warn("[AI] Ollama running but no models. Run: ollama pull mistral")
        except Exception:
            self._available = False

    def _detect_best_model(self) -> str:
        """Auto-detect best available model."""
        try:
            req  = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
            resp = urllib.request.urlopen(req, timeout=3)
            data = json.loads(resp.read())
            names = [m["name"].split(":")[0] for m in data.get("models", [])]
            for preferred in MODELS:
                if preferred in names:
                    return preferred
            return names[0] if names else FAST_MODEL
        except Exception:
            return FAST_MODEL

    def is_available(self) -> bool:
        return self._available

    def _ask(self, prompt: str, system: str = "", max_tokens: int = 500) -> str:
        """Send prompt to Ollama and get response."""
        if not self._available:
            return ""
        try:
            payload = json.dumps({
                "model"  : self.model,
                "prompt" : prompt,
                "system" : system or "You are M7Hunter AI — a security expert assistant.",
                "stream" : False,
                "options": {"num_predict": max_tokens, "temperature": 0.1}
            }).encode()
            req  = urllib.request.Request(
                f"{OLLAMA_URL}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            resp = urllib.request.urlopen(req, timeout=60)
            data = json.loads(resp.read())
            return data.get("response", "").strip()
        except Exception as e:
            if self.log:
                self.log.warn(f"[AI] Query failed: {e}")
            return ""

    # ── Core AI capabilities ───────────────────────────────────────

    def analyze_finding(self, vuln_type: str, url: str,
                        detail: str, response_snippet: str = "") -> dict:
        """
        Analyze a finding and rate it.
        Returns: {confirmed: bool, real_severity: str, reasoning: str, next_steps: list}
        """
        prompt = f"""Security finding to analyze:
Type: {vuln_type}
URL: {url}
Detail: {detail}
Response snippet: {response_snippet[:300] if response_snippet else 'N/A'}

Answer in JSON only:
{{"confirmed": true/false, "real_severity": "critical/high/medium/low/info", 
  "is_false_positive": true/false, "reasoning": "...", 
  "next_steps": ["step1", "step2"]}}"""

        system = "You are a security expert. Analyze findings and output only valid JSON. Be conservative — mark as false positive if unsure."
        resp = self._ask(prompt, system, max_tokens=300)
        try:
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', resp, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception:
            pass
        return {
            "confirmed"       : True,
            "real_severity"   : "medium",
            "is_false_positive": False,
            "reasoning"       : resp[:200] if resp else "AI analysis unavailable",
            "next_steps"      : []
        }

    def generate_nuclei_template(self, endpoint: str, param: str,
                                 vuln_type: str) -> str:
        """Generate a custom Nuclei template for a discovered endpoint."""
        prompt = f"""Create a Nuclei YAML template for:
Endpoint: {endpoint}
Parameter: {param}
Vulnerability type: {vuln_type}

Output only valid YAML nuclei template, nothing else."""

        system = "You are a Nuclei template expert. Output only valid YAML."
        return self._ask(prompt, system, max_tokens=400)

    def analyze_response(self, url: str, response: str) -> dict:
        """
        Analyze HTTP response for hidden vulnerabilities.
        Returns list of potential issues found.
        """
        prompt = f"""Analyze this HTTP response for security vulnerabilities:
URL: {url}
Response (first 500 chars):
{response[:500]}

List vulnerabilities found in JSON:
{{"vulnerabilities": [{{"type": "...", "confidence": "high/medium/low", "evidence": "..."}}]}}"""

        system = "You are a web security expert. Find real vulnerabilities only. Output JSON."
        resp = self._ask(prompt, system, max_tokens=400)
        try:
            import re
            json_match = re.search(r'\{.*\}', resp, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception:
            pass
        return {"vulnerabilities": []}

    def suggest_waf_bypass(self, payload: str, waf_detected: str = "unknown") -> list:
        """Suggest WAF bypass techniques for a blocked payload."""
        prompt = f"""WAF is blocking this payload: {payload}
WAF type: {waf_detected}

Suggest 5 bypass variations. Output as JSON list:
{{"bypasses": ["payload1", "payload2", ...]}}"""

        system = "You are a WAF bypass expert. Suggest only encoding/obfuscation bypasses."
        resp = self._ask(prompt, system, max_tokens=300)
        try:
            import re
            json_match = re.search(r'\{.*\}', resp, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return data.get("bypasses", [])
        except Exception:
            pass
        return []

    def generate_report_text(self, finding: dict) -> str:
        """Generate professional bug bounty report text for a finding."""
        prompt = f"""Write a professional bug bounty report for:
Vulnerability: {finding.get('type', '')}
URL: {finding.get('url', '')}
Severity: {finding.get('severity', '')}
Detail: {finding.get('detail', '')}

Include: Summary, Steps to Reproduce, Impact, Recommendation.
Keep it concise and professional."""

        system = "You are a professional bug bounty hunter writing reports for HackerOne/Bugcrowd."
        return self._ask(prompt, system, max_tokens=600)

    def classify_false_positive(self, vuln_type: str, url: str,
                                 response_diff: int, status_code: int) -> bool:
        """AI-powered false positive classification."""
        prompt = f"""Is this a false positive?
Vuln type: {vuln_type}
URL: {url}
Response length diff: {response_diff} bytes
Status code: {status_code}

Answer only: true (is false positive) or false (is real finding)"""

        resp = self._ask(prompt, max_tokens=10)
        return "true" in resp.lower()

    def chat(self, message: str) -> str:
        """Free-form security chat with AI."""
        system = """You are M7Hunter AI — an expert bug bounty hunter and security researcher.
Help with: vulnerability analysis, payload generation, bypass techniques, report writing.
Be concise and practical."""
        return self._ask(message, system, max_tokens=500)

    # ── Ollama management ──────────────────────────────────────────

    @staticmethod
    def install_ollama() -> bool:
        """Install Ollama on Kali Linux."""
        try:
            r = subprocess.run(
                "curl -fsSL https://ollama.ai/install.sh | sh",
                shell=True, capture_output=True, timeout=300
            )
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def pull_model(model: str = "mistral") -> bool:
        """Download AI model."""
        try:
            r = subprocess.run(
                f"ollama pull {model}",
                shell=True, capture_output=False, timeout=1800
            )
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def list_models() -> list:
        """List available local models."""
        try:
            req  = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
            resp = urllib.request.urlopen(req, timeout=3)
            data = json.loads(resp.read())
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    @staticmethod
    def start_ollama() -> bool:
        """Start Ollama service if not running."""
        try:
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)
            return True
        except Exception:
            return False
