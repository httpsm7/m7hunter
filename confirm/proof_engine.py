#!/usr/bin/env python3
# confirm/proof_engine.py — M7Hunter v5.0 Proof Engine
# Generates reproducible evidence for every confirmed finding
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import base64
import urllib.parse
import time


class ProofEngine:
    """
    V5 Proof Engine — For every confirmed finding, generates:

    1. curl command (copy-paste ready)
    2. Raw HTTP request
    3. Base64-encoded PoC
    4. Reproduction steps (numbered)
    5. Structured proof JSON
    """

    def __init__(self, log=None):
        self.log = log

    def generate(self, finding: dict) -> dict:
        """Generate complete proof for a confirmed finding."""
        url       = finding.get("url", "")
        vuln_type = finding.get("type", "UNKNOWN")
        payload   = finding.get("payload", "")
        detail    = finding.get("detail", "")
        tool      = finding.get("tool", "")
        severity  = finding.get("severity", "medium")

        proof = {
            "generated_at"      : time.strftime("%Y-%m-%d %H:%M:%S"),
            "vuln_type"         : vuln_type,
            "url"               : url,
            "severity"          : severity,
            "curl_command"      : self._build_curl(url, vuln_type, payload),
            "raw_http"          : self._build_raw_http(url, vuln_type, payload),
            "poc_base64"        : self._build_poc_b64(url, payload),
            "repro_steps"       : self._build_repro_steps(vuln_type, url, payload, detail),
            "impact"            : self._get_impact(vuln_type),
            "remediation"       : self._get_remediation(vuln_type),
            "cvss_vector"       : self._get_cvss_vector(vuln_type, severity),
            "references"        : self._get_references(vuln_type),
            "tool_used"         : tool,
            "payload_used"      : payload,
        }
        return proof

    # ── curl command ─────────────────────────────────────────────────
    def _build_curl(self, url: str, vuln_type: str, payload: str) -> str:
        vt = vuln_type.split("_")[0].upper()

        if vt == "SSRF":
            return (
                f'curl -sk --connect-timeout 10 '
                f'-H "User-Agent: M7Hunter-PoC/5.0" '
                f'"{url}" -o - | head -50'
            )
        elif vt == "XSS":
            return (
                f'curl -sk --connect-timeout 10 '
                f'-H "User-Agent: M7Hunter-PoC/5.0" '
                f'"{url}" | grep -i "alert|svg|onerror"'
            )
        elif vt == "LFI":
            return (
                f'curl -sk --connect-timeout 10 '
                f'"{url}" | grep -E "root:x:|daemon:|bin/bash"'
            )
        elif vt == "SQLI":
            return (
                f'curl -sk --connect-timeout 10 '
                f'"{url}" | grep -iE "sql|mysql|syntax|error"'
            )
        elif vt == "SSTI":
            return (
                f'curl -sk --connect-timeout 10 '
                f'"{url}" | grep -E "\\b49\\b|7777777|uid="'
            )
        elif vt == "XXE":
            return (
                f'curl -sk --connect-timeout 10 -X POST '
                f'-H "Content-Type: application/xml" '
                f'-d \'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>\' '
                f'"{url}" | grep "root:x"'
            )
        elif vt in ("CORS", "CORS_MISCONFIG"):
            return (
                f'curl -sk --connect-timeout 10 '
                f'-H "Origin: https://evil.com" '
                f'-H "User-Agent: M7Hunter-PoC/5.0" '
                f'-I "{url}" | grep -i "access-control"'
            )
        elif vt in ("REDIRECT", "OPEN_REDIRECT"):
            return (
                f'curl -sk --connect-timeout 10 '
                f'-v "{url}" 2>&1 | grep -i "location:"'
            )
        elif vt in ("SUBDOMAIN_TAKEOVER", "TAKEOVER"):
            return (
                f'curl -sk --connect-timeout 10 '
                f'"{url}" | head -20'
            )
        else:
            return (
                f'curl -sk --connect-timeout 10 '
                f'-H "User-Agent: M7Hunter-PoC/5.0" '
                f'"{url}"'
            )

    # ── Raw HTTP request ─────────────────────────────────────────────
    def _build_raw_http(self, url: str, vuln_type: str, payload: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            host   = parsed.netloc or parsed.path
            path   = parsed.path or "/"
            query  = ("?" + parsed.query) if parsed.query else ""
            vt     = vuln_type.split("_")[0].upper()

            if vt == "XXE":
                body = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
                return (
                    f"POST {path}{query} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/xml\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"User-Agent: M7Hunter-PoC/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}"
                )
            elif vt in ("CORS", "CORS_MISCONFIG"):
                return (
                    f"GET {path}{query} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Origin: https://evil.com\r\n"
                    f"User-Agent: M7Hunter-PoC/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
            else:
                return (
                    f"GET {path}{query} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: M7Hunter-PoC/5.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                )
        except Exception:
            return f"GET {url} HTTP/1.1\r\nHost: target\r\n\r\n"

    # ── Base64 PoC ────────────────────────────────────────────────────
    def _build_poc_b64(self, url: str, payload: str) -> str:
        poc = f"Target: {url}\nPayload: {payload}\nTool: M7Hunter v5.0"
        return base64.b64encode(poc.encode()).decode()

    # ── Reproduction steps ────────────────────────────────────────────
    def _build_repro_steps(self, vuln_type: str, url: str,
                            payload: str, detail: str) -> list:
        vt = vuln_type.split("_")[0].upper()

        steps = {
            "SSRF": [
                "Open Burp Suite and configure browser proxy",
                f"Navigate to the target URL: {url}",
                "Intercept the request and locate the URL/redirect parameter",
                f"Replace the parameter value with: {payload or 'http://169.254.169.254/latest/meta-data/'}",
                "Forward the request and observe the response",
                "Expected: AWS metadata content (ami-id, instance-id, etc.) in response body",
                "For blind SSRF: Configure Burp Collaborator and use your collaborator URL as payload",
            ],
            "XSS": [
                "Open a modern browser (Chrome/Firefox)",
                f"Navigate to the vulnerable URL: {url}",
                "Observe that the JavaScript payload executes (alert dialog appears)",
                f"Payload used: {payload or '<svg/onload=alert(1)>'}",
                "Verify the payload is reflected without HTML encoding in the page source",
                "To test for stored XSS: submit payload via POST form, then visit the page where content is rendered",
            ],
            "LFI": [
                "Open terminal or Burp Suite",
                f"Send GET request to: {url}",
                "Observe the response body",
                "Expected: Contents of /etc/passwd including 'root:x:0:0:'",
                f"Payload used: {payload or '../../../../etc/passwd'}",
                "Attempt deeper traversal if initial depth fails: ../../../../../etc/passwd",
            ],
            "SQLI": [
                "Open Burp Suite and intercept request to the vulnerable endpoint",
                f"Target URL: {url}",
                "Inject the SQLi payload into the vulnerable parameter",
                f"Payload: {payload or chr(39) + chr(32) + chr(79) + chr(82) + chr(32) + chr(49) + chr(61) + chr(49)} ",
                "Observe the SQL error message in the response",
                "Use sqlmap for automated exploitation: sqlmap -u '<url>' --batch --dbs",
            ],
            "SSTI": [
                f"Navigate to the vulnerable URL: {url}",
                f"Inject SSTI probe payload: {payload or '{{7*7}}'}",
                "Expected response: 49 (or 7777777 for Jinja2 string multiplication)",
                "Identify the template engine from the response behavior",
                "For RCE: use engine-specific payload (see references)",
            ],
            "IDOR": [
                "Authenticate as a regular user and capture your user ID",
                f"Navigate to: {url}",
                "Change the ID parameter to another user's ID (increment/decrement)",
                "Observe if another user's data is returned",
                "Test both numeric IDs and UUIDs",
                "Document any sensitive data exposed (email, phone, address)",
            ],
        }

        return steps.get(vt, [
            f"1. Navigate to: {url}",
            f"2. Apply the payload: {payload}",
            f"3. Observe the response for vulnerability indicators",
            f"4. Detail: {detail}",
        ])

    # ── Impact descriptions ───────────────────────────────────────────
    def _get_impact(self, vuln_type: str) -> str:
        vt = vuln_type.split("_")[0].upper()
        impacts = {
            "SSRF"    : "Attacker can make server-side requests to internal services, cloud metadata APIs, and other internal resources. May lead to credential theft, internal service discovery, or further network access.",
            "XSS"     : "Attacker can execute arbitrary JavaScript in victim's browser context. May lead to session token theft, credential harvesting, keylogging, or forced actions on behalf of the victim.",
            "LFI"     : "Attacker can read arbitrary files from the server. May expose /etc/passwd, configuration files, private keys, application source code, or database credentials.",
            "SQLI"    : "Attacker can manipulate SQL queries. May lead to authentication bypass, data exfiltration of entire database, data modification, or remote code execution via LOAD_FILE/INTO OUTFILE.",
            "SSTI"    : "Attacker can execute arbitrary code via template engine injection. Typically leads to full Remote Code Execution (RCE) on the server.",
            "IDOR"    : "Attacker can access, modify, or delete resources belonging to other users without authorization. Violation of data confidentiality and integrity.",
            "XXE"     : "Attacker can read local files, perform SSRF, or cause denial of service via XML external entity processing.",
            "JWT"     : "Attacker can forge authentication tokens, escalate privileges, or access other users' accounts.",
            "CORS"    : "Attacker can make cross-origin requests from evil.com and read the response, potentially stealing sensitive data from authenticated sessions.",
            "REDIRECT": "Attacker can redirect users to malicious sites, enabling phishing, credential theft, or malware distribution.",
            "CMDI"    : "Attacker can execute arbitrary OS commands on the server, leading to full system compromise.",
            "TAKEOVER": "Attacker can claim the subdomain and serve arbitrary content under the target's domain, enabling phishing, credential theft, or malware distribution.",
        }
        return impacts.get(vt, f"Security vulnerability of type {vuln_type} — review and assess impact based on context.")

    # ── Remediation ───────────────────────────────────────────────────
    def _get_remediation(self, vuln_type: str) -> str:
        vt = vuln_type.split("_")[0].upper()
        remediations = {
            "SSRF"    : "Implement allowlist of permitted destinations. Disable redirects. Block requests to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254). Use a dedicated egress proxy.",
            "XSS"     : "Implement context-aware output encoding (HTML, JavaScript, URL contexts). Set Content-Security-Policy header. Use HTTPOnly and Secure cookie flags. Validate and sanitize all user input.",
            "LFI"     : "Use realpath() or equivalent to resolve paths and validate they are within the intended directory. Avoid passing user input directly to file operations. Maintain a whitelist of allowed files.",
            "SQLI"    : "Use parameterized queries (prepared statements) exclusively. Never concatenate user input into SQL queries. Apply least-privilege database accounts. Use ORM frameworks.",
            "SSTI"    : "Never pass user input to template rendering functions. Use logic-less templates where possible. If dynamic templates are required, run in a sandboxed environment.",
            "IDOR"    : "Implement server-side authorization checks for every resource access. Use indirect object references (map internal IDs to random tokens). Log all access attempts.",
            "XXE"     : "Disable XML external entity processing in all XML parsers. Use a whitelist for XML input. Upgrade XML libraries. Use less complex data formats (JSON) where possible.",
            "JWT"     : "Enforce algorithm verification (reject 'none' algorithm). Use strong random secrets (256+ bits for HS256). Implement token expiration. Validate all claims server-side.",
            "CORS"    : "Implement strict allowlist of permitted origins. Never reflect Origin header directly. Validate combination of Origin + credentials together. Avoid Access-Control-Allow-Origin: *.",
            "REDIRECT": "Maintain allowlist of permitted redirect destinations. Use indirect redirects with token mapping. Warn users when redirecting to external domains.",
            "CMDI"    : "Never pass user input to system commands. Use language-native APIs instead of shell commands. If shell is required, use strict allowlist validation and escape all special characters.",
            "TAKEOVER": "Implement monitoring for dangling DNS records. Remove DNS records before decommissioning services. Regularly audit all subdomains and their corresponding services.",
        }
        return remediations.get(vt, "Review and patch based on vulnerability type. Apply principle of least privilege and input validation.")

    # ── CVSS vector ───────────────────────────────────────────────────
    def _get_cvss_vector(self, vuln_type: str, severity: str) -> dict:
        vt = vuln_type.split("_")[0].upper()
        vectors = {
            "SSRF"    : {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "score": 8.6},
            "XSS"     : {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "score": 8.2},
            "LFI"     : {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
            "SQLI"    : {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
            "SSTI"    : {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
            "IDOR"    : {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "score": 8.1},
            "XXE"     : {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
            "JWT"     : {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": 7.4},
            "CORS"    : {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", "score": 7.1},
            "REDIRECT": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1},
            "CMDI"    : {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
            "TAKEOVER": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": 9.1},
        }
        return vectors.get(vt, {"vector": "N/A", "score": 5.0})

    # ── References ────────────────────────────────────────────────────
    def _get_references(self, vuln_type: str) -> list:
        vt = vuln_type.split("_")[0].upper()
        refs = {
            "SSRF"    : ["https://portswigger.net/web-security/ssrf", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
            "XSS"     : ["https://portswigger.net/web-security/cross-site-scripting", "https://owasp.org/www-community/attacks/xss/"],
            "LFI"     : ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"],
            "SQLI"    : ["https://portswigger.net/web-security/sql-injection", "https://owasp.org/www-community/attacks/SQL_Injection"],
            "SSTI"    : ["https://portswigger.net/web-security/server-side-template-injection", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"],
            "IDOR"    : ["https://portswigger.net/web-security/access-control/idor", "https://owasp.org/www-chapter-ghana/assets/slides/IDOR.pdf"],
            "XXE"     : ["https://portswigger.net/web-security/xxe", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
            "JWT"     : ["https://portswigger.net/web-security/jwt", "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
            "CORS"    : ["https://portswigger.net/web-security/cors", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"],
            "REDIRECT": ["https://portswigger.net/kb/issues/00500100_open-redirection-reflected", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client_Side_URL_Redirect"],
            "CMDI"    : ["https://portswigger.net/web-security/os-command-injection", "https://owasp.org/www-community/attacks/Command_Injection"],
            "TAKEOVER": ["https://github.com/EdOverflow/can-i-take-over-xyz", "https://0xpatrik.com/subdomain-takeover/"],
        }
        return refs.get(vt, ["https://owasp.org/www-project-top-ten/"])
