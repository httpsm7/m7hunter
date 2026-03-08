#!/usr/bin/env python3
# core/utils.py — Format auto-fixer + helpers

import os
import sys
import re

# ─────────────────────────────────────────────────────────────────────
#  ROOT CHECK
# ─────────────────────────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        print("\n\033[91m[!] M7Hunter requires root privileges!\033[0m")
        print("\033[93m    Run: sudo python3 m7hunter.py\033[0m\n")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────
#  FILE PREFIX  (first 3 letters of domain, safe chars only)
# ─────────────────────────────────────────────────────────────────────

def get_prefix(target: str) -> str:
    """
    Extract clean domain name and return first 3 letters as prefix.
    example.com     → exa
    https://abc.com → abc
    192.168.1.1     → 192
    sub.example.com → sub
    """
    # Strip scheme
    domain = re.sub(r'^https?://', '', target).strip()
    # Strip port + path
    domain = re.split(r'[:/]', domain)[0]
    # Take first label of hostname
    label  = domain.split('.')[0]
    # Keep only alnum, take first 3
    clean  = re.sub(r'[^a-zA-Z0-9]', '', label)
    return (clean[:3] if len(clean) >= 3 else clean.ljust(3, '0')).lower()


# ─────────────────────────────────────────────────────────────────────
#  FORMAT AUTO-FIXER
#  Each tool expects a specific input format. This normalises a file
#  of mixed targets so that every line matches what the tool needs.
# ─────────────────────────────────────────────────────────────────────

class FormatFixer:
    """
    Reads a file whose lines may contain bare domains, URLs, IPs or
    a mixture, then writes a normalised version for the given tool.

    Modes
    ─────
    'domain'  → bare domain only          example.com
    'url'     → https:// prefixed URL     https://example.com
    'ip'      → IPv4 only (skip others)   1.2.3.4
    'host'    → domain or IP, no scheme   example.com / 1.2.3.4
    'any'     → pass through unchanged
    """

    @staticmethod
    def _is_ip(value: str) -> bool:
        parts = value.split('.')
        try:
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @staticmethod
    def _strip_scheme(line: str) -> str:
        return re.sub(r'^https?://', '', line).rstrip('/')

    @staticmethod
    def _strip_path(line: str) -> str:
        return re.split(r'[:/]', FormatFixer._strip_scheme(line))[0]

    @classmethod
    def fix(cls, src_file: str, dst_file: str, mode: str) -> int:
        """
        Convert src_file → dst_file according to mode.
        Returns number of lines written.
        """
        if not os.path.isfile(src_file):
            return 0

        with open(src_file) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

        out_lines = []
        for line in lines:
            bare = cls._strip_path(line)     # pure host / IP
            if not bare:
                continue

            if mode == 'domain':
                # Remove any trailing port
                out_lines.append(bare.split(':')[0])

            elif mode == 'url':
                # Add https:// if missing; keep existing scheme if http://
                if line.startswith('http://'):
                    out_lines.append(f"http://{bare}")
                else:
                    out_lines.append(f"https://{bare}")

            elif mode == 'ip':
                if cls._is_ip(bare):
                    out_lines.append(bare)
                # If it's a domain, skip (caller should resolve first)

            elif mode == 'host':
                out_lines.append(bare)

            else:  # 'any'
                out_lines.append(line)

        # Deduplicate, preserve order
        seen = set()
        deduped = []
        for l in out_lines:
            if l not in seen:
                seen.add(l)
                deduped.append(l)

        with open(dst_file, 'w') as f:
            f.write('\n'.join(deduped) + '\n')

        return len(deduped)


# ─────────────────────────────────────────────────────────────────────
#  MISC HELPERS
# ─────────────────────────────────────────────────────────────────────

def count_lines(path: str) -> int:
    try:
        with open(path) as f:
            return sum(1 for l in f if l.strip())
    except Exception:
        return 0


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def safe_read(path: str) -> list:
    """Return list of non-empty lines from a file (silently if missing)."""
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []
