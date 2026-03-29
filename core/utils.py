#!/usr/bin/env python3
import os, sys, re

def check_root():
    if os.geteuid() != 0:
        print("\n\033[91m[!] M7Hunter requires root!\033[0m")
        print("\033[93m    Run: sudo python3 m7hunter.py\033[0m\n")
        sys.exit(1)

def get_prefix(target: str) -> str:
    domain = re.sub(r'^https?://', '', target).strip()
    domain = re.split(r'[:/]', domain)[0]
    label  = domain.split('.')[0]
    clean  = re.sub(r'[^a-zA-Z0-9]', '', label)
    return (clean[:3] if len(clean) >= 3 else clean.ljust(3,'0')).lower()

class FormatFixer:
    @staticmethod
    def _is_ip(v):
        parts = v.split('.')
        try:    return len(parts)==4 and all(0<=int(p)<=255 for p in parts)
        except: return False

    @staticmethod
    def _bare(line):
        # Strip httpx-style suffix: "https://host.com [200] [Title] [tech]"
        line = line.strip()
        line = re.sub(r'\s+\[.*', '', line)          # strip [200][Title]...
        line = re.sub(r'^https?://', '', line)        # strip scheme
        line = re.split(r'[:/]', line)[0]             # strip port/path
        return line.strip()

    @classmethod
    def fix(cls, src, dst, mode) -> int:
        if not os.path.isfile(src): return 0
        with open(src) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        out = []
        for line in lines:
            bare = cls._bare(line)
            if not bare: continue
            if   mode == 'domain': out.append(bare.split(':')[0])
            elif mode == 'url':
                scheme = 'http' if line.startswith('http://') else 'https'
                out.append(f"{scheme}://{bare}")
            elif mode == 'ip':
                if cls._is_ip(bare): out.append(bare)
            elif mode == 'host':   out.append(bare)
            else:                  out.append(line)
        seen, deduped = set(), []
        for l in out:
            if l not in seen:
                seen.add(l); deduped.append(l)
        with open(dst,'w') as f:
            f.write('\n'.join(deduped)+'\n')
        return len(deduped)

def count_lines(path):
    try:
        with open(path) as f: return sum(1 for l in f if l.strip())
    except: return 0

def ensure_dir(path): os.makedirs(path, exist_ok=True)

def safe_read(path):
    try:
        with open(path) as f: return [l.strip() for l in f if l.strip()]
    except: return []

def is_in_scope(url, scope):
    """Return True if url matches any scope entry, or scope is empty."""
    if not scope: return True
    url_lower = url.lower()
    for s in scope:
        s = s.strip().lower()
        if s in url_lower or url_lower.endswith(s):
            return True
    return False
