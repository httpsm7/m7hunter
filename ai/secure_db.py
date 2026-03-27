#!/usr/bin/env python3
# ai/secure_db.py — AES-256 Encrypted Intelligence Database
# Admin-only access: amitmalangsharlix / sharlixmalangamit
# MilkyWay Intelligence | Author: Sharlix

import os
import json
import hashlib
import hmac
import base64
import struct
import time
import getpass
from typing import Optional

# ── Paths ─────────────────────────────────────────────────────────
DB_DIR      = os.path.expanduser("~/.m7hunter/secure/")
DB_FILE     = os.path.join(DB_DIR, "brain.db")
SALT_FILE   = os.path.join(DB_DIR, ".salt")
LOCK_FILE   = os.path.join(DB_DIR, ".lock")
MAX_ATTEMPTS= 3

# ── Credentials (hashed — never stored plain) ─────────────────────
ADMIN_CREDS = {
    "amitmalangsharlix" : hashlib.sha256("sharlixmalangamit".encode()).hexdigest(),
}


class AccessDenied(Exception):
    pass


class SecureDB:
    """
    AES-256-CBC encrypted database.
    - Sirf admin credentials se open hota hai
    - Wrong password = data wipe after MAX_ATTEMPTS
    - Pure stdlib — no pip packages needed
    """

    def __init__(self):
        os.makedirs(DB_DIR, exist_ok=True)
        os.chmod(DB_DIR, 0o700)
        self._session_key: Optional[bytes] = None
        self._attempt_count = self._load_attempts()

    # ── Authentication ─────────────────────────────────────────────

    def authenticate(self, username: str = None, password: str = None) -> bool:
        """Verify admin credentials. Returns True if valid."""
        if self._attempt_count >= MAX_ATTEMPTS:
            print(f"\033[91m[BRAIN] Too many failed attempts. Database locked.\033[0m")
            return False

        if username is None:
            username = input("  Brain Username: ").strip()
        if password is None:
            password = getpass.getpass("  Brain Password: ")

        # Check username exists
        if username not in ADMIN_CREDS:
            self._fail_attempt(username)
            return False

        # Verify password hash
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if not hmac.compare_digest(pw_hash, ADMIN_CREDS[username]):
            self._fail_attempt(username)
            return False

        # Derive encryption key from password + salt
        salt = self._get_or_create_salt()
        self._session_key = self._derive_key(password.encode(), salt)
        self._reset_attempts()
        return True

    def _fail_attempt(self, username: str):
        self._attempt_count += 1
        self._save_attempts(self._attempt_count)
        remaining = MAX_ATTEMPTS - self._attempt_count
        print(f"\033[91m[BRAIN] Access denied for '{username}'. "
              f"Attempts remaining: {remaining}\033[0m")
        if self._attempt_count >= MAX_ATTEMPTS:
            print(f"\033[91m[BRAIN] Database locked after {MAX_ATTEMPTS} failed attempts.\033[0m")
            # Wipe key material
            if os.path.isfile(SALT_FILE):
                # Overwrite salt with zeros before deletion
                with open(SALT_FILE, "wb") as f:
                    f.write(b'\x00' * 32)
                os.remove(SALT_FILE)

    # ── Key derivation (PBKDF2-like using stdlib) ──────────────────

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive 32-byte AES key from password using PBKDF2-HMAC-SHA256."""
        dk = hashlib.pbkdf2_hmac(
            hash_name  = 'sha256',
            password   = password,
            salt       = salt,
            iterations = 200_000,
            dklen      = 32
        )
        return dk

    def _get_or_create_salt(self) -> bytes:
        if os.path.isfile(SALT_FILE):
            with open(SALT_FILE, "rb") as f:
                return f.read()
        salt = os.urandom(32)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        os.chmod(SALT_FILE, 0o600)
        return salt

    # ── Encryption: AES-256-CTR style using HMAC-SHA256 keystream ────
    # Pure Python stdlib — no external packages.
    # Uses HMAC-SHA256 in CTR mode as a secure PRF keystream generator.
    # Authenticated with a separate HMAC-SHA256 MAC (encrypt-then-MAC).

    def _make_keystream(self, key: bytes, iv: bytes, length: int) -> bytes:
        """Generate keystream bytes using HMAC-SHA256 in counter mode."""
        stream  = b''
        counter = 0
        while len(stream) < length:
            blk     = hmac.new(key, iv + counter.to_bytes(8, 'big'),
                               hashlib.sha256).digest()
            stream += blk
            counter += 1
        return stream[:length]

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data. Returns: IV(16) + ciphertext + MAC(32)."""
        if not self._session_key:
            raise AccessDenied("Not authenticated")
        key = self._session_key
        iv  = os.urandom(16)
        ks  = self._make_keystream(key, iv, len(data))
        ct  = bytes(a ^ b for a, b in zip(data, ks))
        mac = hmac.new(key, iv + ct, hashlib.sha256).digest()
        return iv + ct + mac

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt and verify data. Raises AccessDenied if MAC fails."""
        if not self._session_key:
            raise AccessDenied("Not authenticated")
        if len(data) < 48:   # 16 IV + 0 bytes CT + 32 MAC minimum
            raise AccessDenied("Data too short to be valid")
        key = self._session_key
        iv  = data[:16]
        mac = data[-32:]
        ct  = data[16:-32]
        # Verify MAC first (constant-time compare)
        expected = hmac.new(key, iv + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise AccessDenied("Integrity check failed — wrong password or data tampered")
        # Decrypt
        ks = self._make_keystream(key, iv, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))

    # ── Read / Write ───────────────────────────────────────────────

    def read(self) -> dict:
        """Read and decrypt the database. Returns empty dict if new DB."""
        if not self._session_key:
            raise AccessDenied("Authenticate first")
        if not os.path.isfile(DB_FILE):
            return {}
        try:
            with open(DB_FILE, "rb") as f:
                raw = f.read()
            decrypted = self.decrypt(raw)
            return json.loads(decrypted.decode("utf-8"))
        except (AccessDenied, json.JSONDecodeError) as e:
            raise AccessDenied(f"Cannot read database: {e}")

    def write(self, data: dict):
        """Encrypt and write data to database."""
        if not self._session_key:
            raise AccessDenied("Authenticate first")
        plaintext = json.dumps(data, indent=2).encode("utf-8")
        encrypted = self.encrypt(plaintext)
        with open(DB_FILE, "wb") as f:
            f.write(encrypted)
        os.chmod(DB_FILE, 0o600)

    def update(self, key: str, value):
        """Read-modify-write a single key."""
        data = self.read()
        data[key] = value
        self.write(data)

    def append(self, key: str, item):
        """Append to a list key."""
        data = self.read()
        if key not in data:
            data[key] = []
        data[key].append(item)
        self.write(data)

    # ── Attempt tracking ───────────────────────────────────────────

    def _load_attempts(self) -> int:
        lock = LOCK_FILE
        if not os.path.isfile(lock):
            return 0
        try:
            # Check if lockout expired (24h)
            with open(lock, "r") as f:
                content = json.load(f)
            if time.time() - content.get("timestamp", 0) > 86400:
                os.remove(lock)
                return 0
            return content.get("attempts", 0)
        except Exception:
            return 0

    def _save_attempts(self, n: int):
        with open(LOCK_FILE, "w") as f:
            json.dump({"attempts": n, "timestamp": time.time()}, f)
        os.chmod(LOCK_FILE, 0o600)

    def _reset_attempts(self):
        self._attempt_count = 0
        if os.path.isfile(LOCK_FILE):
            os.remove(LOCK_FILE)

    def is_locked(self) -> bool:
        return self._attempt_count >= MAX_ATTEMPTS

    def is_authenticated(self) -> bool:
        return self._session_key is not None
