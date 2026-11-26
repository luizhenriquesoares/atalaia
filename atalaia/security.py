"""Passwords, session tokens, API keys and encryption of stored scan credentials."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

_N, _R, _P = 2 ** 15, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=2 ** 27, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=2 ** 27, dklen=32)
        return hmac.compare_digest(calc.hex(), digest)
    except (ValueError, TypeError):
        return False


# Constant work for unknown e-mails, so login timing does not reveal which accounts exist.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))

COMMON_PASSWORDS = {"password1234", "123456789012", "qwertyuiop12", "senha1234567", "administrator"}


def password_problem(password: str) -> str | None:
    if len(password) < 12:
        return "A senha deve ter pelo menos 12 caracteres"
    if len(password) > 256:
        return "A senha deve ter no máximo 256 caracteres"
    if password.lower() in COMMON_PASSWORDS or len(set(password)) < 5:
        return "Senha muito comum ou repetitiva"
    return None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def make_token(secret: str, user_id: str, version: int, ttl: int) -> str:
    """Compact HS256 JWT."""
    now = int(time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps({"sub": user_id, "ver": version, "iat": now, "exp": now + ttl}, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


def read_token(secret: str, token: str) -> dict | None:
    try:
        header, payload, sig = token.split(".")
        expected = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(sig)):
            return None
        if json.loads(_unb64(header)).get("alg") != "HS256":
            return None
        data = json.loads(_unb64(payload))
        if not isinstance(data, dict) or int(data.get("exp", 0)) < time.time():
            return None
        return data
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


API_KEY_PREFIX = "atl_"


def new_api_key() -> tuple[str, str, str]:
    """Returns (full key shown once, public prefix, sha256 hash stored)."""
    prefix = secrets.token_hex(4)
    key = f"{API_KEY_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    return key, prefix, hash_api_key(key)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class SecretBox:
    def __init__(self, secret: str):
        key = hashlib.sha256(b"atalaia-secretbox-v1:" + secret.encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(key))

    def encrypt_json(self, value) -> str:
        return self._fernet.encrypt(json.dumps(value).encode()).decode()

    def decrypt_json(self, token: str):
        try:
            return json.loads(self._fernet.decrypt(token.encode()))
        except (InvalidToken, ValueError):
            return None


class LoginThrottle:
    """In-memory lockout after repeated failures, keyed by (ip, e-mail) and by e-mail."""

    def __init__(self, max_failures: int, lockout_seconds: int):
        self.max_failures = max_failures
        self.lockout = lockout_seconds
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str) -> list[float]:
        cutoff = time.time() - self.lockout
        items = [t for t in self._fails.get(key, []) if t > cutoff]
        if items:
            self._fails[key] = items
        else:
            self._fails.pop(key, None)
        return items

    def blocked(self, *keys: str) -> bool:
        with self._lock:
            return any(len(self._recent(k)) >= self.max_failures for k in keys)

    def fail(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._recent(k)
                self._fails.setdefault(k, []).append(time.time())

    def reset(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._fails.pop(k, None)
