"""Second factor: TOTP (RFC 6238, compatible with Google Authenticator, Authy, 1Password...) and
single-use recovery codes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"       # no look-alikes (0/o, 1/l/i)


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def verify(secret: str, code: str, *, last_step: int = 0, now: float | None = None, window: int = 1) -> int | None:
    """Returns the matched time step, or None. A step at or before last_step is refused, so a code
    that was observed (shoulder surfing, phishing proxy) cannot be replayed."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != DIGITS:
        return None
    base = current_step(now)
    matched = None
    for step in range(base - window, base + window + 1):
        if hmac.compare_digest(code_at(secret, step), code) and step > last_step:
            matched = step
    return matched


def provisioning_uri(secret: str, account: str, issuer: str = "Atalaia") -> str:
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def qr_matrix(text: str) -> list[str]:
    """QR code as rows of '0'/'1' (with quiet zone). The dashboard draws it on a canvas, so the
    secret never goes to a third-party QR service. Empty when the optional 'segno' is missing."""
    try:
        import segno
    except ImportError:
        return []
    return ["".join("1" if cell else "0" for cell in row) for row in segno.make(text, error="m").matrix_iter(border=4)]


def new_recovery_codes(count: int = 10) -> list[str]:
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        return f"{raw[:5]}-{raw[5:]}"
    return [one() for _ in range(count)]


def normalize_recovery(code: str) -> str:
    return "".join(ch for ch in code.lower() if ch.isalnum())


def hash_recovery(code: str) -> str:
    return hashlib.sha256(b"atalaia-recovery-v1:" + normalize_recovery(code).encode()).hexdigest()


def looks_like_recovery(code: str) -> bool:
    return len(normalize_recovery(code)) == 10 and not normalize_recovery(code).isdigit()
