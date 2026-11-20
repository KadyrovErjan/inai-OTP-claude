"""Cryptographic helpers: OTP digests, pseudonyms, admin session tokens.

Every HMAC uses a sub-key derived from OTP_HMAC_KEY with a distinct domain label,
so an OTP digest can never be confused with a phone pseudonym or a session token.
Messages are length-prefixed, which removes any separator ambiguity.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def _encode(*parts: str | bytes) -> bytes:
    out = bytearray()
    for part in parts:
        b = part.encode("utf-8") if isinstance(part, str) else part
        out += struct.pack(">I", len(b))
        out += b
    return bytes(out)


def _derive(master: bytes, label: str) -> bytes:
    return hmac.new(master, _encode("otp-secure/kdf/v1", label), hashlib.sha256).digest()


class SecurityContext:
    def __init__(self, hmac_key: str, admin_key: str) -> None:
        if not hmac_key:
            raise ValueError("OTP_HMAC_KEY is required")
        master = hmac_key.encode("utf-8")
        self._otp_key = _derive(master, "otp-digest")
        self._pseudo_key = _derive(master, "pseudonym")
        self._session_key = _derive(master, "admin-session")
        self._admin_key = admin_key.encode("utf-8")

    # ---------------------------------------------------------------- OTP
    def otp_digest(self, msisdn: str, challenge_id: str, code: str) -> str:
        msg = _encode("otp/v1", msisdn, challenge_id, code)
        return hmac.new(self._otp_key, msg, hashlib.sha256).hexdigest()

    def otp_matches(self, msisdn: str, challenge_id: str, code: str, stored_digest: str) -> bool:
        candidate = self.otp_digest(msisdn, challenge_id, code)
        return hmac.compare_digest(candidate.encode("ascii"), stored_digest.encode("ascii"))

    # ---------------------------------------------------------- pseudonyms
    def _pseudonym(self, domain: str, value: str) -> str:
        return hmac.new(self._pseudo_key, _encode(domain, value), hashlib.sha256).hexdigest()[:32]

    def phone_id(self, msisdn: str) -> str:
        return self._pseudonym("phone", msisdn)

    def ip_id(self, ip: str) -> str:
        return self._pseudonym("ip", ip)

    # --------------------------------------------------------------- admin
    def admin_key_valid(self, supplied: str | None) -> bool:
        if not supplied or not self._admin_key:
            return False
        return hmac.compare_digest(supplied.encode("utf-8"), self._admin_key)

    def make_session(self, ttl: int) -> str:
        expires = str(int(time.time()) + ttl)
        sig = hmac.new(self._session_key, _encode("session", expires), hashlib.sha256).digest()
        return f"{expires}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"

    def session_valid(self, token: str | None) -> bool:
        if not token or "." not in token:
            return False
        expires, _, sig = token.partition(".")
        if not expires.isdigit() or int(expires) < time.time():
            return False
        expected = hmac.new(self._session_key, _encode("session", expires), hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).decode().rstrip("=")
        return hmac.compare_digest(sig.encode(), expected_b64.encode())
