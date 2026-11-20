"""Cryptographically secure OTP and challenge-id generation (stdlib ``secrets`` only)."""
from __future__ import annotations

import secrets

OTP_DIGITS = 6


def generate_otp() -> str:
    """Exactly 6 decimal digits, leading zeros preserved, uniform over 000000..999999."""
    return f"{secrets.randbelow(10 ** OTP_DIGITS):0{OTP_DIGITS}d}"


def generate_challenge_id() -> str:
    return secrets.token_hex(16)
