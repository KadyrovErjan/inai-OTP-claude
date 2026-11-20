"""Application configuration (pydantic-settings).

All time values are REAL seconds. Production values are the defaults; tests build
their own isolated ``Settings`` objects with shortened intervals.
"""
from __future__ import annotations

import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

log = logging.getLogger("otp_secure.config")

MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # later files override earlier ones; real environment variables win over both
        env_file=(str(BASE_DIR / "data" / "secrets.env"), str(BASE_DIR / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: Literal["development", "test", "production"] = "development"
    debug: bool = False

    host: str = "127.0.0.1"
    port: int = 8000

    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_key_prefix: str = "otp"
    redis_timeout_seconds: float = 2.0

    otp_ttl: int = Field(120, ge=1)
    otp_length: int = Field(6, ge=6, le=6)

    send_window_seconds: int = Field(600, ge=1)
    max_send_per_window: int = Field(3, ge=1)
    send_cooldown_1: int = Field(30, ge=0)
    send_cooldown_2: int = Field(60, ge=0)
    send_cooldown_3: int = Field(120, ge=0)

    max_verify_attempts: int = Field(5, ge=1)
    phone_block_seconds: int = Field(900, ge=1)
    # lifetime of the wrong-attempt counter, counted from the first wrong attempt
    fail_window_seconds: int = Field(900, ge=1)

    ip_verify_limit: int = Field(20, ge=1)
    ip_verify_window: int = Field(60, ge=1)

    otp_hmac_key: str = ""
    admin_api_key: str = ""
    admin_session_ttl: int = 3600

    outbox_path: str = "outbox/sms.jsonl"
    outbox_enabled: bool = True

    audit_max_events: int = Field(1000, ge=10)

    demo_mode: bool = True
    trust_proxy_headers: bool = False

    # where auto-generated development secrets are persisted
    secrets_file: str = "data/secrets.env"

    @field_validator("redis_key_prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        v = v.strip().strip(":")
        if not v:
            raise ValueError("REDIS_KEY_PREFIX must not be empty")
        return v

    # ------------------------------------------------------------------ helpers
    @property
    def send_cooldowns(self) -> list[int]:
        return [self.send_cooldown_1, self.send_cooldown_2, self.send_cooldown_3]

    @property
    def outbox_file(self) -> Path:
        p = Path(self.outbox_path)
        return p if p.is_absolute() else BASE_DIR / p

    @property
    def secrets_path(self) -> Path:
        p = Path(self.secrets_file)
        return p if p.is_absolute() else BASE_DIR / p

    def validate_for_runtime(self) -> None:
        """Refuse insecure configurations in production."""
        if self.app_env != "production":
            return
        problems: list[str] = []
        if len(self.otp_hmac_key) < MIN_SECRET_LENGTH:
            problems.append(f"OTP_HMAC_KEY must be at least {MIN_SECRET_LENGTH} characters")
        if len(self.admin_api_key) < MIN_SECRET_LENGTH:
            problems.append(f"ADMIN_API_KEY must be at least {MIN_SECRET_LENGTH} characters")
        if self.otp_hmac_key and self.otp_hmac_key == self.admin_api_key:
            problems.append("OTP_HMAC_KEY and ADMIN_API_KEY must differ")
        if self.outbox_enabled:
            problems.append("OUTBOX_ENABLED must be false in production (use a real SMS provider)")
        if self.demo_mode:
            problems.append("DEMO_MODE must be false in production")
        if self.debug:
            problems.append("DEBUG must be false in production")
        if problems:
            raise RuntimeError("Insecure production configuration: " + "; ".join(problems))


def _persist_generated_secrets(settings: Settings, values: dict[str, str]) -> None:
    path = settings.secrets_path
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = [f"{k}={v}" for k, v in values.items()]
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows
        pass


def ensure_secrets(settings: Settings) -> Settings:
    """In non-production mode generate missing secrets once and persist them.

    Persisting matters: phone/IP pseudonyms are derived from OTP_HMAC_KEY, so a
    new random key on every restart would silently reset all limits and blocks.
    """
    if settings.app_env == "production":
        return settings
    generated: dict[str, str] = {}
    if not settings.otp_hmac_key:
        generated["OTP_HMAC_KEY"] = secrets.token_urlsafe(48)
    if not settings.admin_api_key:
        generated["ADMIN_API_KEY"] = secrets.token_urlsafe(32)
    if not generated:
        return settings
    if settings.app_env != "test":
        _persist_generated_secrets(settings, generated)
        log.warning(
            "Generated missing secrets %s and stored them in %s (keep this file private)",
            ", ".join(generated),
            settings.secrets_path,
        )
    return settings.model_copy(update={k.lower(): v for k, v in generated.items()})


@lru_cache
def get_settings() -> Settings:
    settings = ensure_secrets(Settings())
    settings.validate_for_runtime()
    return settings
