"""Service container stored on ``app.state`` and FastAPI dependency getters."""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from redis.asyncio import Redis

from app.config import Settings
from app.core.security import SecurityContext
from app.services.audit_service import AuditService
from app.services.otp_service import OtpService
from app.services.rate_limiter import IpRateLimiter
from app.services.sms_outbox import SmsOutboxNotifier
from app.storage.redis_client import Keys, Scripts, create_redis


@dataclass
class Container:
    settings: Settings
    redis: Redis
    keys: Keys
    security: SecurityContext
    audit: AuditService
    outbox: SmsOutboxNotifier
    otp: OtpService
    admin_login_limiter: IpRateLimiter

    @classmethod
    def build(cls, settings: Settings) -> "Container":
        redis = create_redis(settings.redis_url, settings.redis_timeout_seconds)
        keys = Keys(settings.redis_key_prefix)
        scripts = Scripts(redis)
        security = SecurityContext(settings.otp_hmac_key, settings.admin_api_key)
        audit = AuditService(redis, keys, settings.audit_max_events)
        outbox = SmsOutboxNotifier(settings.outbox_file, settings.outbox_enabled)
        ip_limiter = IpRateLimiter(scripts, keys, settings.ip_verify_limit, settings.ip_verify_window)
        admin_keys = Keys(f"{settings.redis_key_prefix}:admin")
        admin_limiter = IpRateLimiter(scripts, admin_keys, 10, 60)
        otp = OtpService(settings, redis, scripts, keys, security, outbox, audit, ip_limiter)
        return cls(settings, redis, keys, security, audit, outbox, otp, admin_limiter)


def get_container(request: Request) -> Container:
    return request.app.state.container


def get_otp_service(request: Request) -> OtpService:
    return request.app.state.container.otp
