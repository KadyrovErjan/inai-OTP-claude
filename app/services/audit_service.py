"""Security audit log.

Events are stored in a capped Redis list (newest first) plus all-time counters, and
mirrored to the ``otp_secure.audit`` logger. Records contain ONLY pseudonyms and
safe metadata - never an OTP, a digest, a secret, a full phone number or a raw IP.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from enum import StrEnum

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.storage.redis_client import Keys

log = logging.getLogger("otp_secure.audit")


class EventType(StrEnum):
    OTP_CREATED = "OTP_CREATED"
    OTP_RESENT = "OTP_RESENT"
    OTP_VERIFIED = "OTP_VERIFIED"
    OTP_INVALID = "OTP_INVALID"
    OTP_EXPIRED = "OTP_EXPIRED"
    OTP_REUSED = "OTP_REUSED"
    OTP_REPLACED = "OTP_REPLACED"
    PHONE_BLOCKED = "PHONE_BLOCKED"
    BLOCKED_ATTEMPT = "BLOCKED_ATTEMPT"
    SEND_RATE_LIMITED = "SEND_RATE_LIMITED"
    IP_RATE_LIMITED = "IP_RATE_LIMITED"
    OUTBOX_FAILURE = "OUTBOX_FAILURE"


SEVERITY = {
    EventType.OTP_CREATED: "info",
    EventType.OTP_RESENT: "info",
    EventType.OTP_VERIFIED: "info",
    EventType.OTP_INVALID: "warning",
    EventType.OTP_EXPIRED: "warning",
    EventType.OTP_REUSED: "warning",
    EventType.OTP_REPLACED: "warning",
    EventType.PHONE_BLOCKED: "critical",
    EventType.BLOCKED_ATTEMPT: "warning",
    EventType.SEND_RATE_LIMITED: "warning",
    EventType.IP_RATE_LIMITED: "critical",
    EventType.OUTBOX_FAILURE: "critical",
}

# keys that must never appear in an audit record
FORBIDDEN_DETAIL_KEYS = {"code", "otp", "digest", "msisdn", "phone", "ip", "secret", "key"}


class AuditService:
    def __init__(self, redis: Redis, keys: Keys, max_events: int) -> None:
        self.redis = redis
        self.keys = keys
        self.max_events = max_events

    async def record(
        self,
        event: EventType,
        *,
        phone_id: str | None = None,
        ip_id: str | None = None,
        **details,
    ) -> None:
        bad = FORBIDDEN_DETAIL_KEYS.intersection(details)
        if bad:  # programming error - refuse loudly instead of leaking
            raise ValueError(f"forbidden audit fields: {sorted(bad)}")
        entry = {
            "event": event.value,
            "severity": SEVERITY[event],
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "ts_ms": int(time.time() * 1000),
            "phone": phone_id[:12] if phone_id else None,
            "ip": ip_id[:12] if ip_id else None,
            "details": details,
        }
        payload = json.dumps(entry, separators=(",", ":"))
        log.info(payload)
        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.lpush(self.keys.events, payload)
                pipe.ltrim(self.keys.events, 0, self.max_events - 1)
                pipe.hincrby(self.keys.stats, event.value, 1)
                await pipe.execute()
        except RedisError as exc:
            # the security decision was already made atomically; losing the audit
            # copy must not flip the HTTP result, but it must be visible
            log.error("Failed to persist audit event %s: %s", event.value, exc.__class__.__name__)

    async def bump(self, event: EventType) -> None:
        """Count a repetitive event (e.g. the 500th rate-limited request) without
        pushing it into the recent-events list, so floods cannot evict real signals."""
        try:
            await self.redis.hincrby(self.keys.stats, event.value, 1)
        except RedisError as exc:
            log.error("Failed to count audit event %s: %s", event.value, exc.__class__.__name__)

    async def recent(self, limit: int = 200, event: str | None = None) -> list[dict]:
        raw = await self.redis.lrange(self.keys.events, 0, self.max_events - 1)
        items = [json.loads(r) for r in raw]
        if event:
            items = [i for i in items if i["event"] == event]
        return items[:limit]

    async def stats(self) -> dict[str, int]:
        raw = await self.redis.hgetall(self.keys.stats)
        return {k: int(v) for k, v in raw.items()}
