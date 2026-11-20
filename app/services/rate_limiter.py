"""Per-IP verify limiter: fixed 60 s window starting at the first request, 20 checks
per window, counted across ALL phone numbers. Backed by Redis (atomic Lua), so it is
shared by every API process and survives restarts."""
from __future__ import annotations

import math
from dataclasses import dataclass

from app.storage.redis_client import Keys, Scripts


@dataclass(slots=True)
class RateDecision:
    allowed: bool
    count: int
    retry_after: int


class IpRateLimiter:
    def __init__(self, scripts: Scripts, keys: Keys, limit: int, window_seconds: int) -> None:
        self.scripts = scripts
        self.keys = keys
        self.limit = limit
        self.window_ms = window_seconds * 1000

    async def hit(self, ip_id: str) -> RateDecision:
        allowed, count, ttl_ms = await self.scripts.rate_limit(
            keys=[self.keys.ip_limit(ip_id)], args=[self.limit, self.window_ms]
        )
        return RateDecision(bool(int(allowed)), int(count), max(1, math.ceil(int(ttl_ms) / 1000)))
