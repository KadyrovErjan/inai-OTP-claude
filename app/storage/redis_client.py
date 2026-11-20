"""Redis connection, key layout and Lua script registry."""
from __future__ import annotations

from pathlib import Path

from redis.asyncio import Redis
from redis.commands.core import AsyncScript

LUA_DIR = Path(__file__).resolve().parent.parent / "lua"


class Keys:
    """Logical key layout. Only HMAC pseudonyms ever appear in key names."""

    def __init__(self, prefix: str) -> None:
        self.p = prefix

    def active(self, pid: str) -> str:
        return f"{self.p}:active:{pid}"

    def spent(self, pid: str) -> str:
        return f"{self.p}:spent:{pid}"

    def send_count(self, pid: str) -> str:
        return f"{self.p}:send_count:{pid}"

    def send_cooldown(self, pid: str) -> str:
        return f"{self.p}:send_cooldown:{pid}"

    def failures(self, pid: str) -> str:
        return f"{self.p}:failures:{pid}"

    def block(self, pid: str) -> str:
        return f"{self.p}:block:{pid}"

    def ip_limit(self, iid: str) -> str:
        return f"{self.p}:ip_limit:{iid}"

    @property
    def events(self) -> str:
        return f"{self.p}:security_events"

    @property
    def stats(self) -> str:
        return f"{self.p}:security_stats"


REVOKE_LUA = """
-- compensation: remove the challenge only if it is still the one we issued,
-- never a newer OTP issued by a concurrent request
if redis.call("HGET", KEYS[1], "cid") == ARGV[1] then
  redis.call("DEL", KEYS[1])
  return 1
end
return 0
"""


class Scripts:
    def __init__(self, redis: Redis) -> None:
        self.issue: AsyncScript = redis.register_script((LUA_DIR / "issue_otp.lua").read_text("utf-8"))
        self.verify: AsyncScript = redis.register_script((LUA_DIR / "verify_otp.lua").read_text("utf-8"))
        self.rate_limit: AsyncScript = redis.register_script((LUA_DIR / "rate_limit.lua").read_text("utf-8"))
        self.revoke: AsyncScript = redis.register_script(REVOKE_LUA)


def create_redis(url: str, timeout: float) -> Redis:
    return Redis.from_url(
        url,
        decode_responses=True,
        socket_timeout=timeout,
        socket_connect_timeout=timeout,
        health_check_interval=30,
    )
