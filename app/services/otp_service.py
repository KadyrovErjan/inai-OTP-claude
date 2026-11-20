"""OTP business logic: issue (/otp/send) and verify (/otp/verify).

Every state transition happens inside a single Redis Lua script, so the service is
correct with any number of concurrent requests and API processes.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.config import Settings
from app.core.exceptions import (
    InvalidOtp,
    IpRateLimited,
    OtpGone,
    PhoneBlocked,
    SendRateLimited,
    ServiceUnavailable,
)
from app.core.otp_generator import generate_challenge_id, generate_otp
from app.core.security import SecurityContext
from app.services.audit_service import AuditService, EventType
from app.services.rate_limiter import IpRateLimiter
from app.services.sms_outbox import OutboxError, SmsOutboxNotifier
from app.storage.redis_client import Keys, Scripts

log = logging.getLogger("otp_secure.otp")


def _seconds(ms: int | str) -> int:
    return max(1, math.ceil(int(ms) / 1000))


@dataclass(slots=True)
class IssueResult:
    expires_in: int
    retry_after: int
    sends_remaining: int


class OtpService:
    def __init__(
        self,
        settings: Settings,
        redis: Redis,
        scripts: Scripts,
        keys: Keys,
        security: SecurityContext,
        outbox: SmsOutboxNotifier,
        audit: AuditService,
        ip_limiter: IpRateLimiter,
    ) -> None:
        self.s = settings
        self.redis = redis
        self.scripts = scripts
        self.keys = keys
        self.sec = security
        self.outbox = outbox
        self.audit = audit
        self.ip_limiter = ip_limiter

    # ------------------------------------------------------------------ send
    async def send(self, msisdn: str, display_msisdn: str, client_ip: str) -> IssueResult:
        pid = self.sec.phone_id(msisdn)
        iid = self.sec.ip_id(client_ip)
        code = generate_otp()
        cid = generate_challenge_id()
        digest = self.sec.otp_digest(msisdn, cid, code)
        issued_at = datetime.now(timezone.utc)

        try:
            res = await self.scripts.issue(
                keys=[
                    self.keys.block(pid),
                    self.keys.send_count(pid),
                    self.keys.send_cooldown(pid),
                    self.keys.active(pid),
                    self.keys.spent(pid),
                ],
                args=[
                    cid,
                    digest,
                    self.s.otp_ttl * 1000,
                    self.s.send_window_seconds * 1000,
                    self.s.max_send_per_window,
                    self.s.otp_ttl * 1000,
                    *[c * 1000 for c in self.s.send_cooldowns],
                ],
            )
        except RedisError as exc:
            log.error("Redis error during send: %s", exc.__class__.__name__)
            raise ServiceUnavailable() from exc

        status = res[0]
        if status == "blocked":
            retry = _seconds(res[1])
            await self.audit.record(
                EventType.SEND_RATE_LIMITED, phone_id=pid, ip_id=iid, reason="phone_blocked", retry_after=retry
            )
            raise PhoneBlocked("Phone number is temporarily blocked", retry_after=retry)
        if status in ("cooldown", "limit"):
            retry = _seconds(res[1])
            reason = "cooldown" if status == "cooldown" else "window_limit"
            await self.audit.record(
                EventType.SEND_RATE_LIMITED, phone_id=pid, ip_id=iid, reason=reason, retry_after=retry
            )
            msg = (
                f"Please wait {retry} s before requesting a new code"
                if status == "cooldown"
                else f"Maximum {self.s.max_send_per_window} codes per {self.s.send_window_seconds // 60} minutes reached"
            )
            raise SendRateLimited(msg, retry_after=retry, reason=reason)

        sends_used, cooldown_ms, replaced = int(res[1]), int(res[2]), int(res[3])

        # Deliver BEFORE answering 200. Redis and the filesystem are not one
        # transaction: on failure we revoke exactly this challenge (never a newer one)
        # and report 503 instead of a false success.
        try:
            await self.outbox.send_otp(display_msisdn, code, issued_at)
        except OutboxError as exc:
            try:
                await self.scripts.revoke(keys=[self.keys.active(pid)], args=[cid])
            except RedisError:
                log.error("Failed to revoke undelivered challenge")
            await self.audit.record(EventType.OUTBOX_FAILURE, phone_id=pid, ip_id=iid)
            raise ServiceUnavailable("OTP could not be delivered, try again later") from exc
        finally:
            del code  # do not keep plaintext around longer than needed

        await self.audit.record(
            EventType.OTP_RESENT if sends_used > 1 else EventType.OTP_CREATED,
            phone_id=pid,
            ip_id=iid,
            send_number=sends_used,
            replaced_previous=bool(replaced),
            cooldown=cooldown_ms // 1000,
            ttl=self.s.otp_ttl,
        )
        return IssueResult(
            expires_in=self.s.otp_ttl,
            retry_after=cooldown_ms // 1000,
            sends_remaining=max(0, self.s.max_send_per_window - sends_used),
        )

    # ---------------------------------------------------------------- verify
    async def verify(self, msisdn: str, code: str, client_ip: str) -> None:
        iid = self.sec.ip_id(client_ip)
        pid = self.sec.phone_id(msisdn)
        try:
            # 1. per-IP limit across all numbers (highest priority -> 429)
            decision = await self.ip_limiter.hit(iid)
            if not decision.allowed:
                if decision.count == self.s.ip_verify_limit + 1:
                    await self.audit.record(
                        EventType.IP_RATE_LIMITED,
                        phone_id=pid,
                        ip_id=iid,
                        limit=self.s.ip_verify_limit,
                        window=self.s.ip_verify_window,
                        retry_after=decision.retry_after,
                    )
                else:  # keep counting without flooding the event list
                    await self.audit.bump(EventType.IP_RATE_LIMITED)
                raise IpRateLimited(retry_after=decision.retry_after)

            # 2. read the current challenge and do the constant-time comparison in Python
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.hmget(self.keys.active(pid), "cid", "digest")
                pipe.hgetall(self.keys.spent(pid))
                (cur_cid, cur_digest), spent = await pipe.execute()

            mode, seen_cid = "none", ""
            if cur_cid and cur_digest:
                seen_cid = cur_cid
                mode = "match" if self.sec.otp_matches(msisdn, cur_cid, code, cur_digest) else "nomatch"
            if mode != "match":
                for s_cid, s_digest in spent.items():
                    if s_cid.startswith("r:"):
                        continue
                    if self.sec.otp_matches(msisdn, s_cid, code, s_digest):
                        mode, seen_cid = "spent", s_cid
                        break

            # 3. atomic finalization: block check, single-use consumption, failure counting
            res = await self.scripts.verify(
                keys=[
                    self.keys.block(pid),
                    self.keys.active(pid),
                    self.keys.failures(pid),
                    self.keys.spent(pid),
                ],
                args=[
                    mode,
                    seen_cid,
                    self.s.max_verify_attempts,
                    self.s.phone_block_seconds * 1000,
                    self.s.fail_window_seconds * 1000,
                    self.s.otp_ttl * 1000,
                ],
            )
        except RedisError as exc:
            log.error("Redis error during verify: %s", exc.__class__.__name__)
            raise ServiceUnavailable() from exc

        status = res[0]
        if status == "verified":
            await self.audit.record(EventType.OTP_VERIFIED, phone_id=pid, ip_id=iid)
            return
        if status == "blocked":
            await self.audit.bump(EventType.BLOCKED_ATTEMPT)
            raise PhoneBlocked(retry_after=_seconds(res[1]))
        if status == "blocked_now":
            retry = _seconds(res[1])
            await self.audit.record(
                EventType.OTP_INVALID, phone_id=pid, ip_id=iid, attempts_left=0
            )
            await self.audit.record(
                EventType.PHONE_BLOCKED,
                phone_id=pid,
                ip_id=iid,
                failed_attempts=self.s.max_verify_attempts,
                block_seconds=self.s.phone_block_seconds,
            )
            raise PhoneBlocked(
                f"Too many wrong codes. Phone blocked for {self.s.phone_block_seconds // 60} minutes",
                retry_after=retry,
            )
        if status == "invalid":
            left = int(res[1])
            await self.audit.record(EventType.OTP_INVALID, phone_id=pid, ip_id=iid, attempts_left=left)
            raise InvalidOtp(attempts_left=left)
        # gone
        reason = res[1]
        event = {
            "used": EventType.OTP_REUSED,
            "replaced": EventType.OTP_REPLACED,
        }.get(reason, EventType.OTP_EXPIRED)
        await self.audit.record(event, phone_id=pid, ip_id=iid, reason=reason)
        messages = {
            "used": "OTP has already been used",
            "replaced": "OTP was replaced by a newer code",
        }
        exc = OtpGone(messages.get(reason, "OTP expired or not found, request a new code"), reason=reason)
        exc.error = {"used": "otp_used", "replaced": "otp_replaced"}.get(reason, "otp_expired")
        raise exc
