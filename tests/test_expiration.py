"""OTP lifetime.

* Production TTL is asserted directly on Redis (PTTL of the challenge ≈ 120 000 ms).
* Expiry behaviour is exercised with a scaled TTL (APP_ENV=test) - same code path.
* ``test_real_120_seconds`` waits the real 120 s ("advance: 120"); opt in with RUN_SLOW=1.
"""
import asyncio
import os

import pytest

from tests.conftest import random_msisdn, send, verify


async def test_production_ttl_is_120_seconds_in_redis(h):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
    pid = h.container.security.phone_id(m)
    pttl = await h.redis.pttl(h.container.keys.active(pid))
    assert 119_000 < pttl <= 120_000


async def test_07_expired_code_returns_410(make_harness):
    async with make_harness(otp_ttl=1) as h:
        m = random_msisdn()
        async with h.client() as c:
            await send(c, m)
            code = h.last_code(m)
            await asyncio.sleep(1.2)
            r = await verify(c, m, code)
    assert r.status_code == 410
    assert r.json()["reason"] == "expired"


async def test_24_valid_just_before_expiry_invalid_right_after(make_harness):
    async with make_harness(otp_ttl=2) as h:
        a, b = random_msisdn(), random_msisdn()
        async with h.client() as c:
            await send(c, a)
            await send(c, b)
            await asyncio.sleep(1.6)  # "01:59"
            assert (await verify(c, a, h.last_code(a))).status_code == 200
            await asyncio.sleep(0.6)  # "02:01"
            assert (await verify(c, b, h.last_code(b))).status_code == 410


async def test_wrong_code_after_expiry_is_410_not_counted(make_harness):
    async with make_harness(otp_ttl=1) as h:
        m = random_msisdn()
        async with h.client() as c:
            await send(c, m)
            await asyncio.sleep(1.2)
            for _ in range(6):
                assert (await verify(c, m, "000000")).status_code in (410,)


@pytest.mark.skipif(os.environ.get("RUN_SLOW") != "1", reason="real 120 s wait; set RUN_SLOW=1")
async def test_real_120_seconds(h):
    a, b = random_msisdn(), random_msisdn()
    async with h.client() as c:
        await send(c, a)
        await send(c, b)
        await asyncio.sleep(118)
        assert (await verify(c, a, h.last_code(a))).status_code == 200
        await asyncio.sleep(3)  # now 121 s after issue
        assert (await verify(c, b, h.last_code(b))).status_code == 410
