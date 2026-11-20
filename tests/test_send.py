import re

import pytest

from app.core import otp_generator
from tests.conftest import random_msisdn, send, verify


def test_01_otp_is_exactly_six_digits():
    codes = {otp_generator.generate_otp() for _ in range(5000)}
    assert all(re.fullmatch(r"\d{6}", c) for c in codes)
    assert len(codes) > 4900  # uniform, no obvious collisions


def test_01b_generator_uses_secrets_not_random(monkeypatch):
    calls = []
    monkeypatch.setattr(otp_generator.secrets, "randbelow", lambda n: calls.append(n) or 7)
    assert otp_generator.generate_otp() == "000007"
    assert calls == [1_000_000]


async def test_02_leading_zeros_survive_end_to_end(h, monkeypatch):
    monkeypatch.setattr(otp_generator.secrets, "randbelow", lambda n: 42)
    msisdn = random_msisdn()
    async with h.client() as c:
        assert (await send(c, msisdn)).status_code == 200
        assert h.last_code(msisdn) == "000042"
        assert (await verify(c, msisdn, "000042")).status_code == 200


async def test_send_response_never_contains_code(h):
    msisdn = random_msisdn()
    async with h.client() as c:
        r = await send(c, msisdn)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True and body["expires_in"] == 120 and body["retry_after"] == 30
    assert h.last_code(msisdn) not in r.text


async def test_redis_stores_only_hmac_digest(h):
    msisdn = random_msisdn()
    async with h.client() as c:
        await send(c, msisdn)
    code = h.last_code(msisdn)
    dump = []
    async for key in h.redis.scan_iter(f"{h.settings.redis_key_prefix}:*"):
        assert msisdn not in key and msisdn.lstrip("+") not in key
        t = await h.redis.type(key)
        if t == "hash":
            dump.extend((await h.redis.hgetall(key)).values())
        elif t == "string":
            dump.append(await h.redis.get(key))
    assert all(code not in v for v in dump if v and len(v) != 64)  # digests are 64 hex chars
    assert all(not re.fullmatch(r"\d{6}", v) for v in dump if v)


@pytest.mark.parametrize("bad", ["", "12345", "abc", "+0123456789", "+99670012345678901"])
async def test_invalid_msisdn_rejected_422(h, bad):
    async with h.client() as c:
        r = await send(c, bad)
    assert r.status_code == 422
    assert h.outbox_records() == []


async def test_number_formats_normalize_to_same_identity(h):
    digits = random_msisdn().lstrip("+")
    async with h.client() as c:
        assert (await send(c, "+" + digits)).status_code == 200
        # same number written differently must share the same cooldown
        assert (await send(c, digits)).status_code == 429
        assert (await send(c, f"00{digits}")).status_code == 429
