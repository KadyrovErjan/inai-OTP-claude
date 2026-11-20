import json
import logging

from app.config import Settings
from tests.conftest import make_settings, random_msisdn, running_app, send, verify, wrong_code


async def test_05_correct_code_returns_200(h):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
        r = await verify(c, m, h.last_code(m))
    assert r.status_code == 200
    assert r.json() == {"success": True, "verified": True, "message": "Phone successfully verified"}


async def test_06_wrong_code_returns_401(h):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
        r = await verify(c, m, wrong_code(h.last_code(m)))
    assert r.status_code == 401
    assert r.json()["attempts_left"] == 4


async def test_08_code_is_single_use(h):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
        code = h.last_code(m)
        assert (await verify(c, m, code)).status_code == 200
        r = await verify(c, m, code)
    assert r.status_code == 410
    assert r.json()["reason"] == "used"


async def test_09_new_send_invalidates_previous_code(make_harness):
    async with make_harness(send_cooldown_1=0) as h:
        m = random_msisdn()
        async with h.client() as c:
            await send(c, m)
            old = h.last_code(m)
            await send(c, m)
            new = h.last_code(m)
            if old != new:  # 1-in-a-million chance they are equal
                r = await verify(c, m, old)
                assert r.status_code == 410 and r.json()["reason"] == "replaced"
            assert (await verify(c, m, new)).status_code == 200


async def test_verify_without_any_otp_is_410(h):
    async with h.client() as c:
        r = await verify(c, random_msisdn(), "123456")
    assert r.status_code == 410


async def test_malformed_code_is_422(h):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
        for bad in ["12345", "1234567", "abcdef", "", None]:
            assert (await verify(c, m, bad)).status_code == 422


async def test_new_send_does_not_reset_wrong_attempts(make_harness):
    async with make_harness(send_cooldown_1=0, send_cooldown_2=0) as h:
        m = random_msisdn()
        async with h.client() as c:
            await send(c, m)
            for _ in range(3):
                assert (await verify(c, m, wrong_code(h.last_code(m)))).status_code == 401
            await send(c, m)
            r = await verify(c, m, wrong_code(h.last_code(m)))
            assert r.json()["attempts_left"] == 1
            assert (await verify(c, m, wrong_code(h.last_code(m), 1))).status_code == 423


async def test_26_redis_unavailable_returns_503(tmp_path):
    s = make_settings(tmp_path, redis_url="redis://127.0.0.1:1/0", redis_timeout_seconds=0.3)
    async with running_app(s) as h:
        async with h.client() as c:
            r1 = await send(c, random_msisdn())
            r2 = await verify(c, random_msisdn(), "123456")
            r3 = await c.get("/health")
    assert r1.status_code == 503 and r2.status_code == 503 and r3.status_code == 503
    assert h.outbox_records() == []  # nothing delivered when the OTP was not stored


async def test_27_logs_and_audit_never_contain_otp(h, caplog):
    caplog.set_level(logging.DEBUG)
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
        code = h.last_code(m)
        await verify(c, m, wrong_code(code))
        await verify(c, m, code)
        await verify(c, m, code)
    pid = h.container.security.phone_id(m)
    events = await h.redis.lrange(h.container.keys.events, 0, -1)
    blob = "\n".join(events) + "\n" + caplog.text
    assert code not in blob
    assert m not in blob and m.lstrip("+") not in blob
    assert "127.0.0.1" not in "\n".join(events)
    assert h.settings.otp_hmac_key not in blob
    kinds = [json.loads(e)["event"] for e in events]
    assert {"OTP_CREATED", "OTP_INVALID", "OTP_VERIFIED", "OTP_REUSED"} <= set(kinds)
    assert all(json.loads(e)["phone"] == pid[:12] for e in events)


async def test_production_config_refuses_weak_settings():
    s = Settings(_env_file=None, app_env="production", otp_hmac_key="short", admin_api_key="short")
    try:
        s.validate_for_runtime()
    except RuntimeError as e:
        assert "OTP_HMAC_KEY" in str(e) and "OUTBOX_ENABLED" in str(e)
    else:
        raise AssertionError("weak production config accepted")
