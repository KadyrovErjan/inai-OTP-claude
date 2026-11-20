import asyncio
import json
import re
from datetime import datetime

from app.services import sms_outbox
from tests.conftest import random_msisdn, send, verify


async def test_03_send_writes_otp_to_outbox(h):
    msisdn = random_msisdn()
    async with h.client() as c:
        r = await send(c, msisdn)
    assert r.status_code == 200
    # the line is on disk at the moment 200 is returned
    recs = h.outbox_records()
    assert len(recs) == 1 and recs[0]["msisdn"] == msisdn


async def test_04_jsonl_structure(h):
    msisdn = random_msisdn()
    async with h.client() as c:
        await send(c, msisdn)
    raw = h.outbox_file.read_bytes().decode("utf-8")
    assert raw.endswith("\n")
    lines = raw.splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert set(rec) == {"msisdn", "code", "timestamp"}
    assert re.fullmatch(r"\d{6}", rec["code"])
    assert rec["timestamp"].endswith("Z")
    datetime.strptime(rec["timestamp"], "%Y-%m-%dT%H:%M:%SZ")


async def test_outbox_created_on_startup(make_harness, tmp_path):
    async with make_harness() as h:
        assert h.outbox_file.exists()
        assert h.outbox_file.read_text() == ""


async def test_21_no_outbox_record_on_429(h):
    msisdn = random_msisdn()
    async with h.client() as c:
        assert (await send(c, msisdn)).status_code == 200
        for _ in range(3):
            assert (await send(c, msisdn)).status_code == 429
    assert len(h.outbox_records()) == 1


async def test_22_multiple_sends_append_history_last_one_valid(make_harness):
    async with make_harness(send_cooldown_1=0, send_cooldown_2=0, send_cooldown_3=0) as h:
        msisdn = random_msisdn()
        async with h.client() as c:
            for _ in range(3):
                assert (await send(c, msisdn)).status_code == 200
            recs = [r for r in h.outbox_records() if r["msisdn"] == msisdn]
            assert len(recs) == 3  # history kept, nothing overwritten
            old, latest = recs[0]["code"], recs[-1]["code"]
            if old != latest:
                assert (await verify(c, msisdn, old)).status_code == 410
            assert (await verify(c, msisdn, latest)).status_code == 200


async def test_23_concurrent_sends_produce_intact_jsonl(h):
    numbers = [random_msisdn() for _ in range(120)]
    async with h.client() as c:
        results = await asyncio.gather(*(send(c, n) for n in numbers))
    assert all(r.status_code == 200 for r in results)
    lines = h.outbox_file.read_text("utf-8").splitlines()
    assert len(lines) == 120
    parsed = [json.loads(l) for l in lines]  # no torn / interleaved lines
    assert {p["msisdn"] for p in parsed} == set(numbers)


async def test_28_outbox_not_reachable_over_http(h):
    async with h.client() as c:
        await send(c, random_msisdn())
        for path in [
            "/outbox/sms.jsonl", "/sms.jsonl", "/static/../outbox/sms.jsonl",
            "/static/%2e%2e/%2e%2e/outbox/sms.jsonl", "/static/outbox/sms.jsonl", "/outbox",
        ]:
            r = await c.get(path)
            assert r.status_code == 404, path
            assert '"code"' not in r.text


async def test_outbox_failure_returns_503_and_revokes(h, monkeypatch):
    msisdn = random_msisdn()

    def boom(self, line):
        raise OSError("disk full")

    monkeypatch.setattr(sms_outbox.SmsOutboxNotifier, "_append_line", boom)
    async with h.client() as c:
        r = await send(c, msisdn)
        assert r.status_code == 503
        assert r.json()["success"] is False
    pid = h.container.security.phone_id(msisdn)
    assert not await h.redis.exists(h.container.keys.active(pid))


async def test_outbox_file_permissions_posix(h):
    import os
    import stat

    import pytest
    if os.name != "posix":
        pytest.skip("POSIX permissions only")
    async with h.client() as c:
        await send(c, random_msisdn())
    assert stat.S_IMODE(os.stat(h.outbox_file).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(h.outbox_file.parent).st_mode) == 0o700
