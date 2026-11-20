import asyncio

from tests.conftest import make_settings, random_msisdn, running_app, send, verify, wrong_code


async def _fail(h, c, m, n):
    code = h.last_code(m)
    return [(await verify(c, m, wrong_code(code, i))).status_code for i in range(n)]


async def test_14_block_after_five_wrong_codes(h):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
        code = h.last_code(m)
        statuses = await _fail(h, c, m, 5)
        assert statuses == [401, 401, 401, 401, 423]
        r = await verify(c, m, code)  # even the right code is refused while blocked
        assert r.status_code == 423
        assert 899 <= r.json()["retry_after"] <= 900
    pid = h.container.security.phone_id(m)
    assert 899_000 < await h.redis.pttl(h.container.keys.block(pid)) <= 900_000


async def test_15_block_expires(make_harness):
    """Scaled 2 s block (production 900 s)."""
    async with make_harness(phone_block_seconds=2, send_cooldown_1=0) as h:
        m = random_msisdn()
        async with h.client() as c:
            await send(c, m)
            await _fail(h, c, m, 5)
            assert (await verify(c, m, "000000")).status_code == 423
            await asyncio.sleep(2.1)
            # blocked challenge was burned -> 410, and no immediate re-block
            assert (await verify(c, m, "000000")).status_code == 410
            assert (await send(c, m)).status_code == 200
            r = await verify(c, m, wrong_code(h.last_code(m)))
            assert r.status_code == 401 and r.json()["attempts_left"] == 4
            assert (await verify(c, m, h.last_code(m))).status_code == 200


async def test_block_survives_send_and_ip_change(h):
    m = random_msisdn()
    async with h.client("127.0.0.1") as c:
        await send(c, m)
        await _fail(h, c, m, 5)
        r = await send(c, m)
        assert r.status_code == 423  # a new send neither unblocks nor issues a code
    assert len([x for x in h.outbox_records() if x["msisdn"] == m]) == 1
    async with h.client("127.0.0.2") as c2:
        assert (await verify(c2, m, "123456")).status_code == 423


async def test_25_limits_survive_api_restart(tmp_path):
    s = make_settings(tmp_path)
    m = random_msisdn()
    async with running_app(s) as h1:
        async with h1.client() as c:
            await send(c, m)
            code = h1.last_code(m)
            assert await _fail(h1, c, m, 3) == [401] * 3
    # brand-new application instance, new Redis connection pool
    async with running_app(s) as h2:
        async with h2.client() as c:
            assert (await send(c, m)).status_code == 429  # cooldown kept
            r = await verify(c, m, wrong_code(code, 7))
            assert r.json()["attempts_left"] == 1          # failure counter kept
            assert (await verify(c, m, wrong_code(code, 8))).status_code == 423
    async with running_app(s) as h3:
        async with h3.client() as c:
            assert (await verify(c, m, code)).status_code == 423  # block kept
    from tests.conftest import cleanup_prefix
    cleanup_prefix(s.redis_key_prefix)


async def test_29_concurrent_wrong_codes_block_exactly_once(h):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
    code = h.last_code(m)
    clients = [h.client(f"127.0.1.{i}") for i in range(30)]  # avoid the IP limit
    try:
        res = await asyncio.gather(*(verify(cl, m, wrong_code(code, i)) for i, cl in enumerate(clients)))
    finally:
        for cl in clients:
            await cl.aclose()
    statuses = [r.status_code for r in res]
    assert statuses.count(401) == 4
    assert statuses.count(423) == 26
    assert statuses.count(200) == 0
    events = await h.container.audit.stats()
    assert events.get("PHONE_BLOCKED") == 1
