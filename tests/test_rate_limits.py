import asyncio

from tests.conftest import random_msisdn, send, verify


async def test_production_send_limits_values(h):
    """Production numbers without waiting: first cooldown is 30 s, 600 s window."""
    m = random_msisdn()
    async with h.client() as c:
        r1 = await send(c, m)
        r2 = await send(c, m)
    assert r1.json()["retry_after"] == 30
    assert r2.status_code == 429 and 29 <= r2.json()["retry_after"] <= 30
    assert r2.headers["Retry-After"] == str(r2.json()["retry_after"])
    pid = h.container.security.phone_id(m)
    assert 599_000 < await h.redis.pttl(h.container.keys.send_count(pid)) <= 600_000


async def test_10_11_12_13_progressive_cooldowns_and_window_limit(make_harness):
    """Scaled 1/2/3 s cooldowns and 12 s window (production: 30/60/120 s and 600 s)."""
    async with make_harness(send_cooldown_1=1, send_cooldown_2=2, send_cooldown_3=3, send_window_seconds=12) as h:
        m = random_msisdn()
        async with h.client() as c:
            r = await send(c, m)
            assert r.status_code == 200 and r.json()["retry_after"] == 1         # 1st -> 30 s
            assert (await send(c, m)).status_code == 429
            await asyncio.sleep(1.1)
            r = await send(c, m)
            assert r.status_code == 200 and r.json()["retry_after"] == 2         # 2nd -> 60 s
            await asyncio.sleep(1.1)
            assert (await send(c, m)).status_code == 429                         # still cooling
            await asyncio.sleep(1.0)
            r = await send(c, m)
            assert r.status_code == 200 and r.json()["retry_after"] == 3         # 3rd -> 120 s
            assert r.json()["sends_remaining"] == 0
            await asyncio.sleep(3.1)
            r = await send(c, m)                                                 # 4th within window
            assert r.status_code == 429 and r.json()["reason"] == "window_limit"
            assert len(h.outbox_records()) == 3


async def test_refused_send_does_not_restart_window(make_harness):
    async with make_harness(send_cooldown_1=0, send_cooldown_2=0, send_cooldown_3=0,
                            max_send_per_window=1, send_window_seconds=2) as h:
        m = random_msisdn()
        async with h.client() as c:
            assert (await send(c, m)).status_code == 200
            await asyncio.sleep(1.0)
            assert (await send(c, m)).status_code == 429  # must not extend the window
            await asyncio.sleep(1.1)
            assert (await send(c, m)).status_code == 200  # window counted from first send


async def test_16_ip_limit_20_per_minute(h):
    async with h.client("127.0.0.1") as c:
        codes = [(await verify(c, random_msisdn(), "123456")).status_code for _ in range(25)]
    assert all(s != 429 for s in codes[:20])
    assert codes[20:] == [429] * 5


async def test_ip_window_resets(make_harness):
    async with make_harness(ip_verify_window=1) as h:
        async with h.client() as c:
            for _ in range(20):
                await verify(c, random_msisdn(), "123456")
            assert (await verify(c, random_msisdn(), "123456")).status_code == 429
            await asyncio.sleep(1.1)
            assert (await verify(c, random_msisdn(), "123456")).status_code != 429


async def test_18_distributed_brute_force_50_numbers_one_ip(h):
    numbers = [random_msisdn() for _ in range(50)]
    async with h.client("127.0.0.1") as c:
        for n in numbers:
            assert (await send(c, n)).status_code == 200
        statuses = []
        for i in range(200):  # 4 guesses per number, spread across all 50 numbers
            n = numbers[i % 50]
            guess = f"{(int(h.last_code(n)) + 1 + i) % 1_000_000:06d}"
            statuses.append((await verify(c, n, guess)).status_code)
    assert statuses.count(200) == 0
    assert sum(1 for s in statuses if s != 429) == 20  # only 20 guesses reach the numbers
    assert statuses[20:] == [429] * 180


async def test_ip_limit_concurrent_requests(h):
    async with h.client("127.0.0.5") as c:
        res = await asyncio.gather(*(verify(c, random_msisdn(), "123456") for _ in range(60)))
    assert sum(1 for r in res if r.status_code != 429) == 20
