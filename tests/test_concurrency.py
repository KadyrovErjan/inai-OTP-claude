import asyncio

import httpx
import pytest

from tests.conftest import random_msisdn, send, verify


async def _race(h, n: int, distinct_ips: bool):
    m = random_msisdn()
    async with h.client() as c:
        await send(c, m)
    code = h.last_code(m)
    clients = [h.client(f"127.0.{i // 250}.{i % 250 + 1}" if distinct_ips else "127.9.9.9") for i in range(n)]
    try:
        res = await asyncio.gather(*(verify(cl, m, code) for cl in clients))
    finally:
        for cl in clients:
            await cl.aclose()
    return [r.status_code for r in res]


@pytest.mark.parametrize("n", [2, 10, 100])
async def test_17_parallel_correct_code_succeeds_exactly_once(h, n):
    statuses = await _race(h, n, distinct_ips=True)
    assert statuses.count(200) == 1
    assert statuses.count(410) == n - 1


async def test_parallel_correct_code_single_ip(h):
    statuses = await _race(h, 100, distinct_ips=False)
    assert statuses.count(200) == 1
    assert set(statuses) <= {200, 410, 429}
    assert statuses.count(429) == 80


async def test_concurrent_send_and_verify(make_harness):
    async with make_harness(send_cooldown_1=0, send_cooldown_2=0, send_cooldown_3=0) as h:
        m = random_msisdn()
        async with h.client() as c:
            await send(c, m)
            code = h.last_code(m)
            ips = [h.client(f"127.0.2.{i}") for i in range(10)]
            tasks = [send(c, m)] + [verify(cl, m, code) for cl in ips]
            res = await asyncio.gather(*tasks)
            for cl in ips:
                await cl.aclose()
        verify_statuses = [r.status_code for r in res[1:]]
        # the old code can win at most once; never a 401 (a replaced code is not a wrong guess)
        assert verify_statuses.count(200) <= 1
        assert set(verify_statuses) <= {200, 410}


def test_30_single_use_across_two_api_processes(live_servers):
    a = live_servers(["--no-proxy-headers"])
    b = live_servers(["--no-proxy-headers"])
    m = random_msisdn()
    assert httpx.post(f"{a.url}/otp/send", json={"msisdn": m}).status_code == 200
    import json
    code = json.loads(a.outbox.read_text().splitlines()[-1])["code"]

    async def run():
        async with httpx.AsyncClient(timeout=10) as client:
            reqs = [client.post(f"{(a if i % 2 else b).url}/otp/verify", json={"msisdn": m, "code": code})
                    for i in range(20)]
            return await asyncio.gather(*reqs)

    statuses = [r.status_code for r in asyncio.run(run())]
    assert statuses.count(200) == 1
    assert set(statuses) <= {200, 410}
