"""Real client IP = TCP peer address. Uses real uvicorn processes and real sockets
bound to 127.0.0.1 / 127.0.0.2 (Linux and Windows route the whole 127/8)."""
import httpx
import pytest

from tests.conftest import loopback_alias_available, random_msisdn

pytestmark = pytest.mark.skipif(not loopback_alias_available(), reason="127.0.0.2 not bindable on this OS")


def _client(ip: str) -> httpx.Client:
    return httpx.Client(transport=httpx.HTTPTransport(local_address=ip), timeout=10)


def _verify(client: httpx.Client, url: str, headers: dict | None = None) -> int:
    body = {"msisdn": random_msisdn(), "code": "111111"}
    return client.post(f"{url}/otp/verify", json=body, headers=headers or {}).status_code


@pytest.mark.parametrize("extra", [["--no-proxy-headers"], []], ids=["jury-flag", "plain-uvicorn"])
def test_19_20_ips_independent_and_xff_ignored(live_servers, extra):
    srv = live_servers(extra)
    with _client("127.0.0.1") as one, _client("127.0.0.2") as two:
        # 20 checks from 127.0.0.1, each claiming a different forwarded address
        for i in range(20):
            assert _verify(one, srv.url, {"X-Forwarded-For": f"10.1.{i}.1", "X-Real-IP": f"10.2.{i}.1"}) != 429
        assert _verify(one, srv.url) == 429
        # spoofing the other loopback / any address does not help 127.0.0.1
        assert _verify(one, srv.url, {"X-Forwarded-For": "127.0.0.2"}) == 429
        assert _verify(one, srv.url, {"Forwarded": "for=127.0.0.3", "X-Forwarded-For": "8.8.8.8"}) == 429
        # 127.0.0.2 is an independent client
        assert _verify(two, srv.url) != 429
        # ... and claiming to be 127.0.0.1 does not hurt / move its own counter
        statuses = [_verify(two, srv.url, {"X-Forwarded-For": "127.0.0.1"}) for _ in range(19)]
        assert all(s != 429 for s in statuses)
        assert _verify(two, srv.url) == 429


def test_changing_phone_does_not_reset_ip_limit(live_servers):
    srv = live_servers(["--no-proxy-headers"])
    with _client("127.0.0.1") as c:
        statuses = [_verify(c, srv.url) for _ in range(21)]  # 21 different numbers
    assert statuses[-1] == 429 and statuses.count(429) == 1


def test_asgi_level_client_ip_is_used(live_servers):
    """The same jury flow over a real socket: send -> outbox -> verify from 127.0.0.2."""
    import json
    srv = live_servers(["--no-proxy-headers"])
    m = random_msisdn()
    with _client("127.0.0.2") as c:
        assert c.post(f"{srv.url}/otp/send", json={"msisdn": m}).status_code == 200
        code = json.loads(srv.outbox.read_text().splitlines()[-1])["code"]
        assert c.post(f"{srv.url}/otp/verify", json={"msisdn": m, "code": code}).status_code == 200
