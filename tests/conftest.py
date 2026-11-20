"""Shared fixtures.

Integration tests talk to a REAL Redis (TEST_REDIS_URL, default
redis://127.0.0.1:6379/15). Every test gets its own random key prefix and a
temporary outbox file, so neither the production keys nor ./outbox/sms.jsonl are
touched.

Tests that need short waits build an isolated APP_ENV=test configuration with
SCALED-DOWN intervals; they verify the same business logic, not the exact
production seconds. Production intervals are asserted separately (Redis PTTL and
retry_after values) and by the opt-in real-time test (RUN_SLOW=1).
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import redis as sync_redis

from app.config import Settings
from app.main import create_app

ROOT = Path(__file__).resolve().parent.parent
REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://127.0.0.1:6379/15")
TEST_HMAC_KEY = "test-hmac-key-" + "x" * 40
TEST_ADMIN_KEY = "test-admin-key-" + "y" * 40


def _redis_available() -> bool:
    try:
        return sync_redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1).ping()
    except Exception:
        return False


if not _redis_available():  # pragma: no cover
    pytest.exit(f"Redis is not reachable at {REDIS_URL} (set TEST_REDIS_URL)", returncode=2)


def random_msisdn() -> str:
    """Random valid test number - business logic never special-cases any number."""
    return "+99670" + "".join(str(uuid.uuid4().int)[:7])


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = dict(
        app_env="test",
        redis_url=REDIS_URL,
        redis_key_prefix=f"test:{uuid.uuid4().hex[:12]}",
        otp_hmac_key=TEST_HMAC_KEY,
        admin_api_key=TEST_ADMIN_KEY,
        outbox_path=str(tmp_path / "outbox" / "sms.jsonl"),
        outbox_enabled=True,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


def cleanup_prefix(prefix: str) -> None:
    r = sync_redis.Redis.from_url(REDIS_URL)
    keys = list(r.scan_iter(f"{prefix}:*", count=500))
    if keys:
        r.delete(*keys)


class Harness:
    def __init__(self, app, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    def client(self, ip: str = "127.0.0.1") -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=self.app, client=(ip, 40000))
        return httpx.AsyncClient(transport=transport, base_url="http://testserver")

    @property
    def outbox_file(self) -> Path:
        return self.settings.outbox_file

    def outbox_records(self) -> list[dict]:
        if not self.outbox_file.exists():
            return []
        return [json.loads(line) for line in self.outbox_file.read_text("utf-8").splitlines() if line]

    def last_code(self, msisdn: str) -> str:
        for rec in reversed(self.outbox_records()):
            if rec["msisdn"] == msisdn:
                return rec["code"]
        raise AssertionError(f"no outbox record for {msisdn}")

    @property
    def redis(self):
        return self.app.state.container.redis

    @property
    def container(self):
        return self.app.state.container


@asynccontextmanager
async def running_app(settings: Settings):
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        yield Harness(app, settings)


@pytest_asyncio.fixture
async def make_harness(tmp_path):
    """Factory: ``async with make_harness(otp_ttl=2) as h`` (prefix cleaned afterwards)."""
    prefixes: list[str] = []

    @asynccontextmanager
    async def factory(settings: Settings | None = None, **overrides):
        s = settings or make_settings(tmp_path, **overrides)
        prefixes.append(s.redis_key_prefix)
        async with running_app(s) as h:
            yield h

    yield factory
    for p in prefixes:
        cleanup_prefix(p)


@pytest_asyncio.fixture
async def h(make_harness):
    """Harness with PRODUCTION intervals (120 / 30-60-120 / 600 / 900 / 20 per 60 s)."""
    async with make_harness() as harness:
        yield harness


async def send(client: httpx.AsyncClient, msisdn: str) -> httpx.Response:
    return await client.post("/otp/send", json={"msisdn": msisdn})


async def verify(client: httpx.AsyncClient, msisdn: str, code: str, **kw) -> httpx.Response:
    return await client.post("/otp/verify", json={"msisdn": msisdn, "code": code}, **kw)


def wrong_code(correct: str, n: int = 0) -> str:
    c = f"{(int(correct) + 1 + n) % 1_000_000:06d}"
    assert c != correct
    return c


# ------------------------------------------------------------ live servers
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LiveServer:
    def __init__(self, port: int, proc: subprocess.Popen, outbox: Path, prefix: str) -> None:
        self.port = port
        self.proc = proc
        self.outbox = outbox
        self.prefix = prefix
        self.url = f"http://127.0.0.1:{port}"


def start_server(tmp_path: Path, prefix: str, extra_args: list[str] | None = None, env: dict | None = None) -> LiveServer:
    port = free_port()
    outbox = tmp_path / "outbox" / "sms.jsonl"
    full_env = {
        **os.environ,
        "APP_ENV": "test",
        "REDIS_URL": REDIS_URL,
        "REDIS_KEY_PREFIX": prefix,
        "OTP_HMAC_KEY": TEST_HMAC_KEY,
        "ADMIN_API_KEY": TEST_ADMIN_KEY,
        "OUTBOX_PATH": str(outbox),
        "OUTBOX_ENABLED": "true",
        **(env or {}),
    }
    cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port),
           "--log-level", "warning", *(extra_args or [])]
    log_path = tmp_path / f"server-{port}.log"
    log_fh = open(log_path, "wb")  # a file, not a pipe: a full pipe would stall the server
    proc = subprocess.Popen(cmd, cwd=ROOT, env=full_env, stdout=log_fh, stderr=subprocess.STDOUT)
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("server exited: " + log_path.read_text(errors="replace"))
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health", timeout=0.5).status_code == 200:
                return LiveServer(port, proc, outbox, prefix)
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("server did not start")


@pytest.fixture
def live_servers(tmp_path):
    """Factory starting real uvicorn processes sharing one Redis prefix."""
    started: list[LiveServer] = []
    prefix = f"test:{uuid.uuid4().hex[:12]}"

    def factory(extra_args: list[str] | None = None) -> LiveServer:
        srv = start_server(tmp_path, prefix, extra_args)
        started.append(srv)
        return srv

    yield factory
    for srv in started:
        srv.proc.terminate()
        try:
            srv.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.proc.kill()
    cleanup_prefix(prefix)


def loopback_alias_available(ip: str = "127.0.0.2") -> bool:
    try:
        with socket.socket() as s:
            s.bind((ip, 0))
        return True
    except OSError:
        return False
