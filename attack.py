#!/usr/bin/env python3
"""OTP Secure - attack simulation against YOUR OWN LOCAL instance.

Scenarios (all verdicts are computed from real HTTP responses):

  single       brute force of one number          -> must be blocked (423) after 5 wrong codes
  distributed  brute force of 50 numbers, one IP   -> at most 20 guesses/min reach the service
  replay       N parallel requests with the right code -> exactly one 200
  dualip       127.0.0.1 vs 127.0.0.2 independent limits + X-Forwarded-For spoofing ignored
  stress       1000 attempts (jury-style)          -> 0 unauthorized successes, limits & blocks hold

Usage:
  python attack.py                       # all scenarios against http://127.0.0.1:8000
  python attack.py --mode replay --target http://127.0.0.1:8000 --outbox outbox/sms.jsonl

Safety: only loopback targets are accepted. No proxies, no header tricks beyond the
explicit X-Forwarded-For spoofing check.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import random
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

try:
    import httpx
except ImportError:  # pragma: no cover
    sys.exit("httpx is required: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent


# --------------------------------------------------------------------------- utils
def ensure_local_target(url: str) -> None:
    host = urlparse(url).hostname or ""
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        sys.exit(f"Cannot resolve target host {host!r}")
    if not addrs or not all(ipaddress.ip_address(a.split("%")[0]).is_loopback for a in addrs):
        sys.exit(f"Refusing to attack non-loopback target {url!r}: attack.py only tests a local OTP Secure instance")


def can_bind(ip: str) -> bool:
    try:
        with socket.socket() as s:
            s.bind((ip, 0))
        return True
    except OSError:
        return False


def random_msisdn() -> str:
    return "+99655" + "".join(random.choice("0123456789") for _ in range(7))


def random_code() -> str:
    return f"{random.randrange(1_000_000):06d}"


@dataclass
class Result:
    name: str
    passed: bool = False
    reason: str = ""
    stats: dict = field(default_factory=dict)


class Attacker:
    def __init__(self, target: str, outbox: Path, aliases: bool) -> None:
        self.target = target.rstrip("/")
        self.outbox = outbox
        self.aliases = aliases
        self._clients: dict[str, httpx.AsyncClient] = {}
        self.unauthorized_successes = 0
        self.authorized_successes = 0
        self.total_requests = 0

    def fresh_ip(self) -> str:
        """A loopback source address unused in this run (Linux/Windows route all 127/8)."""
        if not self.aliases:
            return "127.0.0.1"
        return f"127.{random.randint(10, 250)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def client(self, ip: str) -> httpx.AsyncClient:
        if ip not in self._clients:
            transport = httpx.AsyncHTTPTransport(local_address=ip, retries=0)
            limits = httpx.Limits(max_connections=50, max_keepalive_connections=50)
            self._clients[ip] = httpx.AsyncClient(transport=transport, timeout=15, limits=limits)
        return self._clients[ip]

    async def close(self) -> None:
        for c in self._clients.values():
            await c.aclose()

    async def send(self, msisdn: str, ip: str = "127.0.0.1") -> httpx.Response:
        self.total_requests += 1
        return await self.client(ip).post(f"{self.target}/otp/send", json={"msisdn": msisdn})

    async def verify(self, msisdn: str, code: str, ip: str, headers: dict | None = None,
                     authorized: bool = False) -> httpx.Response:
        self.total_requests += 1
        r = await self.client(ip).post(
            f"{self.target}/otp/verify", json={"msisdn": msisdn, "code": code}, headers=headers or {}
        )
        if r.status_code == 200:
            if authorized:
                self.authorized_successes += 1
            else:
                self.unauthorized_successes += 1
        return r

    def code_from_outbox(self, msisdn: str, timeout: float = 5.0) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.outbox.exists():
                for line in reversed(self.outbox.read_text("utf-8").splitlines()):
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("msisdn") == msisdn:
                        return rec["code"]
            time.sleep(0.1)
        raise RuntimeError(f"no OTP for the test number in {self.outbox}")

    async def wait_quota(self, ip: str) -> None:
        """If this source IP is already rate limited (earlier traffic), wait for the window."""
        r = await self.verify(random_msisdn(), random_code(), ip)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", "60")) + 1
            print(f"   ({ip} still limited by earlier traffic, waiting {wait}s)")
            await asyncio.sleep(wait)


# ------------------------------------------------------------------- scenarios
async def single_number(a: Attacker) -> Result:
    res = Result("Single Number Brute Force")
    ip = a.fresh_ip()
    await a.wait_quota(ip)
    m = random_msisdn()
    r = await a.send(m, ip)
    if r.status_code != 200:
        res.reason = f"/otp/send returned {r.status_code}"
        return res
    statuses = []
    for _ in range(12):
        statuses.append((await a.verify(m, random_code(), ip)).status_code)
    res.stats = {"attempts": len(statuses), "401": statuses.count(401), "423": statuses.count(423),
                 "200": statuses.count(200)}
    first_block = statuses.index(423) + 1 if 423 in statuses else None
    if statuses.count(200):
        res.reason = "a guessed code was accepted"
    elif first_block is None:
        res.reason = "number was never blocked"
    elif statuses.count(401) > 4 or first_block > 5:
        res.reason = f"block came too late (attempt #{first_block})"
    elif any(s != 423 for s in statuses[first_block:]):
        res.reason = "requests after the block were not rejected with 423"
    else:
        res.passed = True
        res.reason = f"blocked on wrong attempt #{first_block}, all later attempts 423"
    return res


async def distributed(a: Attacker) -> Result:
    res = Result("Distributed Brute Force")
    ip = a.fresh_ip()
    await a.wait_quota(ip)
    send_ip = a.fresh_ip()
    numbers = [random_msisdn() for _ in range(50)]
    sent = [await a.send(n, send_ip) for n in numbers]
    if any(r.status_code != 200 for r in sent):
        res.reason = "could not issue OTPs for the 50 numbers"
        return res
    # 4 guesses per number from ONE source IP, concurrently
    tasks = [a.verify(numbers[i % 50], random_code(), ip) for i in range(200)]
    statuses = [r.status_code for r in await asyncio.gather(*tasks)]
    reached = sum(1 for s in statuses if s != 429)
    already_used = 1  # the wait_quota probe consumed one slot of this IP's window
    res.stats = {"numbers": 50, "attempts": 200, "reached_service": reached,
                 "429": statuses.count(429), "200": statuses.count(200)}
    if statuses.count(200):
        res.reason = "a guessed code was accepted"
    elif reached + already_used > 20:
        res.reason = f"{reached} guesses got past the 20/min IP limit"
    else:
        res.passed = True
        res.reason = f"only {reached} of 200 guesses reached the service, rest 429"
    return res


async def replay(a: Attacker, parallel: int = 100) -> Result:
    res = Result("Concurrent Replay")
    m = random_msisdn()
    r = await a.send(m, a.fresh_ip())
    if r.status_code != 200:
        res.reason = f"/otp/send returned {r.status_code}"
        return res
    code = a.code_from_outbox(m)
    ips = [a.fresh_ip() for _ in range(parallel)] if a.aliases else ["127.0.0.1"] * parallel
    tasks = [a.verify(m, code, ip, authorized=True) for ip in ips]
    statuses = [r.status_code for r in await asyncio.gather(*tasks)]
    ok = statuses.count(200)
    res.stats = {"parallel": parallel, "200": ok, "410": statuses.count(410), "429": statuses.count(429)}
    if ok == 1 and all(s in (200, 410, 429) for s in statuses):
        res.passed = True
        res.reason = f"1 success, {parallel - 1} rejected"
    else:
        res.reason = f"{ok} successful verifications of one code"
    # a replay after the race must also fail
    late = await a.verify(m, code, a.fresh_ip(), authorized=True)
    if late.status_code == 200:
        res.passed, res.reason = False, "code accepted again after the race"
    return res


async def dual_ip(a: Attacker, ip_a: str, ip_b: str) -> tuple[Result, Result]:
    iso = Result("Dual IP Isolation")
    xff = Result("X-Forwarded-For Spoofing")
    if not (can_bind(ip_a) and can_bind(ip_b)):
        iso.reason = xff.reason = f"cannot bind {ip_a}/{ip_b} on this host"
        return iso, xff

    for _attempt in range(2):
        # saturate A, every request pretending to come from somewhere else
        statuses = []
        for i in range(25):
            h = {"X-Forwarded-For": f"10.{i}.0.1", "X-Real-IP": f"10.{i}.0.2"}
            statuses.append((await a.verify(random_msisdn(), random_code(), ip_a, h)).status_code)
            if statuses[-1] == 429:
                break
        if 429 not in statuses:
            iso.reason = f"{ip_a} was never limited after {len(statuses)} requests"
            return iso, xff
        probe_b = await a.verify(random_msisdn(), random_code(), ip_b)
        if probe_b.status_code != 429:
            break
        wait = int(probe_b.headers.get("Retry-After", "60")) + 1
        print(f"   ({ip_b} already limited by earlier traffic, waiting {wait}s)")
        await asyncio.sleep(wait)
    else:
        iso.reason = f"{ip_b} inherited the limit of {ip_a}"
        return iso, xff

    iso.passed = True
    iso.stats = {f"{ip_a} requests until 429": len(statuses), f"{ip_b} first status": probe_b.status_code}
    iso.reason = f"{ip_a} limited after {len(statuses) - 1} checks; {ip_b} unaffected ({probe_b.status_code})"

    # spoofing: limited A claims to be B / random -> still 429
    spoof_a = [(await a.verify(random_msisdn(), random_code(), ip_a, {"X-Forwarded-For": v})).status_code
               for v in (ip_b, "203.0.113.7", f"{ip_b}, 198.51.100.1")]
    # fresh C claims to be the limited A -> must NOT be limited
    ip_c = a.fresh_ip() if a.aliases else ip_b
    spoof_c = (await a.verify(random_msisdn(), random_code(), ip_c, {"X-Forwarded-For": ip_a})).status_code
    xff.stats = {"limited IP with spoofed XFF": spoof_a, "fresh IP claiming limited IP": spoof_c}
    if all(s == 429 for s in spoof_a) and spoof_c != 429:
        xff.passed = True
        xff.reason = "X-Forwarded-For had no effect on rate limiting"
    else:
        xff.reason = f"spoofed header changed the outcome: {spoof_a} / {spoof_c}"
    return iso, xff


async def stress(a: Attacker, total: int = 1000) -> Result:
    res = Result(f"Jury Stress Test ({total} attempts)")
    half = total // 2
    # part 1: one IP, many numbers
    ip = a.fresh_ip()
    await a.wait_quota(ip)
    send_ip = a.fresh_ip()
    numbers = [random_msisdn() for _ in range(25)]
    for n in numbers:
        await a.send(n, send_ip)
    sem = asyncio.Semaphore(50)

    async def guarded(coro):
        async with sem:
            return await coro

    p1 = await asyncio.gather(*(guarded(a.verify(numbers[i % 25], random_code(), ip)) for i in range(half)))
    p1s = [r.status_code for r in p1]
    # part 2: one number, many IPs (each within its own 20/min budget)
    victim = random_msisdn()
    await a.send(victim, send_ip)
    ips = [a.fresh_ip() for _ in range(max(1, (total - half) // 20 + 1))] if a.aliases else [ip]
    p2 = await asyncio.gather(*(guarded(a.verify(victim, random_code(), ips[i % len(ips)]))
                                for i in range(total - half)))
    p2s = [r.status_code for r in p2]
    res.stats = {
        "one-IP/many-numbers": {"reached": sum(1 for s in p1s if s != 429), "429": p1s.count(429)},
        "many-IPs/one-number": {"401": p2s.count(401), "423": p2s.count(423), "429": p2s.count(429)},
        "200": p1s.count(200) + p2s.count(200),
    }
    problems = []
    if p1s.count(200) + p2s.count(200):
        problems.append("guessed code accepted")
    if sum(1 for s in p1s if s != 429) > 20:
        problems.append("IP limit exceeded")
    if p2s.count(401) > 4:
        problems.append(f"{p2s.count(401)} wrong guesses before block (max 4 + blocking 5th)")
    if a.aliases and p2s.count(423) < (total - half) - 5 - p2s.count(429):
        problems.append("block not enforced")
    res.passed = not problems
    res.reason = "; ".join(problems) or "no successful guess, limits and block held"
    return res


# ------------------------------------------------------------------------ main
async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="http://127.0.0.1:8000")
    ap.add_argument("--outbox", default=str(ROOT / "outbox" / "sms.jsonl"))
    ap.add_argument("--mode", choices=["all", "single", "distributed", "replay", "dualip", "stress"], default="all")
    ap.add_argument("--ip-a", default="127.0.0.1")
    ap.add_argument("--ip-b", default="127.0.0.2")
    ap.add_argument("--parallel", type=int, default=100, help="parallel requests in the replay scenario")
    ap.add_argument("--attempts", type=int, default=1000, help="attempts in the stress scenario")
    args = ap.parse_args()

    ensure_local_target(args.target)
    loop = asyncio.get_running_loop()

    def quiet(loop_, ctx):  # Windows proactor reports peer resets on close; harmless here
        if isinstance(ctx.get("exception"), ConnectionResetError):
            return
        loop_.default_exception_handler(ctx)

    loop.set_exception_handler(quiet)
    aliases = can_bind("127.0.0.2") and can_bind("127.9.9.9")
    a = Attacker(args.target, Path(args.outbox), aliases)
    try:
        h = await a.client("127.0.0.1").get(f"{a.target}/health")
        if h.status_code != 200:
            print(f"Service unhealthy: {h.status_code} {h.text}")
            return 2
    except httpx.HTTPError as e:
        print(f"Cannot reach {args.target}: {e}")
        return 2

    if not aliases:
        print("NOTE: loopback aliases (127.0.0.x) are not bindable here; scenarios share 127.0.0.1 "
              "and wait for the IP window when needed.")

    results: list[Result] = []
    modes = ["single", "distributed", "replay", "dualip", "stress"] if args.mode == "all" else [args.mode]
    try:
        for mode in modes:
            print(f"-> running {mode} ...", flush=True)
            if mode == "single":
                results.append(await single_number(a))
            elif mode == "distributed":
                results.append(await distributed(a))
            elif mode == "replay":
                results.append(await replay(a, args.parallel))
            elif mode == "dualip":
                results.extend(await dual_ip(a, args.ip_a, args.ip_b))
            elif mode == "stress":
                results.append(await stress(a, args.attempts))
    finally:
        await a.close()

    line = "=" * 56
    print("\n" + line)
    print("OTP SECURE — ATTACK TEST REPORT")
    print(line)
    for r in results:
        print(f"{r.name}: {'PASS' if r.passed else 'FAIL'}")
        print(f"    {r.reason}")
        if r.stats:
            print(f"    {json.dumps(r.stats, ensure_ascii=False)}")
    print()
    print(f"Total HTTP requests: {a.total_requests}")
    print(f"Authorized verifications (known test OTP): {a.authorized_successes}")
    print(f"Unauthorized OTP Successes: {a.unauthorized_successes}")
    overall = all(r.passed for r in results) and a.unauthorized_successes == 0
    print(f"\nOVERALL RESULT: {'PASS' if overall else 'FAIL'}")
    print(line)
    return 0 if overall else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(asyncio.run(main()))
