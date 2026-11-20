"""Recommended launcher: ``python -m app``.

Runs Uvicorn directly (no reverse proxy) with proxy-header processing disabled, so
the client IP is the real TCP peer address. Equivalent to::

    uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
"""
from __future__ import annotations

import argparse

import uvicorn

from app.config import get_settings


def main() -> None:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Run OTP Secure")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        proxy_headers=settings.trust_proxy_headers,
        forwarded_allow_ips="" if not settings.trust_proxy_headers else None,
        server_header=False,
    )


if __name__ == "__main__":
    main()
