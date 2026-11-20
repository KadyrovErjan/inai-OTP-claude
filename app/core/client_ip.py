"""Client IP resolution.

The client IP is ALWAYS the peer address of the real TCP connection as reported by
the ASGI server (``request.client.host``). Headers such as X-Forwarded-For,
X-Real-IP or Forwarded are never consulted.

Caveat: Uvicorn enables its ProxyHeadersMiddleware by default and trusts
X-Forwarded-For from 127.0.0.1 - exactly the address the jury connects from. The
documented launch command passes ``--no-proxy-headers``; in addition, as defense in
depth, ``harden_uvicorn_proxy_headers()`` turns that middleware into a pass-through
when TRUST_PROXY_HEADERS=false, so even a plain ``uvicorn app.main:app`` cannot be
tricked by a spoofed header.
"""
from __future__ import annotations

import logging

from starlette.requests import Request

log = logging.getLogger("otp_secure.client_ip")

_PATCHED = False


def get_client_ip(request: Request) -> str:
    client = request.client
    return client.host if client and client.host else "unknown"


def harden_uvicorn_proxy_headers(trust_proxy_headers: bool) -> None:
    global _PATCHED
    if trust_proxy_headers or _PATCHED:
        return
    try:
        from uvicorn.middleware import proxy_headers
    except Exception:  # pragma: no cover - another ASGI server is used
        return

    async def _passthrough(self, scope, receive, send):  # noqa: ANN001
        return await self.app(scope, receive, send)

    proxy_headers.ProxyHeadersMiddleware.__call__ = _passthrough  # type: ignore[method-assign]
    _PATCHED = True
    log.info("Proxy headers disabled: client IP = TCP peer address only")
