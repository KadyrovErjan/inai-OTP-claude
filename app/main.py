"""OTP Secure - FastAPI application factory."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from redis.exceptions import RedisError

from app.api import admin, health, otp
from app.config import Settings, get_settings
from app.core.client_ip import harden_uvicorn_proxy_headers
from app.core.exceptions import OtpError
from app.dependencies import Container

APP_DIR = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("otp_secure")

DESCRIPTION = """
Secure one-time-password service (INAI Autumn Hackathon 2026, task 6).

* `POST /otp/send` → 200 issued / 429 send limit (423 if the number is blocked)
* `POST /otp/verify` → 200 ok / 401 wrong / 410 expired-used-replaced / 423 blocked / 429 IP limit

OTP codes are **never** returned by the API. In demo mode they are delivered to the
server-side file `outbox/sms.jsonl` (JSON Lines). All intervals use real time
(OTP TTL 120 s, block 900 s, IP window 60 s, send window 600 s).
"""

PAGE_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    harden_uvicorn_proxy_headers(settings.trust_proxy_headers)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        container = Container.build(settings)
        container.outbox.ensure_ready()
        app.state.container = container
        for attempt in range(10):
            try:
                await container.redis.ping()
                log.info("Redis connected (%s)", settings.redis_url.split("@")[-1])
                break
            except RedisError:
                log.warning("Redis not reachable yet (attempt %d/10)", attempt + 1)
                await asyncio.sleep(0.5)
        else:
            log.error("Redis unavailable - API will answer 503 until it is reachable")
        if settings.outbox_enabled:
            log.warning("DEMO SMS outbox enabled: OTPs are written to %s", settings.outbox_file)
        yield
        await container.redis.aclose()

    app = FastAPI(
        title="OTP Secure",
        version="2.0.0",
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    # ---------------------------------------------------------------- errors
    @app.exception_handler(OtpError)
    async def otp_error_handler(_: Request, exc: OtpError):
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after is not None else None
        return JSONResponse(exc.body(), status_code=exc.status_code, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError):
        details = [
            {"field": ".".join(str(p) for p in e["loc"] if p != "body"), "message": e["msg"]}
            for e in exc.errors()
        ]
        return JSONResponse(
            {"success": False, "error": "validation_error", "message": "Invalid request", "details": details},
            status_code=422,
        )

    @app.exception_handler(RedisError)
    async def redis_error_handler(_: Request, exc: RedisError):
        log.error("Unhandled Redis error: %s", exc.__class__.__name__)
        return JSONResponse(
            {"success": False, "error": "service_unavailable", "message": "Service temporarily unavailable"},
            status_code=503,
        )

    # ----------------------------------------------------------- headers
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if path.startswith(("/otp", "/admin")):
            response.headers["Cache-Control"] = "no-store"
        if path in ("/demo", "/admin/dashboard"):
            response.headers["Content-Security-Policy"] = PAGE_CSP
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Cache-Control"] = "no-cache"
        if path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    # ------------------------------------------------------------ routes
    app.include_router(otp.router)
    app.include_router(admin.router)
    app.include_router(health.router)

    # only app/static is public; outbox/ lives outside of it and has no route
    app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

    @app.get("/demo", include_in_schema=False)
    async def demo():
        return FileResponse(APP_DIR / "templates" / "demo.html", media_type="text/html")

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse("/demo")

    return app


def __getattr__(name: str):
    # ``uvicorn app.main:app`` - build lazily so that importing this module (tests)
    # does not require a configured environment.
    if name == "app":
        application = create_app()
        globals()["app"] = application
        return application
    raise AttributeError(name)
