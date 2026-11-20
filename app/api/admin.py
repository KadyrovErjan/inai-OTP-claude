"""Admin security dashboard.

Authentication: the operator types ADMIN_API_KEY into the login form once; the server
answers with an HMAC-signed, HttpOnly, SameSite=Strict session cookie. The key itself
is never embedded in any page or JavaScript. API clients may instead send the key in
the ``X-Admin-Key`` header. Login attempts are rate limited per IP (10/min).
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from redis.exceptions import RedisError

from app.core.client_ip import get_client_ip
from app.dependencies import Container, get_container
from app.services.audit_service import EventType

router = APIRouter(prefix="/admin", tags=["Admin"])

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
COOKIE = "otp_admin_session"


def _authorized(request: Request, c: Container) -> bool:
    if c.security.admin_key_valid(request.headers.get("x-admin-key")):
        return True
    return c.security.session_valid(request.cookies.get(COOKIE))


def require_admin(request: Request, c: Container = Depends(get_container)) -> Container:
    if not _authorized(request, c):
        raise HTTPException(status_code=401, detail="Admin authentication required")
    return c


class LoginBody(BaseModel):
    key: str


@router.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request, c: Container = Depends(get_container)):
    page = "dashboard.html" if _authorized(request, c) else "login.html"
    return FileResponse(TEMPLATES / page, media_type="text/html")


@router.get("", include_in_schema=False)
async def admin_root():
    return RedirectResponse("/admin/dashboard")


@router.post("/login", summary="Exchange ADMIN_API_KEY for a session cookie")
async def login(body: LoginBody, request: Request, c: Container = Depends(get_container)):
    try:
        decision = await c.admin_login_limiter.hit(c.security.ip_id(get_client_ip(request)))
    except RedisError:
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    if not decision.allowed:
        return JSONResponse(
            {"success": False, "message": "Too many login attempts"},
            status_code=429,
            headers={"Retry-After": str(decision.retry_after)},
        )
    if not c.security.admin_key_valid(body.key):
        return JSONResponse({"success": False, "message": "Invalid admin key"}, status_code=401)
    resp = JSONResponse({"success": True})
    resp.set_cookie(
        COOKIE,
        c.security.make_session(c.settings.admin_session_ttl),
        max_age=c.settings.admin_session_ttl,
        httponly=True,
        samesite="strict",
        secure=c.settings.app_env == "production",
        path="/admin",
    )
    return resp


@router.post("/logout", summary="Drop the admin session")
async def logout():
    resp = JSONResponse({"success": True})
    resp.delete_cookie(COOKIE, path="/admin")
    return resp


@router.get("/api/stats", summary="Security counters")
async def stats(c: Container = Depends(require_admin)):
    raw = await c.audit.stats()
    s = {e.value: raw.get(e.value, 0) for e in EventType}
    return {
        "otp_issued": s["OTP_CREATED"] + s["OTP_RESENT"],
        "verified": s["OTP_VERIFIED"],
        "failed": s["OTP_INVALID"] + s["OTP_EXPIRED"] + s["OTP_REUSED"] + s["OTP_REPLACED"],
        "blocks": s["PHONE_BLOCKED"],
        "rate_limited": s["SEND_RATE_LIMITED"] + s["IP_RATE_LIMITED"],
        "blocked_attempts": s["BLOCKED_ATTEMPT"],
        "by_event": s,
    }


@router.get("/api/events", summary="Recent security events (newest first)")
async def events(limit: int = 200, event: str | None = None, c: Container = Depends(require_admin)):
    limit = max(1, min(limit, c.settings.audit_max_events))
    if event and event not in EventType.__members__:
        raise HTTPException(status_code=422, detail="Unknown event type")
    return {"events": await c.audit.recent(limit=limit, event=event)}
