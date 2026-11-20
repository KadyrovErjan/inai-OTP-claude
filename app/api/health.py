from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError

from app.dependencies import Container, get_container

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Liveness and Redis connectivity")
async def health(c: Container = Depends(get_container)):
    try:
        await c.redis.ping()
        redis_ok = True
    except RedisError:
        redis_ok = False
    body = {
        "status": "ok" if redis_ok else "degraded",
        "redis": "up" if redis_ok else "down",
        "env": c.settings.app_env,
        "outbox_enabled": c.settings.outbox_enabled,
    }
    return JSONResponse(body, status_code=200 if redis_ok else 503)
