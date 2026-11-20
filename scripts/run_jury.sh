#!/usr/bin/env bash
# Jury mode on Linux: Redis on localhost + FastAPI directly on the host (no proxy,
# no Docker NAT) so the client IP is the real TCP peer (127.0.0.1 / 127.0.0.2).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8000}"
REDIS_PORT="${REDIS_PORT:-6379}"

if ! (command -v redis-cli >/dev/null && redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1); then
  if command -v redis-server >/dev/null; then
    echo "starting local redis-server on 127.0.0.1:$REDIS_PORT"
    redis-server --bind 127.0.0.1 --port "$REDIS_PORT" --daemonize yes --appendonly yes --dir "$(pwd)/data"
  elif command -v docker >/dev/null; then
    echo "starting Redis via docker (host network)"
    docker compose -f docker-compose.jury.yml up -d redis
  else
    echo "Redis not found: install redis-server or docker" >&2; exit 1
  fi
fi

[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
[ -f .env ] || python scripts/init_env.py
mkdir -p outbox data && chmod 700 outbox data

export REDIS_URL="redis://127.0.0.1:${REDIS_PORT}/0"
echo "OTP Secure on http://127.0.0.1:${PORT}  |  OTPs -> $(pwd)/outbox/sms.jsonl"
exec uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "$PORT" --no-proxy-headers
