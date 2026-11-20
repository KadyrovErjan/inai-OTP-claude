FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY attack.py ./
RUN mkdir -p /app/outbox /app/data \
 && chown -R 1000:1000 /app/outbox /app/data \
 && chmod 700 /app/outbox /app/data

# runs as the host user (see `user:` in compose) so ./outbox/sms.jsonl stays readable on the host
USER 1000:1000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/health', timeout=2)"

# python -m app == uvicorn app.main:app --no-proxy-headers (client IP = TCP peer)
CMD ["sh", "-c", "python -m app --host \"$HOST\" --port \"$PORT\""]
