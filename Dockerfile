FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=127.0.0.1 \
    PORT=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY attack.py ./
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# strip CR in case the repo was checked out with CRLF line endings
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod 755 /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /app/outbox /app/data

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/health', timeout=2)"

# python -m app == uvicorn app.main:app --no-proxy-headers --no-access-log
# (client IP = real TCP peer address, X-Forwarded-For is ignored)
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["sh", "-c", "exec python -m app --host \"$HOST\" --port \"$PORT\""]
