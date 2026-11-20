"""Demo SMS delivery: append issued OTPs to ``outbox/sms.jsonl`` (JSON Lines).

This file is the ONLY place where plaintext OTPs exist. It is meant for the jury /
testers and must never be served over HTTP. In production disable it
(OUTBOX_ENABLED=false) and plug in a real SMS provider instead.

Write protocol (one line per OTP):
  * a single ``os.write`` of the full, newline-terminated UTF-8 line to a file
    opened with O_APPEND;
  * guarded by an in-process lock plus an exclusive OS lock (``fcntl.flock`` on
    Linux/macOS, ``msvcrt.locking`` on a sidecar lock file on Windows), so lines
    from concurrent requests and from several API processes never interleave;
  * followed by ``fsync`` - the line is on disk before HTTP 200 is returned.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

try:  # Linux / macOS
    import fcntl  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt  # type: ignore[import-not-found]

log = logging.getLogger("otp_secure.outbox")


class OutboxError(RuntimeError):
    pass


class SmsOutboxNotifier:
    def __init__(self, path: Path, enabled: bool = True) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ setup
    def ensure_ready(self) -> None:
        if not self.enabled:
            return
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:  # pragma: no cover - e.g. bind mount owned by another user
            pass
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover
            pass

    # ------------------------------------------------------------------ write
    @staticmethod
    def build_record(msisdn: str, code: str, issued_at: datetime | None = None) -> dict:
        ts = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return {
            "msisdn": msisdn,
            "code": code,
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def _append_line(self, line: bytes) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    try:
                        self._write_all(fd, line)
                    finally:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                else:  # pragma: no cover - Windows
                    self._append_windows(fd, line)
            finally:
                os.close(fd)

    @staticmethod
    def _write_all(fd: int, line: bytes) -> None:
        written = os.write(fd, line)
        if written != len(line):
            raise OutboxError(f"short write to outbox ({written}/{len(line)} bytes)")
        os.fsync(fd)

    def _append_windows(self, fd: int, line: bytes) -> None:  # pragma: no cover
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        lfd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.lseek(lfd, 0, os.SEEK_SET)
            msvcrt.locking(lfd, msvcrt.LK_LOCK, 1)
            try:
                self._write_all(fd, line)
            finally:
                os.lseek(lfd, 0, os.SEEK_SET)
                msvcrt.locking(lfd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(lfd)

    async def send_otp(self, msisdn: str, code: str, issued_at: datetime | None = None) -> None:
        """Deliver ``code`` to ``msisdn``. Raises OutboxError if it could not be persisted."""
        if not self.enabled:
            return
        record = self.build_record(msisdn, code, issued_at)
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            await asyncio.to_thread(self._append_line, line)
        except OutboxError:
            raise
        except OSError as exc:
            # never log the record itself - it contains the OTP
            log.error("Outbox write failed: %s", exc.__class__.__name__)
            raise OutboxError("outbox write failed") from exc
