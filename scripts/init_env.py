#!/usr/bin/env python3
"""Create .env from .env.example with freshly generated secrets (never overwrites)."""
import os
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
env, example = root / ".env", root / ".env.example"
if env.exists():
    sys.exit(".env already exists - not touching it")
text = example.read_text("utf-8")
text = text.replace("OTP_HMAC_KEY=\n", f"OTP_HMAC_KEY={secrets.token_urlsafe(48)}\n")
text = text.replace("ADMIN_API_KEY=\n", f"ADMIN_API_KEY={secrets.token_urlsafe(32)}\n")
fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write(text)
print(f"created {env} (mode 600). ADMIN_API_KEY is inside - use it to log into /admin/dashboard")
