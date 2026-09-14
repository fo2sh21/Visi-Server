"""Blind-switchboard guards: no IP logging, in-memory hashed rate buckets (M3)."""
from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict, deque

from fastapi import Request


class _StripIPFilter(logging.Filter):
    """Best-effort: drop common IP fields from any log record message."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        # Never emit client IPs; uvicorn access log is disabled in main.py.
        if "client" in msg and ("127." in msg or "." in msg):
            record.msg = "[access redacted]"
            record.args = ()
        return True


def install_no_ip_logging() -> None:
    for name in ("uvicorn.access", "uvicorn.error", "fastapi"):
        logging.getLogger(name).addFilter(_StripIPFilter())


# M3: fixed-window buckets keyed by sha256(salt + ip), memory only, never logged.
_SALT = hashlib.sha256(b"visi-rl-v1").digest()
_buckets: dict[str, deque[float]] = defaultdict(deque)

WINDOW_SEC = 60.0
MAX_HITS = 10


def _bucket_key(request: Request, scope: str) -> str:
    ip = (request.client.host if request.client else "unknown").encode()
    return hashlib.sha256(_SALT + scope.encode() + ip).hexdigest()


def check_rate_limit(request: Request, scope: str = "login") -> bool:
    """True if allowed. No persistence, no logging of key or IP."""
    now = time.monotonic()
    key = _bucket_key(request, scope)
    q = _buckets[key]
    while q and now - q[0] > WINDOW_SEC:
        q.popleft()
    if len(q) >= MAX_HITS:
        return False
    q.append(now)
    return True
