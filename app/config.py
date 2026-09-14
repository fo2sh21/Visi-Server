"""Server config. SPEC.md is normative for OPAQUE; B1-B4/M1-M4 are locked."""
from __future__ import annotations

import os
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]

# Postgres preferred (SPEC M4). SQLite fallback for local dev only.
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{SERVER_ROOT / 'visi.db'}")

# Sidecar CLI binary (B2: subprocess, NOT PyO3).
_default_bin = SERVER_ROOT / "target" / "release" / (
    "opaque-sidecar.exe" if os.name == "nt" else "opaque-sidecar"
)
SIDECAR_BIN = os.getenv("OPAQUE_SIDECAR_BIN", str(_default_bin))

# B1: ws_tokens need issued_at + 30-day cap.
WS_TOKEN_TTL_DAYS = int(os.getenv("WS_TOKEN_TTL_DAYS", "30"))
WS_TOKEN_MAX_AGE_SEC = WS_TOKEN_TTL_DAYS * 24 * 3600

# B2 gap: login_state TTL (subprocess is stateless; server must hold it).
LOGIN_STATE_TTL_SEC = int(os.getenv("LOGIN_STATE_TTL_SEC", "300"))

# OTA manifest (served verbatim, never logged).
UPDATE_VERSION_CODE = int(os.getenv("UPDATE_VERSION_CODE", "4"))
UPDATE_DOWNLOAD_URL = os.getenv(
    "UPDATE_DOWNLOAD_URL", "https://your-domain.com/releases/visiapp-1.0.4.apk"
)
UPDATE_SHA256 = os.getenv("UPDATE_SHA256", "")
# OTA bucket source of truth (specs/ota-latest-json.md). Empty = local-dev
# fallback to the env-var manifest above, no bucket fetch attempted.
UPDATE_BUCKET_BASE = os.getenv("UPDATE_BUCKET_BASE", "").rstrip("/")
UPDATE_MANIFEST_TTL_SEC = int(os.getenv("UPDATE_MANIFEST_TTL_SEC", "300"))

# FCM push (specs/fcm-push.md). Service-account JSON path, server-side only.
# Absent = push silently disabled (logged once at startup, not per message).
FCM_CREDENTIALS_PATH = os.getenv("FCM_CREDENTIALS_PATH", "")

# Rate limits (M3: buckets keyed by in-memory hash only).
LOGIN_RATE_LIMIT = os.getenv("LOGIN_RATE_LIMIT", "10/minute")
REGISTER_RATE_LIMIT = os.getenv("REGISTER_RATE_LIMIT", "10/minute")

USERNAME_RE = r"^[a-zA-Z0-9_.\-]{3,32}$"
