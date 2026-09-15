"""Server config. SPEC.md is normative for OPAQUE; B1-B4/M1-M4 are locked."""
from __future__ import annotations

import os
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]


def _normalize_db_url(url: str) -> tuple[str, bool]:
    """Make dashboard-pasted Postgres URLs async-engine-ready.

    Neon/Render dashboards hand out libpq-shaped URLs (`postgresql://` +
    `sslmode` / `channel_binding` params) but the async engine needs the
    `postgresql+asyncpg` dialect, and asyncpg chokes on libpq-only params.
    Returns (normalized_url, use_ssl). SQLite URLs pass through untouched.
    """
    scheme, sep, rest = url.partition("://")
    if sep and "+" not in scheme and scheme in ("postgres", "postgresql"):
        scheme = "postgresql+asyncpg"
        url = scheme + "://" + rest
    use_ssl = False
    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

        parts = urlsplit(url)
        if parts.scheme.startswith("postgresql"):
            kept = []
            for k, v in parse_qsl(parts.query, keep_blank_values=True):
                if k == "sslmode":
                    use_ssl = v.lower() != "disable"
                elif k == "channel_binding":
                    continue  # libpq-only; asyncpg rejects it
                else:
                    kept.append((k, v))
            url = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment)
            )
    except Exception:
        pass
    return url, use_ssl


# Postgres preferred (SPEC M4). SQLite fallback for local dev only.
DATABASE_URL, DATABASE_USE_SSL = _normalize_db_url(
    os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{SERVER_ROOT / 'visi.db'}")
)

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

# FCM push (specs/fcm-push.md). Inline service-account JSON first (Render/prod,
# wipe-safe: whole file content as one env value), file path as local fallback.
# Absent both = push silently disabled (logged once at startup, not per msg).
FCM_CREDENTIALS_JSON = os.getenv("FCM_CREDENTIALS_JSON", "")
FCM_CREDENTIALS_PATH = os.getenv("FCM_CREDENTIALS_PATH", "")

# Rate limits (M3: buckets keyed by in-memory hash only).
LOGIN_RATE_LIMIT = os.getenv("LOGIN_RATE_LIMIT", "10/minute")
REGISTER_RATE_LIMIT = os.getenv("REGISTER_RATE_LIMIT", "10/minute")

USERNAME_RE = r"^[a-zA-Z0-9_.\-]{3,32}$"
