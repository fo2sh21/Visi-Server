"""OTA manifest: `latest.json` bucket source of truth, env fallback.

Layout (public R2): `visi-<versionCode>.apk` + `latest.json`
`{"version_code": N, "file": "visi-N.apk", "sha256": "<hex>"}`.

Trust note (stated, not hidden): the sha256 defeats transit corruption and
mismatched uploads. A full bucket takeover could rewrite APK + latest.json
together — mitigated by a write-scoped R2 token, the monotonicity guard
below (max_seen_version fails closed on rollback), and a small trusted
circle. True out-of-band hash pinning (hash via the signed Merkle ledger)
is tracked follow-up work.
"""
from __future__ import annotations

import logging
import re
import time

import httpx
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from .. import config, models, schemas
from ..db import get_db

router = APIRouter(prefix="/api/v1", tags=["update"])

log = logging.getLogger("uvicorn.error")

_FILE_RE = re.compile(r"^[\w][\w.\-]*\.apk$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# 5-min in-memory cache (not per-request, not persistent).
_cache: dict = {"at": 0.0, "manifest": None}
# Last bucket manifest that passed the monotonicity guard. Served verbatim
# if the bucket ever rolls back (fail closed).
_last_good: dict | None = None


def _env_manifest() -> dict:
    return {
        "version_code": config.UPDATE_VERSION_CODE,
        "download_url": config.UPDATE_DOWNLOAD_URL,
        "sha256": config.UPDATE_SHA256,
    }


def _parse_latest(doc: object) -> dict | None:
    """Validate bucket JSON; None = malformed (fall back, never 500)."""
    if not isinstance(doc, dict):
        return None
    v, f, s = doc.get("version_code"), doc.get("file"), doc.get("sha256")
    if not isinstance(v, int) or v <= 0:
        return None
    if not isinstance(f, str) or not _FILE_RE.match(f):
        return None
    if not isinstance(s, str) or not _SHA_RE.match(s):
        return None
    base = config.UPDATE_BUCKET_BASE
    return {"version_code": v, "download_url": f"{base}/{f}", "sha256": s.lower()}


async def _fetch_bucket() -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as http:
            r = await http.get(f"{config.UPDATE_BUCKET_BASE}/latest.json")
        if r.status_code != 200:
            return None
        return _parse_latest(r.json())
    except Exception:
        return None


async def _max_seen(db: AsyncSession, default: int) -> models.OtaState:
    st = await db.get(models.OtaState, 1)
    if st is None:
        st = models.OtaState(id=1, max_seen_version=default)
        db.add(st)
        await db.commit()
    return st


async def _current_manifest(db: AsyncSession) -> dict:
    """Resolve the manifest to serve: cache → bucket → fallback, guarded."""
    global _last_good
    now = time.monotonic()
    if _cache["manifest"] is not None and now - _cache["at"] < config.UPDATE_MANIFEST_TTL_SEC:
        return _cache["manifest"]
    if not config.UPDATE_BUCKET_BASE:
        return _env_manifest()  # local-dev fallback; no bucket, no guard
    fetched = await _fetch_bucket()
    if fetched is None:
        # Bucket error/malformed: last-good cache, else env fallback.
        # No guard trip here — an outage is not a rollback.
        if _cache["manifest"] is not None:
            return _cache["manifest"]
        return _env_manifest()
    st = await _max_seen(db, fetched["version_code"])
    if fetched["version_code"] < st.max_seen_version:
        log.error(
            "OTA ROLLBACK: latest.json reports version %d below served max %d — "
            "failing closed (bucket may be poisoned or rolled back)",
            fetched["version_code"], st.max_seen_version,
        )
        if _last_good is not None:
            return _last_good
        return {"version_code": st.max_seen_version, "download_url": "", "sha256": ""}
    st.max_seen_version = fetched["version_code"]
    await db.commit()
    _last_good = fetched
    _cache.update(at=now, manifest=fetched)
    return fetched


@router.get("/update-check", response_model=schemas.UpdateOut)
async def update_check(
    version_code: int = Query(0, ge=0), db: AsyncSession = Depends(get_db)
):
    m = await _current_manifest(db)
    if m["version_code"] > version_code:
        return m
    # No-update shape: echo the client's version, empty rest (same schema).
    return {"version_code": version_code, "download_url": "", "sha256": ""}
