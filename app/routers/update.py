"""Self-hosted OTA manifest."""
from __future__ import annotations

from fastapi import APIRouter, Query

from .. import config, schemas

router = APIRouter(prefix="/api/v1", tags=["update"])


@router.get("/update-check", response_model=schemas.UpdateOut)
async def update_check(version_code: int = Query(0, ge=0)):
    _ = version_code  # client decides; server always advertises latest manifest.
    return {
        "version_code": config.UPDATE_VERSION_CODE,
        "download_url": config.UPDATE_DOWNLOAD_URL,
        "sha256": config.UPDATE_SHA256,
    }
