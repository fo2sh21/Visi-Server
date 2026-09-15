"""Push-token registration. Tokens are routing metadata (like usernames):
stored plainly, never logged. A user registers only their OWN token."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from .. import fcm, models, schemas
from ..db import get_db
from .presence import _require_user

router = APIRouter(prefix="/api/v1", tags=["push"])


@router.post("/push-token", response_model=schemas.StatusOut)
async def register_token(
    body: schemas.PushTokenIn,
    owner: str = Depends(_require_user),
    db: AsyncSession = Depends(get_db),
):
    if body.username != owner:
        raise HTTPException(403, "cannot register another user's token")
    row = await db.get(models.PushToken, body.username)
    if row is None:
        db.add(models.PushToken(username=body.username, fcm_token=body.fcm_token,
                                 updated_at=int(time.time())))
    else:
        row.fcm_token, row.updated_at = body.fcm_token, int(time.time())
    await db.commit()
    return {"status": "ok"}


@router.post("/push-token/delete", response_model=schemas.StatusOut)
async def delete_token(
    body: schemas.PushTokenDeleteIn,
    owner: str = Depends(_require_user),
    db: AsyncSession = Depends(get_db),
):
    if body.username != owner:
        raise HTTPException(403, "cannot delete another user's token")
    row = await db.get(models.PushToken, body.username)
    if row is not None:
        await db.delete(row)
        await db.commit()
    return {"status": "ok"}


@router.post("/push-test", response_model=schemas.PushTestOut)
async def push_test(
    owner: str = Depends(_require_user),
    db: AsyncSession = Depends(get_db),
):
    """Diagnostic only: data-only ping to the caller's OWN stored token.

    Bisects the pipeline without a peer: `sent` proves server + creds + FCM
    work (fault is then client-side); anything else names the server cause.
    Self-only (username == token owner enforced by construction).
    """
    row = await db.get(models.PushToken, owner)
    if row is None:
        return {"status": "no-token"}
    if fcm._load() is None:
        return {"status": "disabled"}
    outcome = await fcm.send_ping(row.fcm_token)
    if outcome == "ok":
        return {"status": "sent"}
    if outcome == "stale":
        fresh = await db.get(models.PushToken, owner)
        if fresh is not None and fresh.fcm_token == row.fcm_token:
            await db.delete(fresh)
            await db.commit()
        return {"status": "stale"}
    return {"status": "error"}
