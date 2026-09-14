"""Presence query: online + last-seen per contact (visible-to-all v1).

No broadcast (the server has no contact graph); the client polls on
thread-open / reconnect / minute tick. Presence is public-by-design, but a
valid Bearer token (any user) is required — no anonymous harvesting.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models
from ..db import get_db
from ..ws import relay

router = APIRouter(prefix="/api/v1", tags=["presence"])


async def _require_user(authorization: str = Header("")) -> str:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "unauthorized")
    username = await relay.auth_token(token)
    if username is None:
        raise HTTPException(401, "unauthorized")
    return username


@router.get("/presence/{username}")
async def get_presence(
    username: str,
    _me: str = Depends(_require_user),
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(models.Presence, username)
    if row is None:
        return {"online": False, "last_seen": None}  # never seen
    return {"online": bool(row.online), "last_seen": row.last_seen}
