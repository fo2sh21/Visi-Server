"""Directory, key transparency, Merkle root."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import merkle, models, schemas
from ..db import get_db

router = APIRouter(prefix="/api/v1", tags=["directory"])


@router.get("/directory", response_model=schemas.DirectoryOut)
async def directory(
    prefix: str = Query(""), cursor: int = Query(0, ge=0), db: AsyncSession = Depends(get_db)
):
    res = await db.execute(
        select(models.KeyBundle)
        .where(models.KeyBundle.username.like(f"{prefix}%"))
        .order_by(models.KeyBundle.username)
        .offset(cursor)
        .limit(50)
    )
    names = [r.username for r in res.scalars().all()]
    return {"usernames": names, "next_cursor": cursor + len(names)}


@router.get("/keys/{username}", response_model=schemas.KeysOut)
async def get_keys(username: str, db: AsyncSession = Depends(get_db)):
    kb = await db.get(models.KeyBundle, username)
    if kb is None:
        raise HTTPException(404, "unknown user")
    bundle = json.loads(kb.bundle)
    res = await db.execute(select(models.MerkleLeaf).order_by(models.MerkleLeaf.idx))
    leaves = list(res.scalars().all())
    ordered = [l.leaf_hash for l in leaves]
    root, size = merkle.compute_root(ordered)
    idx = next((i for i, l in enumerate(leaves) if l.username == username), None)
    if idx is None:
        raise HTTPException(404, "no leaf")
    return {
        "username": username,
        "bundle": bundle,
        "leaf": merkle.b64e(ordered[idx]),
        "proof": merkle.merkle_proof(ordered, idx),
        "root": merkle.b64e(root),
        "size": size,
    }


@router.get("/merkle/root", response_model=schemas.MerkleRootOut)
async def merkle_root(db: AsyncSession = Depends(get_db)):
    st = await db.get(models.MerkleState, 1)
    if st is None:
        res = await db.execute(select(models.MerkleLeaf).order_by(models.MerkleLeaf.idx))
        leaves = [l.leaf_hash for l in res.scalars().all()]
        root, size = merkle.compute_root(leaves)
    else:
        root, size = st.root, st.size
    return {"root": merkle.b64e(root), "size": size}
