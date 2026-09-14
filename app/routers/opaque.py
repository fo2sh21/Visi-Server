"""OPAQUE auth routers. SPEC.md normative; B1-B4/M1/M4 locked."""
from __future__ import annotations

import base64
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import config, merkle, models, schemas, security, sidecar, tokens
from ..db import get_db

router = APIRouter(prefix="/api/v1/opaque", tags=["opaque"])


def _b64len(field: str, expect: int, name: str) -> None:
    try:
        raw = base64.b64decode(field, validate=True)
    except Exception:
        raise HTTPException(400, f"bad base64 in {name}")
    if len(raw) != expect:
        raise HTTPException(400, f"bad length in {name}: want {expect}")


def validate_bundle(b: schemas.PreKeyBundleIn) -> dict:
    _b64len(b.identity_pub_ed_b64, 32, "identity_pub_ed_b64")
    _b64len(b.signed_pre_pub_x_b64, 32, "signed_pre_pub_x_b64")
    _b64len(b.signed_pre_sig_b64, 64, "signed_pre_sig_b64")
    if b.onetime_pub_x_b64 is not None:  # M1: null accepted
        _b64len(b.onetime_pub_x_b64, 32, "onetime_pub_x_b64")
    return {
        "identity_pub_ed_b64": b.identity_pub_ed_b64,
        "signed_pre_pub_x_b64": b.signed_pre_pub_x_b64,
        "signed_pre_sig_b64": b.signed_pre_sig_b64,
        "onetime_pub_x_b64": b.onetime_pub_x_b64,
    }


async def get_setup_b64(db: AsyncSession) -> str:
    """M4: ServerSetup lives in Postgres single-row table."""
    row = await db.get(models.ServerSetup, 1)
    if row is not None:
        return base64.b64encode(row.blob).decode()
    ok = await sidecar.call("setup_new", {})
    raw = base64.b64decode(ok["setup"])
    db.add(models.ServerSetup(id=1, blob=raw))
    await db.commit()
    return ok["setup"]


async def merkle_append(db: AsyncSession, username: str, bundle: dict) -> None:
    res = await db.execute(select(models.MerkleLeaf).order_by(models.MerkleLeaf.idx))
    leaves = list(res.scalars().all())
    lh = merkle.leaf_hash(username, bundle)
    idx = len(leaves)
    # Replace existing user's leaf position if re-registering, else append.
    existing = next((l for l in leaves if l.username == username), None)
    if existing is not None:
        existing.leaf_hash = lh
        leaves = sorted(leaves, key=lambda l: l.idx)
    else:
        db.add(models.MerkleLeaf(idx=idx, username=username, leaf_hash=lh))
        leaves.append(models.MerkleLeaf(idx=idx, username=username, leaf_hash=lh))
    ordered = [l.leaf_hash for l in sorted(leaves, key=lambda l: l.idx)]
    root, size = merkle.compute_root(ordered)
    st = await db.get(models.MerkleState, 1)
    if st is None:
        db.add(models.MerkleState(id=1, size=size, root=root))
    else:
        st.size, st.root = size, root


@router.post("/register/start", response_model=schemas.RegisterStartOut)
async def register_start(body: schemas.RegisterStartIn, db: AsyncSession = Depends(get_db)):
    setup = await get_setup_b64(db)
    try:
        ok = await sidecar.call(
            "register_start",
            {"setup": setup, "request": body.registration_request_b64, "user_id": body.username},
        )
    except sidecar.SidecarAuthError as e:
        raise HTTPException(400, "registration rejected")
    except sidecar.SidecarInfraError as e:
        raise HTTPException(500, "auth backend unavailable")
    return {"registration_response_b64": ok["response"]}


@router.post("/register/finish", response_model=schemas.StatusOut)
async def register_finish(body: schemas.RegisterFinishIn, db: AsyncSession = Depends(get_db)):
    bundle = validate_bundle(body.bundle)
    if body.envelope_b64:
        try:
            base64.b64decode(body.envelope_b64, validate=True)
        except Exception:
            raise HTTPException(400, "bad base64 in envelope_b64")
    try:
        ok = await sidecar.call("register_finish", {"upload": body.registration_upload_b64})
    except sidecar.SidecarAuthError:
        raise HTTPException(400, "registration rejected")
    except sidecar.SidecarInfraError:
        raise HTTPException(500, "auth backend unavailable")
    pf_raw = base64.b64decode(ok["password_file"])
    # Upsert password file + bundle + envelope (re-registration rotates keys).
    for model, key, val in (
        (models.PasswordFile, body.username, pf_raw),
    ):
        row = await db.get(model, key)
        if row is None:
            db.add(model(username=key, blob=val))
        else:
            row.blob = val
    kb = await db.get(models.KeyBundle, body.username)
    canon = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    if kb is None:
        db.add(models.KeyBundle(username=body.username, bundle=canon, leaf_idx=0))
    else:
        kb.bundle = canon
    env = await db.get(models.UserEnvelope, body.username)
    if env is None:
        db.add(models.UserEnvelope(username=body.username, envelope_b64=body.envelope_b64))
    else:
        env.envelope_b64 = body.envelope_b64
    await merkle_append(db, body.username, bundle)
    # Fix leaf_idx pointer.
    res = await db.execute(
        select(models.MerkleLeaf).where(models.MerkleLeaf.username == body.username)
    )
    leaf = res.scalars().first()
    if leaf is not None and kb is not None:
        kb.leaf_idx = leaf.idx
    await db.commit()
    return {"status": "ok"}


@router.post("/login/start", response_model=schemas.LoginStartOut)
async def login_start(
    body: schemas.LoginStartIn, request: Request, db: AsyncSession = Depends(get_db)
):
    if not security.check_rate_limit(request, "login"):
        raise HTTPException(429, "rate limited")
    setup = await get_setup_b64(db)
    # B3: fetch-or-null, single shape. Omit password_file for unknown users.
    pf = await db.get(models.PasswordFile, body.username)
    fields: dict = {
        "setup": setup,
        "request": body.credential_request_b64,
        "user_id": body.username,
    }
    if pf is not None:
        fields["password_file"] = base64.b64encode(pf.blob).decode()
    try:
        ok = await sidecar.call("login_start", fields)
    except (sidecar.SidecarAuthError, sidecar.SidecarInfraError):
        # Never reveal existence via status/timing branch: generic 401-shaped
        # path only if sidecar itself rejects the request blob.
        raise HTTPException(400, "login rejected")
    # B2: hold login_state server-side, minutes TTL.
    raw_state = base64.b64decode(ok["login_state"])
    exp = int(time.time()) + config.LOGIN_STATE_TTL_SEC
    ls = await db.get(models.LoginState, body.username)
    if ls is None:
        db.add(models.LoginState(username=body.username, blob=raw_state, expires_at=exp))
    else:
        ls.blob, ls.expires_at = raw_state, exp
    await db.commit()
    return {"credential_response_b64": ok["response"]}


@router.post("/login/finish", response_model=schemas.LoginFinishOut)
async def login_finish(
    body: schemas.LoginFinishIn, request: Request, db: AsyncSession = Depends(get_db)
):
    if not security.check_rate_limit(request, "login"):
        raise HTTPException(429, "rate limited")
    ls = await db.get(models.LoginState, body.username)
    if ls is None or ls.expires_at < int(time.time()):
        if ls is not None:
            await db.delete(ls)
            await db.commit()
        raise HTTPException(401, "login failed")  # generic, no oracle
    try:
        ok = await sidecar.call(
            "login_finish",
            {
                "login_state": base64.b64encode(ls.blob).decode(),
                "finalization": body.credential_finalization_b64,
            },
        )
    except sidecar.SidecarAuthError:
        raise HTTPException(401, "login failed")
    except sidecar.SidecarInfraError:
        raise HTTPException(500, "auth backend unavailable")
    finally:
        # Single-use state regardless of outcome.
        await db.delete(ls)
    # B1 verbatim derivation; B4: session_key never leaves this scope.
    session_key = base64.b64decode(ok["session_key"])
    token = tokens.derive_ws_token(session_key, body.username)
    session_key = b"\x00" * len(session_key)
    del session_key
    now = int(time.time())
    exp = now + min(config.WS_TOKEN_MAX_AGE_SEC, 30 * 24 * 3600)  # 30-day cap
    db.add(
        models.WsToken(
            token_hash=tokens.token_hash(token),
            username=body.username,
            issued_at=now,
            expires_at=exp,
        )
    )
    env = await db.get(models.UserEnvelope, body.username)
    await db.commit()
    return {
        "status": "ok",
        "envelope_b64": env.envelope_b64 if env else "",
        "ws_token_b64": tokens.b64e(token),
    }
