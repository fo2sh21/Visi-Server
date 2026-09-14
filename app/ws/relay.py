"""WebSocket relay + offline queue.

M2: INSERT -> push -> DELETE-on-ack (row lives until ack).
Postgres-backed for v1 (no Redis). All fan-out goes through Broker so a
Redis pub/sub impl can replace it later without changing schema/protocol.
Postgres LISTEN/NOTIFY used only as wakeup ping (msg_id), worker SELECTs row.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models, tokens
from ..db import SessionLocal, get_db

router = APIRouter(tags=["ws"])

ACK_TIMEOUT_SEC = 30


class Broker:
    """In-memory fan-out for a single instance. Swap for Redis later."""

    def __init__(self) -> None:
        self.online: dict[str, set[WebSocket]] = {}
        self.acks: dict[str, asyncio.Event] = {}
        self.lock = asyncio.Lock()

    async def connect(self, username: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self.lock:
            self.online.setdefault(username, set()).add(ws)

    async def disconnect(self, username: str, ws: WebSocket) -> None:
        async with self.lock:
            s = self.online.get(username)
            if s is not None:
                s.discard(ws)
                if not s:
                    self.online.pop(username, None)

    def is_online(self, username: str) -> bool:
        return bool(self.online.get(username))

    async def push(self, username: str, payload: dict) -> bool:
        async with self.lock:
            targets = list(self.online.get(username, ()))
        ok = False
        for ws in targets:
            try:
                await ws.send_text(json.dumps(payload))
                ok = True
            except Exception:
                continue
        return ok

    def expect_ack(self, msg_id: str) -> asyncio.Event:
        ev = asyncio.Event()
        self.acks[msg_id] = ev
        return ev

    def resolve_ack(self, msg_id: str) -> None:
        ev = self.acks.pop(msg_id, None)
        if ev is not None:
            ev.set()


broker = Broker()


async def _delete_msg(msg_id: str) -> None:
    async with SessionLocal() as db:
        row = await db.get(models.OfflineQueue, msg_id)
        if row is not None:
            await db.delete(row)
            await db.commit()


async def flush_queue(username: str) -> None:
    """Push queued rows on connect; DELETE after successful send (ack best-effort)."""
    async with SessionLocal() as db:
        res = await db.execute(
            select(models.OfflineQueue)
            .where(models.OfflineQueue.to_user == username)
            .order_by(models.OfflineQueue.created_at)
            .limit(100)
        )
        rows = list(res.scalars().all())
    for r in rows:
        sent = await broker.push(
            username, {"from": r.from_user, "envelope_b64": r.envelope_b64, "msg_id": r.msg_id}
        )
        if sent:
            await _delete_msg(r.msg_id)


async def auth_token(token_b64: str) -> str | None:
    try:
        raw = base64.b64decode(token_b64, validate=True)
    except Exception:
        return None
    th = tokens.token_hash(raw)
    async with SessionLocal() as db:
        row = await db.get(models.WsToken, th)
        if row is None or row.expires_at < int(time.time()):
            return None
        return row.username


@router.websocket("/api/v1/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.query_params.get("token", "")
    username = await auth_token(token)
    if username is None:
        await ws.close(code=4401)
        return
    await broker.connect(username, ws)
    async with SessionLocal() as db:
        if await db.get(models.Presence, username) is None:
            db.add(models.Presence(username=username, connected_at=int(time.time())))
            await db.commit()
    await flush_queue(username)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            # Ack path: {type: ack, msg_id} -> instant hard DELETE.
            if msg.get("type") == "ack" and msg.get("msg_id"):
                broker.resolve_ack(msg["msg_id"])
                await _delete_msg(msg["msg_id"])
                continue
            # Read receipts routed, never stored.
            if msg.get("type") == "read" and msg.get("msg_id"):
                target = msg.get("to", "")
                if target:
                    await broker.push(
                        target,
                        {"type": "read", "from": username, "msg_id": msg["msg_id"]},
                    )
                continue
            to_user, env, msg_id = msg.get("to"), msg.get("envelope_b64"), msg.get(
                "msg_id", uuid.uuid4().hex
            )
            if not to_user or not env:
                continue
            try:
                base64.b64decode(env, validate=True)
            except Exception:
                continue
            # M2: INSERT first, then push, DELETE on ack (timeout keeps row).
            async with SessionLocal() as db:
                db.add(
                    models.OfflineQueue(
                        msg_id=msg_id, to_user=to_user, from_user=username, envelope_b64=env
                    )
                )
                await db.commit()
            if broker.is_online(to_user):
                sent = await broker.push(
                    to_user, {"from": username, "envelope_b64": env, "msg_id": msg_id}
                )
                if sent:
                    ev = broker.expect_ack(msg_id)
                    try:
                        await asyncio.wait_for(ev.wait(), timeout=ACK_TIMEOUT_SEC)
                    except asyncio.TimeoutError:
                        pass  # row stays queued for redelivery on reconnect
                    else:
                        await _delete_msg(msg_id)
    except WebSocketDisconnect:
        pass
    finally:
        await broker.disconnect(username, ws)
        async with SessionLocal() as db:
            row = await db.get(models.Presence, username)
            if row is not None and not broker.is_online(username):
                await db.delete(row)
                await db.commit()
