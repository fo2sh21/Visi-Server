"""WebSocket relay + offline queue.

M2: INSERT -> push -> DELETE-on-ack (row lives until ack).
Postgres-backed for v1 (no Redis). All fan-out goes through Broker so a
Redis pub/sub impl can replace it later without changing schema/protocol.
Postgres LISTEN/NOTIFY used only as wakeup ping (msg_id), worker SELECTs row.

Auth: Authorization: Bearer <ws_token_b64> header ONLY (never ?token=).
Delivery is at-least-once: unacked rows stay queued and are redelivered on
reconnect. Client contract: dedup by msg_id; on an already-seen msg_id,
re-send the ack but do NOT reprocess the envelope (else redeliveries loop).
Acks are idempotent. Only an ack from the owning recipient deletes a row.
Ticks: the ack triggers a best-effort {"type": "delivered"} push to the
original sender when online; when offline, a durable pending-delivered row
is stored instead and flushed on reconnect (same lifecycle as messages:
stored only until acknowledged, never archived). Read receipts to offline
targets are likewise stored. Rekey nudges stay live-only, never stored.
Tick-state sync on reconnect is therefore complete for senders back within
30 days (older pending receipts are lazily swept on flush).
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models, tokens
from ..db import SessionLocal, get_db

router = APIRouter(tags=["ws"])

ACK_TIMEOUT_SEC = 30
RECEIPT_TTL_SEC = 30 * 24 * 3600


class Broker:
    """In-memory fan-out for a single instance. Swap for Redis later."""

    def __init__(self) -> None:
        self.online: dict[str, set[WebSocket]] = {}
        # m3: keyed by (username, msg_id) — bare msg_id collides across users.
        self.acks: dict[tuple[str, str], asyncio.Event] = {}
        # Delivered-tick memory: (recipient, msg_id) -> original sender for
        # rows already hard-deleted, so a duplicate ack re-pushes the
        # identical tick instead of going silent. Bounded FIFO; single-
        # instance v1 like `acks` (a Redis Broker impl would carry this too).
        self.recently_acked: dict[tuple[str, str], str] = {}
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

    def expect_ack(self, username: str, msg_id: str) -> asyncio.Event:
        ev = asyncio.Event()
        self.acks[(username, msg_id)] = ev
        return ev

    def resolve_ack(self, username: str, msg_id: str) -> None:
        ev = self.acks.pop((username, msg_id), None)
        if ev is not None:
            ev.set()

    def remember_acked(self, username: str, msg_id: str, sender: str) -> None:
        self.recently_acked[(username, msg_id)] = sender
        while len(self.recently_acked) > 1024:
            self.recently_acked.pop(next(iter(self.recently_acked)))

    def acked_sender(self, username: str, msg_id: str) -> str | None:
        return self.recently_acked.get((username, msg_id))


broker = Broker()


async def _delete_msg(msg_id: str, to_user: str) -> None:
    """R2: scoped delete — only the owning recipient's ack removes the row."""
    async with SessionLocal() as db:
        row = await db.get(models.OfflineQueue, msg_id)
        if row is not None and row.to_user == to_user:
            await db.delete(row)
            await db.commit()


async def _pop_sender(msg_id: str, to_user: str) -> str | None:
    """Delivered-receipt helper: load the original sender, then hard-DELETE.

    Single scoped SELECT (same msg_id + to_user predicate as R2), so the
    sender lookup and the delete share one ownership check and one round-trip.
    Returns the sender username, or None if no such row (unknown msg_id or
    another user's ack — both are silent no-ops for the tick).
    """
    async with SessionLocal() as db:
        row = await db.get(models.OfflineQueue, msg_id)
        if row is None or row.to_user != to_user:
            return None
        sender = row.from_user
        await db.delete(row)
        await db.commit()
        broker.remember_acked(to_user, msg_id, sender)
        return sender


async def flush_queue(username: str) -> None:
    """R3: push only — never delete on send. Rows die exclusively via the
    ack path, so a client that connects then drops loses nothing; the next
    connect redelivers (at-least-once, client dedups by msg_id).

    Durable receipts ride the same flush: lazy 30-day sweep for this user,
    then pending receipts oldest-first as {type, msg_id, receipt_id}.
    Receipt rows die only on {type:ack, receipt_id} from the addressee."""
    async with SessionLocal() as db:
        res = await db.execute(
            select(models.OfflineQueue)
            .where(models.OfflineQueue.to_user == username)
            .order_by(models.OfflineQueue.created_at)
            .limit(100)
        )
        rows = list(res.scalars().all())
    for r in rows:
        await broker.push(
            username, {"from": r.from_user, "envelope_b64": r.envelope_b64, "msg_id": r.msg_id}
        )
    cutoff = int(time.time()) - RECEIPT_TTL_SEC
    async with SessionLocal() as db:
        await db.execute(
            delete(models.PendingReceipt).where(
                models.PendingReceipt.to_user == username,
                models.PendingReceipt.created_at < cutoff,
            )
        )
        await db.commit()
        res = await db.execute(
            select(models.PendingReceipt)
            .where(models.PendingReceipt.to_user == username)
            .order_by(models.PendingReceipt.created_at)
            .limit(100)
        )
        receipts = list(res.scalars().all())
    for p in receipts:
        await broker.push(
            username, {"type": p.kind, "msg_id": p.msg_id, "receipt_id": p.id}
        )


async def _store_receipt(to_user: str, kind: str, msg_id: str) -> None:
    """Durable backstop: persist a receipt until the addressee acks it.

    Same lifecycle as messages (stored only until acknowledged, never
    archived). Dedup-guarded by UNIQUE(to_user, kind, msg_id) — duplicate
    acks/reads collapse into one row (IntegrityError -> ignore). Never logged.
    """
    async with SessionLocal() as db:
        db.add(models.PendingReceipt(to_user=to_user, kind=kind, msg_id=msg_id))
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()


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
    # R1: header-only. Tokens in URLs leak into proxy/uvicorn logs;
    # native app has no browser constraint justifying ?token=.
    auth = ws.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        await ws.close(code=4401)
        return
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
            # Receipt acks: {type: ack, receipt_id} -> scoped DELETE only.
            # Receipts never generate receipts (no loops); duplicate acks
            # find no row and stay silent.
            if msg.get("type") == "ack" and msg.get("receipt_id"):
                async with SessionLocal() as db:
                    row = await db.get(models.PendingReceipt, msg["receipt_id"])
                    if row is not None and row.to_user == username:
                        await db.delete(row)
                        await db.commit()
                continue
            # Message acks: {type: ack, msg_id} -> live tick if the sender is
            # online, durable pending-delivered row if offline. Duplicate acks
            # re-push the identical tick (client dedups by msg_id).
            if msg.get("type") == "ack" and msg.get("msg_id"):
                broker.resolve_ack(username, msg["msg_id"])
                sender = await _pop_sender(msg["msg_id"], username)
                if sender is None:
                    # Duplicate ack for an already-deleted row: same tick
                    # again. Unknown msg_id or another user's row stays silent
                    # — unless this is a live-tick ack (plain msg_id): consume
                    # a pending row on exact (to_user, msg_id, delivered) match
                    # only, so it can never eat a pending read.
                    sender = broker.acked_sender(username, msg["msg_id"])
                    if sender is None:
                        async with SessionLocal() as db:
                            res = await db.execute(
                                select(models.PendingReceipt).where(
                                    models.PendingReceipt.to_user == username,
                                    models.PendingReceipt.kind == "delivered",
                                    models.PendingReceipt.msg_id == msg["msg_id"],
                                )
                            )
                            prow = res.scalars().first()
                            if prow is not None:
                                await db.delete(prow)
                                await db.commit()
                        continue
                if sender != username:
                    if broker.is_online(sender):
                        await broker.push(
                            sender,
                            {"type": "delivered", "msg_id": msg["msg_id"], "to": sender},
                        )
                    else:
                        await _store_receipt(sender, "delivered", msg["msg_id"])
                continue
            # Read receipts: live route if online, durable backstop if offline.
            if msg.get("type") == "read" and msg.get("msg_id"):
                target = msg.get("to", "")
                if target:
                    if broker.is_online(target):
                        await broker.push(
                            target,
                            {"type": "read", "from": username, "msg_id": msg["msg_id"]},
                        )
                    else:
                        await _store_receipt(target, "read", msg["msg_id"])
                continue
            # Rekey nudge: live-only, never stored — push-if-online, drop
            # otherwise. A missed nudge self-heals: the sender's next send to
            # the stale bundle fails again and draws a fresh nudge.
            if msg.get("type") == "rekey" and msg.get("to"):
                await broker.push(
                    msg["to"], {"type": "rekey", "from": username, "to": msg["to"]}
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
                    ev = broker.expect_ack(to_user, msg_id)
                    try:
                        await asyncio.wait_for(ev.wait(), timeout=ACK_TIMEOUT_SEC)
                    except asyncio.TimeoutError:
                        pass  # row stays queued for redelivery on reconnect
                    else:
                        await _delete_msg(msg_id, to_user)
    except WebSocketDisconnect:
        pass
    finally:
        await broker.disconnect(username, ws)
        async with SessionLocal() as db:
            row = await db.get(models.Presence, username)
            if row is not None and not broker.is_online(username):
                await db.delete(row)
                await db.commit()
