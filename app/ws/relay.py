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
import ipaddress
import json
import logging
import os
import socket
import time
import uuid

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models, tokens
from ..db import SessionLocal, get_db
from ..fcm import send_ping as _fcm_ping

router = APIRouter(tags=["ws"])

log = logging.getLogger("uvicorn.error")

ACK_TIMEOUT_SEC = 30
RECEIPT_TTL_SEC = 30 * 24 * 3600
# Server-side shred backstop: unacked message rows older than this die,
# so dead-forever accounts can't accumulate queue storage without bound.
QUEUE_TTL_SEC = 7 * 24 * 3600


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
    Receipt rows die only on {type:ack, receipt_id} from the addressee.

    Server-side shred: this user's message rows older than QUEUE_TTL_SEC
    (7d) die here too — recipients gone that long miss those messages."""
    cutoff = int(time.time()) - QUEUE_TTL_SEC
    async with SessionLocal() as db:
        await db.execute(
            delete(models.OfflineQueue).where(
                models.OfflineQueue.to_user == username,
                models.OfflineQueue.created_at < cutoff,
            )
        )
        await db.commit()
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


async def sweep_expired_queues() -> int:
    """Global shred backstop: delete ALL message rows older than QUEUE_TTL_SEC.

    The lazy per-user sweep in flush_queue covers returning recipients; this
    covers dead-forever accounts that never reconnect. Idempotent DELETEs —
    safe if a future second instance double-sweeps. Returns rows removed.
    """
    cutoff = int(time.time()) - QUEUE_TTL_SEC
    async with SessionLocal() as db:
        res = await db.execute(
            delete(models.OfflineQueue).where(models.OfflineQueue.created_at < cutoff)
        )
        await db.commit()
        return res.rowcount


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


async def _maybe_ping(to_user: str) -> None:
    """FCM doorbell: data-only ping to an offline recipient's stored token.

    Fire-and-forget from the send path — never blocks the relay. Stale
    (unregistered) tokens are deleted; anything else fails silent. The
    offline queue remains the source of truth; the token is never logged.
    Outcomes are logged WITHOUT identifiers so Render logs show whether
    push is flowing, stale, or dead (creds/network).
    """
    async with SessionLocal() as db:
        row = await db.get(models.PushToken, to_user)
        token = row.fcm_token if row else None
    if not token:
        return
    outcome = await _fcm_ping(token)
    if outcome == "ok":
        # INFO (not debug): Render hides debug, and invisible deliveries
        # cost a debug cycle — the device note is the only other proof.
        log.info("FCM ping delivered")
    elif outcome == "stale":
        log.info("FCM stale token pruned")
        async with SessionLocal() as db:
            row = await db.get(models.PushToken, to_user)
            if row is not None and row.fcm_token == token:
                await db.delete(row)
                await db.commit()
    else:
        log.warning("FCM ping failed (credentials or network?)")


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


# D-browser proxy egress guard (P0): the relay dials ONLY global-unicast
# web ports. Without this, any authed client (or stolen token) turns the
# relay into an open proxy: cloud metadata (169.254.169.254), internal
# ranges, loopback services, and non-web ports (SMTP spam from OUR IP).
# Resolve-then-validate on EVERY open (no cached verdicts across opens, so
# DNS-rebinding at a later open re-validates). PROXY_ALLOW_PRIVATE=1 skips
# ALL rules for the loopback echo harness (tests only — never set in
# prod). Ports are still shape-validated (int, 1-65535) before this.
PROXY_PORTS = (80, 443)

# D-browser dial timeout (P1): a blackholed SYN must never hang a stream
# forever. The wait_for below maps to the existing dial_timeout class.
PROXY_DIAL_TIMEOUT_S = 10.0


# D-browser proxy counters (counts CLASSES only — never hosts, ports,
# payloads, or users). The only proxy observability that exists, by design:
# stream opens/ends plus dial-failure classes. Logged at warning on dial
# failure (the diagnosable event), counted silently otherwise.
proxy_stats = {"open": 0, "refused": 0, "ended": 0,
               "dial_dns": 0, "dial_refused": 0, "dial_timeout": 0,
               "dial_other": 0}


async def _proxy_target_allowed(host: str, port: int) -> bool:
    # Test harness escape hatch (loopback echo servers live on ephemeral
    # ports): skips BOTH rules. Tests only — never set in prod.
    if os.environ.get("PROXY_ALLOW_PRIVATE") == "1":
        return True
    if port not in PROXY_PORTS:
        return False
    try:
        # Loop-backed DNS: never blocks the event loop on resolution.
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM)
    except Exception:
        return False
    addrs = {sa[0] for _, _, _, _, sa in infos}
    if not addrs:
        return False
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


@router.websocket("/api/v1/ws")
async def ws_endpoint(ws: WebSocket):   # R1: header-only. Tokens in URLs leak into proxy/uvicorn logs;
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
    # D-browser proxy: per-connection upstream sessions keyed by the
    # client-generated stream id. Local to this socket (the proxy WS is a
    # dedicated connection, separate from chat) — dies with the connection.
    proxy_sessions: dict = {}

    async def _proxy_pump(sid: str, reader: asyncio.StreamReader) -> None:
        """Upstream -> WS duplex half. Dumb bytes, never logged/inspected."""
        try:
            while True:
                chunk = await reader.read(16 * 1024)
                if not chunk:
                    break
                await broker.push(
                    username,
                    {"type": "proxy-data", "id": sid,
                     "chunk_b64": base64.b64encode(chunk).decode()},
                )
        except Exception:
            pass
        proxy_stats["ended"] += 1
        # Upstream EOF/error: tell the client the stream is dead
        # (fail-closed) so it never hangs on a half-open id.
        try:
            await broker.push(username, {"type": "proxy-close", "id": sid})
        except Exception:
            pass

    async with SessionLocal() as db:
        now = int(time.time())
        row = await db.get(models.Presence, username)
        if row is None:
            db.add(models.Presence(username=username, online=True, connected_at=now))
        else:
            row.online, row.connected_at = True, now
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
            # Heal request (Lane 0 Session 2): "I just reconnected — replay
            # anything of mine you still hold for our thread." Live-only,
            # never stored — exactly like rekey. A missed heal self-heals:
            # the requester re-sends on its next reconnect, and its own
            # outbox drain + backfill already ran. Old clients without the
            # heal branch fall through to envelope parsing inside try/catch
            # (a log line, never a crash); old servers drop heal frames and
            # new clients degrade to self-heal.
            if msg.get("type") == "heal" and msg.get("to"):
                await broker.push(
                    msg["to"], {"type": "heal", "from": username, "to": msg["to"]}
                )
                continue
            # D-browser proxy-open: dial is reachable ONLY after the Bearer
            # handshake above (pre-dial by construction — no new auth code).
            # Fail-closed: refused/unresolvable dial -> proxy-close, never an
            # error string (exception text can carry the hostname — it is
            # neither sent nor logged). Destinations are never logged.
            if msg.get("type") == "proxy-open":
                sid = msg.get("id")
                host = msg.get("host")
                port = msg.get("port")
                if (
                    not isinstance(sid, str) or not sid or len(sid) > 128
                    or not isinstance(host, str) or not host or len(host) > 253
                    or isinstance(port, bool) or not isinstance(port, int)
                    or not (1 <= port <= 65535)
                    or sid in proxy_sessions
                ):
                    continue
                # Egress guard: non-global IPs and non-web ports are refused
                # with proxy-close (fail-closed WITH signal — silent drops
                # would hang the client; the id alone leaks nothing).
                if not await _proxy_target_allowed(host, port):
                    proxy_stats["refused"] += 1
                    try:
                        await broker.push(username, {"type": "proxy-close", "id": sid})
                    except Exception:
                        pass
                    continue
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=PROXY_DIAL_TIMEOUT_S,
                    )
                except Exception as e:
                    # Class-only diagnosis (exception text can carry the
                    # hostname — it is neither sent nor logged).
                    if isinstance(e, socket.gaierror):
                        suffix = "dns"
                    elif isinstance(e, ConnectionRefusedError):
                        suffix = "refused"
                    elif isinstance(e, (asyncio.TimeoutError, TimeoutError)):
                        suffix = "timeout"
                    else:
                        suffix = "other"
                    proxy_stats["dial_" + suffix] += 1
                    log.warning("proxy dial failed: %s", suffix)
                    try:
                        await broker.push(username, {"type": "proxy-close", "id": sid})
                    except Exception:
                        pass
                    continue
                proxy_stats["open"] += 1
                pump = asyncio.create_task(_proxy_pump(sid, reader))
                proxy_sessions[sid] = (writer, pump)
                continue
            # D-browser proxy-data: dumb pipe chunk into the upstream socket.
            # Oversized/undecodable chunks are silently dropped (never cut).
            if msg.get("type") == "proxy-data":
                sid = msg.get("id")
                chunk_b64 = msg.get("chunk_b64")
                entry = proxy_sessions.get(sid) if isinstance(sid, str) else None
                if entry is None or not isinstance(chunk_b64, str):
                    continue
                try:
                    chunk = base64.b64decode(chunk_b64, validate=True)
                except Exception:
                    continue
                if not chunk or len(chunk) > 16 * 1024:
                    continue
                writer, pump = entry
                try:
                    writer.write(chunk)
                    await writer.drain()
                except Exception:
                    proxy_sessions.pop(sid, None)
                    pump.cancel()
                    try:
                        writer.close()
                    except Exception:
                        pass
                    try:
                        await broker.push(username, {"type": "proxy-close", "id": sid})
                    except Exception:
                        pass
                continue
            # D-browser proxy-close: kill one stream; unknown ids are no-ops.
            if msg.get("type") == "proxy-close":
                sid = msg.get("id")
                entry = proxy_sessions.pop(sid, None) if isinstance(sid, str) else None
                if entry is not None:
                    proxy_stats["ended"] += 1
                    writer, pump = entry
                    pump.cancel()
                    try:
                        writer.close()
                    except Exception:
                        pass
                continue
            # Decrypt-failed NACK: the receiver stored our message but no
            # session generation opens it. Live-route if the sender is online;
            # otherwise a DURABLE receipt so the sender heals on next connect
            # (deduped by UNIQUE(to_user, kind, msg_id) like read receipts).
            # Flushed without "from" — the sender resolves the thread from
            # their own row by msg_id. Sender-stamped here, never trusted
            # from the wire.
            if msg.get("type") == "decrypt-failed" and msg.get("msg_id"):
                target = msg.get("to", "")
                if target:
                    if broker.is_online(target):
                        await broker.push(
                            target,
                            {
                                "type": "decrypt-failed",
                                "from": username,
                                "msg_id": msg["msg_id"],
                            },
                        )
                    else:
                        await _store_receipt(target, "decrypt-failed", msg["msg_id"])
                continue
            # Track R truthful ticks: the receiver DECRYPTED (not just
            # stored) our message. Same lifecycle as decrypt-failed —
            # live-route if the sender is online, else a DURABLE receipt
            # so ✓✓ converges on next connect (deduped by
            # UNIQUE(to_user, kind, msg_id)). Flushed without "from" —
            # the sender resolves the thread from their own row by msg_id.
            # Old senders ignore the unknown type (log line, never crash).
            if msg.get("type") == "decrypted" and msg.get("msg_id"):
                target = msg.get("to", "")
                if target:
                    if broker.is_online(target):
                        await broker.push(
                            target,
                            {
                                "type": "decrypted",
                                "from": username,
                                "msg_id": msg["msg_id"],
                            },
                        )
                    else:
                        await _store_receipt(target, "decrypted", msg["msg_id"])
                continue
            # Typing flicker: live-only, never stored — push-if-online, drop
            # otherwise. A lost frame is a missed flicker, never stuck state
            # (client clears on an 8s failsafe). Old clients without the typing
            # branch fall through to envelope parsing inside try/catch — a log
            # line, never a crash — and offline ones never see these at all.
            if msg.get("type") == "typing" and msg.get("to"):
                if msg.get("state") in ("start", "stop"):
                    await broker.push(
                        msg["to"],
                        {"type": "typing", "from": username, "to": msg["to"],
                         "state": msg["state"]},
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
            # FCM doorbell for offline recipients (fire-and-forget task: a
            # slow FCM must never stall the relay). Online recipients drain
            # via the socket below; a redundant ping on a connect race is
            # harmless (doorbell only — the client drains the queue itself).
            if not broker.is_online(to_user):
                asyncio.create_task(_maybe_ping(to_user))
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
        # Shielded cleanup: teardown can arrive as task cancellation (client
        # close under some servers/harnesses, server shutdown), which would
        # otherwise re-raise at the first await below and skip the DB write.
        import anyio

        with anyio.CancelScope(shield=True):
            # D-browser proxy: kill every upstream session with the socket —
            # cancel pumps first, then close writers (generic, never logged).
            for _sid, (_w, _pump) in list(proxy_sessions.items()):
                _pump.cancel()
                try:
                    _w.close()
                except Exception:
                    pass
            proxy_sessions.clear()
            await broker.disconnect(username, ws)
            async with SessionLocal() as db:
                row = await db.get(models.Presence, username)
                if row is not None and not broker.is_online(username):
                    row.online, row.last_seen = False, int(time.time())
                    await db.commit()
