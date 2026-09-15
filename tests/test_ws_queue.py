"""M2/R2/R3: INSERT -> push -> DELETE-on-owning-ack only; flush never deletes.

- Offline message flushed on connect; ack deletes (hard DELETE, scoped).
- Drop-before-ack keeps the row: next connect redelivers (at-least-once).
- Cross-user ack does NOT delete another user's row (R2).
WS auth is Bearer header only (R1).
"""
import asyncio
import base64
import time

from fastapi.testclient import TestClient

from app import tokens


def _mkclient(tmp_path, monkeypatch):
    db = tmp_path / "q.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    import importlib

    import app.config as cfg
    import app.db as dbmod

    importlib.reload(cfg)
    importlib.reload(dbmod)
    import app.models as models_mod
    import app.ws.relay as relay_mod
    import app.main as main_mod
    import app.routers.directory as dir_mod
    import app.routers.opaque as op
    import app.routers.update as upd_mod
    import app.merkle as merkle_mod

    importlib.reload(models_mod)
    importlib.reload(merkle_mod)
    importlib.reload(op)
    importlib.reload(dir_mod)
    importlib.reload(upd_mod)
    importlib.reload(relay_mod)
    importlib.reload(main_mod)
    c = TestClient(main_mod.create_app())
    with c:
        yield c, dbmod, models_mod


def _tok(user_seed: bytes) -> tuple[str, bytes]:
    raw = base64.b64encode(user_seed).decode()
    return raw, tokens.token_hash(base64.b64decode(raw))


def _seed(dbmod, models, toks, msgs):
    async def go():
        async with dbmod.SessionLocal() as db:
            now = int(time.time())
            for user, th in toks:
                db.add(models.WsToken(token_hash=th, username=user,
                                      issued_at=now, expires_at=now + 3600))
            for m in msgs:
                db.add(models.OfflineQueue(**m))
            await db.commit()

    asyncio.run(go())


def _get(dbmod, models, msg_id):
    async def go():
        async with dbmod.SessionLocal() as db:
            return await db.get(models.OfflineQueue, msg_id)

    return asyncio.run(go())


def _pending(dbmod, models, to_user=None):
    from sqlalchemy import select as _select

    async def go():
        async with dbmod.SessionLocal() as db:
            q = _select(models.PendingReceipt).order_by(
                models.PendingReceipt.created_at
            )
            if to_user is not None:
                q = q.where(models.PendingReceipt.to_user == to_user)
            return list((await db.execute(q)).scalars().all())

    return asyncio.run(go())


def test_offline_flush_and_ack_deletes(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"b" * 32)
    _seed(dbmod, models, [("bob", th)],
          [{"msg_id": "m1", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    with client.websocket_connect(
        "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
    ) as ws:
        assert '"m1"' in ws.receive_text()  # flushed
        ws.send_text('{"type": "ack", "msg_id": "m1"}')
        time.sleep(0.5)
    assert _get(dbmod, models, "m1") is None  # hard DELETE on owning ack


def test_drop_before_ack_redelivers(tmp_path, monkeypatch):
    """R3: flush never deletes — connect, drop without ack, reconnect."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"c" * 32)
    _seed(dbmod, models, [("bob", th)],
          [{"msg_id": "m2", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    hdr = {"authorization": f"Bearer {raw}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr) as ws:
        assert '"m2"' in ws.receive_text()
        # close WITHOUT ack
    assert _get(dbmod, models, "m2") is not None  # row survives
    with client.websocket_connect("/api/v1/ws", headers=hdr) as ws2:
        assert '"m2"' in ws2.receive_text()  # redelivered
        ws2.send_text('{"type": "ack", "msg_id": "m2"}')
        time.sleep(0.5)
    assert _get(dbmod, models, "m2") is None


def test_cross_user_ack_does_not_delete(tmp_path, monkeypatch):
    """R2: mallory acking bob's msg_id must not delete it."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    _, th_bob = _tok(b"d" * 32)
    raw_m, th_m = _tok(b"e" * 32)
    _seed(dbmod, models, [("bob", th_bob), ("mallory", th_m)],
          [{"msg_id": "m3", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    with client.websocket_connect(
        "/api/v1/ws", headers={"authorization": f"Bearer {raw_m}"}
    ) as ws:
        ws.send_text('{"type": "ack", "msg_id": "m3"}')
        time.sleep(0.5)
    assert _get(dbmod, models, "m3") is not None  # untouched


def test_query_token_rejected(tmp_path, monkeypatch):
    """R1: ?token= is gone — header-only."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"f" * 32)
    _seed(dbmod, models, [("bob", th)], [])
    import urllib.parse

    q = urllib.parse.quote(raw, safe="")
    try:
        with client.websocket_connect(f"/api/v1/ws?token={q}"):
            pass
        rejected = False
    except Exception:
        rejected = True
    assert rejected


def test_delivered_tick_happy_path(tmp_path, monkeypatch):
    """Ack triggers {"type":"delivered"} to the online original sender."""
    import json

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)],
          [{"msg_id": "m10", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    hdr_a = {"authorization": f"Bearer {raw_a}"}
    hdr_b = {"authorization": f"Bearer {raw_b}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr_a) as alice:
        with client.websocket_connect("/api/v1/ws", headers=hdr_b) as bob:
            assert '"m10"' in bob.receive_text()  # flush
            bob.send_text('{"type": "ack", "msg_id": "m10"}')
            tick = json.loads(alice.receive_text())
            assert tick == {"type": "delivered", "msg_id": "m10", "to": "alice"}
    assert _get(dbmod, models, "m10") is None  # row hard-deleted


def test_delivered_missed_when_sender_offline(tmp_path, monkeypatch):
    """Sender offline at delivery: row still deleted, no tick, no error."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_b, th_b = _tok(b"B" * 32)
    _, th_a = _tok(b"A" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)],
          [{"msg_id": "m11", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    with client.websocket_connect(
        "/api/v1/ws", headers={"authorization": f"Bearer {raw_b}"}
    ) as bob:
        assert '"m11"' in bob.receive_text()
        bob.send_text('{"type": "ack", "msg_id": "m11"}')
        time.sleep(0.5)
    assert _get(dbmod, models, "m11") is None


def test_duplicate_ack_repushes_identical_tick(tmp_path, monkeypatch):
    """Duplicate acks re-push the same payload; row stays gone (idempotent)."""
    import json

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)],
          [{"msg_id": "m12", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    hdr_a = {"authorization": f"Bearer {raw_a}"}
    hdr_b = {"authorization": f"Bearer {raw_b}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr_a) as alice:
        with client.websocket_connect("/api/v1/ws", headers=hdr_b) as bob:
            assert '"m12"' in bob.receive_text()
            bob.send_text('{"type": "ack", "msg_id": "m12"}')
            assert json.loads(alice.receive_text()) == {
                "type": "delivered", "msg_id": "m12", "to": "alice"}
            bob.send_text('{"type": "ack", "msg_id": "m12"}')  # dup
            assert json.loads(alice.receive_text()) == {
                "type": "delivered", "msg_id": "m12", "to": "alice"}
    assert _get(dbmod, models, "m12") is None


def test_offline_sender_delivered_persists_and_flushes(tmp_path, monkeypatch):
    """Sender offline at ack: pending delivered row, flushed with receipt_id,
    deleted only on receipt_id-ack. No tick generated by the receipt ack."""
    import json

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)],
          [{"msg_id": "m20", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    hdr_a = {"authorization": f"Bearer {raw_a}"}
    hdr_b = {"authorization": f"Bearer {raw_b}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr_b) as bob:
        assert '"m20"' in bob.receive_text()
        bob.send_text('{"type": "ack", "msg_id": "m20"}')
        time.sleep(0.5)
    assert _get(dbmod, models, "m20") is None
    rows = _pending(dbmod, models, "alice")
    assert [(r.kind, r.msg_id) for r in rows] == [("delivered", "m20")]
    with client.websocket_connect("/api/v1/ws", headers=hdr_a) as alice:
        frame = json.loads(alice.receive_text())
        assert frame["type"] == "delivered" and frame["msg_id"] == "m20"
        rid = frame["receipt_id"]
        alice.send_text(json.dumps({"type": "ack", "receipt_id": rid}))
        time.sleep(0.5)
    assert _pending(dbmod, models, "alice") == []  # consumed
    assert _pending(dbmod, models) == []  # receipt-ack spawned nothing


def test_read_to_offline_persists_and_flushes(tmp_path, monkeypatch):
    """Read to an offline target is stored, flushed, acked by receipt_id."""
    import json

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)], [])
    hdr_a = {"authorization": f"Bearer {raw_a}"}
    hdr_b = {"authorization": f"Bearer {raw_b}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr_b) as bob:
        bob.send_text(json.dumps({"type": "read", "to": "alice", "msg_id": "m21"}))
        time.sleep(0.5)
    rows = _pending(dbmod, models, "alice")
    assert [(r.kind, r.msg_id) for r in rows] == [("read", "m21")]
    with client.websocket_connect("/api/v1/ws", headers=hdr_a) as alice:
        frame = json.loads(alice.receive_text())
        assert frame == {
            "type": "read", "msg_id": "m21", "receipt_id": frame["receipt_id"]}
        alice.send_text(json.dumps({"type": "ack", "receipt_id": frame["receipt_id"]}))
        time.sleep(0.5)
    assert _pending(dbmod, models, "alice") == []


def test_online_paths_write_no_rows(tmp_path, monkeypatch):
    """Both ends online: live tick + live read, zero pending rows."""
    import json

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)],
          [{"msg_id": "m22", "to_user": "bob", "from_user": "alice",
            "envelope_b64": base64.b64encode(b"ct").decode()}])
    hdr_a = {"authorization": f"Bearer {raw_a}"}
    hdr_b = {"authorization": f"Bearer {raw_b}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr_a) as alice:
        with client.websocket_connect("/api/v1/ws", headers=hdr_b) as bob:
            assert '"m22"' in bob.receive_text()
            bob.send_text('{"type": "ack", "msg_id": "m22"}')
            assert json.loads(alice.receive_text())["type"] == "delivered"
            bob.send_text(json.dumps({"type": "read", "to": "alice", "msg_id": "m22"}))
            assert json.loads(alice.receive_text()) == {
                "type": "read", "from": "bob", "msg_id": "m22"}
    assert _pending(dbmod, models) == []


def test_live_tick_ack_does_not_eat_pending_read(tmp_path, monkeypatch):
    """Plain msg_id ack consumes only kind=delivered rows — pending read safe."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    _seed(dbmod, models, [("alice", th_a)], [])

    async def seed_read():
        import time as _t

        async with dbmod.SessionLocal() as db:
            db.add(models.PendingReceipt(
                to_user="alice", kind="read", msg_id="m30",
                created_at=int(_t.time())))
            await db.commit()

    asyncio.run(seed_read())
    with client.websocket_connect(
        "/api/v1/ws", headers={"authorization": f"Bearer {raw_a}"}
    ) as alice:
        first = alice.receive_text()  # flushed read with receipt_id
        assert '"m30"' in first
        alice.send_text('{"type": "ack", "msg_id": "m30"}')  # live-tick style
        time.sleep(0.5)
    rows = _pending(dbmod, models, "alice")
    assert [(r.kind, r.msg_id) for r in rows] == [("read", "m30")]


def test_cross_user_receipt_ack_noop(tmp_path, monkeypatch):
    """Mallory acking alice's receipt_id deletes nothing."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_m, th_m = _tok(b"M" * 32)
    _seed(dbmod, models, [("alice", th_a), ("mallory", th_m)], [])

    async def seed_read():
        import time as _t

        async with dbmod.SessionLocal() as db:
            db.add(models.PendingReceipt(
                id="r9", to_user="alice", kind="read", msg_id="m31",
                created_at=int(_t.time())))
            await db.commit()

    asyncio.run(seed_read())
    with client.websocket_connect(
        "/api/v1/ws", headers={"authorization": f"Bearer {raw_m}"}
    ) as mallory:
        mallory.send_text('{"type": "ack", "receipt_id": "r9"}')
        time.sleep(0.5)
    assert [(r.kind, r.msg_id) for r in _pending(dbmod, models, "alice")] == [
        ("read", "m31")]


def test_stale_receipts_swept_on_flush(tmp_path, monkeypatch):
    """>30d pending rows die on connect; fresh ones flush."""
    import json
    import time as _t

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    _seed(dbmod, models, [("alice", th_a)], [])

    async def seed():
        now = int(_t.time())
        async with dbmod.SessionLocal() as db:
            db.add(models.PendingReceipt(
                to_user="alice", kind="read", msg_id="old",
                created_at=now - 31 * 24 * 3600))
            db.add(models.PendingReceipt(
                to_user="alice", kind="read", msg_id="fresh", created_at=now))
            await db.commit()

    asyncio.run(seed())
    with client.websocket_connect(
        "/api/v1/ws", headers={"authorization": f"Bearer {raw_a}"}
    ) as alice:
        frame = json.loads(alice.receive_text())
        assert frame["msg_id"] == "fresh"
        alice.send_text(json.dumps({"type": "ack", "receipt_id": frame["receipt_id"]}))
        time.sleep(0.5)
    assert _pending(dbmod, models, "alice") == []


def test_rekey_routing(tmp_path, monkeypatch):
    """Rekey: live-only push-if-online, silent drop offline, no storage."""
    import json

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _, th_m = _tok(b"M" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b), ("mallory", th_m)], [])
    hdr_a = {"authorization": f"Bearer {raw_a}"}
    hdr_b = {"authorization": f"Bearer {raw_b}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr_a) as alice:
        with client.websocket_connect("/api/v1/ws", headers=hdr_b) as bob:
            bob.send_text(json.dumps({"type": "rekey", "to": "alice"}))
            assert json.loads(alice.receive_text()) == {
                "type": "rekey", "from": "bob", "to": "alice"}
            bob.send_text(json.dumps({"type": "rekey", "to": "mallory"}))  # offline
            bob.send_text(json.dumps({"type": "rekey"}))  # malformed
            time.sleep(0.5)
    assert _pending(dbmod, models) == []
    assert _pending(dbmod, models, "mallory") == []


def test_typing_routed_live_only(tmp_path, monkeypatch):
    """Typing start/stop routed verbatim to online peer; dropped offline."""
    import json

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _, th_m = _tok(b"M" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b), ("mallory", th_m)], [])
    hdr_a = {"authorization": f"Bearer {raw_a}"}
    hdr_b = {"authorization": f"Bearer {raw_b}"}
    with client.websocket_connect("/api/v1/ws", headers=hdr_a) as alice:
        with client.websocket_connect("/api/v1/ws", headers=hdr_b) as bob:
            alice.send_text(json.dumps({"type": "typing", "to": "bob", "state": "start"}))
            assert json.loads(bob.receive_text()) == {
                "type": "typing", "from": "alice", "to": "bob", "state": "start"}
            alice.send_text(json.dumps({"type": "typing", "to": "bob", "state": "stop"}))
            assert json.loads(bob.receive_text())["state"] == "stop"
            # offline peer: dropped, nothing stored
            alice.send_text(json.dumps({"type": "typing", "to": "mallory", "state": "start"}))
            # invalid state / missing to: dropped
            alice.send_text(json.dumps({"type": "typing", "to": "bob", "state": "maybe"}))
            alice.send_text(json.dumps({"type": "typing", "state": "start"}))
            time.sleep(0.5)
    assert _pending(dbmod, models) == []

    async def queue():
        from sqlalchemy import select as _select

        async with dbmod.SessionLocal() as db:
            return list((await db.execute(_select(models.OfflineQueue))).scalars().all())

    import asyncio

    assert asyncio.run(queue()) == []


def test_flush_sweeps_stale_queue_rows(tmp_path, monkeypatch):
    """7d TTL: stale rows die on flush undelivered; fresh rows deliver."""
    import time as _t

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("bob", th_b)], [])
    now = int(_t.time())

    async def seed_q():
        async with dbmod.SessionLocal() as db:
            db.add(models.OfflineQueue(
                msg_id="old", to_user="bob", from_user="alice",
                envelope_b64="Y3Q=", created_at=now - 8 * 24 * 3600))
            db.add(models.OfflineQueue(
                msg_id="new", to_user="bob", from_user="alice",
                envelope_b64="Y3Q=", created_at=now))
            await db.commit()

    import asyncio

    asyncio.run(seed_q())
    with client.websocket_connect(
        "/api/v1/ws", headers={"authorization": f"Bearer {raw_b}"}
    ) as bob:
        assert '"new"' in bob.receive_text()
        bob.send_text('{"type": "ack", "msg_id": "new"}')
        time.sleep(0.5)
    assert _get(dbmod, models, "old") is None  # shredded, never delivered
    assert _get(dbmod, models, "new") is None  # acked


def test_sweep_expired_queues_global(tmp_path, monkeypatch):
    """Periodic sweep removes stale rows even for users who never return."""
    import asyncio
    import time as _t

    import app.ws.relay as relay

    gen = _mkclient(tmp_path, monkeypatch)
    _, dbmod, models = next(gen)
    now = int(_t.time())

    async def seed_q():
        async with dbmod.SessionLocal() as db:
            db.add(models.OfflineQueue(
                msg_id="dead", to_user="ghost", from_user="alice",
                envelope_b64="Y3Q=", created_at=now - 8 * 24 * 3600))
            db.add(models.OfflineQueue(
                msg_id="live", to_user="ghost", from_user="alice",
                envelope_b64="Y3Q=", created_at=now))
            await db.commit()

    asyncio.run(seed_q())
    assert asyncio.run(relay.sweep_expired_queues()) == 1
    assert _get(dbmod, models, "dead") is None
    assert _get(dbmod, models, "live") is not None
