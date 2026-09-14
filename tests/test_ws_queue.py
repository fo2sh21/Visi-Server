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
