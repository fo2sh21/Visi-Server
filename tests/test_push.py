"""Push tokens + data-only FCM doorbell (mocked transport, no network)."""
import asyncio
import base64
import time

from fastapi.testclient import TestClient

from app import tokens


def _mkclient(tmp_path, monkeypatch):
    db = tmp_path / "push.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    monkeypatch.delenv("UPDATE_BUCKET_BASE", raising=False)
    import importlib

    import app.config as cfg
    import app.db as dbmod

    importlib.reload(cfg)
    importlib.reload(dbmod)
    import app.models as models_mod
    import app.fcm as fcm_mod
    import app.ws.relay as relay_mod
    import app.main as main_mod
    import app.routers.directory as dir_mod
    import app.routers.opaque as op
    import app.routers.update as upd_mod
    import app.routers.presence as pres_mod
    import app.routers.push as push_mod
    import app.merkle as merkle_mod

    importlib.reload(models_mod)
    importlib.reload(merkle_mod)
    importlib.reload(op)
    importlib.reload(dir_mod)
    importlib.reload(upd_mod)
    importlib.reload(pres_mod)
    importlib.reload(push_mod)
    importlib.reload(fcm_mod)
    importlib.reload(relay_mod)
    importlib.reload(main_mod)
    c = TestClient(main_mod.create_app())
    with c:
        yield c, dbmod, models_mod, relay_mod, fcm_mod


def _tok(seed: bytes) -> tuple[str, bytes]:
    raw = base64.b64encode(seed).decode()
    return raw, tokens.token_hash(base64.b64decode(raw))


def _seed(dbmod, models, toks):
    async def go():
        async with dbmod.SessionLocal() as db:
            now = int(time.time())
            for user, th in toks:
                db.add(models.WsToken(token_hash=th, username=user,
                                      issued_at=now, expires_at=now + 3600))
            await db.commit()

    asyncio.run(go())


def _hdr(raw: str) -> dict:
    return {"authorization": f"Bearer {raw}"}


def _rows(dbmod, models):
    from sqlalchemy import select as _select

    async def go():
        async with dbmod.SessionLocal() as db:
            return list((await db.execute(_select(models.PushToken))).scalars().all())

    return asyncio.run(go())


def test_register_update_delete_and_403(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models, _, _ = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)])
    r = client.post("/api/v1/push-token", headers=_hdr(raw_a),
                    json={"username": "alice", "fcm_token": "tok1"})
    assert r.json() == {"status": "ok"}
    assert [(t.username, t.fcm_token) for t in _rows(dbmod, models)] == [("alice", "tok1")]
    # cross-user forbidden
    r = client.post("/api/v1/push-token", headers=_hdr(raw_a),
                    json={"username": "bob", "fcm_token": "evil"})
    assert r.status_code == 403
    # no token
    assert client.post("/api/v1/push-token",
                       json={"username": "alice", "fcm_token": "x"}).status_code == 401
    # update + delete hygiene
    client.post("/api/v1/push-token", headers=_hdr(raw_a),
                json={"username": "alice", "fcm_token": "tok2"})
    assert _rows(dbmod, models)[0].fcm_token == "tok2"
    r = client.post("/api/v1/push-token/delete", headers=_hdr(raw_a),
                    json={"username": "alice"})
    assert r.json() == {"status": "ok"} and _rows(dbmod, models) == []
    r = client.post("/api/v1/push-token/delete", headers=_hdr(raw_a),
                    json={"username": "alice"})
    assert r.json() == {"status": "ok"}  # idempotent


def test_offline_insert_pings_once_data_only(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models, relay, _ = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)])
    client.post("/api/v1/push-token", headers=_hdr(raw_b),
                json={"username": "bob", "fcm_token": "bobtok"})

    calls = []

    async def fake_ping(token):
        calls.append(token)
        return "ok"

    monkeypatch.setattr(relay, "_fcm_ping", fake_ping)
    with client.websocket_connect("/api/v1/ws", headers=_hdr(raw_a)) as alice:
        alice.send_text('{"to": "bob", "envelope_b64": "'
                        + base64.b64encode(b"ct").decode()
                        + '", "msg_id": "p1"}')
        time.sleep(1.0)
    assert calls == ["bobtok"]  # exactly one doorbell for the insert


def test_online_recipient_no_ping_no_token_needed(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models, relay, _ = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)])

    calls = []

    async def fake_ping(token):
        calls.append(token)
        return "ok"

    monkeypatch.setattr(relay, "_fcm_ping", fake_ping)
    with client.websocket_connect("/api/v1/ws", headers=_hdr(raw_a)):
        with client.websocket_connect("/api/v1/ws", headers=_hdr(raw_b)) as bob:
            import json as _json

            # alice sends via her own socket: open a second alice socket
            with client.websocket_connect("/api/v1/ws", headers=_hdr(raw_a)) as a2:
                a2.send_text(_json.dumps(
                    {"to": "bob", "envelope_b64": base64.b64encode(b"ct").decode(),
                     "msg_id": "p2"}))
                assert '"p2"' in bob.receive_text()
                bob.send_text(_json.dumps({"type": "ack", "msg_id": "p2"}))
                time.sleep(1.0)
    assert calls == []


def test_stale_token_deleted(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models, relay, _ = next(gen)
    raw_a, th_a = _tok(b"A" * 32)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("alice", th_a), ("bob", th_b)])
    client.post("/api/v1/push-token", headers=_hdr(raw_b),
                json={"username": "bob", "fcm_token": "dead"})

    async def fake_ping(token):
        return "stale"

    monkeypatch.setattr(relay, "_fcm_ping", fake_ping)
    with client.websocket_connect("/api/v1/ws", headers=_hdr(raw_a)) as alice:
        alice.send_text('{"to": "bob", "envelope_b64": "'
                        + base64.b64encode(b"ct").decode()
                        + '", "msg_id": "p3"}')
        time.sleep(1.0)
    assert _rows(dbmod, models) == []  # stale token pruned
    # queue itself is untouched (source of truth)
    from sqlalchemy import select as _select

    async def q():
        async with dbmod.SessionLocal() as db:
            return await db.get(models.OfflineQueue, "p3")

    assert asyncio.run(q()) is not None


def test_fcm_payload_shape_and_outcomes(tmp_path, monkeypatch):
    """Data-only (no notification block); ok/stale/error mapping; no creds."""
    gen = _mkclient(tmp_path, monkeypatch)
    _, _, _, _, fcm = next(gen)
    sent = {}

    class Resp:
        def __init__(self, status, body=None):
            self.status_code = status
            self._body = body or {}

        def json(self):
            return self._body

    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent.update(url=url, headers=headers, json=json)
            return Resp(*Client.next_resp)

    class Creds:
        token = "AT"

    monkeypatch.setattr(fcm, "_load", lambda: (Creds(), "proj"))
    monkeypatch.setattr(fcm, "_access_token", lambda c: asyncio.sleep(0, result="AT"))
    import httpx as _httpx

    monkeypatch.setattr(_httpx, "AsyncClient", Client)

    Client.next_resp = (200, {})
    assert asyncio.run(fcm.send_ping("t")) == "ok"
    assert sent["json"] == {"message": {"token": "t", "data": {"ping": "true"}}}
    assert "notification" not in sent["json"]["message"]
    assert sent["headers"] == {"Authorization": "Bearer AT"}
    assert sent["url"].endswith("/v1/projects/proj/messages:send")

    Client.next_resp = (404, {"error": {"status": "NOT_FOUND",
                                       "details": [{"reason": "UNREGISTERED"}]}})
    assert asyncio.run(fcm.send_ping("t")) == "stale"
    Client.next_resp = (500, {})
    assert asyncio.run(fcm.send_ping("t")) == "error"

    monkeypatch.setattr(fcm, "_load", lambda: None)
    assert asyncio.run(fcm.send_ping("t")) == "error"  # no creds, no network
