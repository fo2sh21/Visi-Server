"""M2: INSERT -> push -> DELETE-on-ack. Offline message flushed on connect."""
import asyncio
import base64
import time
import urllib.parse

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


def test_offline_flush_and_ack_deletes(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    tok = base64.b64encode(b"0" * 32).decode()
    th = tokens.token_hash(base64.b64decode(tok))
    now = int(time.time())

    async def seed():
        async with dbmod.SessionLocal() as db:
            db.add(models.WsToken(token_hash=th, username="bob",
                                  issued_at=now, expires_at=now + 3600))
            db.add(models.OfflineQueue(msg_id="m1", to_user="bob",
                                       from_user="alice", envelope_b64=base64.b64encode(b"ct").decode()))
            await db.commit()

    asyncio.run(seed())
    q = urllib.parse.quote(tok, safe="")
    with client.websocket_connect(f"/api/v1/ws?token={q}") as ws:
        msg = ws.receive_text()
        assert '"m1"' in msg  # flushed
        ws.send_text('{"type": "ack", "msg_id": "m1"}')
        time.sleep(0.5)

    async def check_gone():
        async with dbmod.SessionLocal() as db:
            return await db.get(models.OfflineQueue, "m1")

    assert asyncio.run(check_gone()) is None  # hard DELETE on ack
