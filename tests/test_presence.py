"""Presence: online + last-seen query, disconnect flip, old-table migration."""
import base64
import time

from fastapi.testclient import TestClient

from app import tokens


def _mkclient(tmp_path, monkeypatch):
    db = tmp_path / "p.db"
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
    import app.routers.presence as pres_mod
    import app.merkle as merkle_mod

    importlib.reload(models_mod)
    importlib.reload(merkle_mod)
    importlib.reload(op)
    importlib.reload(dir_mod)
    importlib.reload(upd_mod)
    importlib.reload(pres_mod)
    importlib.reload(relay_mod)
    importlib.reload(main_mod)
    c = TestClient(main_mod.create_app())
    with c:
        yield c, dbmod, models_mod


def _tok(seed: bytes) -> tuple[str, bytes]:
    import asyncio

    raw = base64.b64encode(seed).decode()
    return raw, tokens.token_hash(base64.b64decode(raw))


def _seed(dbmod, models, toks):
    import asyncio

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


def test_online_shape_while_connected(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_b, th_b = _tok(b"B" * 32)
    raw_a, th_a = _tok(b"A" * 32)
    _seed(dbmod, models, [("bob", th_b), ("alice", th_a)])
    with client.websocket_connect("/api/v1/ws", headers=_hdr(raw_b)):
        # any-user token reads anyone's presence
        r = client.get("/api/v1/presence/bob", headers=_hdr(raw_a))
        assert r.status_code == 200
        assert r.json() == {"online": True, "last_seen": None}


def test_disconnect_flips_to_last_seen(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("bob", th_b)])
    before = int(time.time())
    with client.websocket_connect("/api/v1/ws", headers=_hdr(raw_b)) as bob:
        # Harness note: TestClient teardown (close→cancel→no-join) races the
        # server unwind, so deliver the close explicitly and poll for the flip
        # while the socket task is still alive — not after teardown.
        bob.close(1000)
        body = None
        for _ in range(100):
            r = client.get("/api/v1/presence/bob", headers=_hdr(raw_b))
            assert r.status_code == 200
            body = r.json()
            if body["last_seen"] is not None:
                break
            time.sleep(0.05)
    assert body["online"] is False
    assert before <= body["last_seen"] <= int(time.time())


def test_unknown_user_never_seen(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw_b, th_b = _tok(b"B" * 32)
    _seed(dbmod, models, [("bob", th_b)])
    r = client.get("/api/v1/presence/ghost", headers=_hdr(raw_b))
    assert r.json() == {"online": False, "last_seen": None}


def test_presence_requires_token(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    assert client.get("/api/v1/presence/bob").status_code == 401
    assert client.get(
        "/api/v1/presence/bob", headers=_hdr(base64.b64encode(b"z" * 32).decode())
    ).status_code == 401


def test_old_table_migrates(tmp_path, monkeypatch):
    """Pre-existing two-column presence table gains the new columns on boot."""
    import sqlite3

    dbfile = tmp_path / "old.db"
    con = sqlite3.connect(dbfile)
    con.execute(
        "CREATE TABLE presence (username VARCHAR(32) PRIMARY KEY, "
        "connected_at BIGINT NOT NULL)"
    )
    con.execute(
        "INSERT INTO presence (username, connected_at) VALUES ('zoe', 123)"
    )
    con.commit()
    con.close()
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{dbfile}")
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
    import app.routers.presence as pres_mod
    import app.merkle as merkle_mod

    importlib.reload(models_mod)
    importlib.reload(merkle_mod)
    importlib.reload(op)
    importlib.reload(dir_mod)
    importlib.reload(upd_mod)
    importlib.reload(pres_mod)
    importlib.reload(relay_mod)
    importlib.reload(main_mod)

    import asyncio

    async def seed_tok():
        import time as _t

        now = int(_t.time())
        async with dbmod.SessionLocal() as db:
            th = tokens.token_hash(b"Q" * 32)
            db.add(models_mod.WsToken(token_hash=th, username="q",
                                      issued_at=now, expires_at=now + 3600))
            await db.commit()
            return base64.b64encode(b"Q" * 32).decode()

    # lifespan ran create_all + ALTERs on the old-shape table; old row reads
    with TestClient(main_mod.create_app()) as c:
        raw = asyncio.run(seed_tok())
        r = c.get("/api/v1/presence/zoe", headers=_hdr(raw))
        assert r.status_code == 200, r.text
        assert r.json()["online"] is False
