"""Render deploy spec: /health keeper alias, pg engine args, inline FCM creds."""
import base64
import json
import time

from fastapi.testclient import TestClient

from app import tokens


def _mkclient(tmp_path, monkeypatch):
    db = tmp_path / "d.db"
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
        yield c, dbmod, fcm_mod


def test_health_alias(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch)
    client, _, _ = next(gen)
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/healthz").json() == {"status": "ok"}


def test_postgres_engine_disables_statement_cache(tmp_path, monkeypatch):
    """Neon pgbouncer: prepared statements die without statement_cache_size=0."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@host/db")
    import importlib

    import app.config as cfg
    import app.db as dbmod

    importlib.reload(cfg)
    importlib.reload(dbmod)
    assert dbmod.connect_args == {"statement_cache_size": 0}


def test_neon_url_normalized_for_asyncpg():
    """Dashboard-pasted libpq URLs become asyncpg-ready; TLS moves to ssl=True."""
    import app.config as cfg

    url, ssl = cfg._normalize_db_url(
        "postgresql://u:p@host/db?sslmode=require&channel_binding=require"
    )
    assert url == "postgresql+asyncpg://u:p@host/db"
    assert ssl is True

    url, ssl = cfg._normalize_db_url("postgres://u:p@host/db")
    assert url == "postgresql+asyncpg://u:p@host/db"
    assert ssl is False

    url, ssl = cfg._normalize_db_url(
        "postgresql+asyncpg://u:p@host/db?sslmode=require"
    )
    assert url == "postgresql+asyncpg://u:p@host/db"
    assert ssl is True

    url, ssl = cfg._normalize_db_url("sqlite+aiosqlite:///x.db")
    assert (url, ssl) == ("sqlite+aiosqlite:///x.db", False)


def test_fcm_inline_json_wins_over_file(tmp_path, monkeypatch):
    """FCM_CREDENTIALS_JSON (Render/prod) takes precedence; file untouched."""
    gen = _mkclient(tmp_path, monkeypatch)
    _, _, fcm = next(gen)
    import google.oauth2.service_account as sa

    seen = {}

    class Creds:
        token = "AT"

    def fake_info(info, scopes=None):
        seen.update(info=info, scopes=scopes)
        return Creds()

    def boom(*a, **k):
        raise AssertionError("file path must not be read when inline is set")

    monkeypatch.setattr(sa.Credentials, "from_service_account_info", fake_info)
    monkeypatch.setattr(sa.Credentials, "from_service_account_file", boom)
    monkeypatch.setattr(fcm, "_access_token", lambda c: __import__("asyncio").sleep(0, result="AT"))

    import httpx as _httpx

    class Resp:
        status_code = 200

        def json(self):
            return {}

    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            return Resp()

    monkeypatch.setattr(_httpx, "AsyncClient", Client)
    import app.config as cfg

    monkeypatch.setattr(cfg, "FCM_CREDENTIALS_JSON",
                        json.dumps({"project_id": "p", "private_key": "k",
                                    "client_email": "e"}))
    fcm._creds.update(loaded=False, creds=None, project_id="")
    import asyncio

    assert asyncio.run(fcm.send_ping("t")) == "ok"
    assert seen["info"]["project_id"] == "p"


def test_dockerfile_matches_spec():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    for needle in ("rust:1.85-slim", "cargo build --release -p opaque-sidecar",
                   "python:3.13-slim", "OPAQUE_SIDECAR_BIN=/srv/bin/opaque-sidecar",
                   "${PORT:-10000}"):
        assert needle in text, needle
