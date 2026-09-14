"""OTA: bucket latest.json source of truth, echo-X no-update, rollback guard."""
import pytest
from fastapi.testclient import TestClient


def _mkclient(tmp_path, monkeypatch, env=None):
    db = tmp_path / "ota.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    monkeypatch.delenv("UPDATE_BUCKET_BASE", raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
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
    import app.routers.update as upd
    import app.routers.presence as pres_mod
    import app.routers.push as push_mod
    import app.merkle as merkle_mod

    importlib.reload(models_mod)
    importlib.reload(merkle_mod)
    importlib.reload(op)
    importlib.reload(dir_mod)
    importlib.reload(upd)
    importlib.reload(pres_mod)
    importlib.reload(push_mod)
    importlib.reload(relay_mod)
    importlib.reload(main_mod)
    upd._cache.update(at=0.0, manifest=None)
    import app.routers.update as upd_fresh

    upd_fresh._last_good = None
    c = TestClient(main_mod.create_app())
    with c:
        yield c, upd_fresh


def _manifest(v, base="https://cdn.example"):
    return {"version_code": v, "download_url": f"{base}/visi-{v}.apk",
            "sha256": "ab" * 32}


def test_env_fallback_newer_and_echo(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch,
                    {"UPDATE_VERSION_CODE": "7", "UPDATE_SHA256": "cd" * 32,
                     "UPDATE_DOWNLOAD_URL": "https://x/visi-7.apk"})
    client, _ = next(gen)
    r = client.get("/api/v1/update-check?version_code=6")
    assert r.json()["version_code"] == 7
    r = client.get("/api/v1/update-check?version_code=7")
    assert r.json() == {"version_code": 7, "download_url": "", "sha256": ""}
    r = client.get("/api/v1/update-check?version_code=99")
    assert r.json()["version_code"] == 99  # echo-X, never downgrade the client


def test_bucket_newer_and_echo(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch,
                    {"UPDATE_BUCKET_BASE": "https://cdn.example"})
    client, upd = next(gen)

    async def fake():
        return _manifest(9)

    monkeypatch.setattr(upd, "_fetch_bucket", fake)
    r = client.get("/api/v1/update-check?version_code=8")
    assert r.json() == _manifest(9)
    r = client.get("/api/v1/update-check?version_code=9")
    assert r.json() == {"version_code": 9, "download_url": "", "sha256": ""}


def test_bucket_error_falls_back(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch,
                    {"UPDATE_BUCKET_BASE": "https://cdn.example",
                     "UPDATE_VERSION_CODE": "3", "UPDATE_SHA256": "ef" * 32,
                     "UPDATE_DOWNLOAD_URL": "https://x/visi-3.apk"})
    client, upd = next(gen)

    async def boom():
        return None

    monkeypatch.setattr(upd, "_fetch_bucket", boom)
    r = client.get("/api/v1/update-check?version_code=1")
    assert r.status_code == 200 and r.json()["version_code"] == 3


def test_rollback_fails_closed(tmp_path, monkeypatch):
    gen = _mkclient(tmp_path, monkeypatch,
                    {"UPDATE_BUCKET_BASE": "https://cdn.example"})
    client, upd = next(gen)
    seen = {"v": 5}

    async def fake():
        return _manifest(seen["v"])

    monkeypatch.setattr(upd, "_fetch_bucket", fake)
    assert client.get("/api/v1/update-check?version_code=1").json()["version_code"] == 5
    upd._cache.update(at=0.0, manifest=None)  # force refetch
    seen["v"] = 4  # poisoned/rolled-back bucket
    r = client.get("/api/v1/update-check?version_code=1")
    assert r.json()["version_code"] == 5  # higher cached manifest kept


def test_parse_latest_rejects():
    import app.routers.update as upd

    assert upd._parse_latest({"version_code": 1, "file": "../evil.apk",
                              "sha256": "ab" * 32}) is None
    assert upd._parse_latest({"version_code": 1, "file": "visi-1.apk",
                              "sha256": "zzz"}) is None
    assert upd._parse_latest({"version_code": 0, "file": "visi-0.apk",
                              "sha256": "ab" * 32}) is None
    assert upd._parse_latest("nope") is None
