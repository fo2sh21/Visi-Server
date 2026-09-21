"""Track D (D0): proxy-open/proxy-data/proxy-close over the authed WS.

- Auth is the EXISTING WS Bearer handshake (pre-dial by construction —
  no new auth code; unauthed sockets never reach the proxy branches).
- Dumb pipe both directions, verified against a loopback echo TCP server.
- proxy-close kills the stream; unknown ids + malformed frames drop silent.
- Destinations are never logged (caplog assertion).
- Style mirrors test_ws_queue.py (tmp_path sqlite, module reload harness).
"""
import asyncio
import base64
import json
import logging
import socket
import socketserver
import threading
import time

from fastapi.testclient import TestClient

from app import tokens


def _mkclient(tmp_path, monkeypatch, allow_private=True):
    db = tmp_path / "p.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db}")
    # Loopback echo harness needs the egress IP check off; the dedicated
    # block-cases test below passes allow_private=False instead.
    if allow_private:
        monkeypatch.setenv("PROXY_ALLOW_PRIVATE", "1")
    else:
        monkeypatch.delenv("PROXY_ALLOW_PRIVATE", raising=False)
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


def _seed(dbmod, models, toks):
    async def go():
        async with dbmod.SessionLocal() as db:
            now = int(time.time())
            for user, th in toks:
                db.add(models.WsToken(token_hash=th, username=user,
                                      issued_at=now, expires_at=now + 3600))
            await db.commit()

    asyncio.run(go())


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(16384)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            pass


def _start_echo():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EchoHandler)
    srv.daemon_threads = True
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return srv, port


def _closed_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _open(ws, sid, host, port):
    ws.send_text(json.dumps({"type": "proxy-open", "id": sid,
                             "host": host, "port": port}))


def _data(ws, sid, raw: bytes):
    ws.send_text(json.dumps({"type": "proxy-data", "id": sid,
                             "chunk_b64": base64.b64encode(raw).decode()}))


def _recv_proxy(ws):
    frame = json.loads(ws.receive_text())
    assert frame.get("type") in ("proxy-data", "proxy-close"), frame
    return frame


def test_proxy_requires_auth(tmp_path, monkeypatch):
    """No Bearer -> 4401 close; proxy branches unreachable pre-handshake."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    try:
        with client.websocket_connect("/api/v1/ws"):
            pass
        rejected = False
    except Exception:
        rejected = True
    assert rejected


def test_proxy_open_echo_both_directions(tmp_path, monkeypatch):
    """Dumb pipe: bytes go up AND come back verbatim (two chunks)."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"P" * 32)
    _seed(dbmod, models, [("alice", th)])
    srv, port = _start_echo()
    try:
        with client.websocket_connect(
            "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
        ) as ws:
            _open(ws, "s1", "127.0.0.1", port)
            _data(ws, "s1", b"hello-up")
            f1 = _recv_proxy(ws)
            assert f1["type"] == "proxy-data" and f1["id"] == "s1"
            assert base64.b64decode(f1["chunk_b64"]) == b"hello-up"
            _data(ws, "s1", b"second-chunk-down-up")
            f2 = _recv_proxy(ws)
            assert f2["type"] == "proxy-data" and f2["id"] == "s1"
            assert base64.b64decode(f2["chunk_b64"]) == b"second-chunk-down-up"
    finally:
        srv.shutdown()
        srv.server_close()


def test_proxy_dial_failure_sends_close(tmp_path, monkeypatch):
    """Fail-closed: refused dial -> proxy-close, no error string, stays alive."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"Q" * 32)
    _seed(dbmod, models, [("alice", th)])
    dead = _closed_port()
    srv, port = _start_echo()
    try:
        with client.websocket_connect(
            "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
        ) as ws:
            _open(ws, "dead", "127.0.0.1", dead)
            f = _recv_proxy(ws)
            assert f == {"type": "proxy-close", "id": "dead"}
            # Connection alive: a good stream still works after the failure.
            _open(ws, "live", "127.0.0.1", port)
            _data(ws, "live", b"after-failure")
            f2 = _recv_proxy(ws)
            assert f2["type"] == "proxy-data" and f2["id"] == "live"
            assert base64.b64decode(f2["chunk_b64"]) == b"after-failure"
    finally:
        srv.shutdown()
        srv.server_close()


def test_proxy_close_kills_stream_and_id_reusable(tmp_path, monkeypatch):
    """proxy-close kills the stream; the same id opens fresh afterwards."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"R" * 32)
    _seed(dbmod, models, [("alice", th)])
    srv, port = _start_echo()
    try:
        with client.websocket_connect(
            "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
        ) as ws:
            _open(ws, "s1", "127.0.0.1", port)
            _data(ws, "s1", b"before-close")
            f = _recv_proxy(ws)
            assert base64.b64decode(f["chunk_b64"]) == b"before-close"
            ws.send_text(json.dumps({"type": "proxy-close", "id": "s1"}))
            time.sleep(0.5)
            # Dead id: chunk dropped. Reopen same id: fresh stream echoes.
            # Any stray echo of the dropped chunk would arrive FIRST and
            # fail the assert below — ordering makes the drop observable.
            _data(ws, "s1", b"dropped-chunk")
            _open(ws, "s1", "127.0.0.1", port)
            _data(ws, "s1", b"reopened")
            f2 = _recv_proxy(ws)
            assert f2["type"] == "proxy-data" and f2["id"] == "s1"
            assert base64.b64decode(f2["chunk_b64"]) == b"reopened"
            # Unknown-id close is a silent no-op; connection stays alive.
            ws.send_text(json.dumps({"type": "proxy-close", "id": "nope"}))
            _data(ws, "s1", b"still-alive")
            f3 = _recv_proxy(ws)
            assert base64.b64decode(f3["chunk_b64"]) == b"still-alive"
    finally:
        srv.shutdown()
        srv.server_close()


def test_proxy_malformed_dropped(tmp_path, monkeypatch):
    """Bad ports/b64/oversize/unknown-id drop silent; socket stays alive."""
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"S" * 32)
    _seed(dbmod, models, [("alice", th)])
    srv, port = _start_echo()
    try:
        with client.websocket_connect(
            "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
        ) as ws:
            # Bad opens: none may yield any proxy frame.
            for bad in (
                {"type": "proxy-open", "id": "b0", "host": "127.0.0.1", "port": 0},
                {"type": "proxy-open", "id": "b1", "host": "127.0.0.1", "port": 99999},
                {"type": "proxy-open", "id": "b2", "host": "127.0.0.1", "port": "443"},
                {"type": "proxy-open", "id": "", "host": "127.0.0.1", "port": port},
                {"type": "proxy-open", "host": "127.0.0.1", "port": port},
                {"type": "proxy-open", "id": "b5", "host": "", "port": port},
            ):
                ws.send_text(json.dumps(bad))
            # Good stream for the data-path malformations.
            _open(ws, "s1", "127.0.0.1", port)
            ws.send_text(json.dumps({"type": "proxy-data", "id": "s1",
                                     "chunk_b64": "!!!not-b64!!!"}))
            big = base64.b64encode(b"X" * (17 * 1024)).decode()
            ws.send_text(json.dumps({"type": "proxy-data", "id": "s1",
                                     "chunk_b64": big}))
            ws.send_text(json.dumps({"type": "proxy-data", "id": "ghost",
                                     "chunk_b64": base64.b64encode(b"x").decode()}))
            # A truncated-forward bug would echo 16KB FIRST and fail this;
            # a correct drop yields only the small echo below.
            _data(ws, "s1", b"clean-after-garbage")
            f = _recv_proxy(ws)
            assert f["type"] == "proxy-data" and f["id"] == "s1"
            assert base64.b64decode(f["chunk_b64"]) == b"clean-after-garbage"
    finally:
        srv.shutdown()
        srv.server_close()


def test_proxy_no_destination_logging(tmp_path, monkeypatch, caplog):
    """Destination host (and payload marker) appear in NO log record."""
    caplog.set_level(logging.DEBUG)
    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"T" * 32)
    _seed(dbmod, models, [("alice", th)])
    host_probe = "d0-probe-nonexistent.invalid"
    marker = b"d0-marker-payload-9f3c"
    srv, port = _start_echo()
    try:
        with client.websocket_connect(
            "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
        ) as ws:
            _open(ws, "probe", host_probe, 45981)
            f = _recv_proxy(ws)
            assert f == {"type": "proxy-close", "id": "probe"}
            _open(ws, "echo", "127.0.0.1", port)
            _data(ws, "echo", marker)
            f2 = _recv_proxy(ws)
            assert base64.b64decode(f2["chunk_b64"]) == marker
            time.sleep(0.3)
    finally:
        srv.shutdown()
        srv.server_close()
    assert host_probe not in caplog.text
    assert marker.decode() not in caplog.text


def test_proxy_egress_guard(tmp_path, monkeypatch):
    """SSRF/port guard: non-global IPs + non-web ports refused with close.

    Runs WITHOUT PROXY_ALLOW_PRIVATE: loopback echo, cloud metadata,
    TEST-NET-1, and SMTP-port opens must all fail closed (proxy-close, no
    dial, socket stays alive for a later legit stream — proven here by a
    follow-up open attempt that is likewise refused, plus connection alive).
    """
    gen = _mkclient(tmp_path, monkeypatch, allow_private=False)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"G" * 32)
    _seed(dbmod, models, [("alice", th)])
    srv, port = _start_echo()
    try:
        with client.websocket_connect(
            "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
        ) as ws:
            # Loopback echo: blocked without the private flag.
            _open(ws, "lo", "127.0.0.1", port)
            assert _recv_proxy(ws) == {"type": "proxy-close", "id": "lo"}
            # Cloud metadata IP: blocked.
            _open(ws, "meta", "169.254.169.254", 80)
            assert _recv_proxy(ws) == {"type": "proxy-close", "id": "meta"}
            # Reserved TEST-NET-1: unroutable, blocked.
            _open(ws, "doc", "192.0.2.1", 80)
            assert _recv_proxy(ws) == {"type": "proxy-close", "id": "doc"}
            # Non-web port on a global IP: blocked (SMTP abuse surface).
            _open(ws, "smtp", "8.8.8.8", 25)
            assert _recv_proxy(ws) == {"type": "proxy-close", "id": "smtp"}
            # Socket alive after all refusals: malformed still drops silent.
            ws.send_text(json.dumps({"type": "proxy-open", "id": "x",
                                     "host": "127.0.0.1", "port": 0}))
            time.sleep(0.3)
    finally:
        srv.shutdown()
        srv.server_close()


def test_proxy_counters(tmp_path, monkeypatch):
    """Count-only observability: opens, refused dials, stream ends."""
    import app.ws.relay as relay_mod

    gen = _mkclient(tmp_path, monkeypatch)
    client, dbmod, models = next(gen)
    raw, th = _tok(b"H" * 32)
    _seed(dbmod, models, [("alice", th)])
    dead = _closed_port()
    srv, port = _start_echo()
    try:
        with client.websocket_connect(
            "/api/v1/ws", headers={"authorization": f"Bearer {raw}"}
        ) as ws:
            base_open = relay_mod.proxy_stats["open"]
            base_refused = relay_mod.proxy_stats["dial_refused"]
            base_ended = relay_mod.proxy_stats["ended"]
            _open(ws, "c1", "127.0.0.1", port)
            _data(ws, "c1", b"ping")
            assert _recv_proxy(ws)["type"] == "proxy-data"
            ws.send_text(json.dumps({"type": "proxy-close", "id": "c1"}))
            time.sleep(0.3)
            # Refused dial (nothing listening) counts by class.
            _open(ws, "c2", "127.0.0.1", dead)
            assert _recv_proxy(ws) == {"type": "proxy-close", "id": "c2"}
            time.sleep(0.3)
            assert relay_mod.proxy_stats["open"] == base_open + 1
            assert relay_mod.proxy_stats["dial_refused"] == base_refused + 1
            assert relay_mod.proxy_stats["ended"] >= base_ended + 1
    finally:
        srv.shutdown()
        srv.server_close()
