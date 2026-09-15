"""FCM send-leg diagnostics (mocked transport, no network).

Each test pins observable behavior of app.fcm.send_ping: the outcome string
AND what lands in the logs. The prod outage that motivated this file showed
only "FCM ping failed (credentials or network?)" for every failure — the
HTTP status + FCM error status asserted here are what names the next one
(API-disabled vs IAM vs transport).
"""
import asyncio
import logging
import pathlib

import pytest

from app import fcm as fcm_mod


@pytest.fixture(autouse=True)
def _fresh_creds_cache():
    saved = dict(fcm_mod._creds)
    fcm_mod._creds.update(loaded=False, creds=None, project_id="")
    yield
    fcm_mod._creds.update(saved)


class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


def _client_factory(next_resp, sent, explode=False):
    class Client:
        constructed = False

        def __init__(self, *a, **k):
            Client.constructed = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            if explode:
                raise OSError("network down")
            sent.update(url=url, headers=headers, json=json)
            status, body = next_resp
            return _Resp(status, body)

    return Client


class _Creds:
    token = "AT"


def _patch(monkeypatch, next_resp=(200, {}), explode=False):
    sent = {}
    import httpx as _httpx

    monkeypatch.setattr(fcm_mod, "_load", lambda: (_Creds(), "proj"))
    monkeypatch.setattr(fcm_mod, "_access_token", lambda c: asyncio.sleep(0, result="AT"))
    monkeypatch.setattr(_httpx, "AsyncClient", _client_factory(next_resp, sent, explode))
    return sent


def test_ok_returns_ok_silently(monkeypatch):
    _patch(monkeypatch)
    assert asyncio.run(fcm_mod.send_ping("t")) == "ok"


def test_maybe_ping_logs_delivery_at_info(monkeypatch, caplog):
    """The relay-side proof Render actually shows (debug is hidden)."""
    from app.ws import relay as relay_mod

    class FakeDB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            class R:
                fcm_token = "tok"

            return R()

    monkeypatch.setattr(relay_mod, "SessionLocal", lambda: FakeDB())
    monkeypatch.setattr(relay_mod, "_fcm_ping",
                        lambda tok: asyncio.sleep(0, result="ok"))
    caplog.set_level(logging.INFO, logger="uvicorn.error")
    asyncio.run(relay_mod._maybe_ping("someone"))
    assert "FCM ping delivered" in caplog.text


def test_403_api_disabled_names_status(monkeypatch, caplog):
    # GCP shape when the Firebase Cloud Messaging API (V1) is not enabled.
    _patch(monkeypatch, (403, {"error": {
        "status": "PERMISSION_DENIED",
        "details": "Firebase Cloud Messaging API has not been used in project 123 before or it is disabled.",
    }}))
    assert asyncio.run(fcm_mod.send_ping("t")) == "error"
    assert "http=403" in caplog.text
    assert "PERMISSION_DENIED" in caplog.text


def test_403_iam_names_status(monkeypatch, caplog):
    _patch(monkeypatch, (403, {"error": {
        "status": "PERMISSION_DENIED",
        "details": "The caller does not have permission",
    }}))
    assert asyncio.run(fcm_mod.send_ping("t")) == "error"
    assert "http=403" in caplog.text
    assert "PERMISSION_DENIED" in caplog.text


def test_500_maps_to_error_with_status(monkeypatch, caplog):
    _patch(monkeypatch, (500, {}))
    assert asyncio.run(fcm_mod.send_ping("t")) == "error"
    assert "http=500" in caplog.text


def test_transport_exception_is_error(monkeypatch, caplog):
    _patch(monkeypatch, explode=True)
    assert asyncio.run(fcm_mod.send_ping("t")) == "error"
    assert "FCM post failed" in caplog.text
    assert "OSError" in caplog.text


def test_oauth_failure_logged(monkeypatch, caplog):
    class DeadCreds:
        def refresh(self, request):
            raise ValueError("invalid_grant: account not found")

    assert asyncio.run(fcm_mod._access_token(DeadCreds())) is None
    assert "FCM oauth failed" in caplog.text
    assert "invalid_grant" in caplog.text


def test_non_json_body_logs_status(monkeypatch, caplog):
    sent = {}

    class HtmlResp(_Resp):
        def json(self):
            raise ValueError("No JSON object could be decoded")

    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent["url"] = url
            return HtmlResp(502)

    import httpx as _httpx

    monkeypatch.setattr(fcm_mod, "_load", lambda: (_Creds(), "proj"))
    monkeypatch.setattr(fcm_mod, "_access_token", lambda c: asyncio.sleep(0, result="AT"))
    monkeypatch.setattr(_httpx, "AsyncClient", Client)
    assert asyncio.run(fcm_mod.send_ping("t")) == "error"
    assert "http=502" in caplog.text
    assert "non-json" in caplog.text


def test_no_creds_no_network(monkeypatch):
    import httpx as _httpx

    constructed = []

    class Client:
        def __init__(self, *a, **k):
            constructed.append(True)

    monkeypatch.setattr(fcm_mod, "_load", lambda: None)
    monkeypatch.setattr(_httpx, "AsyncClient", Client)
    assert asyncio.run(fcm_mod.send_ping("t")) == "error"
    assert constructed == []


def test_payload_is_data_only_high_priority(monkeypatch):
    sent = _patch(monkeypatch)
    assert asyncio.run(fcm_mod.send_ping("t")) == "ok"
    msg = sent["json"]["message"]
    assert msg == {"token": "t", "data": {"ping": "true"},
                   "android": {"priority": "HIGH"}}
    assert "notification" not in msg
    assert sent["headers"] == {"Authorization": "Bearer AT"}
    assert sent["url"].endswith("/v1/projects/proj/messages:send")


def test_requirements_pins_requests():
    """Deployment contract: fcm.py uses google.auth.transport.requests,
    which hard-requires the requests package. It happened to exist in dev
    site-packages as a transitive dep, so only Render's clean pip install
    exposed the gap — every ping died in OAuth with ImportError. An import
    test would pass locally and prove nothing; pin the file instead."""
    req = pathlib.Path(__file__).resolve().parent.parent / "requirements.txt"
    lines = [ln.strip().lower() for ln in req.read_text().splitlines()]
    assert any(
        ln == "requests" or ln.startswith("requests==") or ln.startswith("requests>=")
        for ln in lines
    ), "requirements.txt must pin requests for the FCM OAuth transport"
