"""Data-only FCM wakeups. FCM is a doorbell, never a mailbox.

Payload is always `{data: {ping: "true"}}` — never a `notification` block
(that would let FCM/System render uncontrolled text and leak metadata into
system notification logs). No content, sender, count, or timestamp: timing
alone leaks "something arrived" (accepted, documented in-app).

Lightweight stack: google-auth (OAuth) + httpx direct to FCM HTTP v1 — no
firebase-admin (grpc weight, slow cold starts on free tiers).
"""
from __future__ import annotations

import asyncio
import json
import logging

import httpx

from . import config

log = logging.getLogger("uvicorn.error")

_FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"

# Module-level credential cache (no per-message file reads / OAuth dances).
_creds = {"loaded": False, "creds": None, "project_id": ""}
_disabled_logged = False


def _load() -> tuple | None:
    """Load service-account creds once. None = push disabled (no creds).

    Precedence: inline `FCM_CREDENTIALS_JSON` env (whole JSON as one value —
    the Render/prod path, wipe-safe) first, `FCM_CREDENTIALS_PATH` file as
    local-dev fallback.
    """
    global _disabled_logged
    if _creds["loaded"]:
        return (_creds["creds"], _creds["project_id"]) if _creds["creds"] else None
    _creds["loaded"] = True
    try:
        from google.oauth2 import service_account

        info = config.FCM_CREDENTIALS_JSON
        if info:
            doc = json.loads(info)
            creds = service_account.Credentials.from_service_account_info(
                doc, scopes=[_FCM_SCOPE]
            )
            project_id = doc.get("project_id", "")
        else:
            path = config.FCM_CREDENTIALS_PATH
            if not path:
                return None
            creds = service_account.Credentials.from_service_account_file(
                path, scopes=[_FCM_SCOPE]
            )
            with open(path, encoding="utf-8") as f:
                project_id = json.load(f).get("project_id", "")
        if not project_id:
            return None
        _creds.update(creds=creds, project_id=project_id)
        return creds, project_id
    except Exception as e:
        if not _disabled_logged:
            _disabled_logged = True
            log.error("FCM disabled: cannot load credentials: %.100s", e)
        return None


async def _access_token(creds) -> str | None:
    try:
        import google.auth.transport.requests

        # google-auth refresh is sync urllib: keep it off the event loop.
        await asyncio.to_thread(
            creds.refresh, google.auth.transport.requests.Request()
        )
        return creds.token
    except Exception:
        return None


async def send_ping(fcm_token: str) -> str:
    """Send a data-only ping. Returns 'ok' | 'stale' | 'error'.

    'stale' (unregistered token) → caller deletes the stored token.
    The token is never logged.
    """
    loaded = _load()
    if loaded is None:
        return "error"
    creds, project_id = loaded
    access = await _access_token(creds)
    if not access:
        return "error"
    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            r = await http.post(
                url,
                headers={"Authorization": f"Bearer {access}"},
                # HIGH priority: without it Doze batches/defer data messages
                # and the headless drain may never wake in time. Priority is
                # delivery urgency, not user visibility (still data-only).
                json={
                    "message": {
                        "token": fcm_token,
                        "data": {"ping": "true"},
                        "android": {"priority": "HIGH"},
                    }
                },
            )
    except Exception:
        return "error"
    if r.status_code == 200:
        return "ok"
    try:
        err = r.json().get("error", {})
        status = err.get("status", "")
        details = str(err.get("details", ""))
    except Exception:
        status, details = "", ""
        return "error"
    if status in ("NOT_FOUND", "INVALID_ARGUMENT") and (
        "UNREGISTERED" in details or status == "NOT_FOUND"
    ):
        return "stale"
    # Name the rejection (HTTP + FCM status only — no token, no user, no
    # identifiers). Bare "error" cost a full debug cycle when every ping
    # died the same silent way; the status distinguishes API-disabled (403
    # PERMISSION_DENIED, enable the FCM API) from IAM (403, grant the sender
    # role) from transport failures.
    log.warning("FCM ping error: http=%s status=%s", r.status_code, status or "?")
    return "error"
