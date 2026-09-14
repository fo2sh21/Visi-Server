"""Subprocess wrapper for the Rust OPAQUE sidecar (B2: shell out, no PyO3).

Protocol (SPEC.md, normative):
  stdin  {"op": ..., ...}  — binary fields b64-std
  stdout {"ok": {...}}     — success, exit 0
  stdout {"error": "..."}  — NORMAL auth failure (e.g. wrong password), exit 0
  stderr + nonzero exit    — ONLY case treated as infra fault (500).
"""
from __future__ import annotations

import asyncio
import json

from . import config


class SidecarInfraError(RuntimeError):
    pass


class SidecarAuthError(RuntimeError):
    """Protocol-level auth rejection (wrong password, bad message). Not a 500."""


async def call(op: str, fields: dict) -> dict:
    payload = json.dumps({"op": op, **fields}).encode()
    try:
        proc = await asyncio.create_subprocess_exec(
            config.SIDECAR_BIN,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as e:
        raise SidecarInfraError(f"sidecar spawn failed: {e}") from e
    out, err = await proc.communicate(payload)
    if proc.returncode != 0:
        raise SidecarInfraError(f"sidecar crash: {(err or out)[:500]!r}")
    try:
        doc = json.loads(out.decode())
    except Exception as e:
        raise SidecarInfraError(f"sidecar bad stdout: {e}") from e
    if "ok" in doc:
        return doc["ok"]
    # {"error": ...} with exit 0 = auth outcome, never convert to success.
    raise SidecarAuthError(str(doc.get("error", "auth failed")))
