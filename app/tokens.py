"""B1 LOCKED — HKDF-SHA256 WS token derivation. Byte-exact, verbatim.

token = HKDF-SHA256(salt=b"", IKM=session_key,
                    info=b"Visi-WS-Token-v1" + b"\\x00" + username.encode("utf-8"),
                    L=32)

The username binding and exact info string are load-bearing. Do NOT rename.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Verbatim constants (B1).
WS_TOKEN_INFO_PREFIX = b"Visi-WS-Token-v1"
WS_TOKEN_SEP = b"\x00"
WS_TOKEN_LEN = 32


def ws_info(username: str) -> bytes:
    return WS_TOKEN_INFO_PREFIX + WS_TOKEN_SEP + username.encode("utf-8")


def derive_ws_token(session_key: bytes, username: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=WS_TOKEN_LEN,
        salt=b"",
        info=ws_info(username),
    )
    return hkdf.derive(session_key)


def token_hash(token: bytes) -> bytes:
    return hashlib.sha256(token).digest()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)
