"""Pydantic schemas. All binary fields are base64-std at the boundary."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


def _b64_or_empty(v: str) -> str:
    import base64

    base64.b64decode(v, validate=True)
    return v


class RegisterStartIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.\-]{3,32}$")
    registration_request_b64: str


class RegisterStartOut(BaseModel):
    registration_response_b64: str


class PreKeyBundleIn(BaseModel):
    identity_pub_ed_b64: str
    signed_pre_pub_x_b64: str
    signed_pre_sig_b64: str
    # M1: null accepted when client has no one-time pre-key left.
    onetime_pub_x_b64: Optional[str] = None


class RegisterFinishIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.\-]{3,32}$")
    registration_upload_b64: str
    bundle: PreKeyBundleIn
    # Encrypted backup blob (under export key; server stores opaquely).
    envelope_b64: str = ""


class StatusOut(BaseModel):
    status: str = "ok"


class LoginStartIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.\-]{3,32}$")
    credential_request_b64: str


class LoginStartOut(BaseModel):
    credential_response_b64: str


class LoginFinishIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.\-]{3,32}$")
    credential_finalization_b64: str


class LoginFinishOut(BaseModel):
    """B4: all three fields. session_key itself never leaves the server."""

    status: str = "ok"
    envelope_b64: str
    ws_token_b64: str


class KeysOut(BaseModel):
    username: str
    bundle: dict
    leaf: str
    proof: list[str]
    root: str
    size: int


class MerkleRootOut(BaseModel):
    root: str
    size: int


class DirectoryOut(BaseModel):
    usernames: list[str]
    next_cursor: int


class UpdateOut(BaseModel):
    version_code: int
    download_url: str
    sha256: str


class PushTokenIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.\-]{3,32}$")
    fcm_token: str = Field(min_length=1, max_length=4096)


class PushTokenDeleteIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.\-]{3,32}$")
