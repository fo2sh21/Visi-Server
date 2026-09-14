"""B1 vector: locked derivation must match byte-exact reference (cryptography HKDF)."""
import base64
import hashlib
import hmac as hmac_mod

from app.tokens import WS_TOKEN_INFO_PREFIX, WS_TOKEN_SEP, derive_ws_token, ws_info


def _hkdf_sha256_manual(ikm: bytes, salt: bytes, info: bytes, L: int = 32) -> bytes:
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    for i in range(1, (L + 31) // 32 + 1):
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:L]


def test_info_string_verbatim():
    assert WS_TOKEN_INFO_PREFIX == b"Visi-WS-Token-v1"
    assert WS_TOKEN_SEP == b"\x00"
    assert ws_info("alice") == b"Visi-WS-Token-v1\x00alice"


def test_derive_matches_rfc5869_reference():
    sk = bytes(range(32))
    assert derive_ws_token(sk, "alice") == _hkdf_sha256_manual(
        sk, b"", b"Visi-WS-Token-v1\x00alice"
    )
    # Username binding: different user -> different token.
    assert derive_ws_token(sk, "alice") != derive_ws_token(sk, "bob")
