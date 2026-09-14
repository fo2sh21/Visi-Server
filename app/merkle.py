"""Append-only SHA256 Merkle ledger for username->bundle bindings (§E).

leaf = sha256(username || 0x00 || canonical_bundle_bytes)
root/proof computed over power-of-two padded tree (duplicate-last).
Free-tier: leaves cached in DB, root recomputed incrementally on append only.
"""
from __future__ import annotations

import base64
import hashlib
import json


def canonical_bundle(bundle: dict) -> bytes:
    return json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()


def leaf_hash(username: str, bundle: dict) -> bytes:
    h = hashlib.sha256()
    h.update(username.encode())
    h.update(b"\x00")
    h.update(canonical_bundle(bundle))
    return h.digest()


def compute_root(leaves: list[bytes]) -> tuple[bytes, int]:
    if not leaves:
        return hashlib.sha256(b"visi-empty-tree").digest(), 0
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0], len(leaves)


def merkle_proof(leaves: list[bytes], index: int) -> list[str]:
    proof: list[str] = []
    level = list(leaves)
    i = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = i ^ 1
        proof.append(base64.b64encode(level[sib]).decode())
        level = [
            hashlib.sha256(level[j] + level[j + 1]).digest()
            for j in range(0, len(level), 2)
        ]
        i //= 2
    return proof


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()
