"""SQLAlchemy models. Blind switchboard: blobs stored, never inspected/logged."""
from __future__ import annotations

import time
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ServerSetup(Base):
    """Single-row table (id=1). M4: Postgres preferred, file only fallback."""

    __tablename__ = "server_setup"
    id: Mapped[int] = mapped_column(primary_key=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class PasswordFile(Base):
    __tablename__ = "password_files"
    username: Mapped[str] = mapped_column(String(32), primary_key=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class KeyBundle(Base):
    """Public pre-key bundle JSON (all values b64-std, onetime may be null — M1)."""

    __tablename__ = "key_bundles"
    username: Mapped[str] = mapped_column(String(32), primary_key=True)
    bundle: Mapped[str] = mapped_column(Text, nullable=False)  # canonical JSON
    leaf_idx: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class UserEnvelope(Base):
    """Encrypted backup blob (under client export key; opaque to server)."""

    __tablename__ = "user_envelopes"
    username: Mapped[str] = mapped_column(String(32), primary_key=True)
    envelope_b64: Mapped[str] = mapped_column(Text, nullable=False, default="")


class LoginState(Base):
    """B2: sidecar subprocess is stateless; hold login_state here w/ minutes TTL."""

    __tablename__ = "login_states"
    username: Mapped[str] = mapped_column(String(32), primary_key=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class Presence(Base):
    __tablename__ = "presence"
    username: Mapped[str] = mapped_column(String(32), primary_key=True)
    online: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    connected_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=lambda: int(time.time())
    )
    last_seen: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)


class OfflineQueue(Base):
    """M2: INSERT -> push -> DELETE-on-ack. Row lives until ack/timeout."""

    __tablename__ = "offline_queue"
    msg_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: uuid.uuid4().hex
    )
    to_user: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    from_user: Mapped[str] = mapped_column(String(32), nullable=False)
    envelope_b64: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=lambda: int(time.time())
    )


class WsToken(Base):
    """B1: issued_at + 30-day cap. Only sha256(token) stored."""

    __tablename__ = "ws_tokens"
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    issued_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class PendingReceipt(Base):
    """Durable receipts: same lifecycle as messages — stored only until the
    addressee acks, never archived. kind ∈ {delivered, read}. The UNIQUE
    guard makes generation idempotent under duplicate acks/reads."""

    __tablename__ = "pending_receipts"
    __table_args__ = (UniqueConstraint("to_user", "kind", "msg_id"),)
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: uuid.uuid4().hex
    )
    to_user: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    msg_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=lambda: int(time.time())
    )


class MerkleLeaf(Base):
    __tablename__ = "merkle_leaves"
    idx: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), nullable=False)
    leaf_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)


class MerkleState(Base):
    __tablename__ = "merkle_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    root: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
