"""Async DB engine. Free-tier: small pool, pre-ping, fast cold start."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from . import config

connect_args: dict = {}
if config.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    # Neon pooled URL sits behind pgbouncer: prepared statements die on
    # pgbouncer, so asyncpg must not use its statement cache (deploy blocker
    # per specs/render-deploy.md §2). ssl=True carries the stripped
    # sslmode=require (Neon mandates TLS; publicly-trusted certs verify fine).
    connect_args = {"statement_cache_size": 0}
    if config.DATABASE_USE_SSL:
        connect_args["ssl"] = True

engine = create_async_engine(
    config.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=5,
    connect_args=connect_args,
)

SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with SessionLocal() as s:
        yield s
