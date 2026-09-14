"""FastAPI blind switchboard. No IP logging; TLS 1.3 at ingress."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import models, security
from .db import engine
from .routers import directory, opaque, presence, update
from .ws import relay


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
        # create_all never adds columns to pre-existing tables: backfill any
        # column added after a deployment first created the table. Presence
        # data is ephemeral (everyone reconnects), so ALTER-and-continue is
        # safe; already-exists errors are ignored on both SQLite + Postgres.
        # A failed DDL poisons its transaction (Postgres aborts on error),
        # so each statement runs in its own transaction.
        from sqlalchemy import text

        for ddl in (
            "ALTER TABLE presence ADD COLUMN online BOOLEAN",
            "ALTER TABLE presence ADD COLUMN last_seen BIGINT",
        ):
            try:
                async with engine.begin() as conn2:
                    await conn2.execute(text(ddl))
            except Exception:
                pass
    yield
    await engine.dispose()


def create_app() -> FastAPI:
    security.install_no_ip_logging()
    logging.getLogger("uvicorn.access").disabled = True
    app = FastAPI(title="Visi Relay", version="1.0.0", lifespan=lifespan)
    app.include_router(opaque.router)
    app.include_router(directory.router)
    app.include_router(update.router)
    app.include_router(presence.router)
    app.include_router(relay.router)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app


app = create_app()
