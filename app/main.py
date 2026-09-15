"""FastAPI blind switchboard. No IP logging; TLS 1.3 at ingress."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import config, models, security
from .db import engine
from .routers import directory, opaque, presence, push, update
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
    sweeper = asyncio.create_task(_sweep_loop())
    try:
        yield
    finally:
        # Join the sweeper so test harnesses and shutdown don't leak a
        # pending 24h sleep (which hangs process teardown).
        sweeper.cancel()
        try:
            await sweeper
        except (asyncio.CancelledError, Exception):
            pass
    await engine.dispose()


async def _sweep_loop() -> None:
    """Daily global shred of expired offline_queue rows (dead-forever
    accounts). The keeper keeps the free instance awake enough for this to
    run ~daily; returning users are additionally swept lazily on flush."""
    while True:
        await asyncio.sleep(24 * 3600)
        try:
            n = await relay.sweep_expired_queues()
        except asyncio.CancelledError:
            raise
        except Exception:
            logging.getLogger("uvicorn.error").exception("queue sweep failed")
        else:
            if n:
                logging.getLogger("uvicorn.error").info("queue sweep removed %d", n)


def create_app() -> FastAPI:
    security.install_no_ip_logging()
    logging.getLogger("uvicorn.access").disabled = True
    if config.DATABASE_URL.startswith("sqlite"):
        # Deploy guardrail (specs/render-deploy.md §3): a file DB evaporates
        # on the first restart. Prod must set DATABASE_URL to hosted Postgres.
        logging.getLogger("uvicorn.error").error(
            "DATABASE_URL is SQLite — ephemeral on hosted free tiers; "
            "set hosted Postgres or all data is lost on restart"
        )
    app = FastAPI(title="Visi Relay", version="1.0.0", lifespan=lifespan)
    app.include_router(opaque.router)
    app.include_router(directory.router)
    app.include_router(update.router)
    app.include_router(presence.router)
    app.include_router(push.router)
    app.include_router(relay.router)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/health")
    async def health():
        # Keeper alias (specs/render-deploy.md §4): external cron pings this
        # every 10 min so the free instance doesn't sleep. Same shape as /healthz.
        return {"status": "ok"}

    return app


app = create_app()
