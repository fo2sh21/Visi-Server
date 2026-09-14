"""FastAPI blind switchboard. No IP logging; TLS 1.3 at ingress."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import models, security
from .db import engine
from .routers import directory, opaque, update
from .ws import relay


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    yield
    await engine.dispose()


def create_app() -> FastAPI:
    security.install_no_ip_logging()
    logging.getLogger("uvicorn.access").disabled = True
    app = FastAPI(title="Visi Relay", version="1.0.0", lifespan=lifespan)
    app.include_router(opaque.router)
    app.include_router(directory.router)
    app.include_router(update.router)
    app.include_router(relay.router)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app


app = create_app()
