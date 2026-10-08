"""
S.H.A.D.E. Backend — Application Entry Point
Role: Member 1 — Core Architecture + Backend + Database + Integration

FastAPI ASGI application factory with lifecycle management.
All endpoints are bound to 127.0.0.1 (localhost-only, device-local).
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.core.config import settings
from backend.app.core.errors import ShadeError
from backend.app.database.session import init_db
from backend.app.api.v1 import router as api_v1_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle: startup → yield → shutdown."""
    # ── Startup ──────────────────────────────────────────────────────────────
    await init_db()
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────────
    # Cleanup handled by SQLAlchemy engine dispose on garbage collection.


def create_app() -> FastAPI:
    """Factory that assembles the S.H.A.D.E. FastAPI application."""
    app = FastAPI(
        title="S.H.A.D.E. API",
        description=(
            "Synthetic Host for Automated Data Extractor — "
            "Local-first, privacy-first security backend. "
            "Listens exclusively on 127.0.0.1 (device-local)."
        ),
        version="1.0.0",
        openapi_url="/api/v1/openapi.json" if settings.debug else None,
        docs_url="/api/v1/docs" if settings.debug else None,
        redoc_url=None,
        lifespan=lifespan,
    )

    # ── CORS: localhost only ──────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Device-ID"],
    )

    # ── Global error handler ──────────────────────────────────────────────────
    @app.exception_handler(ShadeError)
    async def shade_error_handler(request: Request, exc: ShadeError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": exc.detail,
            },
        )

    # ── API v1 router ─────────────────────────────────────────────────────────
    app.include_router(api_v1_router, prefix="/api/v1")

    # ── Health probe ──────────────────────────────────────────────────────────
    @app.get("/health", tags=["system"])
    async def health() -> dict:
        return {"status": "ok", "service": "shade-backend", "local_only": True}

    return app


app = create_app()
