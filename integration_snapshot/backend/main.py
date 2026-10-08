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

    # ── Frontend HUD & Static files ───────────────────────────────────────────
    import os
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
    if os.path.exists(frontend_dir):
        @app.get("/", include_in_schema=False)
        @app.get("/app", include_in_schema=False)
        async def serve_frontend():
            index_path = os.path.join(frontend_dir, "index.html")
            if os.path.exists(index_path):
                return FileResponse(index_path)
            return {"service": "S.H.A.D.E. Backend", "status": "active"}

        @app.get("/styles.css", include_in_schema=False)
        @app.get("/static/styles.css", include_in_schema=False)
        @app.get("/static/css/styles.css", include_in_schema=False)
        @app.get("/static/css/style.css", include_in_schema=False)
        async def serve_frontend_styles():
            css_path = os.path.join(frontend_dir, "styles.css")
            if os.path.exists(css_path):
                return FileResponse(css_path, media_type="text/css")
            return {"error": "styles.css not found"}

        @app.get("/app.js", include_in_schema=False)
        @app.get("/static/app.js", include_in_schema=False)
        @app.get("/static/js/app.js", include_in_schema=False)
        async def serve_frontend_script():
            js_path = os.path.join(frontend_dir, "app.js")
            if os.path.exists(js_path):
                return FileResponse(js_path, media_type="application/javascript")
            return {"error": "app.js not found"}

        app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    return app


app = create_app()
