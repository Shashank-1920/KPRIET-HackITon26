"""
S.H.A.D.E. — Database Session & Initialization
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides async SQLAlchemy engine, session factory, and database initializer.
Uses plain SQLite via aiosqlite — tables created by SQLAlchemy metadata.
"""

import logging
import os
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.core.config import settings
from backend.app.database.encrypted_sqlite import configure_sqlite_encryption
from backend.app.database.models import Base

logger = logging.getLogger(__name__)

# ── Engine ────────────────────────────────────────────────────────────────────
_engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args={"check_same_thread": False},
)
configure_sqlite_encryption(_engine)


# ── Session factory ───────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def init_db() -> None:
    """
    Create the data directory and initialise all database tables.
    Called once during application startup lifespan.
    """
    db_path = settings.database_url.replace("sqlite+aiosqlite:///", "")
    data_dir = Path(db_path).parent
    data_dir.mkdir(parents=True, exist_ok=True)

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("[DB] Local vault initialised at: %s", db_path)


async def get_db() -> AsyncSession:
    """
    FastAPI dependency that yields a database session per request.
    Automatically commits on success or rolls back on exception.

    Usage:
        @router.get("/example")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
