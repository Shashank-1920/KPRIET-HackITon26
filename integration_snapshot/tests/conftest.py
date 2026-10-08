"""
S.H.A.D.E. — Shared Pytest Configuration & Test Fixtures
"""

import os
from pathlib import Path
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.app.core.config import settings
from backend.app.database.session import init_db, AsyncSessionLocal, _engine
from backend.app.database.models import Base


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    """Ensure a fresh database is initialized for the test session."""
    db_path = settings.database_url.replace("sqlite+aiosqlite:///", "")
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    
    # Drop and recreate tables cleanly for test session
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def client():
    """Shared async test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def db():
    """Shared async DB session fixture."""
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()
