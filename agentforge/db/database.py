"""Async SQLAlchemy engine + session factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentforge.config import get_settings


def _normalize_db_url(url: str) -> str:
    """Force asyncpg dialect — Railway's DATABASE_URL ships plain `postgresql://`.

    Without this, SQLAlchemy tries the sync psycopg driver and crashes on first
    use. We also accept `postgres://` (Heroku-style) for compatibility.
    """
    if url.startswith("postgresql+asyncpg://") or url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url[len("postgresql://"):]
    if url.startswith("postgres://"):
        return "postgresql+asyncpg://" + url[len("postgres://"):]
    return url


def _build_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(
        _normalize_db_url(settings.database_url),
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        future=True,
    )


engine: AsyncEngine = _build_engine()

SessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Yield an async session with commit/rollback handling.

    Why: every write-path agent and repository needs a session with consistent
    transaction semantics. Using a context manager avoids leaking connections.
    """
    session = SessionLocal()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields a request-scoped session."""
    async with session_scope() as session:
        yield session


async def dispose_engine() -> None:
    """Dispose of the pool on app shutdown."""
    await engine.dispose()
