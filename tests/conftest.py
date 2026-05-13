"""Shared pytest fixtures for AgentForge tests."""

from __future__ import annotations

import os

# Ensure we never read a real .env in unit tests — set placeholder values
# *before* importing anything from agentforge.config.
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "unit-test-secret-key-not-for-production-use-only-32chars")
os.environ.setdefault("ADMIN_API_KEY", "unit-test-admin-key")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://agentforge:agentforge@localhost:5432/agentforge")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("BACKEND_URL", "http://localhost:3000")

import pytest  # noqa: E402

from agentforge.config import get_settings  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Reset the cached settings between tests so env overrides take effect."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
