"""Auth API: exchange an API key for a short-lived JWT."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.config import Settings, get_settings
from agentforge.db.database import get_session
from agentforge.security.auth import (
    Role,
    _constant_time_eq,
    _principal_from_api_key,
    create_access_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    role: str


@router.post("/token", response_model=TokenOut)
async def issue_token(
    api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TokenOut:
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="X-API-Key required")

    # ENV admin key fast-path.
    admin_key = settings.admin_api_key.get_secret_value()
    role: Role | None = None
    subject = "unknown"
    if admin_key and _constant_time_eq(api_key, admin_key):
        role = Role.ADMIN
        subject = "admin-env"
    else:
        principal = await _principal_from_api_key(api_key, settings, db)
        if principal is not None:
            role = principal.role
            subject = principal.subject

    if role is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    token = create_access_token(subject, role, settings=settings)
    return TokenOut(
        access_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expiry_minutes),
        role=role.value,
    )
