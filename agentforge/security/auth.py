"""Authentication + RBAC for AgentForge.

Implements CLAUDE.md §8.1:
  - JWT issue/verify (HS256, 60-min expiry)
  - API key authentication (bcrypt-hashed in DB)
  - RBAC roles: viewer / operator / admin
  - Reusable FastAPI dependencies: require_viewer, require_operator, require_admin

Why model: passlib's CryptContext gives a stable hash/verify API that we can
swap algorithms on later (argon2) without touching call sites.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.config import Settings, get_settings
from agentforge.db.database import get_session
from agentforge.db.models import ApiKey

# bcrypt is the canonical algorithm; auto-deprecate any future weaker hashes.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


# Role hierarchy: admin > operator > viewer. Each role inherits the lower ones.
_ROLE_ORDER = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}


@dataclass(frozen=True)
class Principal:
    """An authenticated caller (either a JWT subject or an API key)."""

    subject: str
    role: Role
    auth_method: str  # "jwt" | "api_key"

    def has_role(self, required: Role) -> bool:
        return _ROLE_ORDER[self.role] >= _ROLE_ORDER[required]


# --- Password / API key hashing ---------------------------------------------------

def hash_secret(plaintext: str) -> str:
    return pwd_context.hash(plaintext)


def verify_secret(plaintext: str, hashed: str) -> bool:
    return pwd_context.verify(plaintext, hashed)


# --- JWT issue / verify -----------------------------------------------------------

def create_access_token(
    subject: str,
    role: Role,
    *,
    settings: Settings | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    s = settings or get_settings()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=s.jwt_expiry_minutes))
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role.value,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, s.secret_key.get_secret_value(), algorithm=s.jwt_algorithm)


def decode_access_token(token: str, *, settings: Settings | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    try:
        payload = jwt.decode(
            token, s.secret_key.get_secret_value(), algorithms=[s.jwt_algorithm]
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    return payload


# --- FastAPI dependencies ---------------------------------------------------------

async def _principal_from_jwt(
    creds: HTTPAuthorizationCredentials | None,
    settings: Settings,
) -> Principal | None:
    if creds is None or creds.scheme.lower() != "bearer":
        return None
    payload = decode_access_token(creds.credentials, settings=settings)
    sub = payload.get("sub")
    role_str = payload.get("role")
    if not sub or not role_str:
        raise HTTPException(status_code=401, detail="Token missing required claims")
    try:
        role = Role(role_str)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Unknown role: {role_str}") from e
    return Principal(subject=str(sub), role=role, auth_method="jwt")


async def _principal_from_api_key(
    api_key: str | None,
    settings: Settings,
    db: AsyncSession,
) -> Principal | None:
    if not api_key:
        return None

    # Fast path: the master admin API key from env (constant-time compare).
    admin_key = settings.admin_api_key.get_secret_value()
    if admin_key and _constant_time_eq(api_key, admin_key):
        return Principal(subject="admin-env", role=Role.ADMIN, auth_method="api_key")

    # DB-backed keys are bcrypt-hashed. We must check against every active key
    # because bcrypt hashes are not reversible — load only active keys.
    result = await db.execute(select(ApiKey).where(ApiKey.is_active.is_(True)))
    for key_row in result.scalars():
        if verify_secret(api_key, key_row.key_hash):
            try:
                role = Role(key_row.role)
            except ValueError:
                continue
            return Principal(subject=str(key_row.id), role=role, auth_method="api_key")

    return None


def _constant_time_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing side-channels."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode(), strict=True):
        result |= x ^ y
    return result == 0


async def get_current_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Resolve the caller's identity from JWT or API key.

    Why both paths: humans use JWT (issued from a key exchange); machine
    integrations (CI, deployment webhooks) use the long-lived API key.
    """
    principal = await _principal_from_jwt(creds, settings)
    if principal is None:
        principal = await _principal_from_api_key(api_key, settings, db)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Stash on request.state so audit/logging middleware can pick it up.
    request.state.principal = principal
    return principal


def require_role(required: Role):
    """Build a dependency that enforces a minimum role."""

    async def _checker(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not principal.has_role(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required.value}",
            )
        return principal

    return _checker


require_viewer = require_role(Role.VIEWER)
require_operator = require_role(Role.OPERATOR)
require_admin = require_role(Role.ADMIN)


async def require_admin_with_confirm(
    principal: Principal = Depends(require_admin),
    x_admin_confirm: str | None = Header(default=None, alias="X-Admin-Confirm"),
) -> Principal:
    """Admin endpoints additionally require X-Admin-Confirm: true (CLAUDE.md §8.1)."""
    if (x_admin_confirm or "").lower() != "true":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin actions require X-Admin-Confirm: true header",
        )
    return principal
