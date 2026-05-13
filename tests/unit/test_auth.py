"""Unit tests for agentforge.security.auth."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import HTTPException

from agentforge.security import auth
from agentforge.security.auth import (
    Principal,
    Role,
    _constant_time_eq,
    create_access_token,
    decode_access_token,
    hash_secret,
    verify_secret,
)


class TestRoleHierarchy:
    def test_admin_has_all_roles(self):
        p = Principal(subject="x", role=Role.ADMIN, auth_method="jwt")
        assert p.has_role(Role.VIEWER)
        assert p.has_role(Role.OPERATOR)
        assert p.has_role(Role.ADMIN)

    def test_operator_has_viewer_and_operator(self):
        p = Principal(subject="x", role=Role.OPERATOR, auth_method="jwt")
        assert p.has_role(Role.VIEWER)
        assert p.has_role(Role.OPERATOR)
        assert not p.has_role(Role.ADMIN)

    def test_viewer_has_only_viewer(self):
        p = Principal(subject="x", role=Role.VIEWER, auth_method="jwt")
        assert p.has_role(Role.VIEWER)
        assert not p.has_role(Role.OPERATOR)
        assert not p.has_role(Role.ADMIN)


class TestSecretHashing:
    def test_hash_then_verify_roundtrip(self):
        secret = "correct-horse-battery-staple"
        hashed = hash_secret(secret)
        assert hashed != secret
        assert verify_secret(secret, hashed)

    def test_verify_rejects_wrong_secret(self):
        hashed = hash_secret("right")
        assert not verify_secret("wrong", hashed)

    def test_two_hashes_of_same_input_differ(self):
        # bcrypt salts each call, so identical inputs yield different hashes.
        assert hash_secret("same") != hash_secret("same")


class TestJWT:
    def test_issue_and_decode_roundtrip(self):
        token = create_access_token("user-123", Role.OPERATOR)
        payload = decode_access_token(token)
        assert payload["sub"] == "user-123"
        assert payload["role"] == "operator"
        assert "exp" in payload and "iat" in payload

    def test_expired_token_raises_401(self):
        token = create_access_token("user-x", Role.VIEWER, expires_delta=timedelta(seconds=-10))
        with pytest.raises(HTTPException) as excinfo:
            decode_access_token(token)
        assert excinfo.value.status_code == 401

    def test_tampered_token_raises_401(self):
        token = create_access_token("user-x", Role.VIEWER)
        # Replace the signature entirely — base64url has enough redundancy that
        # single-char flips on the last char can be a no-op.
        head, payload, _ = token.rsplit(".", 2)
        tampered = f"{head}.{payload}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        with pytest.raises(HTTPException) as excinfo:
            decode_access_token(tampered)
        assert excinfo.value.status_code == 401


class TestConstantTimeEq:
    def test_equal_strings(self):
        assert _constant_time_eq("abc123", "abc123")

    def test_unequal_same_length(self):
        assert not _constant_time_eq("abc123", "xyz789")

    def test_unequal_different_length(self):
        assert not _constant_time_eq("abc", "abcdef")


class TestRequireRole:
    @pytest.mark.asyncio
    async def test_passes_when_role_sufficient(self):
        principal = Principal(subject="u", role=Role.OPERATOR, auth_method="jwt")
        checker = auth.require_role(Role.VIEWER)
        result = await checker(principal=principal)
        assert result is principal

    @pytest.mark.asyncio
    async def test_rejects_when_role_insufficient(self):
        principal = Principal(subject="u", role=Role.VIEWER, auth_method="jwt")
        checker = auth.require_role(Role.ADMIN)
        with pytest.raises(HTTPException) as excinfo:
            await checker(principal=principal)
        assert excinfo.value.status_code == 403


class TestAdminConfirm:
    @pytest.mark.asyncio
    async def test_admin_confirm_required(self):
        principal = Principal(subject="u", role=Role.ADMIN, auth_method="api_key")
        with pytest.raises(HTTPException) as excinfo:
            await auth.require_admin_with_confirm(principal=principal, x_admin_confirm=None)
        assert excinfo.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_confirm_accepted(self):
        principal = Principal(subject="u", role=Role.ADMIN, auth_method="api_key")
        result = await auth.require_admin_with_confirm(principal=principal, x_admin_confirm="true")
        assert result is principal
