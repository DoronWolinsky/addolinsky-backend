"""Authenticate users by their personal install token, and administrators by the admin token in a request header or
by an admin session cookie (with an anti-CSRF header required for cookie-authenticated changes)."""

from __future__ import annotations

import hashlib
import hmac

from fastapi import HTTPException, Request

from ..db import Store
from .sessions import AdminSessionRegistry

ADMIN_SESSION_COOKIE = "addolinsky_admin_session"
LEGACY_ADMIN_COOKIE = "addolinsky_admin"          # held the master token; no longer accepted, deleted on login/logout


def hash_install_token(install_token: str) -> str:
    return hashlib.sha256(install_token.encode()).hexdigest()


def find_user_by_install_token(store: Store, install_token: str) -> dict | None:
    if not 16 <= len(install_token) <= 64:
        return None
    return store.user_by_token_hash(hash_install_token(install_token))


def require_authenticated_user(store: Store, install_token: str) -> dict:
    user = find_user_by_install_token(store, install_token)
    if not user:
        raise HTTPException(404, "not found")
    return user


def is_admin_token(provided_admin_token: str, expected_admin_token: str) -> bool:
    return bool(provided_admin_token) and hmac.compare_digest(provided_admin_token.encode(),
                                                              expected_admin_token.encode())


def require_admin_access(request: Request, expected_admin_token: str, admin_sessions: AdminSessionRegistry) -> None:
    """Allow the admin token in X-Admin-Token (tools), or a valid admin session cookie (the admin page). A header,
    when present, decides alone. Cookie-authenticated changes also need X-Requested-With: addolinsky."""
    provided_admin_token = request.headers.get("x-admin-token") or ""
    if provided_admin_token:
        if not is_admin_token(provided_admin_token, expected_admin_token):
            raise HTTPException(401, "admin authentication required")
        return
    if not admin_sessions.is_valid(request.cookies.get(ADMIN_SESSION_COOKIE, "")):
        raise HTTPException(401, "admin authentication required")
    if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "addolinsky":
        raise HTTPException(403, "missing anti-CSRF header")
