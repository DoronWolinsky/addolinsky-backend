"""Admin browser sessions: random, revocable session ids, stored server-side only as SHA-256 hashes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

ADMIN_SESSION_TTL_S = 7 * 86400
MAX_ADMIN_SESSIONS = 50


class AdminSessionRegistry:
    """In memory, one per app and process: sessions end on logout, expiry or service restart."""

    def __init__(self):
        self._expiry_by_hash: dict[str, float] = {}
        self._lock = threading.Lock()

    def create(self) -> str:
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._expiry_by_hash = {digest: expiry for digest, expiry in self._expiry_by_hash.items() if expiry > now}
            if len(self._expiry_by_hash) >= MAX_ADMIN_SESSIONS:       # keep the newest sessions only
                for digest in sorted(self._expiry_by_hash, key=self._expiry_by_hash.get)[:-MAX_ADMIN_SESSIONS + 1]:
                    del self._expiry_by_hash[digest]
            self._expiry_by_hash[_digest(session_id)] = now + ADMIN_SESSION_TTL_S
        return session_id

    def is_valid(self, session_id: str) -> bool:
        if not session_id or len(session_id) > 100:
            return False
        provided_digest = _digest(session_id)
        now = time.time()
        with self._lock:
            for digest, expiry in self._expiry_by_hash.items():
                if hmac.compare_digest(digest, provided_digest):
                    return expiry > now
        return False

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._expiry_by_hash.pop(_digest(session_id or ""), None)


def _digest(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()
