"""Issue and consume the one-time confirmation tokens ("nonces") carried by the confirm request track (D-123).

Tokens live in memory in one registry per app and process, and are lost on restart. A token is consumed only by a
request from the user it was issued to, for the same video, within its lifetime; the check and the removal are one
atomic step, so a token starts or retries work at most once."""

from __future__ import annotations

import secrets
import threading
import time

NONCE_TTL_S = 6 * 3600
# Stremio lists subtitles twice per playback (filename, then +video hash) and the Android TV app merges the lists by
# id, so an unused nonce is re-issued for the same user and video for NONCE_REUSE_S (one stable confirm entry).
# A matching fetch of the confirm URL uses the nonce up even when the request is then refused (quota, funding), so a
# remembered confirm track can never match a later listing.
NONCE_REUSE_S = 600
MAX_TOKENS_BEFORE_PRUNING = 20000


class ConfirmationTokenRegistry:
    def __init__(self):
        self._records: dict[str, tuple[str, str, float]] = {}       # token -> (user_id, video_id, issued_at)
        self._unused_token: dict[tuple[str, str], str] = {}         # (user_id, video_id) -> its unused token
        self._lock = threading.Lock()

    def get_or_create_confirmation_token(self, user_id: str, video_id: str) -> str:
        now = time.time()
        with self._lock:
            confirmation_token = self._unused_token.get((user_id, video_id))
            record = self._records.get(confirmation_token)
            if record and now - record[2] <= NONCE_REUSE_S:
                return confirmation_token          # same playback: same confirm entry (no duplicates on TV)
            if len(self._records) > MAX_TOKENS_BEFORE_PRUNING:
                self._remove_expired(now)
            confirmation_token = secrets.token_urlsafe(9)
            self._records[confirmation_token] = (user_id, video_id, now)
            self._unused_token[(user_id, video_id)] = confirmation_token
        return confirmation_token

    def validate_and_consume_confirmation_token(self, confirmation_token: str, user_id: str, video_id: str) -> bool:
        """True exactly once for a token issued to this user for this video within NONCE_TTL_S. A token presented
        for another user or video is left untouched; an expired token is removed."""
        if not confirmation_token:
            return False
        with self._lock:
            record = self._records.get(confirmation_token)
            if record is None:
                return False
            if time.time() - record[2] > NONCE_TTL_S:
                self._remove(confirmation_token, record)
                return False
            if (record[0], record[1]) != (user_id, video_id):
                return False
            self._remove(confirmation_token, record)
            return True

    def _remove(self, confirmation_token: str, record: tuple[str, str, float]) -> None:
        del self._records[confirmation_token]
        if self._unused_token.get((record[0], record[1])) == confirmation_token:
            del self._unused_token[(record[0], record[1])]

    def _remove_expired(self, now: float) -> None:
        for expired_token, record in [(token, record) for token, record in self._records.items()
                                      if now - record[2] > NONCE_TTL_S]:
            self._remove(expired_token, record)
