"""Create and verify signed per-user, per-video tokens (`<user_id>.<24 hex HMAC-SHA256>`) carried by request-track
and delivery URLs. Verification proves only which user a URL was issued to: callers must still check that the user
is active."""

from __future__ import annotations

import hashlib
import hmac


def create_signed_video_token(server_secret: bytes, user_id: str, content_type: str, video_id: str) -> str:
    signature = hmac.new(server_secret, f"{user_id}|{content_type}|{video_id}".encode(),
                         hashlib.sha256).hexdigest()[:24]
    return f"{user_id}.{signature}"


def verify_signed_video_token(server_secret: bytes, signed_token: str, content_type: str, video_id: str) -> str | None:
    user_id = signed_token.split(".", 1)[0]
    return user_id if hmac.compare_digest(
        signed_token.encode(), create_signed_video_token(server_secret, user_id, content_type, video_id).encode()
    ) else None
