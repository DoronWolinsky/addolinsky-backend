"""Protect HTTP requests: host allow-list, admin isolation in public mode, per-client rate limiting, cross-origin
checks and security headers."""

from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import Request
from fastapi.responses import JSONResponse

from ..config import Settings


class RequestRateLimiter:
    """Sliding one-minute window per client key (in memory; one process)."""

    def __init__(self):
        self._lock, self._request_history = threading.Lock(), {}

    def check_and_record_request(self, client_key: str, max_requests: int, window_seconds: float = 60.0) -> bool:
        now = time.time()
        with self._lock:
            request_timestamps = self._request_history.setdefault(client_key, deque())
            while request_timestamps and request_timestamps[0] <= now - window_seconds:
                request_timestamps.popleft()
            if len(request_timestamps) >= max_requests:
                return False
            request_timestamps.append(now)
            if len(self._request_history) > 50_000:            # bound memory
                self._request_history = {key: timestamps for key, timestamps in self._request_history.items()
                                         if timestamps and timestamps[-1] > now - window_seconds}
            return True


def get_client_ip_address(request: Request, public_mode: bool) -> str:
    # Behind the TLS proxy (public mode) the proxy's X-Forwarded-For is authoritative; we only bind to loopback.
    if public_mode:
        forwarded_for_header = request.headers.get("x-forwarded-for", "")
        if forwarded_for_header:
            return forwarded_for_header.split(",")[0].strip()[:64]
    return request.client.host if request.client else "?"


def is_cross_origin_request(request: Request, allowed_hosts: set[str]) -> bool:
    """True when the request names an Origin whose host is not served here (requests without Origin pass)."""
    origin = request.headers.get("origin")
    return bool(origin) and origin.split("://", 1)[-1] not in allowed_hosts


async def enforce_request_security(request: Request, call_next, *, allowed_hosts: set[str], public_mode: bool,
                                   rate_limiter: RequestRateLimiter, settings: Settings):
    host = request.headers.get("host", "")
    if host not in allowed_hosts:  # DNS-rebinding protection: only known host names are served
        return JSONResponse({"error": "forbidden host"}, status_code=403)
    path = request.url.path
    is_admin_route = path == "/" or path.startswith("/api/")
    if public_mode and is_admin_route and request.headers.get("x-forwarded-for"):
        return JSONResponse({"error": "not found"}, status_code=404)   # admin only via SSH tunnel
    if public_mode and not is_admin_route and not rate_limiter.check_and_record_request(
            get_client_ip_address(request, public_mode), settings.requests_per_ip_min):
        return JSONResponse({"error": "too many requests"}, status_code=429, headers={"Retry-After": "60"})
    if path.startswith("/api/") and request.method not in ("GET", "HEAD") and \
            is_cross_origin_request(request, allowed_hosts):
        return JSONResponse({"error": "cross-origin request rejected"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not path.startswith(("/manifest.json", "/subtitles/", "/subs/")):
        response.headers["X-Frame-Options"] = "DENY"
    return response
