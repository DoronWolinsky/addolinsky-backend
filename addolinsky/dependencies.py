"""Hold the state shared by all routes and services of one application instance and expose it to FastAPI."""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import Depends, Request

from .config import Settings
from .db import Store
from .security.middleware import RequestRateLimiter
from .security.nonces import ConfirmationTokenRegistry
from .security.secrets import get_admin_token, get_or_create_secret
from .security.sessions import AdminSessionRegistry


@dataclass
class AppContext:
    """Created once per application. The confirmation-token registry, the job-start lock, the rate limiter and the
    verified-output cache must each exist exactly once: a second instance would let a confirmation token be reused
    or a quota check race a job start."""

    settings: Settings
    allowed_hosts: set[str]
    public_mode: bool                     # served through the TLS reverse proxy at settings.public_base_url
    admin_token: str
    server_secret: bytes                  # HMAC key of signed video tokens and of sign-up network keys
    rate_limiter: RequestRateLimiter = field(default_factory=RequestRateLimiter)
    confirmation_tokens: ConfirmationTokenRegistry = field(default_factory=ConfirmationTokenRegistry)
    admin_sessions: AdminSessionRegistry = field(default_factory=AdminSessionRegistry)
    job_start_lock: threading.Lock = field(default_factory=threading.Lock)   # quota checks + job creation are atomic
    verified_outputs: dict[str, tuple[int, int]] = field(default_factory=dict)   # output_id -> (mtime_ns, size)
    access_denials: Counter = field(default_factory=Counter)   # refused subtitle fetches by reason (admin metrics)
    _store: Store | None = field(default=None, repr=False)

    @property
    def store(self) -> Store:
        """The application's Store, opened on first use (one SQLite connection per thread)."""
        if self._store is None:
            self._store = Store(self.settings.db_path)
        return self._store


def build_app_context(settings: Settings, store: Store | None = None, allowed_hosts: set[str] | None = None) -> AppContext:
    admin_token = get_admin_token(settings)
    hosts = allowed_hosts or {f"127.0.0.1:{settings.port}", f"localhost:{settings.port}", "127.0.0.1", "localhost"}
    if settings.public_host:
        hosts = hosts | {settings.public_host}
    return AppContext(settings=settings, allowed_hosts=hosts, public_mode=bool(settings.public_base_url),
                      admin_token=admin_token,
                      server_secret=get_or_create_secret(settings, "server_secret", 32).encode(), _store=store)


async def get_app_context(request: Request) -> AppContext:
    return request.app.state.context


Context = Annotated[AppContext, Depends(get_app_context)]
