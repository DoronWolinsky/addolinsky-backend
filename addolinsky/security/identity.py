"""Website identity through Firebase Authentication (F1, D-132): ID-token verification and explicit account linking.

Firebase only proves who signed in on the website. It never replaces, issues or rotates the install tokens that
Stremio uses, never creates Addolinsky users and never
matches accounts by e-mail address: a user links a Firebase identity only while presenting their own install token.

Verification follows Firebase's third-party JWT rules: RS256 only; `kid` must name a current Google securetoken
certificate; `aud` = project id; `iss` = https://securetoken.google.com/<project id>; `exp` in the future; `iat` and
`auth_time` in the past; non-empty `sub` (the uid). Certificates are public and cached for their Cache-Control max-age;
an unknown `kid` triggers at most one refetch per minute; a failed refetch never extends expired certificates (fail
closed). Revocation is NOT checked (that needs the Admin SDK and a service account): an ID token stays valid until it
expires (about 1 hour). Callers therefore keep no session derived from it and require a recent `auth_time` for
sensitive operations.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from ..config import Settings
from ..db import Store
from .auth import find_user_by_install_token

CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
MAX_TOKEN_CHARS = 4096
CLOCK_SKEW_S = 30
CERT_TTL_DEFAULT_S = 3600
CERT_TTL_MAX_S = 24 * 3600
REFETCH_MIN_INTERVAL_S = 60
LINK_MAX_AUTH_AGE_S = 600          # linking needs a sign-in from the last 10 minutes


class IdentityError(Exception):
    """A website identity was refused. `code` is safe to log; the token itself never is."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FirebaseIdentity:
    uid: str
    email: str | None
    email_verified: bool
    sign_in_provider: str | None
    auth_time: float
    issued_at: float


def _default_http_get(url: str) -> tuple[int, dict, bytes]:
    import httpx
    response = httpx.get(url, timeout=10.0, follow_redirects=False)
    return response.status_code, dict(response.headers), response.content


def _max_age(headers: dict) -> int:
    cache_control = next((value for name, value in headers.items() if name.lower() == "cache-control"), "")
    max_age_match = re.search(r"max-age=(\d+)", cache_control)
    return min(int(max_age_match.group(1)), CERT_TTL_MAX_S) if max_age_match else CERT_TTL_DEFAULT_S


class FirebaseTokenVerifier:
    """One per app (holds the certificate cache). Thread-safe."""

    def __init__(self, project_id: str, http_get: Callable[[str], tuple[int, dict, bytes]] = _default_http_get,
                 clock: Callable[[], float] = time.time):
        if not PROJECT_ID_RE.fullmatch(project_id or ""):
            raise ValueError("invalid Firebase project id")
        import jwt  # noqa: F401  (optional dependency: fail at construction, not at first sign-in)
        self.project_id, self._http_get, self._clock = project_id, http_get, clock
        self._lock = threading.Lock()
        self._keys: dict[str, object] = {}
        self._expires_at = 0.0
        self._last_fetch = float("-inf")

    def now(self) -> float:
        return self._clock()

    def _fetch(self, now: float) -> None:
        from cryptography.x509 import load_pem_x509_certificate
        self._last_fetch = now
        try:
            status, headers, body = self._http_get(CERTS_URL)
            if status != 200:
                return
            keys = {kid: load_pem_x509_certificate(pem.encode()).public_key() for kid, pem in json.loads(body).items()}
        except Exception:   # network or format problem: keep what we have, never extend its lifetime
            return
        if keys:
            self._keys, self._expires_at = keys, now + _max_age(headers)

    def _key(self, kid: str):
        now = self._clock()
        with self._lock:
            if now >= self._expires_at:
                self._keys, self._expires_at = {}, 0.0          # expired certificates are never used
                if now - self._last_fetch >= REFETCH_MIN_INTERVAL_S:
                    self._fetch(now)
            elif kid not in self._keys and now - self._last_fetch >= REFETCH_MIN_INTERVAL_S:
                self._fetch(now)                                # key rotation: one refetch per minute at most
            return self._keys.get(kid)

    def verify(self, id_token: str) -> FirebaseIdentity:
        import jwt
        if not isinstance(id_token, str) or not 0 < len(id_token) <= MAX_TOKEN_CHARS:
            raise IdentityError("malformed_token")
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            raise IdentityError("malformed_token") from None
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise IdentityError("bad_algorithm_or_key_id")
        key = self._key(header["kid"])
        if key is None:
            raise IdentityError("unknown_key")
        now = self._clock()
        try:
            claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=self.project_id,
                                issuer=f"https://securetoken.google.com/{self.project_id}", leeway=CLOCK_SKEW_S,
                                options={"require": ["exp", "iat", "aud", "iss", "sub", "auth_time"],
                                         "verify_iat": False, "verify_exp": False})
        except jwt.InvalidAudienceError:
            raise IdentityError("wrong_audience") from None
        except jwt.InvalidIssuerError:
            raise IdentityError("wrong_issuer") from None
        except jwt.PyJWTError:
            raise IdentityError("invalid_token") from None
        exp, iat, auth_time = claims.get("exp"), claims.get("iat"), claims.get("auth_time")
        if not all(isinstance(timestamp, (int, float)) for timestamp in (exp, iat, auth_time)):
            raise IdentityError("invalid_token")
        if exp <= now - CLOCK_SKEW_S:                          # checked against our clock (testable, explicit)
            raise IdentityError("expired")
        if iat > now + CLOCK_SKEW_S or auth_time > now + CLOCK_SKEW_S:
            raise IdentityError("issued_in_future")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not 0 < len(sub) <= 128:
            raise IdentityError("invalid_subject")
        firebase_claims = claims.get("firebase") if isinstance(claims.get("firebase"), dict) else {}
        email = claims.get("email") if isinstance(claims.get("email"), str) else None
        return FirebaseIdentity(uid=sub, email=email, email_verified=claims.get("email_verified") is True,
                                sign_in_provider=firebase_claims.get("sign_in_provider") if isinstance(
                                    firebase_claims.get("sign_in_provider"), str) else None,
                                auth_time=float(auth_time), issued_at=float(iat))


def build_verifier(settings: Settings, **kwargs) -> FirebaseTokenVerifier | None:
    """The app's verifier, or None while the feature is off (the default)."""
    if not (settings.firebase_auth and settings.firebase_project_id):
        return None
    return FirebaseTokenVerifier(settings.firebase_project_id, **kwargs)


def _verified_identity(verifier: FirebaseTokenVerifier | None, id_token: str) -> FirebaseIdentity:
    if verifier is None:
        raise IdentityError("disabled")
    ident = verifier.verify(id_token)
    if not ident.email_verified:
        raise IdentityError("email_not_verified")           # unverified sign-ins never reach an account
    return ident


def recent_verified_identity(verifier: FirebaseTokenVerifier | None, id_token: str) -> FirebaseIdentity:
    """A verified identity whose sign-in is at most LINK_MAX_AUTH_AGE_S old (sensitive operations)."""
    ident = _verified_identity(verifier, id_token)
    if verifier.now() - ident.auth_time > LINK_MAX_AUTH_AGE_S:
        raise IdentityError("reauthentication_required")
    return ident


def link_firebase_identity(store: Store, verifier: FirebaseTokenVerifier | None, install_token: str,
                           id_token: str) -> dict:
    """Explicitly link a verified website identity to the user who presents their own install token. Requires a
    sign-in from the last LINK_MAX_AUTH_AGE_S. Never matches by e-mail, never moves an existing link, never touches the
    install token. Returns the user row; raises IdentityError otherwise."""
    ident = _verified_identity(verifier, id_token)
    if verifier.now() - ident.auth_time > LINK_MAX_AUTH_AGE_S:
        raise IdentityError("reauthentication_required")
    user = find_user_by_install_token(store, install_token)    # None for unknown, malformed or disabled
    if not user:
        raise IdentityError("user_unavailable")
    result = store.link_identity(user["user_id"], ident.uid, "firebase", ident.email, ident.email_verified,
                                 ident.sign_in_provider)
    if result not in ("linked", "already_linked"):
        raise IdentityError(result)
    return user


def authenticate_firebase(store: Store, verifier: FirebaseTokenVerifier | None, id_token: str) -> dict:
    """The active user linked to this verified website identity. Read-only apart from last-seen details: no account is
    created for an unlinked identity, no account is found by e-mail, and no install token is issued or rotated."""
    ident = _verified_identity(verifier, id_token)
    link = store.identity_for_uid(ident.uid)
    if not link:
        raise IdentityError("not_linked")
    user = store.get_user(link["user_id"])
    if not user or user["disabled"] or user.get("status", "active") == "rejected":
        raise IdentityError("user_unavailable")
    if user.get("status", "active") != "active":
        raise IdentityError("pending_approval")             # only active accounts may sign in
    store.touch_identity(ident.uid, ident.email, ident.email_verified, ident.sign_in_provider)
    return user
