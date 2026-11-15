"""Website account routes (D-133, D-139): sign-in page, registration, linking an existing install link, the account
dashboard, install-link rotation, renewal changes, and the billing webhook.

Everything under /account is off (404) unless the Firebase verifier exists (`ADDOLINSKY_FIREBASE_AUTH` + project id)
and the public web configuration is set. Identity checks reuse security/identity.py: every call carries a fresh
Firebase ID token in its JSON body, verified server-side (signature, issuer, audience, expiry), with a verified
e-mail; identities are keyed by Firebase uid only, never by e-mail.

- No backend session or cookie, so no CSRF surface; same-origin only (foreign Origin rejected), no CORS headers,
  no-store and no-referrer on every response, and per-IP limits on top of the global public rate limit.
- Secrets never travel in URLs: install links and ID tokens are POST body fields, never logged or echoed (validation
  errors return a fixed code). A new install link is returned once, in a no-store response.
- Sensitive operations (registration, linking, link rotation, renewal changes) need a sign-in from the last
  10 minutes. Plans are never taken from the browser: the dashboard reports server-side records only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from html import escape

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .billing.provider import WebhookRejected
from .billing.service import BillingUnavailable, change_renewal, ingest_event, start_checkout
from .config import Settings
from .security.identity import (
    LINK_MAX_AUTH_AGE_S,
    IdentityError,
    authenticate_firebase,
    link_firebase_identity,
    recent_verified_identity,
)
from .security.middleware import RequestRateLimiter, get_client_ip_address, is_cross_origin_request
from .services.accounts import (
    AccountError,
    dashboard,
    register_account,
    registration_state,
    rotate_install_token,
)

FIREBASE_SDK = "https://www.gstatic.com/firebasejs/10.12.2"      # pinned official Firebase JS SDK (ES modules)
INSTALL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
LINK_ATTEMPTS_PER_IP_MIN = 10
SENSITIVE_ATTEMPTS_PER_IP_MIN = 10
WEBHOOK_MAX_BYTES = 64 * 1024
WEBHOOK_REQUESTS_PER_IP_MIN = 120
webhook_logger = logging.getLogger(__name__ + ".billing_webhook")
NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}

# Refusal code -> HTTP status. Codes are safe to show; they never contain a token.
STATUS = {"disabled": 404, "malformed_token": 401, "bad_algorithm_or_key_id": 401, "unknown_key": 401,
          "wrong_audience": 401, "wrong_issuer": 401, "invalid_token": 401, "expired": 401, "issued_in_future": 401,
          "invalid_subject": 401, "reauthentication_required": 401, "email_not_verified": 403,
          "user_unavailable": 403, "pending_approval": 403, "confirmation_required": 400, "invalid_install_link": 400,
          "uid_linked_elsewhere": 409, "user_has_other_identity": 409, "too_many_attempts": 429,
          "not_linked": 403, "already_registered": 409, "registration_closed": 403, "invalid_invite": 403,
          "terms_required": 400, "too_many_registrations": 429, "registrations_paused": 429, "owner_link_uses_cli": 403,
          "billing_unavailable": 404}


class StatusIn(BaseModel):
    id_token: str = Field(max_length=4096)


class LinkIn(BaseModel):
    id_token: str = Field(max_length=4096)
    install_link: str = Field(max_length=300)
    confirm: bool = False


class RegisterIn(BaseModel):
    id_token: str = Field(max_length=4096)
    invite_code: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9_-]*$")
    accept_terms: bool = False


class ConfirmIn(BaseModel):
    id_token: str = Field(max_length=4096)
    confirm: bool = False


class CheckoutIn(BaseModel):
    id_token: str = Field(max_length=4096)
    plan: str = Field(max_length=40, pattern=r"^[a-z_]+$")       # a code from billing/plans.py, checked there


def install_token_from_link(text: str) -> str | None:
    """The token from a personal install link (https://, stremio:// or the bare token); None if it has no such
    shape. Validity is decided only by the existing token lookup."""
    text = (text or "").strip()
    link_match = re.search(r"/([A-Za-z0-9_-]{16,64})/manifest\.json$", text)
    token = link_match.group(1) if link_match else text
    return token if INSTALL_TOKEN_RE.fullmatch(token) else None


def account_page_csp(auth_domain: str) -> str:
    return ("default-src 'none'; script-src 'self' https://www.gstatic.com https://apis.google.com; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com; "
            f"frame-src https://{auth_domain}; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")


def web_config(settings: Settings) -> dict | None:
    """Public Firebase web configuration (the web API key is a public identifier, not a secret), or None."""
    if not (settings.firebase_web_api_key and settings.firebase_project_id):
        return None
    return {"apiKey": settings.firebase_web_api_key, "projectId": settings.firebase_project_id,
            "authDomain": settings.firebase_auth_domain or f"{settings.firebase_project_id}.firebaseapp.com"}


def register_account_routes(app: FastAPI, *, db, settings: Settings, allowed_hosts: set[str], public_mode: bool,
                            rate_limiter: RequestRateLimiter, static_dir, base_url) -> None:
    def verifier_or_404(request: Request):
        verifier = request.app.state.firebase_verifier
        if verifier is None or web_config(settings) is None:
            raise HTTPException(404, "not found")
        return verifier

    def same_origin(request: Request) -> None:
        if is_cross_origin_request(request, allowed_hosts):
            raise HTTPException(403, "cross-origin request rejected")

    def refused(code: str) -> JSONResponse:
        return JSONResponse({"error": code}, status_code=STATUS.get(code, 400), headers=NO_STORE)

    def ok(data: dict) -> JSONResponse:
        return JSONResponse(data, headers=NO_STORE)

    def limited(request: Request, bucket: str, per_minute: int) -> bool:
        return not rate_limiter.check_and_record_request(
            f"{bucket}:" + get_client_ip_address(request, public_mode), per_minute)

    def install_link(request: Request, token: str) -> str:
        return f"{base_url(request)}/{token}/manifest.json"

    prior_validation_handler = app.exception_handlers.get(RequestValidationError)

    async def validation_error(request: Request, exc: RequestValidationError):
        if request.url.path.startswith(("/account/", "/billing/")):     # never echo submitted tokens back
            return refused("malformed_request")
        if prior_validation_handler:
            return await prior_validation_handler(request, exc)
        from fastapi.exception_handlers import request_validation_exception_handler
        return await request_validation_exception_handler(request, exc)

    app.add_exception_handler(RequestValidationError, validation_error)

    @app.get("/account", response_class=HTMLResponse)
    def account_page(request: Request):
        verifier_or_404(request)
        firebase_config = web_config(settings)
        # The JSON block is data, not script; "<" is escaped so it can never close the element.
        page_config = json.dumps({"firebase": firebase_config, "sdk": FIREBASE_SDK,
                                  "linkMaxAgeS": LINK_MAX_AUTH_AGE_S}).replace("<", "\\u003c")
        html = (static_dir / "account.html").read_text(encoding="utf-8").replace("{{CONFIG}}", page_config)
        return HTMLResponse(html, headers={**NO_STORE, "Content-Security-Policy": account_page_csp(
            escape(firebase_config["authDomain"]))})

    @app.get("/account/account.js")
    def account_script(request: Request):
        verifier_or_404(request)
        return Response((static_dir / "account.js").read_text(encoding="utf-8"), media_type="text/javascript",
                        headers=NO_STORE)

    @app.post("/account/status")
    def account_status(request: Request, body: StatusIn):
        """Is this verified identity linked? Read-only: creates nothing, issues or rotates nothing."""
        same_origin(request)
        verifier = verifier_or_404(request)
        try:
            user = authenticate_firebase(db(), verifier, body.id_token)
        except IdentityError as error:
            if error.code == "not_linked":
                return ok({"linked": False, "registration": registration_state(settings)})
            return refused(error.code)
        ident = db().identity_for_user(user["user_id"])
        return ok({"linked": True, "role": user["role"], "linked_at": ident["linked_at"],
                   "sign_in_provider": ident["sign_in_provider"]})

    @app.post("/account/link")
    def account_link(request: Request, body: LinkIn):
        """Explicitly link the signed-in identity to the account that owns this install link (D-133)."""
        same_origin(request)
        verifier = verifier_or_404(request)
        if limited(request, "account-link", LINK_ATTEMPTS_PER_IP_MIN):
            return refused("too_many_attempts")
        if body.confirm is not True:
            return refused("confirmation_required")
        token = install_token_from_link(body.install_link)
        if token is None:
            return refused("invalid_install_link")
        try:
            user = link_firebase_identity(db(), verifier, token, body.id_token)
        except IdentityError as error:
            return refused(error.code)
        return ok({"linked": True, "role": user["role"]})

    @app.post("/account/register")
    def account_register(request: Request, body: RegisterIn):
        """Create a Free account for a verified, recently signed-in identity (open registration with approved
        Terms, or an operator invitation code). Returns the personal install link once."""
        same_origin(request)
        verifier = verifier_or_404(request)
        if limited(request, "account-sensitive", SENSITIVE_ATTEMPTS_PER_IP_MIN):
            return refused("too_many_attempts")
        try:
            ident = recent_verified_identity(verifier, body.id_token)
            network_key = hashlib.sha256(request.app.state.context.server_secret +
                                         get_client_ip_address(request, public_mode).encode()).hexdigest()[:32]
            _, token = register_account(db(), settings, uid=ident.uid, email=ident.email,
                                        sign_in_provider=ident.sign_in_provider, invite_code=body.invite_code,
                                        accept_terms=body.accept_terms, network_key=network_key)
        except (IdentityError, AccountError) as error:
            return refused(error.code)
        return ok({"registered": True, "install_link": install_link(request, token)})

    @app.post("/account/dashboard")
    def account_dashboard(request: Request, body: StatusIn):
        """The signed-in account's own profile, plan, credits, grants and translations (server records only)."""
        same_origin(request)
        verifier = verifier_or_404(request)
        try:
            user = authenticate_firebase(db(), verifier, body.id_token)
        except IdentityError as error:
            return refused(error.code)
        return ok(dashboard(db(), settings, user, request.app.state.billing_provider))

    def sensitive_user(request: Request, id_token: str) -> dict:
        """The active linked user of a recent sign-in, or raises IdentityError."""
        verifier = verifier_or_404(request)
        recent_verified_identity(verifier, id_token)
        return authenticate_firebase(db(), verifier, id_token)

    @app.post("/account/install-link/rotate")
    def account_rotate_link(request: Request, body: ConfirmIn):
        """Issue a new install link (shown once) and stop the old one immediately."""
        same_origin(request)
        if limited(request, "account-sensitive", SENSITIVE_ATTEMPTS_PER_IP_MIN):
            return refused("too_many_attempts")
        if body.confirm is not True:
            return refused("confirmation_required")
        try:
            user = sensitive_user(request, body.id_token)
            token = rotate_install_token(db(), user["user_id"], actor=f"user:{user['user_id']}")
        except (IdentityError, AccountError) as error:
            return refused(error.code)
        return ok({"install_link": install_link(request, token)})

    @app.post("/account/checkout")
    def account_checkout(request: Request, body: CheckoutIn):
        """The provider's hosted payment page; Premium starts only after a verified payment event."""
        same_origin(request)
        if limited(request, "account-sensitive", SENSITIVE_ATTEMPTS_PER_IP_MIN):
            return refused("too_many_attempts")
        try:
            user = sensitive_user(request, body.id_token)
            url = start_checkout(db(), request.app.state.billing_provider, settings, user["user_id"], body.plan,
                                 return_url=f"{base_url(request)}/account?checkout=returned")
        except IdentityError as error:
            return refused(error.code)
        except BillingUnavailable:
            return refused("billing_unavailable")
        return ok({"redirect_url": url})

    @app.post("/account/subscription/{action}")
    def account_renewal(request: Request, action: str, body: ConfirmIn):
        """Turn renewal off (Premium continues until the paid-through time) or back on."""
        same_origin(request)
        if action not in ("cancel", "resume"):
            raise HTTPException(404, "not found")
        if limited(request, "account-sensitive", SENSITIVE_ATTEMPTS_PER_IP_MIN):
            return refused("too_many_attempts")
        if body.confirm is not True:
            return refused("confirmation_required")
        try:
            user = sensitive_user(request, body.id_token)
            change_renewal(db(), request.app.state.billing_provider, user["user_id"], cancel=action == "cancel")
        except IdentityError as error:
            return refused(error.code)
        except BillingUnavailable:
            return refused("billing_unavailable")
        return ok(dashboard(db(), settings, user, request.app.state.billing_provider))

    @app.post("/billing/webhook/{provider_name}")
    async def billing_webhook(request: Request, provider_name: str):
        """Provider-authenticated events (server to server). 404 unless billing is on for exactly this provider."""
        provider = request.app.state.billing_provider
        if provider is None or provider_name != provider.name:
            raise HTTPException(404, "not found")
        if limited(request, "billing-webhook", WEBHOOK_REQUESTS_PER_IP_MIN):
            raise HTTPException(429, "too many requests")
        body = await _read_body_limited(request, WEBHOOK_MAX_BYTES)
        try:
            events = provider.verify_webhook(dict(request.headers), body)
        except WebhookRejected as rejection:
            webhook_logger.warning("billing webhook rejected (%s): %s", provider.name, rejection)
            raise HTTPException(400, "rejected") from None
        # SQLite work runs in the thread pool, never on the event loop
        results = await run_in_threadpool(lambda: [ingest_event(db(), provider.name, event) for event in events])
        return JSONResponse({"received": len(results), "results": results}, headers=NO_STORE)


async def _read_body_limited(request: Request, max_bytes: int) -> bytes:
    """The request body, refused with 413 as soon as it (or its declared length) exceeds max_bytes."""
    declared_length = request.headers.get("content-length", "")
    if declared_length.isdigit() and int(declared_length) > max_bytes:
        raise HTTPException(413, "too large")
    received = bytearray()
    async for chunk in request.stream():
        received += chunk
        if len(received) > max_bytes:
            raise HTTPException(413, "too large")
    return bytes(received)
