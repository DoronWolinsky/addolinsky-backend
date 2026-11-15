"""Website accounts: registration of a verified Firebase identity, invitation codes, versioned consent, install-link
rotation and the account dashboard.

- A Firebase uid maps to exactly one internal user id (immutable; never derived from or matched by e-mail).
- Registration needs a verified e-mail, a sign-in from the last LINK_MAX_AUTH_AGE_S, and either open registration
  (`account_signup` AND approved current Terms and Privacy, which the user must accept) or a single-use invitation code
  from the operator (closed beta). Draft documents are never recorded as accepted.
- The new account is created atomically: user (role `user`, plan Free), identity link, consent rows, invitation use and
  audit entry. Its install token is returned once; only the SHA-256 is stored.
- Rotating the install link replaces the hash in one transaction (the old link stops at once). The owner's link
  follows data/addon_key and is rotated only with the CLI.
"""

from __future__ import annotations

import hashlib
import secrets
import time

from ..billing.plans import PLANS, public_plan_offers
from ..db import Store
from ..legal import KINDS, get_document, is_approved, rendered_hash
from ..security.auth import hash_install_token
from .entitlements import audit, credit_summary, current_subscription, entitlements_for, owned_translations

INVITE_CODE_BYTES = 12


class AccountError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def documents_approved(settings) -> bool:
    """True only when the owner approved the current rendered Terms and Privacy texts (never for drafts)."""
    return all(get_document(kind) is not None and is_approved(get_document(kind), settings) for kind in KINDS)


def registration_state(settings) -> dict:
    """What registration needs right now (shown to an unlinked, verified visitor)."""
    approved = documents_approved(settings)
    return {"open": bool(settings.account_signup and approved), "invite_accepted": True,
            "terms_required": approved,
            "documents": {kind: {"version": get_document(kind).version,
                                 "status": "approved" if is_approved(get_document(kind), settings) else "draft"}
                          for kind in KINDS}}


# ---------------------------------------------------------------- invitations (operator, CLI)
def create_invite(store: Store, *, note: str, days: float, actor: str) -> str:
    code = secrets.token_urlsafe(INVITE_CODE_BYTES)
    now = time.time()
    with store.tx() as transaction:
        transaction.execute(
            "INSERT INTO account_invites(code_sha256,note,actor,created_at,expires_at) VALUES(?,?,?,?,?)",
            (hashlib.sha256(code.encode()).hexdigest(), note[:120], actor[:80], now, now + days * 86400))
        audit(transaction, actor, "account_invite_created", None, note=note[:120], days=days)
    return code


# ---------------------------------------------------------------- registration
def register_account(store: Store, settings, *, uid: str, email: str | None, sign_in_provider: str | None,
                     invite_code: str, accept_terms: bool, network_key: str) -> tuple[str, str]:
    """Create a Free account for a verified identity. Returns (user_id, install token). Raises AccountError."""
    approved = documents_approved(settings)
    code_hash = hashlib.sha256(invite_code.encode()).hexdigest() if invite_code else ""
    if not code_hash and not (settings.account_signup and approved):
        raise AccountError("registration_closed")
    if approved and not accept_terms:
        raise AccountError("terms_required")
    now = time.time()
    user_id, install_token = "u" + secrets.token_hex(6), secrets.token_urlsafe(24)
    with store.tx() as transaction:
        if transaction.execute("SELECT 1 FROM identities WHERE uid=?", (uid,)).fetchone():
            raise AccountError("already_registered")
        invite = None
        if code_hash:
            invite = transaction.execute("SELECT * FROM account_invites WHERE code_sha256=? AND used_at IS NULL "
                                         "AND expires_at>?", (code_hash, now)).fetchone()
            if invite is None:
                raise AccountError("invalid_invite")
        registrations_today = transaction.execute("SELECT COUNT(*) FROM users WHERE created_at>=? AND origin=?",
                                                  (now - 86400, network_key)).fetchone()[0]
        if registrations_today >= settings.signups_per_ip_day:
            raise AccountError("too_many_registrations")
        if invite is None:      # open registration: a global daily ceiling against automated sign-ups
            open_registrations_today = transaction.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action='account_registered' AND ts>=? AND "
                "json_extract(detail,'$.via')='open'", (now - 86400,)).fetchone()[0]
            if open_registrations_today >= settings.max_account_registrations_per_day:
                raise AccountError("registrations_paused")
        transaction.execute("INSERT INTO users(user_id,token_sha256,role,created_at,origin,label) "
                            "VALUES(?,?,'user',?,?,?)",
                            (user_id, hash_install_token(install_token), now, network_key, "account"))
        transaction.execute("INSERT INTO identities(uid,user_id,provider,email,email_verified,sign_in_provider,"
                            "linked_at,last_seen_at) VALUES(?,?,'firebase',?,1,?,?,?)",
                            (uid, user_id, (email or "")[:254], (sign_in_provider or "")[:40], now, now))
        if approved:
            for kind in KINDS:
                document = get_document(kind)
                transaction.execute("INSERT INTO consents(user_id,kind,version,text_sha256,created_at) "
                                    "VALUES(?,?,?,?,?)",
                                    (user_id, kind, document.version, rendered_hash(document, settings), now))
        if invite is not None:
            used_count = transaction.execute("UPDATE account_invites SET used_at=?, used_by=? WHERE code_sha256=? "
                                             "AND used_at IS NULL", (now, user_id, code_hash)).rowcount
            if used_count != 1:
                raise AccountError("invalid_invite")
        audit(transaction, f"firebase:{uid}", "account_registered", user_id,
              via="invite" if invite is not None else "open", consent_recorded=approved,
              sign_in_provider=sign_in_provider)
    return user_id, install_token


def rotate_install_token(store: Store, user_id: str, actor: str) -> str:
    """Replace a user's install token (the old link stops working at once). Returns the new token once."""
    install_token = secrets.token_urlsafe(24)
    with store.tx() as transaction:
        row = transaction.execute("SELECT role FROM users WHERE user_id=? AND disabled=0 AND status='active'",
                                  (user_id,)).fetchone()
        if not row:
            raise AccountError("user_unavailable")
        if row[0] == "owner":
            raise AccountError("owner_link_uses_cli")
        transaction.execute("UPDATE users SET token_sha256=? WHERE user_id=?",
                            (hash_install_token(install_token), user_id))
        audit(transaction, actor, "install_link_rotated", user_id)
    return install_token


# ---------------------------------------------------------------- dashboard
def dashboard(store: Store, settings, user: dict, provider) -> dict:
    """Everything the signed-in account page shows. Contains no install token and no other user's data."""
    now = time.time()
    entitlements = entitlements_for(store, user["user_id"], now)
    subscription = current_subscription(store, user["user_id"])
    identity = store.identity_for_user(user["user_id"]) or {}
    creations = []
    for row in owned_translations(store, user["user_id"])[:100]:
        creations.append({"video_id": row["video_id"], "created_at": row["created_at"], "status": row["status"],
                          "available": bool(row["output_id"] and row["valid"])})
    premium = bool(entitlements and entitlements.premium)
    renewal_off = bool(entitlements and entitlements.cancel_at_period_end)
    checkout_available = bool(provider is not None and settings.checkout_enabled and not premium)
    managed_by_provider = bool(premium and subscription and provider is not None
                               and subscription["provider"] == provider.name)
    capabilities = provider.capabilities if managed_by_provider else None
    return {
        "account": {"user_id": user["user_id"], "role": user["role"], "created_at": user["created_at"],
                    "email": identity.get("email"), "sign_in_provider": identity.get("sign_in_provider"),
                    "linked_at": identity.get("linked_at")},
        "plan": {"state": entitlements.plan if entitlements else "unavailable", "premium": premium,
                 "paid_through": entitlements.paid_through if entitlements else None,
                 "renews": premium and not renewal_off, "cancel_at_period_end": renewal_off,
                 "access_all": bool(entitlements and entitlements.access_all),
                 "can_create": bool(entitlements and entitlements.can_create)},
        "credits": credit_summary(store, entitlements) if entitlements else None,
        "grants": [{"kind": grant["kind"], "ends_at": grant["ends_at"], "access_all": bool(grant["access_all"]),
                    "can_create": bool(grant["can_create"]), "credits_per_period": grant["credits_per_period"]}
                   for grant in (entitlements.grants if entitlements else ())],
        "billing": {"provider_connected": provider is not None,
                    "checkout_available": checkout_available,
                    "plans": public_plan_offers() if checkout_available else [],
                    "current_plan": (subscription["plan_code"] if premium and subscription["plan_code"] in PLANS
                                     else None),
                    "can_cancel": bool(capabilities and not renewal_off and capabilities.cancel_at_period_end),
                    "can_resume": bool(capabilities and renewal_off and capabilities.reactivate)},
        "translations": creations,
        "install_link": {"rotatable": user["role"] != "owner"},
        "now": now,
    }
