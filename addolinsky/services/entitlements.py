"""Who may see which translations and who may create new ones: plans, manual grants, creation ownership and credits.

Three independent dimensions (never inferred from each other):
- role (users.role): `owner` (the operator's own install link), `friend` (closed-beta invitation), `user` (account);
  administration is the admin token / admin session, never a role or a plan.
- plan: Free, or Premium derived only from provider-verified billing facts (`subscriptions`, written by
  billing/service.py) and the trusted server clock. A browser never sets a plan.
- grants: manual, audited entitlements with actor, reason, scope, period and revocation (`beta` for closed-beta
  invitations, `test_premium`/`manual` for operator tests). A grant is never a payment.

Access: every user may receive the translations they created (the creator of the job that produced the output) and
the open catalogue (translations that existed before plans, `open_catalogue_outputs`, D-141); `access_all`
(owner, Premium, or a grant with that scope) adds every other finished translation. Viewing never confers ownership
and never uses a creation credit. Creation: owner,
Premium, or a grant with `can_create`; always inside the global switches, funding and daily limits.

Credits: Premium = the plan's creations per allowance month (a monthly plan has one allowance month per paid
period, a yearly plan twelve; billing/plans.py); a test/manual grant = its own `credits_per_period` per
`period_days` anchored at the grant start; `beta` grants keep the beta quotas (services/quotas.py); the owner has no
per-user limit. A credit is reserved in the same transaction as the job and counts as used only while the job is
active or after it produced a NEW output: a failure, a cancellation or a reused (cached) output releases it
(settled lazily, so the engine is untouched).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from dataclasses import dataclass, field

from ..billing.plans import PLANS
from ..db import Store

PAST_DUE_GRACE_SECONDS = 0          # no grace beyond the verified paid-through time (policy; change only by decision)
GRANT_KINDS = ("beta", "test_premium", "manual")
PREMIUM_STATUSES = ("active", "past_due")      # provider states that keep access until the paid-through time
_ENDED_BY_DECISION = ("refunded", "disputed", "revoked")
_SECONDS_PER_DAY = 86400


class CreditsExhausted(Exception):
    def __init__(self, entitlements: Entitlements):
        super().__init__("creation credits exhausted")
        self.entitlements = entitlements


@dataclass(frozen=True)
class Entitlements:
    user_id: str
    role: str
    plan: str                       # free | premium | premium_canceling | expired | refunded | disputed | revoked
    paid_through: float | None
    cancel_at_period_end: bool
    subscription_id: str | None
    access_all: bool
    can_create: bool
    credit_source: str | None       # owner | premium | grant | beta | None
    credit_ref: str | None          # subscription id or grant id
    credits_limit: int | None       # None: no per-period credit limit (owner, beta quotas)
    period_start: float | None      # the current credit window (an allowance month for Premium)
    period_end: float | None
    grants: tuple = field(default_factory=tuple)

    @property
    def premium(self) -> bool:
        return self.plan in ("premium", "premium_canceling")


def _connection(store_or_connection: Store | sqlite3.Connection) -> sqlite3.Connection:
    return store_or_connection.conn if isinstance(store_or_connection, Store) else store_or_connection


def audit(connection: sqlite3.Connection, actor: str, action: str, user_id: str | None, **detail) -> None:
    connection.execute("INSERT INTO audit_log(ts,actor,action,user_id,detail) VALUES(?,?,?,?,?)",
                       (time.time(), actor[:80], action[:60], user_id,
                        json.dumps(detail, ensure_ascii=False, default=str)))


# ---------------------------------------------------------------- plan state
def subscription_plan(subscription: dict | None, now: float) -> str:
    """Commercial plan from the stored, provider-verified subscription facts."""
    if not subscription:
        return "free"
    status = subscription["status"]
    if status in _ENDED_BY_DECISION:
        return status
    paid_through = subscription["current_period_end"] or 0
    grace_seconds = PAST_DUE_GRACE_SECONDS if status == "past_due" else 0
    if subscription["verified_payment"] and now < paid_through + grace_seconds:
        if status in PREMIUM_STATUSES or status == "canceled":
            renewal_off = subscription["cancel_at_period_end"] or status == "canceled"
            return "premium_canceling" if renewal_off else "premium"
    return "expired"


def current_subscription(store_or_connection, user_id: str) -> dict | None:
    row = _connection(store_or_connection).execute(
        "SELECT * FROM subscriptions WHERE user_id=? ORDER BY COALESCE(current_period_end,0) DESC, updated_at DESC "
        "LIMIT 1", (user_id,)).fetchone()
    return dict(row) if row else None


def active_grants(connection, user_id: str, now: float) -> list[dict]:
    rows = connection.execute("SELECT * FROM grants WHERE user_id=? AND revoked_at IS NULL AND starts_at<=? AND "
                              "(ends_at IS NULL OR ends_at>?) ORDER BY created_at", (user_id, now, now)).fetchall()
    return [dict(row) for row in rows]


def grant_period(grant: dict, now: float) -> tuple[float, float]:
    period_seconds = max(1, int(grant["period_days"] or 30)) * _SECONDS_PER_DAY
    elapsed_periods = int((now - grant["starts_at"]) // period_seconds)
    period_start = grant["starts_at"] + elapsed_periods * period_seconds
    period_end = period_start + period_seconds
    if grant["ends_at"]:
        period_end = min(period_end, grant["ends_at"])
    return period_start, period_end


def _premium_credit_window(subscription: dict, now: float) -> tuple[int, float, float]:
    """(credits per window, window start, window end) for a Premium subscription. An unknown plan code grants no
    creation (fail closed) while access to existing translations is kept."""
    period_start, period_end = subscription["current_period_start"], subscription["current_period_end"]
    plan = PLANS.get(subscription["plan_code"])
    if plan is None:
        return 0, period_start, period_end
    window_start, window_end = plan.allowance_window(period_start, period_end, now)
    return plan.creations_per_month, window_start, window_end


def entitlements_for(store_or_connection, user_id: str, now: float | None = None) -> Entitlements | None:
    """Entitlements of an enabled, active user (None otherwise). Reads only server-side records."""
    now = time.time() if now is None else now
    connection = _connection(store_or_connection)
    user_row = connection.execute("SELECT role FROM users WHERE user_id=? AND disabled=0 AND status='active'",
                                  (user_id,)).fetchone()
    if not user_row:
        return None
    role = user_row[0]
    subscription = current_subscription(connection, user_id)
    plan = subscription_plan(subscription, now)
    grants = active_grants(connection, user_id, now)
    is_premium = plan in ("premium", "premium_canceling")
    credit_source = credit_ref = credits_limit = window_start = window_end = None
    if role == "owner":
        credit_source = "owner"
    elif is_premium:
        credit_source, credit_ref = "premium", subscription["subscription_id"]
        credits_limit, window_start, window_end = _premium_credit_window(subscription, now)
    else:
        credit_grant = next((grant for grant in grants
                             if grant["can_create"] and grant["credits_per_period"] is not None), None)
        beta_grant = next((grant for grant in grants if grant["can_create"] and grant["kind"] == "beta"
                           and grant["credits_per_period"] is None), None)
        if credit_grant:
            credit_source, credit_ref = "grant", credit_grant["grant_id"]
            credits_limit = int(credit_grant["credits_per_period"])
            window_start, window_end = grant_period(credit_grant, now)
        elif beta_grant:
            credit_source, credit_ref = "beta", beta_grant["grant_id"]
    renewal_off = bool(subscription and (subscription["cancel_at_period_end"] or subscription["status"] == "canceled"))
    return Entitlements(user_id=user_id, role=role, plan=plan,
                        paid_through=subscription["current_period_end"] if subscription else None,
                        cancel_at_period_end=renewal_off,
                        subscription_id=subscription["subscription_id"] if subscription else None,
                        access_all=role == "owner" or is_premium or any(grant["access_all"] for grant in grants),
                        can_create=credit_source is not None, credit_source=credit_source, credit_ref=credit_ref,
                        credits_limit=credits_limit, period_start=window_start, period_end=window_end,
                        grants=tuple(grants))


# ---------------------------------------------------------------- ownership and access
def output_creator(connection, output: dict) -> str | None:
    """The account that created the job which produced this output (None: unknown or no recorded creator)."""
    return job_creator(connection, output["job_id"])


def job_creator(connection, job_id: str) -> str | None:
    row = connection.execute("SELECT user_id FROM creations WHERE job_id=?", (job_id,)).fetchone()
    return row[0] if row else None


def is_in_open_catalogue(connection, output_id: str) -> bool:
    return connection.execute("SELECT 1 FROM open_catalogue_outputs WHERE output_id=?",
                              (output_id,)).fetchone() is not None


def can_access_output(connection, entitlements: Entitlements | None, output: dict) -> bool:
    """May this registered, active user receive this output? All outputs with `access_all`; otherwise their own
    creations and the open catalogue. Unidentified requests (no active user) receive nothing."""
    if entitlements is None:
        return False
    if entitlements.access_all or output_creator(connection, output) == entitlements.user_id:
        return True
    return is_in_open_catalogue(connection, output["output_id"])


def accessible_outputs(store: Store, entitlements: Entitlements | None, outputs: list[dict]) -> list[dict]:
    return [output for output in outputs if can_access_output(store.conn, entitlements, output)]


def owned_translations(store: Store, user_id: str) -> list[dict]:
    """Translations this account created, newest first (a job counts once it produced its own output)."""
    rows = store.conn.execute(
        "SELECT c.job_id, c.video_id, c.created_at, c.source, j.status, o.output_id, o.valid "
        "FROM creations c JOIN jobs j ON j.job_id=c.job_id LEFT JOIN outputs o ON o.output_id=j.output_id "
        "AND o.job_id=c.job_id WHERE c.user_id=? ORDER BY c.created_at DESC LIMIT 500", (user_id,))
    return [dict(row) for row in rows]


# ---------------------------------------------------------------- credits
def settle_credits(connection, *, job_id: str | None = None, user_id: str | None = None) -> None:
    """Finalize reserved credits whose job ended: consumed when it produced its own output, released when it failed,
    was cancelled or reused an existing output. Active jobs keep their reservation."""
    where_clause, arguments = ("cc.job_id=?", (job_id,)) if job_id else ("cc.user_id=?", (user_id,))
    rows = connection.execute(
        f"SELECT cc.credit_id, cc.job_id, j.status, o.job_id AS output_job_id FROM creation_credits cc "
        f"JOIN jobs j ON j.job_id=cc.job_id LEFT JOIN outputs o ON o.output_id=j.output_id "
        f"WHERE cc.status='reserved' AND {where_clause}", arguments).fetchall()
    now = time.time()
    for credit_id, credit_job_id, job_status, output_job_id in rows:
        if job_status == "READY":
            settled_status = "consumed" if output_job_id == credit_job_id else "released"   # reuse costs nothing
        elif job_status in ("FAILED", "CANCELLED"):
            settled_status = "released"
        else:
            continue
        connection.execute("UPDATE creation_credits SET status=?, settled_at=? WHERE credit_id=?",
                           (settled_status, now, credit_id))


def credits_used(connection, entitlements: Entitlements) -> int:
    if entitlements.credits_limit is None:
        return 0
    settle_credits(connection, user_id=entitlements.user_id)
    return connection.execute(
        "SELECT COUNT(*) FROM creation_credits WHERE source=? AND source_ref=? AND period_start=? "
        "AND status IN ('reserved','consumed')",
        (entitlements.credit_source, entitlements.credit_ref, entitlements.period_start)).fetchone()[0]


def credit_summary(store: Store, entitlements: Entitlements) -> dict:
    with store.tx() as connection:
        used = credits_used(connection, entitlements)
    limit = entitlements.credits_limit
    return {"source": entitlements.credit_source, "limit": limit, "used": used,
            "remaining": None if limit is None else max(0, limit - used),
            "period_start": entitlements.period_start, "period_end": entitlements.period_end}


def reserve_credit(connection, entitlements: Entitlements, job_id: str, attempt: int = 0) -> None:
    """Inside the job's transaction: record the creator (first attempt) and reserve one credit for this attempt.
    Raises CreditsExhausted (rolling the whole transaction back) when the window's credits are used up."""
    now = time.time()
    if entitlements.credits_limit is not None and credits_used(connection, entitlements) >= entitlements.credits_limit:
        raise CreditsExhausted(entitlements)
    if attempt == 0:
        video_id = connection.execute("SELECT video_id FROM jobs WHERE job_id=?", (job_id,)).fetchone()[0]
        connection.execute("INSERT INTO creations(job_id,user_id,video_id,source,created_at) VALUES(?,?,?,'live',?)",
                           (job_id, entitlements.user_id, video_id, now))
    connection.execute(
        "INSERT INTO creation_credits(credit_id,idempotency_key,user_id,job_id,source,source_ref,period_start,"
        "period_end,status,created_at) VALUES(?,?,?,?,?,?,?,?,'reserved',?)",
        ("c" + secrets.token_hex(8), f"{job_id}:{attempt}", entitlements.user_id, job_id, entitlements.credit_source,
         entitlements.credit_ref or entitlements.credit_source, entitlements.period_start or 0,
         entitlements.period_end or 0, now))


# ---------------------------------------------------------------- grants (operator actions, audited)
def create_grant(store: Store, *, user_id: str, kind: str, actor: str, reason: str, days: float | None,
                 access_all: bool = True, can_create: bool = True, credits_per_period: int | None = None,
                 period_days: int | None = None) -> str:
    if kind not in GRANT_KINDS:
        raise ValueError(f"unknown grant kind {kind!r}")
    if not reason.strip() or not actor.strip():
        raise ValueError("a grant needs an actor and a reason")
    if kind != "beta" and can_create and credits_per_period is None:
        raise ValueError("a creation grant other than beta needs credits per period (no unlimited creation)")
    if kind != "beta" and days is None:
        raise ValueError("test and manual grants need an expiry")
    now = time.time()
    grant_id = "g" + secrets.token_hex(6)
    with store.tx() as connection:
        if not connection.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,)).fetchone():
            raise ValueError("unknown user")
        connection.execute(
            "INSERT INTO grants(grant_id,user_id,kind,access_all,can_create,credits_per_period,period_days,"
            "starts_at,ends_at,reason,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (grant_id, user_id, kind, int(access_all), int(can_create), credits_per_period,
             period_days or (30 if credits_per_period is not None else None), now,
             now + days * _SECONDS_PER_DAY if days is not None else None, reason[:300], actor[:80], now))
        audit(connection, actor, "grant_created", user_id, grant_id=grant_id, kind=kind, access_all=access_all,
              can_create=can_create, credits_per_period=credits_per_period, days=days, reason=reason[:300])
    return grant_id


def revoke_grant(store: Store, grant_id: str, *, actor: str, reason: str) -> bool:
    if not reason.strip():
        raise ValueError("a revocation needs a reason")
    with store.tx() as connection:
        row = connection.execute("SELECT user_id FROM grants WHERE grant_id=? AND revoked_at IS NULL",
                                 (grant_id,)).fetchone()
        if not row:
            return False
        connection.execute("UPDATE grants SET revoked_at=?, revoked_by=?, revoke_reason=? WHERE grant_id=?",
                           (time.time(), actor[:80], reason[:300], grant_id))
        audit(connection, actor, "grant_revoked", row[0], grant_id=grant_id, reason=reason[:300])
    return True


# ---------------------------------------------------------------- reports
def ownership_review(store: Store) -> list[dict]:
    """Cloud jobs without a recorded creator (provenance unknown): for human review, never auto-assigned."""
    return [dict(row) for row in store.conn.execute(
        "SELECT j.job_id, j.video_id, j.status, j.output_id, j.created_at FROM jobs j LEFT JOIN creations c "
        "ON c.job_id=j.job_id WHERE j.provider='cloud' AND c.job_id IS NULL ORDER BY j.created_at")]


def _rows_as_dicts(connection, sql: str, *arguments) -> list[dict]:
    return [dict(row) for row in connection.execute(sql, arguments)]


def account_report(store: Store, user_id: str, now: float | None = None) -> dict | None:
    user = store.get_user(user_id)
    if not user:
        return None
    entitlements = entitlements_for(store, user_id, now)
    connection = store.conn
    return {"user": {key: user[key] for key in ("user_id", "role", "label", "origin", "created_at", "disabled",
                                                "status")},
            "entitlements": None if entitlements is None else {**entitlements.__dict__,
                                                               "grants": list(entitlements.grants)},
            "credits": credit_summary(store, entitlements) if entitlements else None,
            "identity": store.identity_for_user(user_id),
            "grants": _rows_as_dicts(connection, "SELECT * FROM grants WHERE user_id=? ORDER BY created_at", user_id),
            "subscriptions": _rows_as_dicts(connection, "SELECT * FROM subscriptions WHERE user_id=?", user_id),
            "payments": _rows_as_dicts(connection, "SELECT p.* FROM payments p JOIN subscriptions s ON "
                                       "s.subscription_id=p.subscription_id WHERE s.user_id=? ORDER BY p.occurred_at",
                                       user_id),
            "creations": owned_translations(store, user_id),
            "credit_rows": _rows_as_dicts(connection, "SELECT * FROM creation_credits WHERE user_id=? "
                                          "ORDER BY created_at", user_id),
            "audit": _rows_as_dicts(connection, "SELECT ts, actor, action, detail FROM audit_log WHERE user_id=? "
                                    "ORDER BY id", user_id)}


def plan_metrics(store: Store, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    accounts_by_plan: dict[str, int] = {}
    for (user_id,) in store.conn.execute("SELECT user_id FROM users WHERE disabled=0 AND status='active'"):
        entitlements = entitlements_for(store, user_id, now)
        key = entitlements.role if entitlements.role == "owner" else entitlements.plan
        accounts_by_plan[key] = accounts_by_plan.get(key, 0) + 1

    def counts(sql: str, *arguments) -> dict:
        return dict(store.conn.execute(sql, arguments).fetchall())

    return {"accounts_by_plan": accounts_by_plan,
            "subscriptions_by_plan": counts("SELECT plan_code, COUNT(*) FROM subscriptions WHERE status IN "
                                            "('active','past_due') AND current_period_end>? GROUP BY plan_code", now),
            "active_grants_by_kind": counts("SELECT kind, COUNT(*) FROM grants WHERE revoked_at IS NULL AND "
                                            "(ends_at IS NULL OR ends_at>?) GROUP BY kind", now),
            "credits_last_30_days": counts("SELECT status, COUNT(*) FROM creation_credits WHERE created_at>? "
                                           "GROUP BY status", now - 30 * _SECONDS_PER_DAY),
            "billing_events_by_status": counts("SELECT status, COUNT(*) FROM billing_events GROUP BY status"),
            "payments_by_status": counts("SELECT status, COUNT(*) FROM payments GROUP BY status"),
            "open_catalogue_outputs": store.conn.execute("SELECT COUNT(*) FROM open_catalogue_outputs").fetchone()[0],
            "creations_unknown_provenance": len(ownership_review(store))}
