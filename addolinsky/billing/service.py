"""Apply provider-verified billing events to subscriptions, start checkouts and change renewal.

Rules:
- Only authenticated webhook events change entitlements (the adapter verifies them); a checkout redirect never does.
- Each event is stored once per (provider, provider event id) before it is applied: duplicates are ignored, and the
  stored normalized event can be replayed (`replay_pending`) when it arrived before the subscription it refers to.
- Ordering: status changes apply only when the event is not older than the last applied status change; a payment
  extends the paid-through time only forward. Refunds and chargebacks are facts and always recorded, and a later
  event never turns a refunded or charged-back payment back into a successful one.
- A payment grants Premium only when its amount and currency equal the plan's price and its period is no longer than
  the plan's interval. A first payment must match an open, unexpired checkout of a user without an active
  subscription; anything else is recorded as `needs_review` (money received, nothing granted) for the operator.
- A chargeback suspends Premium ("disputed") until an administrator decides; a full refund of the current period
  ends it at the refund time; a later successful payment can start a new period after a refund.
- Card data never reaches this service (hosted checkout only)."""

from __future__ import annotations

import dataclasses
import json
import logging
import secrets
import sqlite3
import time

from ..config import Settings
from ..db import Store
from ..services.entitlements import audit, current_subscription, subscription_plan
from .mock import MockProvider
from .plans import PLANS, Plan
from .provider import BillingProvider, EventType, ProviderEvent

logger = logging.getLogger(__name__)

CHECKOUT_LIFETIME_SECONDS = 2 * 86400     # a payment for an older checkout is held for review
_FUTURE_PERIOD_TOLERANCE_SECONDS = 86400  # a paid period may start at most this long after the event
_SUSPENDED_UNTIL_ADMIN = ("disputed", "revoked")
_FINAL_PAYMENT_STATUSES = ("refunded", "chargeback")
_PREMIUM_PLANS = ("premium", "premium_canceling")
_SUBSCRIPTION_COLUMNS = frozenset({"status", "verified_payment", "current_period_start", "current_period_end",
                                   "cancel_at_period_end", "status_event_at", "updated_at"})


class BillingUnavailable(Exception):
    """Billing, checkout or the requested operation is not enabled or not supported."""


def build_provider(settings: Settings) -> BillingProvider | None:
    """The configured provider adapter, or None while billing is off. No live adapter exists yet: a provider name
    other than the offline mock yields None (fail closed)."""
    if not settings.billing_enabled or not settings.billing_provider:
        return None
    if settings.billing_provider == "mock":
        return MockProvider(settings.billing_webhook_secret or "")
    return None


# ---------------------------------------------------------------- webhook ingestion
def ingest_event(store: Store, provider_name: str, event: ProviderEvent) -> str:
    """Store and apply one verified event. Returns processed | duplicate | ignored | unmatched | rejected | failed."""
    payload = json.dumps(_event_as_dict(event), sort_keys=True)
    with store.tx() as transaction:
        try:
            transaction.execute(
                "INSERT INTO billing_events(event_id,provider,provider_event_id,type,occurred_at,payload,received_at,"
                "status) VALUES(?,?,?,?,?,?,?,'received')",
                ("e" + secrets.token_hex(8), provider_name, event.provider_event_id, event.type.value,
                 event.occurred_at, payload, time.time()))
        except sqlite3.IntegrityError:
            logger.info("billing event %s/%s: duplicate", provider_name, event.provider_event_id)
            return "duplicate"
        status, note = _apply_in_savepoint(transaction, provider_name, event)
        _set_event_status(transaction, provider_name, event.provider_event_id, status, note)
    logger.info("billing event %s/%s (%s): %s %s", provider_name, event.provider_event_id, event.type.value, status,
                note)
    if status == "processed":
        replay_pending(store, provider_name)
    return status


def _event_as_dict(event: ProviderEvent) -> dict:
    return {key: (value.value if isinstance(value, EventType) else value)
            for key, value in dataclasses.asdict(event).items()}


def _set_event_status(transaction, provider_name: str, provider_event_id: str, status: str, note: str) -> None:
    transaction.execute("UPDATE billing_events SET status=?, note=? WHERE provider=? AND provider_event_id=?",
                        (status, note, provider_name, provider_event_id))


def _apply_in_savepoint(transaction, provider_name: str, event: ProviderEvent) -> tuple[str, str]:
    """Apply an event completely or not at all; an unexpected error is recorded as `failed` (replayable)."""
    transaction.execute("SAVEPOINT apply_event")
    try:
        result = _apply_event(transaction, provider_name, event)
    except Exception as error:
        logger.exception("billing event %s/%s failed", provider_name, event.provider_event_id)
        transaction.execute("ROLLBACK TO apply_event")
        transaction.execute("RELEASE apply_event")
        return "failed", type(error).__name__
    transaction.execute("RELEASE apply_event")
    return result


def replay_pending(store: Store, provider_name: str) -> int:
    """Re-apply stored events that could not be matched or failed, oldest first. Returns how many now applied."""
    applied_count = 0
    pending_rows = store.conn.execute(
        "SELECT provider_event_id, payload FROM billing_events WHERE provider=? AND status IN ('unmatched','failed') "
        "ORDER BY occurred_at", (provider_name,)).fetchall()
    for provider_event_id, payload in pending_rows:
        stored_fields = json.loads(payload)
        event = ProviderEvent(**{**stored_fields, "type": EventType(stored_fields["type"])})
        with store.tx() as transaction:
            status, note = _apply_in_savepoint(transaction, provider_name, event)
            if status in ("unmatched", "failed"):
                continue        # unchanged; the transaction writes nothing new
            _set_event_status(transaction, provider_name, provider_event_id, status, note)
            applied_count += 1
        logger.info("billing event %s/%s replayed: %s %s", provider_name, provider_event_id, status, note)
    return applied_count


def _find_subscription(transaction, provider_name: str, provider_subscription_id: str) -> dict | None:
    row = transaction.execute("SELECT * FROM subscriptions WHERE provider=? AND provider_subscription_id=?",
                              (provider_name, provider_subscription_id)).fetchone()
    return dict(row) if row else None


def _update_subscription(transaction, subscription_id: str, **columns) -> None:
    unknown_columns = set(columns) - _SUBSCRIPTION_COLUMNS
    if unknown_columns:
        raise ValueError(f"not a subscription column: {sorted(unknown_columns)}")
    columns["updated_at"] = time.time()
    assignments = ",".join(f"{column}=?" for column in columns)
    transaction.execute(f"UPDATE subscriptions SET {assignments} WHERE subscription_id=?",
                        (*columns.values(), subscription_id))


def _record_payment(transaction, provider_name: str, event: ProviderEvent, subscription_id: str | None,
                    status: str) -> None:
    """Insert or update the payment; a refunded or charged-back payment keeps that final status."""
    if not event.provider_payment_id:
        return
    transaction.execute(
        "INSERT INTO payments(payment_id,provider,provider_payment_id,subscription_id,amount_minor,currency,status,"
        "period_start,period_end,occurred_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(provider, provider_payment_id) DO UPDATE SET status=CASE WHEN payments.status IN "
        f"({','.join('?' * len(_FINAL_PAYMENT_STATUSES))}) THEN payments.status ELSE excluded.status END",
        ("p" + secrets.token_hex(8), provider_name, event.provider_payment_id, subscription_id,
         event.amount_minor or 0, event.currency or "", status, event.period_start, event.period_end,
         event.occurred_at, time.time(), *_FINAL_PAYMENT_STATUSES))


def _apply_event(transaction, provider_name: str, event: ProviderEvent) -> tuple[str, str]:
    if event.type == EventType.PAYMENT_SUCCEEDED:
        return _apply_payment(transaction, provider_name, event)
    subscription = _find_subscription(transaction, provider_name, event.provider_subscription_id)
    if subscription is None:
        if event.type in (EventType.REFUNDED, EventType.CHARGEBACK):
            _record_payment(transaction, provider_name, event, None, event.type.value)
        return "unmatched", "no subscription yet"
    handler = _STATUS_EVENT_HANDLERS.get(event.type)
    if handler is None:
        return "ignored", "unsupported event type"
    return handler(transaction, provider_name, event, subscription)


def _is_newer(event: ProviderEvent, subscription: dict) -> bool:
    return event.occurred_at >= subscription["status_event_at"]


def _audit_provider(transaction, provider_name: str, action: str, subscription: dict, **detail) -> None:
    audit(transaction, f"provider:{provider_name}", action, subscription["user_id"],
          subscription_id=subscription["subscription_id"], **detail)


def _on_payment_failed(transaction, provider_name, event, subscription) -> tuple[str, str]:
    _record_payment(transaction, provider_name, event, subscription["subscription_id"], "failed")
    if _is_newer(event, subscription) and subscription["status"] == "active":
        _update_subscription(transaction, subscription["subscription_id"], status="past_due",
                             status_event_at=event.occurred_at)
    _audit_provider(transaction, provider_name, "payment_failed", subscription)
    return "processed", ""


def _on_cancel_at_period_end(transaction, provider_name, event, subscription) -> tuple[str, str]:
    if not _is_newer(event, subscription):
        return "ignored", "older than the last status change"
    _update_subscription(transaction, subscription["subscription_id"], cancel_at_period_end=1,
                         status_event_at=event.occurred_at)
    _audit_provider(transaction, provider_name, "cancel_at_period_end", subscription)
    return "processed", ""


def _on_reactivated(transaction, provider_name, event, subscription) -> tuple[str, str]:
    if not _is_newer(event, subscription) or subscription["status"] not in ("active", "past_due"):
        return "ignored", "older or not active"
    _update_subscription(transaction, subscription["subscription_id"], cancel_at_period_end=0,
                         status_event_at=event.occurred_at)
    _audit_provider(transaction, provider_name, "reactivated", subscription)
    return "processed", ""


def _on_subscription_ended(transaction, provider_name, event, subscription) -> tuple[str, str]:
    if not _is_newer(event, subscription) or subscription["status"] in _SUSPENDED_UNTIL_ADMIN + ("refunded",):
        return "ignored", "older or already ended"
    _update_subscription(transaction, subscription["subscription_id"], status="canceled", cancel_at_period_end=1,
                         status_event_at=event.occurred_at)
    _audit_provider(transaction, provider_name, "subscription_ended", subscription)
    return "processed", ""


def _on_refunded(transaction, provider_name, event, subscription) -> tuple[str, str]:
    _record_payment(transaction, provider_name, event, subscription["subscription_id"], "refunded")
    paid_through = subscription["current_period_end"] or 0
    refunds_current_period = event.period_end is None or event.period_end >= paid_through
    if event.full_refund and subscription["status"] not in _SUSPENDED_UNTIL_ADMIN and refunds_current_period:
        _update_subscription(transaction, subscription["subscription_id"], status="refunded",
                             current_period_end=min(paid_through or event.occurred_at, event.occurred_at),
                             status_event_at=max(subscription["status_event_at"], event.occurred_at))
    _audit_provider(transaction, provider_name, "refunded", subscription, full=event.full_refund)
    return "processed", ""


def _on_chargeback(transaction, provider_name, event, subscription) -> tuple[str, str]:
    _record_payment(transaction, provider_name, event, subscription["subscription_id"], "chargeback")
    _update_subscription(transaction, subscription["subscription_id"], status="disputed",
                         status_event_at=max(subscription["status_event_at"], event.occurred_at))
    _audit_provider(transaction, provider_name, "chargeback", subscription)
    return "processed", ""


def _on_document_issued(transaction, provider_name, event, subscription) -> tuple[str, str]:
    transaction.execute("UPDATE payments SET document_id=?, document_status=? WHERE provider=? AND "
                        "provider_payment_id=?",
                        (event.document_id, event.document_status, provider_name, event.provider_payment_id))
    return "processed", ""


_STATUS_EVENT_HANDLERS = {
    EventType.PAYMENT_FAILED: _on_payment_failed,
    EventType.CANCEL_AT_PERIOD_END: _on_cancel_at_period_end,
    EventType.REACTIVATED: _on_reactivated,
    EventType.SUBSCRIPTION_ENDED: _on_subscription_ended,
    EventType.REFUNDED: _on_refunded,
    EventType.CHARGEBACK: _on_chargeback,
    EventType.DOCUMENT_ISSUED: _on_document_issued,
}


def _payment_problem(event: ProviderEvent, plan: Plan | None) -> str:
    """Why this payment cannot pay for the plan ('' when it can)."""
    if plan is None:
        return "unknown plan"
    if event.amount_minor != plan.price_minor or (event.currency or "").upper() != plan.currency:
        return "amount or currency does not match the plan"
    if event.period_end - event.period_start > plan.max_period_days * 86400:
        return "paid period longer than the plan's interval"
    if event.period_start > event.occurred_at + _FUTURE_PERIOD_TOLERANCE_SECONDS:
        return "paid period starts in the future"
    return ""


def _apply_payment(transaction, provider_name: str, event: ProviderEvent) -> tuple[str, str]:
    if not (event.provider_payment_id and event.period_start and event.period_end
            and event.period_end > event.period_start):
        return "rejected", "payment without id or period"
    subscription = _find_subscription(transaction, provider_name, event.provider_subscription_id)
    if subscription is None:
        return _apply_first_payment(transaction, provider_name, event)
    return _apply_renewal_payment(transaction, provider_name, event, subscription)


def _apply_first_payment(transaction, provider_name: str, event: ProviderEvent) -> tuple[str, str]:
    checkout = transaction.execute("SELECT * FROM checkouts WHERE checkout_id=? AND provider=?",
                                   (event.checkout_ref or "", provider_name)).fetchone()
    if not checkout:
        _record_payment(transaction, provider_name, event, None, "unmatched")
        return "unmatched", "no checkout for this subscription"
    plan = PLANS.get(checkout["plan_code"])
    problem = _payment_problem(event, plan)
    if problem:
        _record_payment(transaction, provider_name, event, None, "amount_mismatch")
        return "rejected", problem
    user_id = checkout["user_id"]
    review_reason = ""
    if checkout["status"] != "open":
        review_reason = f"checkout is {checkout['status']}"
    elif event.occurred_at > checkout["created_at"] + CHECKOUT_LIFETIME_SECONDS:
        review_reason = "checkout expired"
    elif subscription_plan(current_subscription(transaction, user_id), event.occurred_at) in _PREMIUM_PLANS:
        review_reason = "the user already has an active subscription"
    if review_reason:
        _record_payment(transaction, provider_name, event, None, "needs_review")
        audit(transaction, f"provider:{provider_name}", "payment_needs_review", user_id,
              checkout_id=checkout["checkout_id"], provider_payment_id=event.provider_payment_id,
              reason=review_reason)
        return "processed", f"payment held for review: {review_reason}"
    now = time.time()
    subscription_id = "s" + secrets.token_hex(8)
    transaction.execute(
        "INSERT INTO subscriptions(subscription_id,user_id,provider,provider_customer_id,provider_subscription_id,"
        "plan_code,price_minor,currency,interval,status,verified_payment,current_period_start,current_period_end,"
        "cancel_at_period_end,status_event_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'active',1,?,?,0,?,?,?)",
        (subscription_id, user_id, provider_name, event.provider_customer_id, event.provider_subscription_id,
         plan.code, plan.price_minor, plan.currency, plan.billing_interval, event.period_start, event.period_end,
         event.occurred_at, now, now))
    transaction.execute("UPDATE checkouts SET status='completed' WHERE checkout_id=?", (checkout["checkout_id"],))
    _record_payment(transaction, provider_name, event, subscription_id, "succeeded")
    audit(transaction, f"provider:{provider_name}", "subscription_started", user_id, subscription_id=subscription_id,
          plan=plan.code, paid_through=event.period_end)
    return "processed", ""


def _apply_renewal_payment(transaction, provider_name: str, event: ProviderEvent,
                           subscription: dict) -> tuple[str, str]:
    subscription_id = subscription["subscription_id"]
    problem = _payment_problem(event, PLANS.get(subscription["plan_code"]))
    if problem:
        _record_payment(transaction, provider_name, event, subscription_id, "amount_mismatch")
        return "rejected", problem
    _record_payment(transaction, provider_name, event, subscription_id, "succeeded")
    if subscription["status"] in _SUSPENDED_UNTIL_ADMIN:
        _audit_provider(transaction, provider_name, "payment_held", subscription)
        return "processed", "payment recorded; subscription suspended until an administrator decides"
    changes = {"verified_payment": 1}
    if event.period_end > (subscription["current_period_end"] or 0):
        changes.update(current_period_start=event.period_start, current_period_end=event.period_end)
    if _is_newer(event, subscription):
        changes.update(status="active", cancel_at_period_end=0, status_event_at=event.occurred_at)
    _update_subscription(transaction, subscription_id, **changes)
    _audit_provider(transaction, provider_name, "payment_succeeded", subscription,
                    paid_through=max(event.period_end, subscription["current_period_end"] or 0))
    return "processed", ""


# ---------------------------------------------------------------- user and admin operations
def start_checkout(store: Store, provider: BillingProvider | None, settings: Settings, user_id: str, plan_code: str,
                   return_url: str) -> str:
    """Create a checkout on the provider's hosted page and return its URL. Activation happens only through a
    verified payment event. Earlier open checkouts of the user are superseded, so at most one can still activate."""
    plan = PLANS.get(plan_code)
    if provider is None or not settings.checkout_enabled or plan is None:
        raise BillingUnavailable("checkout is not available")
    if provider.live and not (settings.live_provider_enabled and plan.approved):
        raise BillingUnavailable("live checkout needs an approved plan and the live-provider switch")
    if subscription_plan(current_subscription(store, user_id), time.time()) in _PREMIUM_PLANS:
        raise BillingUnavailable("already subscribed")
    checkout_id = "k" + secrets.token_hex(10)
    session = provider.create_checkout(checkout_ref=checkout_id, plan_code=plan.code, price_minor=plan.price_minor,
                                       currency=plan.currency, return_url=return_url)
    with store.tx() as transaction:
        transaction.execute("UPDATE checkouts SET status='superseded' WHERE user_id=? AND status='open'", (user_id,))
        transaction.execute(
            "INSERT INTO checkouts(checkout_id,user_id,provider,plan_code,provider_ref,status,created_at) "
            "VALUES(?,?,?,?,?,'open',?)", (checkout_id, user_id, provider.name, plan.code, session.provider_ref,
                                           time.time()))
        audit(transaction, f"user:{user_id}", "checkout_started", user_id, checkout_id=checkout_id, plan=plan.code)
    logger.info("checkout %s started for plan %s", checkout_id, plan.code)
    return session.redirect_url


def change_renewal(store: Store, provider: BillingProvider | None, user_id: str, *, cancel: bool) -> dict:
    """Turn renewal off (access continues to the paid-through time) or back on. Only lowers entitlements locally
    before the provider confirms; reactivation waits for the provider's event."""
    subscription = current_subscription(store, user_id)
    if provider is None or subscription is None or subscription["provider"] != provider.name:
        raise BillingUnavailable("no subscription with an active billing provider")
    if subscription_plan(subscription, time.time()) not in _PREMIUM_PLANS:
        raise BillingUnavailable("the subscription is not active")
    supported = provider.capabilities.cancel_at_period_end if cancel else provider.capabilities.reactivate
    if not supported:
        raise BillingUnavailable("not supported by this provider")
    if cancel:
        provider.cancel_at_period_end(subscription["provider_subscription_id"])
    else:
        provider.reactivate(subscription["provider_subscription_id"])
    with store.tx() as transaction:
        if cancel:
            _update_subscription(transaction, subscription["subscription_id"], cancel_at_period_end=1)
        audit(transaction, f"user:{user_id}", "renewal_cancel_requested" if cancel else "renewal_resume_requested",
              user_id, subscription_id=subscription["subscription_id"])
    return current_subscription(store, user_id)


def admin_set_subscription_status(store: Store, subscription_id: str, status: str, *, actor: str,
                                  reason: str) -> bool:
    """Administrator decision after a dispute (restore to active, or revoke)."""
    if status not in ("active", "revoked") or not reason.strip():
        raise ValueError("status must be active or revoked, with a reason")
    with store.tx() as transaction:
        row = transaction.execute("SELECT user_id FROM subscriptions WHERE subscription_id=?",
                                  (subscription_id,)).fetchone()
        if not row:
            return False
        _update_subscription(transaction, subscription_id, status=status)
        audit(transaction, actor, f"subscription_{status}_by_admin", row[0], subscription_id=subscription_id,
              reason=reason)
    return True


def payments_needing_review(store: Store) -> list[dict]:
    """Money received that granted nothing (late, superseded or duplicate checkout; plan mismatch): the operator
    refunds or resolves each one with the provider."""
    return [dict(row) for row in store.conn.execute(
        "SELECT provider, provider_payment_id, amount_minor, currency, status, occurred_at FROM payments "
        "WHERE status IN ('needs_review','amount_mismatch','unmatched') ORDER BY occurred_at")]
