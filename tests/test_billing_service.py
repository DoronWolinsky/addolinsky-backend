"""Billing service rules at the service layer: verified provider events start, renew and end Premium only when
they match the plan and an open checkout; everything else is recorded and grants nothing. Offline mock provider."""

import json
import time

import pytest

from addolinsky.billing import service as billing
from addolinsky.billing.mock import MockProvider, sign
from addolinsky.billing.provider import WebhookRejected
from addolinsky.security.auth import hash_install_token
from addolinsky.services import entitlements as access

SECRET = "mock-webhook-secret-0123456789"
DAY = 86400


@pytest.fixture
def subscriber(store):
    store.add_user("ua", hash_install_token("A" * 24), "user", "test")
    return store


def open_checkout(store, plan_code="premium_monthly", checkout_id="k1", created_at=None):
    store.conn.execute("INSERT INTO checkouts(checkout_id,user_id,provider,plan_code,status,created_at) "
                       "VALUES(?,?,'mock',?,'open',?)", (checkout_id, "ua", plan_code, created_at or time.time()))


def payment_event(event_id, amount, period_days, checkout_id="k1", subscription="sub1", payment=None):
    start = time.time() - DAY
    return {"id": event_id, "type": "payment_succeeded", "occurred_at": start, "subscription": subscription,
            "checkout_ref": checkout_id, "payment": payment or f"pay-{event_id}", "amount": amount,
            "currency": "ILS", "period_start": start, "period_end": start + period_days * DAY}


def deliver(store, provider, body: dict) -> list[str]:
    raw = json.dumps(body).encode()
    events = provider.verify_webhook({"X-Mock-Signature": sign(SECRET, raw)}, raw)
    return [billing.ingest_event(store, provider.name, event) for event in events]


def test_signatures_are_verified_before_anything_is_stored(subscriber):
    provider = MockProvider(SECRET)
    raw = json.dumps(payment_event("e1", 2500, 30)).encode()
    for headers in ({}, {"X-Mock-Signature": sign("another-secret-0123456789", raw)},
                    {"X-Mock-Signature": sign(SECRET, raw, int(time.time()) - 3600)}):
        with pytest.raises(WebhookRejected):
            provider.verify_webhook(headers, raw)


def test_a_matching_payment_starts_premium_once(subscriber):
    store, provider = subscriber, MockProvider(SECRET)
    open_checkout(store)
    body = payment_event("e1", 2500, 30)
    assert deliver(store, provider, body) == ["processed"]
    assert deliver(store, provider, body) == ["duplicate"]
    entitlements = access.entitlements_for(store, "ua")
    assert entitlements.plan == "premium" and entitlements.credits_limit == 4 and entitlements.access_all


def test_yearly_plan_refreshes_four_credits_each_month(subscriber):
    store, provider = subscriber, MockProvider(SECRET)
    open_checkout(store, plan_code="premium_yearly")
    assert deliver(store, provider, payment_event("e1", 24000, 365)) == ["processed"]
    subscription = access.current_subscription(store, "ua")
    first = access.entitlements_for(store, "ua", subscription["current_period_start"] + DAY)
    second = access.entitlements_for(store, "ua", subscription["current_period_start"] + 40 * DAY)
    assert first.credits_limit == second.credits_limit == 4
    assert first.period_end <= second.period_start                 # a new allowance month, not a carried balance


@pytest.mark.parametrize("amount, days", [(100, 30), (2500, 365), (24000, 30)])
def test_wrong_amount_or_period_grants_nothing(subscriber, amount, days):
    store, provider = subscriber, MockProvider(SECRET)
    open_checkout(store)
    assert deliver(store, provider, payment_event("e1", amount, days)) == ["rejected"]
    assert access.entitlements_for(store, "ua").plan == "free"


def test_expired_checkout_payment_is_held_for_review(subscriber):
    store, provider = subscriber, MockProvider(SECRET)
    open_checkout(store, created_at=time.time() - 10 * DAY)
    assert deliver(store, provider, payment_event("e1", 2500, 30)) == ["processed"]
    assert access.entitlements_for(store, "ua").plan == "free"
    assert [row["status"] for row in billing.payments_needing_review(store)] == ["needs_review"]


def test_refund_ends_premium_and_is_never_reverted(subscriber):
    store, provider = subscriber, MockProvider(SECRET)
    open_checkout(store)
    deliver(store, provider, payment_event("e1", 2500, 30, payment="p1"))
    deliver(store, provider, {"id": "e2", "type": "refunded", "occurred_at": time.time(), "subscription": "sub1",
                              "payment": "p1", "full_refund": True})
    assert access.entitlements_for(store, "ua").plan == "refunded"
    deliver(store, provider, payment_event("e3", 2500, 30, payment="p1"))
    status = store.conn.execute("SELECT status FROM payments WHERE provider_payment_id='p1'").fetchone()[0]
    assert status == "refunded"
