"""Deterministic mock provider for offline tests and local sandbox runs. It moves no money, and settings refuse it in
public mode (config.load_settings), so it can never grant Premium on the production site.

Webhooks: JSON body, header `X-Mock-Signature: t=<unix time>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>`, at most
300 s old (replays of an old signed body are rejected even before deduplication)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

from .provider import Capabilities, CheckoutSession, EventType, ProviderEvent, WebhookRejected

SIGNATURE_TOLERANCE_SECONDS = 300
_MIN_SECRET_LENGTH = 16


def _signature_digest(secret: str, timestamp: int, body: bytes) -> str:
    return hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


def sign(secret: str, body: bytes, timestamp: int | None = None) -> str:
    signed_at = int(time.time()) if timestamp is None else timestamp
    return f"t={signed_at},v1={_signature_digest(secret, signed_at, body)}"


def _event_from_json(item: dict) -> ProviderEvent:
    return ProviderEvent(provider_event_id=str(item["id"]), type=EventType(item["type"]),
                         occurred_at=float(item["occurred_at"]), provider_subscription_id=str(item["subscription"]),
                         checkout_ref=item.get("checkout_ref"), provider_customer_id=item.get("customer"),
                         provider_payment_id=item.get("payment"), amount_minor=item.get("amount"),
                         currency=item.get("currency"), period_start=item.get("period_start"),
                         period_end=item.get("period_end"), full_refund=bool(item.get("full_refund")),
                         document_id=item.get("document_id"), document_status=item.get("document_status"))


class MockProvider:
    name = "mock"
    live = False
    capabilities = Capabilities(hosted_checkout=True, cancel_at_period_end=True, reactivate=True,
                                refunds_via_api=False, plan_changes=False, payment_method_update=False)

    def __init__(self, webhook_secret: str, clock=time.time):
        if not webhook_secret or len(webhook_secret) < _MIN_SECRET_LENGTH:
            raise ValueError("the mock provider needs a webhook secret of at least 16 characters")
        self.__webhook_secret = webhook_secret       # class-private: never exposed through an attribute or repr
        self._clock = clock
        self.cancel_calls: list[str] = []
        self.reactivate_calls: list[str] = []

    def __repr__(self) -> str:
        return "MockProvider()"

    def create_checkout(self, *, checkout_ref: str, plan_code: str, price_minor: int, currency: str,
                        return_url: str) -> CheckoutSession:
        return CheckoutSession(provider_ref="mock_" + checkout_ref,
                               redirect_url=f"https://mock-provider.invalid/pay/{checkout_ref}")

    def verify_webhook(self, headers: dict[str, str], body: bytes) -> list[ProviderEvent]:
        signature_header = {name.lower(): value for name, value in headers.items()}.get("x-mock-signature", "")
        signature_parts = dict(part.split("=", 1) for part in signature_header.split(",") if "=" in part)
        try:
            signed_at = int(signature_parts.get("t", ""))
        except ValueError:
            raise WebhookRejected("missing signature") from None
        expected_digest = _signature_digest(self.__webhook_secret, signed_at, body)
        if not hmac.compare_digest(expected_digest, signature_parts.get("v1", "")):
            raise WebhookRejected("bad signature")
        if abs(self._clock() - signed_at) > SIGNATURE_TOLERANCE_SECONDS:
            raise WebhookRejected("stale signature")
        try:
            decoded = json.loads(body)
            items = decoded if isinstance(decoded, list) else [decoded]
            return [_event_from_json(item) for item in items]
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise WebhookRejected(f"malformed event: {type(error).__name__}") from None

    def cancel_at_period_end(self, provider_subscription_id: str) -> None:
        self.cancel_calls.append(provider_subscription_id)

    def reactivate(self, provider_subscription_id: str) -> None:
        self.reactivate_calls.append(provider_subscription_id)
