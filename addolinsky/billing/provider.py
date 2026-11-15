"""The interface every payment-provider adapter implements, and the normalized events it produces.

An adapter translates one provider's API and webhooks into these types; nothing outside the adapter knows provider
payloads. Adapters never handle card data: checkout is the provider's hosted page, and the only proof of payment is
an authenticated server-to-server event (a browser redirect proves nothing)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class EventType(StrEnum):
    PAYMENT_SUCCEEDED = "payment_succeeded"            # a period was paid: activates or renews
    PAYMENT_FAILED = "payment_failed"                  # renewal failed (dunning); access continues to paid-through
    CANCEL_AT_PERIOD_END = "cancel_at_period_end"      # renewal turned off; access continues to paid-through
    REACTIVATED = "reactivated"                        # renewal turned back on before the period ended
    SUBSCRIPTION_ENDED = "subscription_ended"          # no further renewals (provider closed it)
    REFUNDED = "refunded"                              # a payment was refunded (full refunds end that period)
    CHARGEBACK = "chargeback"                          # disputed payment: access revoked until an admin decides
    DOCUMENT_ISSUED = "document_issued"                # receipt / invoice issued by the provider's legal workflow


class WebhookRejected(Exception):
    """Authentication or format failure; the event is not stored or applied."""


@dataclass(frozen=True)
class ProviderEvent:
    provider_event_id: str
    type: EventType
    occurred_at: float                         # provider timestamp (ordering); never the receive time
    provider_subscription_id: str
    checkout_ref: str | None = None            # our checkout id, echoed by the provider (maps to the user)
    provider_customer_id: str | None = None
    provider_payment_id: str | None = None
    amount_minor: int | None = None
    currency: str | None = None
    period_start: float | None = None
    period_end: float | None = None
    full_refund: bool = False
    document_id: str | None = None
    document_status: str | None = None


@dataclass(frozen=True)
class CheckoutSession:
    provider_ref: str
    redirect_url: str                          # the provider's hosted payment page


@dataclass(frozen=True)
class Capabilities:
    hosted_checkout: bool
    cancel_at_period_end: bool
    reactivate: bool
    refunds_via_api: bool
    plan_changes: bool                         # proration: not supported anywhere yet
    payment_method_update: bool


class BillingProvider(Protocol):
    name: str
    live: bool                                 # moves real money
    capabilities: Capabilities

    def create_checkout(self, *, checkout_ref: str, plan_code: str, price_minor: int, currency: str,
                        return_url: str) -> CheckoutSession: ...

    def verify_webhook(self, headers: dict[str, str], body: bytes) -> list[ProviderEvent]: ...

    def cancel_at_period_end(self, provider_subscription_id: str) -> None: ...

    def reactivate(self, provider_subscription_id: str) -> None: ...
