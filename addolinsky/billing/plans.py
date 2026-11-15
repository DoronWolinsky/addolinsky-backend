"""Subscription plans and their creation allowance. Prices are in minor units (agorot) and are the final prices the
customer pays (the business registers as osek zair; VAT treatment to be confirmed with the accountant before live
sales). A plan's `approved` flag stays False until the
owner approves live sales (provider offer configured to the same price, Terms and Privacy approved, sandbox tests
passed); start_checkout refuses a live checkout of an unapproved plan."""

from __future__ import annotations

import calendar
import datetime as dt
from dataclasses import dataclass

CREATIONS_PER_MONTH = 4            # new translations per allowance month; reusing an existing translation is free
_PERIOD_TOLERANCE_DAYS = 2         # provider periods may run slightly longer than the nominal interval (time zones)


@dataclass(frozen=True)
class Plan:
    code: str
    price_minor: int               # 2500 = ILS 25.00
    currency: str
    billing_interval: str          # "month" | "year": one payment per interval
    months_per_period: int         # allowance months in one paid period
    creations_per_month: int
    approved: bool

    @property
    def max_period_days(self) -> int:
        """The longest paid period a provider event may grant for this plan (longer periods are rejected)."""
        return self.months_per_period * 31 + _PERIOD_TOLERANCE_DAYS

    def allowance_window(self, period_start: float, period_end: float, now: float) -> tuple[float, float]:
        """The allowance month of the paid period that contains `now`: monthly steps from the period start (same
        day of month, clamped to the month's length); the last month ends with the period, so a period never yields
        more than `months_per_period` allowances."""
        window_start = period_start
        for month_index in range(1, self.months_per_period):
            next_start = _add_months(period_start, month_index)
            if now < next_start or next_start >= period_end:
                return window_start, min(next_start, period_end)
            window_start = next_start
        return window_start, period_end


def _add_months(timestamp: float, months: int) -> float:
    start = dt.datetime.fromtimestamp(timestamp, dt.UTC)
    month_zero_based = start.month - 1 + months
    year, month = start.year + month_zero_based // 12, month_zero_based % 12 + 1
    day = min(start.day, calendar.monthrange(year, month)[1])
    return start.replace(year=year, month=month, day=day).timestamp()


PREMIUM_MONTHLY = Plan(code="premium_monthly", price_minor=2500, currency="ILS", billing_interval="month",
                       months_per_period=1, creations_per_month=CREATIONS_PER_MONTH, approved=False)
PREMIUM_YEARLY = Plan(code="premium_yearly", price_minor=24000, currency="ILS", billing_interval="year",
                      months_per_period=12, creations_per_month=CREATIONS_PER_MONTH, approved=False)
PLANS = {plan.code: plan for plan in (PREMIUM_MONTHLY, PREMIUM_YEARLY)}


def public_plan_offers() -> list[dict]:
    """What the account page may show about the plans (no internal flags)."""
    return [{"code": plan.code, "price_minor": plan.price_minor, "currency": plan.currency,
             "billing_interval": plan.billing_interval, "creations_per_month": plan.creations_per_month}
            for plan in PLANS.values()]
