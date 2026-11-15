"""Runtime settings of the service. Secrets are read from the environment / .env and never logged."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field, fields
from pathlib import Path

from dotenv import dotenv_values

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"          # admin UI and account page assets


def _parse_flag(value: str) -> bool:
    return value.lower() in ("1", "true", "yes")


@dataclass
class Settings:
    data_dir: Path = PROJECT_ROOT / "data"
    host: str = "127.0.0.1"
    port: int = 7000
    # scheduling
    workers: int = 2                  # translation jobs processed concurrently
    max_auto_jobs_per_day: int = 4    # new translation jobs per rolling 24 h, all users together
    max_jobs_per_user_day: int = 3    # new translation jobs per user per rolling 24 h (owner exempt)
    # public deployment (empty public_base_url = local mode: no proxy, links point at the local address)
    public_base_url: str = ""         # e.g. https://addolinsky.com (served behind a TLS reverse proxy)
    public_signup: bool = False       # allow /configure to issue personal install links
    paid_jobs: bool = False           # master switch: create/run paid translation jobs (owner approval required)
    friends_paid_jobs: bool = False   # invited (non-owner) users may request paid jobs (owner approval required)
    member_paid_jobs: bool = False    # accounts (Premium / test grants) may request paid jobs (owner approval required)
    # accounts and billing (all off by default; see docs/DECISIONS.md D-139)
    account_signup: bool = False      # public account registration (also needs APPROVED Terms and Privacy)
    billing_enabled: bool = False     # accept provider webhooks for the configured billing provider
    checkout_enabled: bool = False    # offer checkout (needs billing_enabled and a live provider)
    live_provider_enabled: bool = False   # a real payment provider may be used (separate owner approval)
    billing_provider: str = ""        # provider adapter name; "mock" is refused in public mode
    billing_webhook_secret: str | None = field(default=None, repr=False)
    max_jobs_per_user_month: int = 8  # new translation jobs per invited user per rolling 30 days (owner exempt)
    max_active_friends: int = 5       # active invitation links (enforced by `addolinsky invite` / restore)
    signups_per_ip_day: int = 5
    requests_per_ip_min: int = 120    # per-IP request rate limit on public routes
    contact_email: str = ""           # rights-holder / support contact shown on /policy, /terms and /privacy
    operator_name: str = ""           # the operator named in the Terms and Privacy Policy
    # SHA-256 of the rendered Terms/Privacy texts the owner approved (shown on each page); nothing else is in force
    legal_approved_sha256: tuple = ()
    max_account_registrations_per_day: int = 50   # open registrations per rolling 24 h, all networks together
    donation_url: str = ""            # optional, shown only when the monthly allowance is exhausted
    # website identity through Firebase Authentication (Spark plan; D-132). Off unless both are set. Firebase never
    # replaces install tokens: it only proves a website sign-in, which an existing user must explicitly link.
    firebase_auth: bool = False
    firebase_project_id: str = ""     # public project id (token audience), not a secret
    firebase_web_api_key: str = ""    # public Firebase web API key (client identifier, not a secret); /account needs it
    firebase_auth_domain: str = ""    # default <project id>.firebaseapp.com
    # public Anime Kitsu addon: its meta endpoint maps Kitsu ids to IMDb ids (empty = Kitsu titles unsupported)
    kitsu_addon_url: str = "https://anime-kitsu.strem.fun"

    @classmethod
    def environment_variables(cls) -> dict:
        """Environment variable -> (attribute, parser) for this settings class."""
        return dict(_SERVICE_ENVIRONMENT_VARIABLES)

    def validate(self) -> None:
        """Refuse unsafe combinations and clamp bounded values (raises ValueError)."""
        if self.public_base_url and not self.public_base_url.startswith("https://"):
            raise ValueError("public_base_url must be an https:// URL")
        if self.billing_provider == "mock" and self.public_base_url:
            raise ValueError("the mock billing provider is for offline tests only; never in public mode")
        if self.checkout_enabled and not (self.billing_enabled and self.live_provider_enabled
                                          and self.billing_provider):
            raise ValueError("checkout needs billing_enabled, live_provider_enabled and a billing provider")
        self.workers = max(1, min(self.workers, 8))

    def translation_engine_ready(self) -> bool:
        """Whether new translations can be produced; the service settings alone configure no engine."""
        return False

    @property
    def public_host(self) -> str:
        return self.public_base_url.split("://", 1)[-1].strip("/") if self.public_base_url else ""

    @property
    def db_path(self) -> Path:
        return self.data_dir / "addolinsky.sqlite3"

    @property
    def outputs_dir(self) -> Path:
        return self.data_dir / "outputs"

    def ensure_dirs(self) -> None:
        self.outputs_dir.mkdir(parents=True, exist_ok=True)


_SERVICE_ENVIRONMENT_VARIABLES = {
    "ADDOLINSKY_DATA_DIR": ("data_dir", Path),
    "ADDOLINSKY_PORT": ("port", int),
    "ADDOLINSKY_HOST": ("host", str),
    "ADDOLINSKY_WORKERS": ("workers", int),
    "ADDOLINSKY_MAX_JOBS_PER_DAY": ("max_auto_jobs_per_day", int),
    "ADDOLINSKY_MAX_JOBS_PER_USER_DAY": ("max_jobs_per_user_day", int),
    "ADDOLINSKY_PUBLIC_BASE_URL": ("public_base_url", str),
    "ADDOLINSKY_PUBLIC_SIGNUP": ("public_signup", _parse_flag),
    "ADDOLINSKY_PAID_JOBS": ("paid_jobs", _parse_flag),
    "ADDOLINSKY_FRIENDS_PAID_JOBS": ("friends_paid_jobs", _parse_flag),
    "ADDOLINSKY_MEMBER_PAID_JOBS": ("member_paid_jobs", _parse_flag),
    "ADDOLINSKY_ACCOUNT_SIGNUP": ("account_signup", _parse_flag),
    "ADDOLINSKY_BILLING_ENABLED": ("billing_enabled", _parse_flag),
    "ADDOLINSKY_CHECKOUT_ENABLED": ("checkout_enabled", _parse_flag),
    "ADDOLINSKY_LIVE_PROVIDER_ENABLED": ("live_provider_enabled", _parse_flag),
    "ADDOLINSKY_BILLING_PROVIDER": ("billing_provider", str),
    "ADDOLINSKY_BILLING_WEBHOOK_SECRET": ("billing_webhook_secret", str),
    "ADDOLINSKY_MAX_JOBS_PER_USER_MONTH": ("max_jobs_per_user_month", int),
    "ADDOLINSKY_MAX_ACTIVE_FRIENDS": ("max_active_friends", int),
    "ADDOLINSKY_CONTACT_EMAIL": ("contact_email", str),
    "ADDOLINSKY_OPERATOR_NAME": ("operator_name", str),
    "ADDOLINSKY_LEGAL_APPROVED_SHA256": ("legal_approved_sha256",
                                         lambda value: tuple(item.strip().lower() for item in value.split(",")
                                                             if item.strip())),
    "ADDOLINSKY_MAX_ACCOUNT_REGISTRATIONS_PER_DAY": ("max_account_registrations_per_day", int),
    "ADDOLINSKY_DONATION_URL": ("donation_url", str),
    "ADDOLINSKY_FIREBASE_AUTH": ("firebase_auth", _parse_flag),
    "ADDOLINSKY_FIREBASE_PROJECT_ID": ("firebase_project_id", str),
    "ADDOLINSKY_FIREBASE_WEB_API_KEY": ("firebase_web_api_key", str),
    "ADDOLINSKY_FIREBASE_AUTH_DOMAIN": ("firebase_auth_domain", str),
}


def load_settings(env_file: Path | None = None, *, settings_class: type[Settings] = Settings, **overrides):
    """Build settings from .env (not exported to os.environ), then the process environment, then overrides, and
    validate them. `settings_class` selects a subclass that adds its own settings."""
    environment_variables = settings_class.environment_variables()
    raw_values: dict[str, str] = {}
    env_path = env_file if env_file is not None else PROJECT_ROOT / ".env"
    if env_path and Path(env_path).is_file():
        raw_values.update({name: value for name, value in dotenv_values(env_path).items() if value is not None})
    raw_values.update({name: value for name, value in os.environ.items() if name in environment_variables})
    settings = settings_class()
    for variable_name, (attribute, parse) in environment_variables.items():
        if raw_values.get(variable_name):
            setattr(settings, attribute, parse(raw_values[variable_name].strip()))
    known_attributes = {settings_field.name for settings_field in fields(settings_class)}
    for attribute, value in overrides.items():
        if attribute not in known_attributes:
            raise TypeError(f"unknown setting {attribute}")
        setattr(settings, attribute, value)
    settings.validate()
    return settings


def assert_loopback(host: str) -> None:
    """The service must only ever bind to a loopback address."""
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError(f"refusing to bind to non-loopback host {host!r}")
