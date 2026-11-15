"""Create and read the secret files in the data directory: owner install token, admin token and server signing
secret. Existing secret files are never rewritten."""

from __future__ import annotations

import secrets

from ..config import Settings


def get_or_create_secret(settings: Settings, secret_name: str, random_bytes_count: int) -> str:
    secret_file_path = settings.data_dir / secret_name
    if not secret_file_path.exists():
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        secret_file_path.write_text(secrets.token_urlsafe(random_bytes_count), encoding="utf-8")
    return secret_file_path.read_text(encoding="utf-8").strip()


def get_owner_install_token(settings: Settings) -> str:
    """The owner's personal install token (path segment of the owner's addon URL)."""
    return get_or_create_secret(settings, "addon_key", 18)


def get_admin_token(settings: Settings) -> str:
    return get_or_create_secret(settings, "admin_token", 32)
