from pathlib import Path

import pytest

from addolinsky.cloud import downloads
from addolinsky.config import load_settings
from addolinsky.db import Store

PUBLIC_TEST_ADDRESS = "93.184.215.14"     # a globally routable address; tests never open real connections


@pytest.fixture(autouse=True)
def no_real_dns(monkeypatch):
    """Download destination checks resolve host names; tests use fake hosts served by httpx.MockTransport."""
    monkeypatch.setattr(downloads, "resolve_host_addresses", lambda hostname: [PUBLIC_TEST_ADDRESS])


@pytest.fixture
def settings(tmp_path):
    return load_settings(env_file=Path("does-not-exist.env"), data_dir=tmp_path / "data")


@pytest.fixture
def store(settings):
    settings.ensure_dirs()
    database = Store(settings.db_path)
    yield database
    database.close()
