"""
Shared pytest fixtures for the Sentinel backend suite.

Fixtures:
    api_client    -- unauthenticated ninja TestClient bound to the full API
    user          -- 'alice' (active, primary actor)
    other_user    -- 'bob'   (secondary actor for cross-tenant / IDOR probes)
    access_token  -- JWT access token minted for alice via POST /auth/pair
    auth_client   -- api_client preloaded with `Authorization: Bearer <token>`
    vault_record  -- VaultRecord owned by alice (auto-emits an audit row)

All fixtures require the SQLite test database, which pytest-django rebuilds
transactionally per test.
"""

import logging

import pytest
from django.contrib.auth import get_user_model
from ninja.testing import TestClient

from monitor.urls import api
from vault.models import VaultRecord

# --------------------------------------------------------------------------
# Fast password hashing for the test run only. Passwords in tests are shared
# fixtures, not real credentials; the default PBKDF2 hasher would burn
# minutes of CPU on every `create_user`. Django reads this constant
# dynamically, and production settings are untouched.
# --------------------------------------------------------------------------
from django.conf import settings as django_settings

django_settings.PASSWORD_HASHERS = ("django.contrib.auth.hashers.MD5PasswordHasher",)

logger = logging.getLogger(__name__)

ALICE_PASSWORD = "correct-horse-battery-staple"
BOB_PASSWORD = "tr0ub4dor-and-3"


@pytest.fixture(autouse=True)
def _reset_throttle_history():
    """
    Clear Django's default cache before every test.

    Every authenticated test mints a fresh JWT through POST /auth/token,
    which is IP-throttled at 30/min (LocMem cache). With ~70 tests in one
    process those mints would exhaust the anon bucket and turn the whole
    suite into 429s. Clearing per test (~free on LocMem) keeps the throttle
    exercised (test_throttle still trips it inside a single test) without
    letting history leak across tests.
    """
    from django.core.cache import cache

    cache.clear()


@pytest.fixture
def api_client():
    """Unauthenticated client bound to the entire Sentinel API surface."""
    return TestClient(api)


@pytest.fixture
def user(db):
    """Primary actor for most tests."""
    return get_user_model().objects.create_user(username="alice", password=ALICE_PASSWORD)


@pytest.fixture
def other_user(db):
    """Secondary actor used for cross-tenant probes."""
    return get_user_model().objects.create_user(username="bob", password=BOB_PASSWORD)


@pytest.fixture
def access_token(user, api_client):
    """A fresh JWT access token minted through the real /auth/token route."""
    resp = api_client.post(
        "/auth/token", json={"username": "alice", "password": ALICE_PASSWORD}
    )
    assert resp.status_code == 200, f"token mint failed: {resp.content!r}"
    return resp.json()["access"]


@pytest.fixture
def vault_record(user):
    """A VaultRecord owned by alice (emits an audit row via signals)."""
    return VaultRecord.objects.create(
        owner=user, title="prod-db", secret_data="super-secret"
    )


@pytest.fixture
def auth_client(api_client, access_token):
    """Authenticated client for alice: JWT attached to every request."""
    api_client.headers = {"Authorization": f"Bearer {access_token}"}
    return api_client
