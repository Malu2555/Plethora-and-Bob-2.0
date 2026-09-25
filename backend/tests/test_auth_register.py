"""
Self-service account creation — POST /api/v1/auth/register.

    201  account created + JWT pair (caller is signed in immediately)
    409  username OR email already taken (generic message, anti-enumeration)
    422  malformed fields, or a password rejected by Django's
         AUTH_PASSWORD_VALIDATORS (short/common/similar)
    429  registration ceiling exceeded — dedicated anon-register bucket,
         isolated from the login/refresh 30/m anon bucket
"""

import logging

import pytest
from django.contrib.auth import authenticate, get_user_model
from django.core.cache import cache

from auditlog.models import AuditLog

logger = logging.getLogger(__name__)

CAROL = {
    "username": "carol",
    "email": "carol@example.com",
    "password": "carol-strong-pass",
}


@pytest.fixture(autouse=True)
def _fresh_throttle_buckets():
    """
    Reset throttle buckets around every test in this module.

    LocMemCache outlives the per-test database rollback, so without this reset
    the 12/m anon-register ceiling would leak between tests in the same run.
    """
    cache.clear()
    yield
    cache.clear()


def _register(api_client, **overrides):
    payload = {**CAROL, **overrides}
    return api_client.post("/auth/register", json=payload)


def test_register_returns_201_pair_signs_in_and_audits(api_client, db):
    resp = _register(api_client)
    assert resp.status_code == 201
    body = resp.json()
    assert isinstance(body.get("access"), str) and body["access"]
    assert isinstance(body.get("refresh"), str) and body["refresh"]
    assert body["username"] == "carol"

    user = get_user_model().objects.get(username="carol")
    assert user.email == "carol@example.com"
    assert AuditLog.objects.filter(action="register", user=user).count() == 1


def test_register_token_works_against_protected_endpoints(api_client, db):
    access = _register(api_client).json()["access"]
    api_client.headers = {"Authorization": f"Bearer {access}"}
    resp = api_client.get("/vault/")
    assert resp.status_code == 200
    assert resp.json() == []


def test_register_password_satisfies_authenticate(api_client, db):
    assert _register(api_client).status_code == 201
    user = authenticate(username=CAROL["username"], password=CAROL["password"])
    assert user is not None


def test_duplicate_username_returns_409(api_client, db):
    assert _register(api_client).status_code == 201
    resp = _register(api_client, email="carol-alias@example.com")
    assert resp.status_code == 409


def test_duplicate_email_returns_409(api_client, db):
    assert _register(api_client).status_code == 201
    resp = _register(api_client, username="carol2")
    assert resp.status_code == 409


def test_short_username_returns_422(api_client, db):
    assert _register(api_client, username="cd").status_code == 422


def test_invalid_email_returns_422(api_client, db):
    assert _register(api_client, email="not-an-email").status_code == 422


def test_short_password_returns_422(api_client, db):
    # Blocked at the pydantic layer (min_length=8).
    assert _register(api_client, password="short7").status_code == 422


def test_password_too_similar_to_username_returns_422(api_client, db):
    # Blocked by Django's UserAttributeSimilarityValidator, i.e. the handler
    # really does run AUTH_PASSWORD_VALIDATORS, not just pydantic shapes.
    # The validator uses quick_ratio() >= 0.7: "carol123" scores 2*5/(8+5),
    # comfortably above the threshold, while a longer pad dilutes it below.
    assert _register(api_client, password="carol123").status_code == 422


def test_registration_burst_eventually_returns_429(api_client, db):
    """
    The 12/m ceiling trips inside one test (the bucket is reset per test).

    Exactly one request succeeds (201); the rest are 409 until the throttle
    kicks in, then 429. The burst rides the isolated anon-register bucket, so
    it cannot pollute the shared anon bucket used by login/refresh tests.
    """
    statuses = [_register(api_client).status_code for _ in range(15)]
    assert statuses.count(201) == 1
    assert 429 in statuses
