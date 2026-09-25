"""
Authentication & ownership constraints for the vault API.

    401 — missing JWT, malformed JWT, wrong auth scheme, or bad password
    404 — record exists but belongs to another user (BOB probing ALICE's
          record sees exactly what he would see if it did not exist)
"""

import logging

from vault.models import VaultRecord

logger = logging.getLogger(__name__)


def test_list_without_token_returns_401(api_client):
    assert api_client.get("/vault/").status_code == 401


def test_garbage_token_returns_401(api_client):
    api_client.headers = {"Authorization": "Bearer not-a-real-jwt"}
    assert api_client.get("/vault/").status_code == 401


def test_wrong_scheme_returns_401(api_client, access_token):
    # django-ninja-jwt only accepts the `Bearer` scheme.
    api_client.headers = {"Authorization": f"Token {access_token}"}
    assert api_client.get("/vault/").status_code == 401


def test_token_pair_returns_access_and_refresh(api_client, user):
    resp = api_client.post(
        "/auth/token",
        json={"username": "alice", "password": "correct-horse-battery-staple"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body.get("access"), str) and body["access"]
    assert isinstance(body.get("refresh"), str) and body["refresh"]


def test_token_pair_with_bad_password_returns_401(api_client, user):
    resp = api_client.post(
        "/auth/token", json={"username": "alice", "password": "wrong-password"}
    )
    assert resp.status_code == 401


def test_token_pair_with_bad_username_returns_401(api_client, user):
    resp = api_client.post(
        "/auth/token", json={"username": "mallory", "password": "whatever-123"}
    )
    assert resp.status_code == 401


def test_refresh_exchanges_refresh_for_new_access(api_client, user):
    pair = api_client.post(
        "/auth/token",
        json={"username": "alice", "password": "correct-horse-battery-staple"},
    ).json()
    resp = api_client.post("/auth/refresh", json={"refresh": pair["refresh"]})
    assert resp.status_code == 200
    assert isinstance(resp.json().get("access"), str)


def test_cross_user_read_is_404(api_client, other_user, vault_record):
    """Bob probing alice's record sees 404 — same as 'does not exist'."""
    pair = api_client.post(
        "/auth/token", json={"username": "bob", "password": "tr0ub4dor-and-3"}
    ).json()
    api_client.headers = {"Authorization": f"Bearer {pair['access']}"}
    assert api_client.get(f"/vault/{vault_record.pk}").status_code == 404


def test_cross_user_patch_is_404(api_client, other_user, vault_record):
    pair = api_client.post(
        "/auth/token", json={"username": "bob", "password": "tr0ub4dor-and-3"}
    ).json()
    api_client.headers = {"Authorization": f"Bearer {pair['access']}"}
    resp = api_client.patch(f"/vault/{vault_record.pk}", json={"title": "stolen"})
    assert resp.status_code == 404
    vault_record.refresh_from_db()
    assert vault_record.title == "prod-db"  # untouched


def test_cross_user_delete_is_404_and_record_survives(
    api_client, other_user, vault_record
):
    pair = api_client.post(
        "/auth/token", json={"username": "bob", "password": "tr0ub4dor-and-3"}
    ).json()
    api_client.headers = {"Authorization": f"Bearer {pair['access']}"}
    resp = api_client.delete(f"/vault/{vault_record.pk}")
    assert resp.status_code == 404
    assert VaultRecord.objects.filter(pk=vault_record.pk).exists()
