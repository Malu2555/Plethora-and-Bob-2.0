"""
Vault CRUD success-path tests.

Contract asserted here:
    200 GET    list / detail
    201 POST   create  (+ Location header, whitespace-normalized title)
    200 PATCH  partial update (untouched fields stay intact)
    204 DELETE empty body and the row is really gone
    422 on every schema violation probed
scoping: alice never sees bob's rows in a list.
"""

import logging

from vault.models import VaultRecord

logger = logging.getLogger(__name__)


def test_list_returns_200_with_owned_records(auth_client, vault_record):
    resp = auth_client.get("/vault/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    row = data[0]
    assert row["title"] == "prod-db"
    assert row["secret_data"] == "super-secret"
    assert row["owner_username"] == "alice"
    assert row["created_at"]


def test_list_hides_other_users_records(auth_client, other_user, vault_record):
    # Bob creates his own record; alice must still only see hers.
    VaultRecord.objects.create(owner=other_user, title="bob-notes", secret_data="ns")
    resp = auth_client.get("/vault/")
    assert resp.status_code == 200
    titles = [row["title"] for row in resp.json()]
    assert titles == ["prod-db"]


def test_get_detail_returns_200(auth_client, vault_record):
    resp = auth_client.get(f"/vault/{vault_record.pk}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == vault_record.pk
    assert body["owner_username"] == "alice"


def test_create_returns_201_with_location(auth_client):
    resp = auth_client.post(
        "/vault/", json={"title": "  api-key  ", "secret_data": "sk_live_42"}
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["title"] == "api-key"  # surrounding whitespace stripped
    assert body["secret_data"] == "sk_live_42"
    assert body["owner_username"] == "alice"
    record_id = body["id"]
    # RFC 7231: Location points at the freshly created resource.
    assert resp["Location"].endswith(f"/vault/{record_id}")
    assert VaultRecord.objects.filter(pk=record_id, owner__username="alice").exists()


def test_patch_updates_only_sent_fields(auth_client, vault_record):
    resp = auth_client.patch(f"/vault/{vault_record.pk}", json={"title": "renamed"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "renamed"
    vault_record.refresh_from_db()
    assert vault_record.title == "renamed"
    assert vault_record.secret_data == "super-secret"  # untouched


def test_patch_returned_record_shows_new_values(auth_client, vault_record):
    resp = auth_client.patch(
        f"/vault/{vault_record.pk}", json={"secret_data": "rotated-secret"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["secret_data"] == "rotated-secret"
    assert body["title"] == "prod-db"


def test_delete_returns_204_empty_body(auth_client, vault_record):
    resp = auth_client.delete(f"/vault/{vault_record.pk}")
    assert resp.status_code == 204
    assert resp.content == b""
    assert not VaultRecord.objects.filter(pk=vault_record.pk).exists()


def test_delete_missing_record_returns_404(auth_client):
    resp = auth_client.delete("/vault/999999")
    assert resp.status_code == 404


def test_create_missing_secret_returns_422(auth_client):
    resp = auth_client.post("/vault/", json={"title": "no-secret"})
    assert resp.status_code == 422


def test_create_blank_title_returns_422(auth_client):
    resp = auth_client.post("/vault/", json={"title": "", "secret_data": "x"})
    assert resp.status_code == 422


def test_patch_blank_title_returns_422(auth_client, vault_record):
    resp = auth_client.patch(f"/vault/{vault_record.pk}", json={"title": "   "})
    assert resp.status_code == 422
