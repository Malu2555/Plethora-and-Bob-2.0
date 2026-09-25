"""
Audit trail integrity: every vault mutation must produce exactly one
severity-appropriate AuditLog row, and the feed must expose them paginated
and newest-first.
"""

import logging

from auditlog.models import AuditLog, Severity

logger = logging.getLogger(__name__)


def test_create_emits_exactly_one_info_row(auth_client):
    before = AuditLog.objects.count()
    resp = auth_client.post("/vault/", json={"title": "s3-bucket", "secret_data": "k"})
    assert resp.status_code == 201
    rows = AuditLog.objects.filter(action="create", target_id=resp.json()["id"])
    assert rows.count() == 1
    assert rows.get().severity == Severity.INFO
    assert AuditLog.objects.count() == before + 1  # exactly one new row


def test_update_emits_exactly_one_info_row(auth_client, vault_record):
    before = AuditLog.objects.count()
    resp = auth_client.patch(f"/vault/{vault_record.pk}", json={"title": "renamed"})
    assert resp.status_code == 200
    rows = AuditLog.objects.filter(action="update", target_id=vault_record.pk)
    assert rows.count() == 1
    assert rows.get().severity == Severity.INFO
    assert AuditLog.objects.count() == before + 1


def test_delete_emits_exactly_one_warning_row(auth_client, vault_record):
    before = AuditLog.objects.count()
    resp = auth_client.delete(f"/vault/{vault_record.pk}")
    assert resp.status_code == 204
    rows = AuditLog.objects.filter(action="delete", target_id=vault_record.pk)
    assert rows.count() == 1
    assert rows.get().severity == Severity.WARNING
    assert AuditLog.objects.count() == before + 1


def test_direct_orm_create_also_emits_audit_row(user):
    """Signals fire for ORM writes too, not just through the API."""
    from vault.models import VaultRecord

    before = AuditLog.objects.count()
    VaultRecord.objects.create(owner=user, title="cli-record", secret_data="z")
    assert AuditLog.objects.filter(action="create", target_id__isnull=False).count() == before + 1


def test_audit_feed_requires_token(api_client):
    assert api_client.get("/audit/").status_code == 401


def test_audit_feed_is_paginated_and_latest_first(auth_client):
    for i in range(3):
        auth_client.post("/vault/", json={"title": f"bucket-{i}", "secret_data": "zz"})

    resp = auth_client.get("/audit/?limit=2&offset=0")
    assert resp.status_code == 200
    body = resp.json()
    assert {"items", "count"} <= set(body.keys())
    assert body["count"] >= 3
    assert len(body["items"]) == 2
    ids = [row["id"] for row in body["items"]]
    assert ids == sorted(ids, reverse=True)  # newest first
    assert body["items"][0]["username"] == "alice"
