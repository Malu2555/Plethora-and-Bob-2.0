"""
Security posture snapshot contract.

The dashboard homepage renders exclusively from GET /api/v1/security/posture,
so the payload shape AND the scoring formula are pinned here:

    score = max(0, 100 - 25*critical - 15*high)
"""

import logging

from auditlog.models import AuditLog, Severity
from vault.models import VaultRecord

logger = logging.getLogger(__name__)


def test_posture_requires_token(api_client):
    assert api_client.get("/security/posture").status_code == 401


def test_clean_system_scores_100_with_zero_vulns(auth_client):
    resp = auth_client.get("/security/posture")
    assert resp.status_code == 200
    body = resp.json()
    assert body["posture_score"] == 100
    assert body["critical"] == 0
    assert body["high"] == 0
    assert body["medium"] == 0
    assert body["low"] == 0
    assert body["info"] == 0
    assert body["vault_count"] == 0
    assert body["audit_events_24h"] == 0
    assert body["last_event_at"] is None


def test_posture_reflects_vault_and_audit_activity(auth_client, vault_record):
    """
    One created record -> one info audit row: critical/high stay 0, the score
    stays 100, but vault_count / audit_events_24h / info move together.
    """
    resp = auth_client.get("/security/posture")
    assert resp.status_code == 200
    body = resp.json()
    assert body["posture_score"] == 100
    assert body["vault_count"] == 1
    assert body["audit_events_24h"] == 1
    assert body["info"] == 1
    assert body["last_event_at"] is not None


def test_posture_counts_deletion_as_high_and_docks_score(auth_client, vault_record):
    """
    Deleting the fixture record emits one warning row: high=1, score drops
    to 85 (100 - 15*1), critical stays 0.
    """
    assert auth_client.delete(f"/vault/{vault_record.pk}").status_code == 204
    resp = auth_client.get("/security/posture")
    assert resp.status_code == 200
    body = resp.json()
    assert body["high"] == 1
    assert body["critical"] == 0
    assert body["posture_score"] == 85


def test_posture_drops_to_0_when_flooded_with_critical_events(auth_client):
    """
    Formula floor: five critical rows exceed 100 damage, so the score must
    clamp at 0 rather than going negative.
    """
    # Emit 5 critical severity rows straight into the ORM so the severity
    # is fully under test control.
    for i in range(5):
        AuditLog.objects.create(action="intrusion", target_id=None, severity=Severity.CRITICAL, message=f"intrusion #{i}")
    resp = auth_client.get("/security/posture")
    assert resp.status_code == 200
    body = resp.json()
    assert body["critical"] == 5
    assert body["posture_score"] == 0
