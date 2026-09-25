"""
Scanner API contract: the three security endpoints (findings snapshot, scan
history, scan trigger) plus the posture v2 attribution split.

POST /scan is exercised in sync mode (SECURITY_SCAN_SYNC=True) so assertions
never race a background thread; the endpoint response shape is identical in
threaded mode and is covered by the 202/409/422 contracts here.
"""

import logging

from django.test import override_settings
from django.utils import timezone

from security.models import Finding, ScanRun

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Authentication envelope
# --------------------------------------------------------------------------


def test_scanner_endpoints_require_token(api_client):
    assert api_client.get("/security/findings").status_code == 401
    assert api_client.get("/security/scan/runs").status_code == 401
    assert api_client.post("/security/scan", json={}).status_code == 401


# --------------------------------------------------------------------------
# GET /findings
# --------------------------------------------------------------------------


def test_findings_empty_snapshot(auth_client):
    resp = auth_client.get("/security/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan"] is None
    assert body["total"] == 0
    assert body["findings_deduction"] == 0
    assert len(body["by_rule"]) == 7
    rule_ids = {r["rule_id"] for r in body["by_rule"]}
    assert rule_ids == {
        "raw_sql", "missing_auth", "hardcoded_secret", "missing_rate_limit",
        "absent_tests", "n_plus_one", "missing_pydantic",
    }
    assert all(r["count"] == 0 for r in body["by_rule"])
    assert all(r["why"] for r in body["by_rule"])  # prose ships even when empty


def test_findings_reflects_latest_run(db, auth_client):
    run = ScanRun.objects.create(branch="flawed", trigger="test", exit_code=1)
    Finding.objects.create(
        scan_run=run,
        rule_id="hardcoded_secret",
        severity="critical",
        file_path="vault/config.py",
        line_no=7,
        message="credential-shaped literal (value redacted)",
        fingerprint=Finding.make_fingerprint("hardcoded_secret", "vault/config.py", 7),
    )
    run.findings_total = 1
    run.save(update_fields=["findings_total"])

    resp = auth_client.get("/security/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan"]["branch"] == "flawed"
    assert body["total"] == 1
    # weight(25) hardcoded_secret, capped at 80 -> full deduction
    assert body["findings_deduction"] == 25
    rule = next(r for r in body["by_rule"] if r["rule_id"] == "hardcoded_secret")
    assert rule["count"] == 1
    assert body["items"][0]["file_path"] == "vault/config.py"
    assert body["items"][0]["why"]  # guidance attached


# --------------------------------------------------------------------------
# GET /scan/runs
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# POST /scan
# --------------------------------------------------------------------------


def test_start_scan_rejects_unknown_rule(auth_client):
    resp = auth_client.post("/security/scan", json={"rule_ids": ["borrowed_code"]})
    assert resp.status_code == 422


@override_settings(SECURITY_SCAN_SYNC=True)
def test_start_scan_sync_mode_completes_clean_tree(db, auth_client):
    resp = auth_client.post(
        "/security/scan",
        json={"branch": "unit", "runtime_probe": False, "collect_tests": False},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "completed"
    run = ScanRun.objects.get(pk=body["scan_run_id"])
    assert run.exit_code == 0  # clean tree: zero findings, green CI gate
    assert run.findings_total == 0
    assert run.finished_at is not None


def test_start_scan_conflicts_while_running(auth_client, monkeypatch):
    import security.api as api_module

    monkeypatch.setattr(api_module, "_ACTIVE_RUN_ID", 999)
    resp = auth_client.post("/security/scan", json={})
    assert resp.status_code == 409
    assert "999" in resp.json()["detail"]


def test_posture_v2_weighs_findings_with_attribution(db, auth_client):
    """One critical finding (25) + clean audit -> score 75, split attribution."""
    run = ScanRun.objects.create(
        branch="flawed", trigger="test", exit_code=1, finished_at=timezone.now()
    )
    Finding.objects.create(
        scan_run=run,
        rule_id="raw_sql",
        severity="critical",
        message="interpolated query text",
        fingerprint=Finding.make_fingerprint("raw_sql", "vault/api.py", 10),
    )
    run.findings_total = 1
    run.save(update_fields=["findings_total"])

    resp = auth_client.get("/security/posture")
    assert resp.status_code == 200
    body = resp.json()
    assert body["posture_score"] == 75
    assert body["findings_deduction"] == 25
    assert body["findings_total"] == 1
    assert body["audit_deduction"] == 0
    assert body["last_scan_branch"] == "flawed"
    assert body["last_scan_exit_code"] == 1


def test_posture_findings_deduction_is_capped(db, auth_client):
    """Five hardcoded_secret findings (125 raw) must cap at 80 -> score 20."""
    run = ScanRun.objects.create(branch="flawed", trigger="test", exit_code=1)
    for i in range(5):
        Finding.objects.create(
            scan_run=run,
            rule_id="hardcoded_secret",
            severity="critical",
            message=f"credential-shaped literal #{i} (value redacted)",
            fingerprint=Finding.make_fingerprint("hardcoded_secret", f"x{i}.py", i),
        )
    resp = auth_client.get("/security/posture")
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings_deduction"] == 80
    assert body["posture_score"] == 20


def test_scan_history_lists_newest_first(db, auth_client):
    older = ScanRun.objects.create(branch="a", trigger="cli", exit_code=0)
    newer = ScanRun.objects.create(branch="b", trigger="api", exit_code=1)
    resp = auth_client.get("/security/scan/runs")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 2
    ids = [r["id"] for r in body["items"]]
    assert ids.index(newer.pk) < ids.index(older.pk)
