"""
Security posture API for the dashboard.

    GET    /api/v1/security/posture      -> 200 aggregate snapshot consumed by:
        PostureScoreGauge.vue      (posture_score + deduction attribution)
        AuditTelemetryTiles.vue    (critical / high / medium / low / info)
        MetricsTiles.vue           (vault_count / audit_events_24h / last_event_at)
    GET    /api/v1/security/findings     -> 200 latest scan + per-rule rollups
    GET    /api/v1/security/scan/runs    -> 200 scan history (newest first)
    POST   /api/v1/security/scan         -> 202 {scan_run_id} starts a scan job
                                            409 while another scan is running
                                            422 unknown rule id in payload

Two streams, never mixed: the posture score now weighs BOTH the runtime audit
telemetry (events that happened, last 24h) and the latest static scan
(Findings: code-state snapshot). Findings live in their own tables -- never
in AuditLog -- so scanner output stays invisible to the telemetry feed.

Posture v2 formula (pinned here, asserted in the test suite):

    score = max(0, 100 - findings_deduction - 25*critical - 15*high)

with findings_deduction = min(80, SUM(weight * count) over the latest run).

POST /scan runs the job in a background thread (daemon). When Django is
configured with SECURITY_SCAN_SYNC=True the scan executes inline before the
202 returns -- used by the test suite to keep assertions deterministic.
"""

import logging
import threading
from collections import Counter
from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone
from ninja import Router
from ninja.errors import HttpError
from ninja.responses import Status
from ninja.throttling import UserRateThrottle
from ninja_jwt.authentication import JWTAuth
from pydantic import BaseModel

from auditlog.models import AuditLog, Severity
from security.models import Finding, ScanRun
from security.weights import (
    FINDINGS_DEDUCTION_CAP,
    RULE_GUIDANCE,
    RULE_IDS,
    RULE_LABELS,
    RULE_SEVERITY,
    RULE_WEIGHTS,
)
from vault.models import VaultRecord
from security.schemas import (
    FindingOut,
    FindingsOut,
    RuleAggOut,
    RunsOut,
    ScanAcceptedOut,
    ScanIn,
    ScanRunOut,
)

logger = logging.getLogger(__name__)

router = Router(tags=["Security"], auth=JWTAuth())

# POST /scan is a mutating endpoint: it must carry a throttle (R4 contract).
SCAN_THROTTLE = UserRateThrottle("12/m")

# Single-flight guard: one scan per process. A daemon thread runs the job so
# the request returns immediately; the dashboard polls /scan/runs.
_SCAN_LOCK = threading.Lock()
_ACTIVE_RUN_ID = None


class PostureOut(BaseModel):
    """Aggregate snapshot rendered by the dashboard homepage."""

    posture_score: int  # 0..100; 100 minus findings + audit deductions
    critical: int  # severity=critical rows within 24h
    high: int  # severity=warning rows within 24h (e.g. deletions)
    medium: int  # reserved for future scanner integrations
    low: int  # reserved for future scanner integrations
    info: int  # severity=info rows within 24h
    vault_count: int  # total VaultRecords across the system
    audit_events_24h: int  # total audit rows within 24h
    last_event_at: datetime | None  # timestamp of newest audit row
    # --- posture v2: attribution split for the gauge tooltip ---
    findings_deduction: int  # capped deduction from the latest scan run
    findings_total: int  # findings on the latest scan run
    audit_deduction: int  # uncapped deduction from the 24h audit window
    last_scan_finished_at: datetime | None
    last_scan_branch: str | None
    last_scan_exit_code: int | None


def _findings_deduction(run) -> tuple[int, int]:
    """
    Compute (deduction, total) for the latest scan run; (0, 0) when the app
    has never been scanned. Deduction is capped (FINDINGS_DEDUCTION_CAP).
    """
    if run is None:
        return 0, 0
    rule_counts = Counter(
        Finding.objects.filter(scan_run=run).values_list("rule_id", flat=True)
    )
    raw = sum(RULE_WEIGHTS[rule_id] * count for rule_id, count in rule_counts.items())
    total = sum(rule_counts.values())
    return min(raw, FINDINGS_DEDUCTION_CAP), total


@router.get("/posture", response=PostureOut)
def posture_snapshot(request):
    """
    Compute the security snapshot in one readable function.

    Scoring formula (pinned here so the frontend and the test suite rely on
    the same numbers):

        score = max(0, 100 - findings_deduction - 25*critical - 15*high)

    where findings_deduction is the weight-sum over the LATEST scan run's
    findings (capped at 80) and the audit terms count the last 24h of
    telemetry. A fresh deployment therefore reports 100.
    """
    window_start = timezone.now() - timedelta(hours=24)
    since = {"created_at__gte": window_start}

    critical = AuditLog.objects.filter(severity=Severity.CRITICAL, **since).count()
    high = AuditLog.objects.filter(severity=Severity.WARNING, **since).count()
    info = AuditLog.objects.filter(severity=Severity.INFO, **since).count()
    vault_count = VaultRecord.objects.count()
    audit_events = AuditLog.objects.filter(**since).count()
    last_event = (
        AuditLog.objects.order_by("-created_at")
        .values_list("created_at", flat=True)
        .first()
    )

    latest_run = ScanRun.objects.order_by("-started_at", "-id").first()
    findings_deduction, findings_total = _findings_deduction(latest_run)
    audit_deduction = critical * 25 + high * 15
    score = max(0, 100 - findings_deduction - audit_deduction)

    logger.info(
        "posture.snapshot score=%d findings=%d(-%d) critical=%d high=%d vault=%d",
        score,
        findings_total,
        findings_deduction,
        critical,
        high,
        vault_count,
    )
    return PostureOut(
        posture_score=score,
        critical=critical,
        high=high,
        medium=0,  # no medium/low sources exist yet (documented limitation)
        low=0,
        info=info,
        vault_count=vault_count,
        audit_events_24h=audit_events,
        last_event_at=last_event,
        findings_deduction=findings_deduction,
        findings_total=findings_total,
        audit_deduction=audit_deduction,
        last_scan_finished_at=latest_run.finished_at if latest_run else None,
        last_scan_branch=latest_run.branch if latest_run else None,
        last_scan_exit_code=latest_run.exit_code if latest_run else None,
    )


# --------------------------------------------------------------------------
# Scanner-facing endpoints (findings snapshot, history, scan trigger)
# --------------------------------------------------------------------------

RUNS_PAGE_LIMIT = 20


def _to_run_out(run) -> ScanRunOut:
    return ScanRunOut(
        id=run.pk,
        branch=run.branch,
        trigger=run.trigger,
        started_at=run.started_at,
        finished_at=run.finished_at,
        exit_code=run.exit_code,
        findings_total=run.findings_total,
        rules_run=run.rules_run,
    )


def _to_finding_out(finding) -> FindingOut:
    """Attach the rule's prose guidance -- the dashboard renders it as-is."""
    guidance = RULE_GUIDANCE.get(finding.rule_id, {"why": "", "recommended": ""})
    return FindingOut(
        id=finding.pk,
        rule_id=finding.rule_id,
        severity=finding.severity,
        file_path=finding.file_path,
        line_no=finding.line_no,
        message=finding.message,
        why=guidance["why"],
        recommended=guidance["recommended"],
    )


@router.get("/findings", response=FindingsOut)
def findings_snapshot(request):
    """
    Latest scan run (if any) + the seven per-rule rollups + every stored
    finding with its prose guidance attached. The empty state is meaningful:
    total == 0 with scan == null means the tree has never been scanned.
    """
    latest_run = ScanRun.objects.order_by("-started_at", "-id").first()

    if latest_run is not None:
        rule_counts = Counter(
            Finding.objects.filter(scan_run=latest_run).values_list(
                "rule_id", flat=True
            )
        )
    else:
        rule_counts = Counter()

    by_rule = []
    for rule_id in RULE_IDS:
        guidance = RULE_GUIDANCE[rule_id]
        by_rule.append(
            RuleAggOut(
                rule_id=rule_id,
                label=RULE_LABELS[rule_id],
                weight=RULE_WEIGHTS[rule_id],
                severity=RULE_SEVERITY[rule_id],
                count=rule_counts.get(rule_id, 0),
                why=guidance["why"],
                recommended=guidance["recommended"],
            )
        )

    findings = list(Finding.objects.filter(scan_run=latest_run)) if latest_run else []
    deduction, _total = _findings_deduction(latest_run)

    logger.info(
        "security.findings user=%s scan=%s total=%d",
        request.auth.pk,
        "none" if latest_run is None else latest_run.pk,
        len(findings),
    )
    return FindingsOut(
        scan=_to_run_out(latest_run) if latest_run else None,
        total=len(findings),
        findings_deduction=deduction,
        by_rule=by_rule,
        items=[_to_finding_out(f) for f in findings],
    )


@router.get("/scan/runs", response=RunsOut)
def scan_history(request):
    """Newest-first scan history (latest RUNS_PAGE_LIMIT rows)."""
    runs = ScanRun.objects.all()[:RUNS_PAGE_LIMIT]
    total = ScanRun.objects.count()
    logger.info("security.scan_runs user=%s total=%d", request.auth.pk, total)
    return RunsOut(items=[_to_run_out(r) for r in runs], count=total)

def _run_scan_job(branch, rule_ids, runtime_probe, collect_tests):
    """Background worker for POST /scan; always clears the single-flight lock."""
    global _ACTIVE_RUN_ID
    import django.db
    from security.scanner import run_scan_and_store

    try:
        run = run_scan_and_store(
            branch=branch,
            trigger="api",
            rule_ids=rule_ids,
            runtime_probe=runtime_probe,
            collect_tests=collect_tests,
        )
        logger.info("security.scan job finished run=%s", run.pk)
    except Exception:  # pragma: no cover - thread boundary
        logger.exception("security.scan job crashed")
    finally:
        # Close worker-held connections so dev SQLite frees its file handle.
        django.db.connections.close_all()
        with _SCAN_LOCK:
            _ACTIVE_RUN_ID = None


@router.post("/scan", response={202: ScanAcceptedOut}, throttle=SCAN_THROTTLE)
def start_scan(request, payload: ScanIn):
    """
    Queue (or run) a scanner pass over the live tree (202).

    Contract:
        202 {scan_run_id, status}  -- scan queued (sync mode: completed)
        409                         -- an earlier scan is still running
        422                         -- unknown rule id in payload
    """
    from security.scanner import run_scan_and_store, selected_rules

    try:
        pending = list(selected_rules(payload.rule_ids)) if payload.rule_ids else []
    except ValueError as exc:
        raise HttpError(422, str(exc)) from exc

    branch = (payload.branch or "").strip() or "worktree"
    sync_mode = bool(getattr(settings, "SECURITY_SCAN_SYNC", False))

    global _ACTIVE_RUN_ID
    with _SCAN_LOCK:
        if _ACTIVE_RUN_ID is not None:
            active = _ACTIVE_RUN_ID
            raise HttpError(409, f"A scan is already running (run #{active}).")

    if sync_mode:
        # Test/dev convenience: run inline so callers can assert on the
        # stored rows without racing a thread (see SECURITY_SCAN_SYNC).
        run = run_scan_and_store(
            branch=branch,
            trigger="api",
            rule_ids=payload.rule_ids,
            runtime_probe=payload.runtime_probe,
            collect_tests=payload.collect_tests,
        )
        return Status(202, ScanAcceptedOut(scan_run_id=run.pk, status="completed"))

    # Placeholder row first: the dashboard shows the job as "running" while
    # polling the history endpoint.
    placeholder = ScanRun.objects.create(
        branch=branch,
        trigger="api",
        rules_run=",".join(pending) if pending else ",".join(RULE_IDS),
    )
    with _SCAN_LOCK:
        _ACTIVE_RUN_ID = placeholder.pk
    worker = threading.Thread(
        target=_run_scan_job,
        args=(branch, payload.rule_ids, payload.runtime_probe, payload.collect_tests),
        daemon=True,
        name="security-scan",
    )
    worker.start()
    logger.info(
        "security.scan queued run=%s branch=%s rules=%s",
        placeholder.pk,
        branch,
        ",".join(pending) if pending else "all",
    )
    return Status(202, ScanAcceptedOut(scan_run_id=placeholder.pk, status="queued"))