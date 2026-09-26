"""
Scanner entry point for the security dashboard.

`collect_findings` runs the seven rules from `security.rules` and returns
plain evidence dicts (storage-free, testable). `run_scan_and_store` wraps
that in a persisted ScanRun with idempotent Finding UPSERTs keyed by
fingerprint, then closes the run with an exit code the CLI can propagate.

Design notes:

    * Routers are introspected live (ninja template routers expose their full
      path/operation table) so the registry can never drift from the real
      mount points in monitor/urls.py.
    * Each rule runs in isolation: a failing rule logs and is skipped, never
      aborting the scan.
    * The scanner only READS the codebase. Nothing here edits a file.
"""

import logging
from pathlib import Path

from django.utils import timezone

from security.models import Finding, ScanRun
from security.rules import ALL_RULES
from security.weights import RULE_IDS, RULE_SEVERITY

logger = logging.getLogger(__name__)

BACKEND_ROOT = Path(__file__).resolve().parents[1]

# Severity ladder for the exit-code contract (see models.ScanRun).
CRITICAL_SEVERITY = "critical"


def _default_options(runtime_probe: bool, collect_tests: bool) -> dict:
    return {"runtime_probe": runtime_probe, "collect_tests": collect_tests}


def selected_rules(rule_ids=None) -> dict:
    """Validate + slice ALL_RULES; an unknown id raises ValueError."""
    if not rule_ids:
        return dict(ALL_RULES)
    unknown = sorted(set(rule_ids) - set(ALL_RULES))
    if unknown:
        raise ValueError(f"unknown rule(s): {', '.join(unknown)}")
    return {rule_id: ALL_RULES[rule_id] for rule_id in RULE_IDS if rule_id in rule_ids}


def collect_findings(*, root=BACKEND_ROOT, routers=None, rule_ids=None, runtime_probe=True, collect_tests=False):
    """
    Execute every selected rule and flatten their evidence dicts.

    Returns (drafts, per_rule_log) where drafts is the ordered list of
    finding dicts and per_rule_log maps rule_id -> error string for any rule
    that raised (logged, not re-raised: one bad rule must not sink a scan).
    """
    from security.rules.helpers import default_routers

    if routers is None:
        routers = default_routers()
    options = _default_options(runtime_probe, collect_tests)
    rules = selected_rules(rule_ids)

    drafts = []
    per_rule_log = {}
    for rule_id in RULE_IDS:
        check = rules.get(rule_id)
        if check is None:
            continue
        try:
            rule_drafts = check(root=root, routers=routers, options=options)
            drafts.extend(rule_drafts)
            logger.info("scanner.rule %s -> %d finding(s)", rule_id, len(rule_drafts))
        except Exception:  # pragma: no cover - resilience path
            logger.exception("scanner rule %s failed; continuing", rule_id)
            per_rule_log[rule_id] = "rule raised during the scan (see backend logs)"
    return drafts, per_rule_log


def run_scan_and_store(
    *,
    root=None,
    branch="worktree",
    trigger="cli",
    rule_ids=None,
    runtime_probe=True,
    collect_tests=False,
):
    """
    Run a full scan and persist it as a new ScanRun.

    `root` overrides the scanned backend tree (default: this checkout's
    `backend/`). Only the source-file rules follow it -- registry and runtime
    rules always introspect the live Django process, which is why the CLI
    documents `--root` as a source-scope switch.

    Every run gets its own rows (history is append-only across runs); within
    a run, evidence dicts colliding on the same (rule, file, line)
    fingerprint are UPSERTed via update_or_create so duplicate rules cannot
    double-store the same location. Returns the persisted ScanRun.
    """
    drafts, per_rule_log = collect_findings(
        root=Path(root).resolve() if root else BACKEND_ROOT,
        rule_ids=rule_ids,
        runtime_probe=runtime_probe,
        collect_tests=collect_tests,
    )

    run = ScanRun.objects.create(
        branch=branch,
        trigger=trigger,
        rules_run=",".join(selected_rules(rule_ids)),
    )

    for draft in drafts:
        rule_id = draft["rule_id"]
        file_path = draft.get("file_path") or ""
        line_no = draft.get("line_no")
        fingerprint = Finding.make_fingerprint(rule_id, file_path, line_no)
        defaults = {
            "rule_id": rule_id,
            "severity": draft.get("severity", RULE_SEVERITY[rule_id]),
            "file_path": file_path,
            "line_no": line_no,
            "message": draft["message"],
        }
        # update_or_create on the (scan_run, fingerprint) unique pair -> no dupes.
        Finding.objects.update_or_create(
            scan_run=run,
            fingerprint=fingerprint,
            defaults=defaults,
        )

    has_critical = Finding.objects.filter(
        scan_run=run, severity=CRITICAL_SEVERITY
    ).exists()
    run.exit_code = 1 if has_critical else 0
    run.findings_total = Finding.objects.filter(scan_run=run).count()
    run.finished_at = timezone.now()
    run.save(update_fields=["exit_code", "findings_total", "finished_at"])

    if per_rule_log:
        logger.warning("scan completed with rule errors: %s", sorted(per_rule_log))
    logger.info(
        "scanner.done branch=%s findings=%d exit=%d trigger=%s",
        branch,
        run.findings_total,
        run.exit_code,
        trigger,
    )
    return run
