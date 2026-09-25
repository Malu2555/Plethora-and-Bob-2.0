"""
security_scan -- run the vulnerability scanner from the command line.

    python manage.py security_scan                 # full scan, persisted
    python manage.py security_scan --dry-run       # print only, nothing stored
    python manage.py security_scan --rule raw_sql --rule n_plus_one
    python manage.py security_scan --no-runtime-probe   # static rules only

Exit code contract (CI-gate friendly):

    * 0 -- scan finished with no critical findings
    * 1 -- scan finished with at least one critical finding
    * 2 -- misconfiguration (unknown rule id, etc.)

The scan is observational: it reads the backend tree and the live router
registry, persists a ScanRun + Findings snapshot, and never edits source.
"""

import logging
import os
import sys

from django.core.management.base import BaseCommand, CommandError

from security.scanner import BACKEND_ROOT, collect_findings, run_scan_and_store
from security.weights import RULE_IDS

logger = logging.getLogger(__name__)

# A named worktree label beats a path hash in the scan history; operators can
# pin it via SENTINEL_SCAN_BRANCH for CI (otherwise the repo dir name).
DEFAULT_BRANCH = os.environ.get("SENTINEL_SCAN_BRANCH") or BACKEND_ROOT.parent.name or "worktree"


class Command(BaseCommand):
    """Invoked as `manage.py security_scan`."""

    help = "Scan backend/{monitor,vault,auditlog,security} for the 7 vulnerability classes."

    def add_arguments(self, parser):
        parser.add_argument(
            "--rule",
            action="append",
            choices=RULE_IDS,
            dest="rule_ids",
            help="Run only this rule (repeatable); default = all 7.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print findings to stdout without writing ScanRun/Finding rows.",
        )
        parser.add_argument(
            "--branch",
            default=None,
            help="Branch label stored on the ScanRun (default: checkout dir name).",
        )
        parser.add_argument(
            "--no-runtime-probe",
            action="store_true",
            help="Skip the N+1 runtime probe (static source rules only).",
        )
        parser.add_argument(
            "--no-collect-tests",
            action="store_true",
            help="Skip the pytest collection subprocess used by absent_tests.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        branch = options["branch"] or DEFAULT_BRANCH
        rule_ids = options["rule_ids"] or None
        runtime_probe = not options["no_runtime_probe"]
        collect_tests = not options["no_collect_tests"]

        try:
            if dry_run:
                drafts, _ = collect_findings(
                    root=BACKEND_ROOT,
                    rule_ids=rule_ids,
                    runtime_probe=runtime_probe,
                    collect_tests=collect_tests,
                )
                print_findings(self.stdout, drafts)
                if any(d["severity"] == "critical" for d in drafts):
                    sys.exit(1)
                return

            run = run_scan_and_store(
                branch=branch,
                trigger="cli",
                rule_ids=rule_ids,
                runtime_probe=runtime_probe,
                collect_tests=collect_tests,
            )
            self.stdout.write(
                f"scan #{run.pk} '{run.branch}' -> {run.findings_total} finding(s), "
                f"exit_code={run.exit_code}"
            )
            sys.exit(run.exit_code)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc


def print_findings(stdout, drafts):
    """Render a dry-run result table grouped by rule (no database needed)."""
    if not drafts:
        stdout.write("0 findings — the scanned tree is clean.")
        return
    by_rule = {}
    for d in drafts:
        by_rule.setdefault(d["rule_id"], []).append(d)
    for rule_id, items in by_rule.items():
        stdout.write(f"[{rule_id}] {len(items)} finding(s)")
        for d in sorted(items, key=lambda x: (x.get("file_path") or "", x.get("line_no") or 0)):
            location = f"{d.get('file_path') or '-'}:{d.get('line_no') or '-'}"
            stdout.write(f"    {d['severity']:<8} {location:<40} {d['message']}")
