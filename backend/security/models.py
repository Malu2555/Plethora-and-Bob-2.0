"""
Security scanner models.

This app previously held no models; the posture aggregation in `api.py` only
mirrored `AuditLog`. The scanner changes that with two NEW tables that are
deliberately kept apart from `AuditLog`:

    ScanRun  -- one row per scanner execution (branch, timings, exit state)
    Finding  -- one row per flagged code location inside a run

The separation matters because the two streams have different semantics:
`AuditLog` records runtime facts (something HAPPENED), while a Finding is a
static snapshot (something IS in the code right now). Findings are therefore
idempotent per scan -- keyed by a fingerprint of rule + file + line -- and are
never written through the audit signals, so scanner traffic stays invisible
to the runtime telemetry feed.
"""

import hashlib
import logging

from django.db import models

logger = logging.getLogger(__name__)


class FindingSeverity(models.TextChoices):
    """Severity ladder for static findings (extends auditlog's with HIGH)."""

    INFO = "info", "Info"
    WARNING = "warning", "Warning"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class ScanRun(models.Model):
    """
    One scanner execution against the checked-out tree.

    `exit_code` mirrors a CLI convention: 0 = no critical findings, 1 = at
    least one critical finding. UI-triggered scans record the same contract
    so the dashboard history and the command line agree.
    """

    branch = models.CharField(
        max_length=64,
        default="worktree",
        db_index=True,
        help_text="Branch or worktree label the scanner was pointed at",
    )
    trigger = models.CharField(
        max_length=16,
        default="cli",
        help_text="What started the scan: cli / api / test",
    )
    started_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    exit_code = models.SmallIntegerField(
        null=True, blank=True, help_text="0 = clean, 1 = critical findings"
    )
    findings_total = models.PositiveIntegerField(
        default=0, help_text="Number of findings stored for this run"
    )
    rules_run = models.CharField(
        max_length=256, blank=True, default="", help_text="Comma list of rule ids"
    )

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:  # pragma: no cover - console/admin nicety
        return f"ScanRun<{self.branch} at={self.started_at} exit={self.exit_code}>"


class Finding(models.Model):
    """
    One flagged code location, immutable facts discovered by a rule.

    The rule writes ONLY evidence (file, line, message, severity). Fix
    guidance is looked up from `security.weights` at render time and is
    prose-only by design -- nothing in this model can mutate source code.
    """

    scan_run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="findings",
        db_index=True,
        help_text="Scan execution that observed this finding",
    )
    rule_id = models.CharField(
        max_length=32,
        db_index=True,
        help_text="Registry key from security.weights (e.g. raw_sql)",
    )
    severity = models.CharField(
        max_length=16,
        choices=FindingSeverity.choices,
        default=FindingSeverity.INFO,
        db_index=True,
    )
    file_path = models.CharField(
        max_length=512,
        blank=True,
        default="",
        help_text="Location relative to backend/ (empty for runtime probes)",
    )
    line_no = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="1-based source line, when the evidence is textual",
    )
    message = models.TextField(help_text="One-line evidence summary")
    fingerprint = models.CharField(
        max_length=64,
        db_index=True,
        help_text="sha256(rule|file|line) -- idempotent UPSERT key per scan",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["rule_id", "file_path", "line_no"]
        constraints = [
            models.UniqueConstraint(
                fields=["scan_run", "fingerprint"],
                name="uniq_finding_per_scan",
            ),
        ]

    def __str__(self) -> str:  # pragma: no cover - console/admin nicety
        return f"Finding<{self.rule_id} {self.file_path}:{self.line_no}>"

    @staticmethod
    def make_fingerprint(rule_id: str, file_path: str, line_no) -> str:
        """Deterministic key so re-scans UPSERT instead of duplicating."""
        location = f"{rule_id}|{file_path or ''}|{line_no or 0}"
        return hashlib.sha256(location.encode("utf-8")).hexdigest()[:64]
