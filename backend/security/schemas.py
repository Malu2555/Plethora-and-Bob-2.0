"""
Pydantic schemas for the scanner-facing security endpoints.

Findings travel WITH their prose guidance (`why` / `recommended`) attached so
the dashboard renders a self-contained drill-down panel; those fields always
ship registry prose, never code, keeping the UI firmly observational.
"""

import logging
from datetime import datetime

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ScanIn(BaseModel):
    """Payload accepted by POST /api/v1/security/scan."""

    branch: str | None = Field(default=None, max_length=64)
    rule_ids: list[str] | None = None
    runtime_probe: bool = True
    collect_tests: bool = False


class ScanAcceptedOut(BaseModel):
    """202 envelope: the client polls GET /scan/runs until finished_at."""

    scan_run_id: int
    status: str  # "queued" or "completed" (sync mode)
    detail: str | None = None


class ScanRunOut(BaseModel):
    """One persisted scan execution for the dashboard history list."""

    id: int
    branch: str
    trigger: str
    started_at: datetime
    finished_at: datetime | None
    exit_code: int | None
    findings_total: int
    rules_run: str


class FindingOut(BaseModel):
    """One finding + registry prose for the drill-down panel."""

    id: int
    rule_id: str
    severity: str
    file_path: str
    line_no: int | None
    message: str
    why: str
    recommended: str


class RuleAggOut(BaseModel):
    """Per-rule rollup: the seven dashboard tiles."""

    rule_id: str
    label: str
    weight: int
    severity: str
    count: int
    why: str
    recommended: str


class FindingsOut(BaseModel):
    """Complete snapshot consumed by SecurityPage.vue."""

    scan: ScanRunOut | None
    total: int
    findings_deduction: int  # capped posture deduction from the latest scan
    by_rule: list[RuleAggOut]
    items: list[FindingOut]


class RunsOut(BaseModel):
    """Scan history envelope (newest first, short page)."""

    items: list[ScanRunOut]
    count: int
