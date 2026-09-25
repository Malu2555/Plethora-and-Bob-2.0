"""
Schemas for the audit telemetry feed.
"""

import logging
from datetime import datetime

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AuditLogOut(BaseModel):
    """One audit row as delivered to the dashboard telemetry feed."""

    id: int
    action: str
    target_id: int | None
    message: str
    severity: str
    username: str
    created_at: datetime


def to_out(row) -> AuditLogOut:
    """
    Serialize one AuditLog row for the feed.

    `row.user` may be None after account deletion (SET_NULL) — render the
    actor as 'system' in that case. Built explicitly because ninja 1.7's
    response wrapper does not run resolve_* methods during model_validate.
    """
    return AuditLogOut(
        id=row.id,
        action=row.action,
        target_id=row.target_id,
        message=row.message,
        severity=row.severity,
        username=row.user.username if row.user is not None else "system",
        created_at=row.created_at,
    )

