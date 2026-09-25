"""
Audit trail models for the Sentinel Monitor backend.

Every mutation on `VaultRecord` emits exactly one AuditLog row via
`auditlog.signals`. The trail powers:

  * the live telemetry feed (GET /api/v1/audit)
  * the vulnerability counters on the dashboard (severity != info rows
    count against the posture score)

The model is append-only: there are no update/delete endpoints, so the
trail is immutable by construction.
"""

import logging

from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)


class Severity(models.TextChoices):
    """Severity ladder consumed by the dashboard's vulnerability counters."""

    INFO = "info", "Info"
    WARNING = "warning", "Warning"
    CRITICAL = "critical", "Critical"


class AuditLog(models.Model):
    """
    Append-only record of a security-relevant event.

    Fields:
        user       -- actor that triggered the event (SET_NULL on account
                      deletion so history survives)
        action     -- machine-readable verb: create / update / delete
        target_id  -- PK of the affected VaultRecord (or NULL for system events)
        message    -- human-readable description for the telemetry feed
        severity   -- info (creates/updates) or warning (deletes)
        created_at -- event timestamp (auto-set on insert)
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,  # history survives account deletion
        null=True,
        blank=True,
        related_name="audit_events",
        db_index=True,
        help_text="Actor that triggered the event (may be NULL for system events)",
    )
    action = models.CharField(
        max_length=32,
        db_index=True,
        help_text="Machine-readable verb, e.g. create/update/delete",
    )
    target_id = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="PK of the affected model row",
    )
    message = models.TextField(help_text="Human-readable description for the feed")
    severity = models.CharField(
        max_length=16,
        choices=Severity.choices,
        default=Severity.INFO,
        db_index=True,
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]  # newest first; matches the feed default

    def __str__(self) -> str:  # pragma: no cover - console/admin nicety
        return f"AuditLog<{self.action} by={getattr(self.user, 'pk', None)} at={self.created_at}>"

    @classmethod
    def emit(cls, *, user, action, target_id=None, message, severity=Severity.INFO):
        """
        Factory used by `auditlog.signals` — one INSERT, pure ORM.
        """
        row = cls.objects.create(
            user=user,
            action=action,
            target_id=target_id,
            message=message,
            severity=severity,
        )
        logger.info(
            "audit.emit action=%s severity=%s target=%s user=%s",
            action,
            severity,
            target_id,
            getattr(user, "pk", None),
        )
        return row
