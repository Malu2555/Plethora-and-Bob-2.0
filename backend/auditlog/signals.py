"""
Signal handlers that turn VaultRecord mutations into audit events.

Connected in `AuditlogConfig.ready()`. Each handler writes exactly one
AuditLog row via AuditLog.emit (pure ORM) and the write is also visible in
backend/logs/sentinel.log.
"""

import logging

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from auditlog.models import AuditLog, Severity
from vault.models import VaultRecord

logger = logging.getLogger(__name__)


def _actor_of(instance):
    """
    Resolve the acting user without crashing if the account vanished.

    The FK access costs one indexed lookup when the relation was not already
    preloaded (select_related in vault.views usually preloads it).
    """
    if instance.owner_id is None:
        return None
    try:
        return instance.owner
    except Exception:  # pragma: no cover - dangling FK edge case
        logger.exception("audit.signal actor unresolved for VaultRecord %s", instance.pk)
        return None


@receiver(post_save, sender=VaultRecord)
def audit_vault_save(sender, instance, created, **kwargs):
    """Convert every create/update into an info-severity audit row."""
    action = "create" if created else "update"
    AuditLog.emit(
        user=_actor_of(instance),
        action=action,
        target_id=instance.pk,
        message=f"{action} VaultRecord #{instance.pk} '{instance.title}'",
        severity=Severity.INFO,
    )


@receiver(post_delete, sender=VaultRecord)
def audit_vault_delete(sender, instance, **kwargs):
    """Convert every delete into a warning-severity audit row."""
    AuditLog.emit(
        user=_actor_of(instance),
        action="delete",
        target_id=instance.pk,
        message=f"delete VaultRecord #{instance.pk} '{instance.title}'",
        severity=Severity.WARNING,
    )
