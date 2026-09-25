"""
App configuration for the Sentinel audit log domain.
"""

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class AuditlogConfig(AppConfig):
    """Registers the vault mutation signal receivers when Django starts."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "auditlog"

    def ready(self):
        # Importing the module performs the receiver registration (side
        # effect) — this MUST run after the ORM is loaded, hence ready().
        from auditlog import signals  # noqa: F401

        logger.info("auditlog signals registered")
