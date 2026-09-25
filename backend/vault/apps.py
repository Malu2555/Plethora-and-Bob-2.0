"""
App configuration for the Sentinel vault domain.
"""

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class VaultConfig(AppConfig):
    """Lights up the vault app; no signal hooks of its own (auditlog listens)."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "vault"
