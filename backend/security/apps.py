"""
App configuration for the Sentinel security domain.
"""

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class SecurityConfig(AppConfig):
    """Simple config; posture aggregations live in api.py."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "security"
