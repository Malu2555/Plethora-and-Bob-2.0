"""
Vault domain models.

`VaultRecord` stores a confidential blob owned by exactly one user. Records
may only be touched through `vault.api` endpoints, which enforce both JWT
authentication and object-level ownership — probes on other users' records
return 404 (identical to "not found") so resource existence is never leaked.

All queries stay in the ORM; raw SQL is forbidden by design (see
tests/test_no_raw_sql.py).
"""

import logging

from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)


class VaultRecord(models.Model):
    """
    A single confidential record inside a user's vault.

    Fields:
        title       -- short human-readable label (unique per owner)
        secret_data -- confidential payload, treated as opaque text and never
                       written to any log line (only lengths are logged)
        owner       -- FK to the owning user; records vanish with the account
        created_at  -- insertion timestamp (auto-set on create)
    """

    title = models.CharField(
        max_length=200,
        db_index=True,
        help_text="Human-readable label",
    )
    secret_data = models.TextField(
        help_text="Confidential payload (opaque, never logged)",
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vault_records",
        db_index=True,
        help_text="User that owns this record",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]  # newest first on every list
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "title"],
                name="uniq_vault_title_per_owner",
            ),
        ]

    def __str__(self) -> str:  # pragma: no cover - console/admin nicety
        return f"VaultRecord<{self.title!r} owner={getattr(self, 'owner_id', None)}>"

    @classmethod
    def visible_to(cls, user):
        """
        Return the queryset of records visible to `user`.

        `select_related("owner")` resolves the FK with one SQL join so schema
        serialization never triggers N+1 queries.
        """
        return cls.objects.filter(owner=user)
