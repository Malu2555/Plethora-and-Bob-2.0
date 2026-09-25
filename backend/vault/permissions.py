"""
Ownership guards shared by every vault endpoint.

Returning 404 (rather than 403) when a record exists but belongs to another
user hides resource existence — a deliberate anti-enumeration / IDOR measure.
Each denial is logged at WARNING so attempted cross-user access is greppable
in backend/logs/sentinel.log.
"""

import logging

from django.http import Http404

from vault.models import VaultRecord

logger = logging.getLogger(__name__)


def get_owned_or_404(user, pk: int) -> VaultRecord:
    """
    Fetch a VaultRecord by `pk` ONLY if it belongs to `user`.

    The ownership condition is enforced by the ORM-filtered query itself (no
    post-fetch check in Python, no raw SQL).

    Raises:
        Http404: record missing, or owned by someone else — indistinguishable
                 to a caller without the right to see it.
    """
    try:
        return VaultRecord.visible_to(user).get(pk=pk)
    except VaultRecord.DoesNotExist:
        logger.warning(
            "vault.access_denied user=%s pk=%s (missing or cross-user)", user.pk, pk
        )
        raise Http404("Vault record not found.")
