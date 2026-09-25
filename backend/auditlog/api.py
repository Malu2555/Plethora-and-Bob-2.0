"""
Audit API — the read-only telemetry feed.

    GET /api/v1/audit -> 200 {items, count} newest-first, limit/offset

No mutation endpoints exist on purpose: rows are written exclusively by
domain signals, so the trail cannot be tampered with through the API.
Pagination is performed with ORM slicing (SQL-side LIMIT/OFFSET) and rows are
serialized explicitly.
"""

import logging

from ninja import Router
from ninja_jwt.authentication import JWTAuth
from pydantic import BaseModel

from auditlog.models import AuditLog
from auditlog.schemas import AuditLogOut, to_out

logger = logging.getLogger(__name__)

router = Router(tags=["Audit"], auth=JWTAuth())


class AuditPage(BaseModel):
    """Limit/offset envelope mirrored by the frontend feed component."""

    items: list[AuditLogOut]
    count: int


def _clamp_int(raw, default, lo, hi):
    """Parse a query param into a bounded integer; fall back to `default`."""
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


@router.get("/", response=AuditPage)
def list_audit(request):
    """
    Return audit rows newest-first inside a {items, count} envelope.

    select_related("user") joins the actor in one SQL round-trip; slicing the
    queryset pushes LIMIT/OFFSET down to SQL instead of materializing the
    whole table in Python.
    """
    limit = _clamp_int(request.GET.get("limit"), default=50, lo=1, hi=100)
    offset = _clamp_int(request.GET.get("offset"), default=0, lo=0, hi=100_000)

    qs = AuditLog.objects.select_related("user")
    total = qs.count()
    rows = qs[offset : offset + limit]
    items = [to_out(row) for row in rows]

    logger.info(
        "audit.list user=%s total=%d limit=%d offset=%d",
        request.auth.pk,
        total,
        limit,
        offset,
    )
    return AuditPage(items=items, count=total)
