"""
Vault CRUD API.

Every endpoint requires a valid JWT (JWTAuth) and is rate limited per user
(UserRateThrottle 120/m). Status-code contract:

    200  GET list / GET detail / PATCH success
    201  POST create (+ Location header)
    204  DELETE success
    401  missing, malformed or expired token (raised by JWTAuth)
    404  record absent OR owned by another user (anti-IDOR, permissions.py)
    422  schema violation (pydantic)
    429  throttle ceiling exceeded (Retry-After header included)

`secret_data` contents are never written to any log line — only lengths.
"""

import logging

from ninja import Router
from ninja.responses import Response, Status
from ninja.throttling import UserRateThrottle
from ninja_jwt.authentication import JWTAuth

from vault.models import VaultRecord
from vault.permissions import get_owned_or_404
from vault.schemas import VaultRecordIn, VaultRecordOut, VaultRecordPatch, to_out

logger = logging.getLogger(__name__)

# Shared router-wide auth + per-user throttle (120 requests / minute).
# NOTE: "/m" suffix, not "/min" — see the comment in monitor/settings.py.
router = Router(tags=["Vault"], auth=JWTAuth())
USER_THROTTLE = UserRateThrottle("120/m")


@router.get("/", response=list[VaultRecordOut], throttle=USER_THROTTLE)
def list_vault(request):
    """
    List every VaultRecord owned by the caller (200).

    `VaultRecord.visible_to` uses select_related("owner") so each row's user
    is fetched with ONE join — no N+1 queries during serialization.
    """
    records = [to_out(r) for r in VaultRecord.visible_to(request.auth)]
    logger.info("vault.list user=%s count=%d", request.auth.pk, len(records))
    return records


@router.post("/", response={201: VaultRecordOut}, throttle=USER_THROTTLE)
def create_vault(request, payload: VaultRecordIn):
    """
    Create a new VaultRecord for the caller (201 + Location header).

    The owner comes from the authenticated user, never from the payload — a
    client cannot mint a record on someone else's behalf.
    """
    record = VaultRecord.objects.create(
        title=payload.title,  # already whitespace-normalized by the schema
        secret_data=payload.secret_data,
        owner=request.auth,
    )
    logger.info(
        "vault.create user=%s pk=%s secret_len=%d",
        request.auth.pk,
        record.pk,
        len(payload.secret_data),
    )
    # Explicit Response helper so we can attach the RFC 7231 Location header.
    return Response(
        to_out(record),
        status=201,
        headers={"Location": f"/vault/{record.pk}"},
    )


@router.get("/{int:pk}", response=VaultRecordOut, throttle=USER_THROTTLE)
def get_vault(request, pk: int):
    """
    Return one of the caller's records (200), or 404 when absent/foreign.
    """
    record = get_owned_or_404(request.auth, pk)
    logger.info("vault.get user=%s pk=%s", request.auth.pk, pk)
    return to_out(record)


@router.patch("/{int:pk}", response=VaultRecordOut, throttle=USER_THROTTLE)
def update_vault(request, pk: int, payload: VaultRecordPatch):
    """
    Partially update the caller's record (200).

    `exclude_unset` keeps the diff honest: fields the client did not send
    are left untouched. Unsetting values is not supported — strict by design.
    """
    record = get_owned_or_404(request.auth, pk)  # 404 on IDOR / missing
    changes = payload.model_dump(exclude_unset=True)

    if "title" in changes and changes["title"] is not None:
        record.title = changes["title"]  # schema already stripped + validated
    if "secret_data" in changes and changes["secret_data"] is not None:
        record.secret_data = changes["secret_data"]

    if changes:
        record.save(
            update_fields=[k for k in changes if k in ("title", "secret_data")]
        )
    logger.info(
        "vault.update user=%s pk=%s fields=%s",
        request.auth.pk,
        pk,
        sorted(k for k in changes if changes[k] is not None),
    )
    return to_out(record)


@router.delete("/{int:pk}", response={204: None}, throttle=USER_THROTTLE)
def delete_vault(request, pk: int):
    """
    Delete one of the caller's records (204, empty body).

    The post_delete signal in `auditlog` emits a severity=warning audit row
    for every deletion — the trail cannot be severed through the API.
    """
    record = get_owned_or_404(request.auth, pk)
    record.delete()
    logger.info("vault.delete user=%s pk=%s", request.auth.pk, pk)
    return Status(204, None)
