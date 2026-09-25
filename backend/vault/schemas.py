"""
Pydantic request/response schemas for the vault API.

Strictness rules:
  * `title`       -- 1..200 chars; surrounding whitespace is stripped by a
                     validator and titles that end up empty are rejected (422)
  * `secret_data` -- 1..4096 chars (guards against accidental megabyte pastes)

Full-replace (PUT) semantics are intentionally absent: the PATCH schema keeps
partial updates explicit and easy to audit.
"""

import logging
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


def _clean_title(value: str | None) -> str | None:
    """
    Strip surrounding whitespace from a title; reject blanks.

    None passes through so PATCH payloads may omit the field entirely.
    """
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("title must not be blank")
    return cleaned


class VaultRecordIn(BaseModel):
    """Payload accepted by POST /api/v1/vault."""

    title: str = Field(min_length=1, max_length=200, description="Human-readable label")
    secret_data: str = Field(
        min_length=1, max_length=4096, description="Confidential payload"
    )

    @field_validator("title")
    @classmethod
    def _normalize_title(cls, v: str) -> str:
        """Strip whitespace; a whitespace-only title is a validation error."""
        return _clean_title(v)  # type: ignore[return-value]


class VaultRecordPatch(BaseModel):
    """Partial payload accepted by PATCH /api/v1/vault/{id}."""

    title: str | None = Field(default=None, min_length=1, max_length=200)
    secret_data: str | None = Field(default=None, min_length=1, max_length=4096)

    @field_validator("title")
    @classmethod
    def _normalize_title(cls, v: str | None) -> str | None:
        """Strip whitespace; a whitespace-only title is a validation error."""
        return _clean_title(v)


class VaultRecordOut(BaseModel):
    """
    Serialized VaultRecord as returned by every successful vault call.

    Built field-by-field by `to_out()` below (rather than relying on ninja's
    resolve_* mechanism, which the ninja 1.7 response wrapper does not run
    during model_validate for nested/ORM sources).
    """

    id: int
    title: str
    secret_data: str
    owner_username: str
    created_at: datetime


def to_out(record) -> VaultRecordOut:
    """
    Serialize a VaultRecord to its response schema.

    `record.owner` must be loaded — the callers always query through
    VaultRecord.visible_to() (select_related) or had the owner assigned
    during create(), so no extra query is issued here.
    """
    return VaultRecordOut(
        id=record.id,
        title=record.title,
        secret_data=record.secret_data,
        owner_username=record.owner.username,
        created_at=record.created_at,
    )

