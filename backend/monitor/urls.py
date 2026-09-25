"""
URL configuration for the Sentinel Monitor backend.

A single core NinjaAPI is mounted under /api/v1/ so every dashboard capability
lives under one versioned prefix:

    POST   /api/v1/auth/token           -> JWT access + refresh pair
    POST   /api/v1/auth/refresh         -> fresh access token
    POST   /api/v1/auth/register        -> 201 created (+ JWT pair, auto-login)
    GET    /api/v1/vault                -> 200 list of the caller's VaultRecords
    POST   /api/v1/vault                -> 201 created (+ Location header)
    GET    /api/v1/vault/{id}           -> 200 record detail
    PATCH  /api/v1/vault/{id}           -> 200 updated record
    DELETE /api/v1/vault/{id}           -> 204 deleted
    GET    /api/v1/audit                -> 200 paginated telemetry feed
    GET    /api/v1/security/posture     -> 200 aggregate security snapshot

Interactive OpenAPI docs are served by django-ninja at /api/v1/docs.
"""

import logging

from django.contrib import admin
from django.urls import path
from ninja import NinjaAPI

from auditlog.api import router as audit_router
from monitor.auth_api import router as auth_router
from security.api import router as security_router
from vault.api import router as vault_router

logger = logging.getLogger(__name__)

api = NinjaAPI(
    title="Sentinel Monitor API",
    version="1.0.0",
    description=(
        "Security posture snapshots, audit telemetry and per-user vault CRUD "
        "for the Sentinel Monitor Dashboard."
    ),
)

# NOTE: authentication is declared per-router (JWTAuth) rather than API-wide
# so the JWT token/refresh endpoints stay public — otherwise no client could
# ever obtain a token in the first place.
api.add_router("auth", auth_router, tags=["Auth"])
api.add_router("vault", vault_router, tags=["Vault"])
api.add_router("audit", audit_router, tags=["Audit"])
api.add_router("security", security_router, tags=["Security"])

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", api.urls),
]

logger.info("Sentinel API registered at /api/v1/ (4 routers mounted)")

