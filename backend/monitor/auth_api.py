"""
JWT authentication endpoints (pair issuance + refresh).

Implemented directly on ninja_jwt.tokens instead of the ninja-extra router so
the auth surface stays on the core django-ninja stack and every status code
is explicit for the frontend:

    POST /api/v1/auth/token    -> 200 {access, refresh}
                                 401 invalid credentials
                                 422 malformed body
                                 429 too many attempts (anon IP throttle)
    POST /api/v1/auth/refresh  -> 200 {access}
                                 401 invalid/expired refresh token
    POST /api/v1/auth/register -> 201 {access, refresh, username} (auto-login)
                                 409 username/email already taken (generic)
                                 422 invalid fields or rejected password
                                 429 account-creation ceiling (own bucket)

The credential endpoints are IP-rate-limited (30/min) as a brute-force guard;
register gets a dedicated stricter bucket (12/min) — see *_THROTTLE below.
"""

import logging

from django.contrib.auth import (
    authenticate,
    get_user_model,
    password_validation,
)
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError
from ninja import Router
from ninja.errors import HttpError
from ninja.responses import Status
from ninja.throttling import AnonRateThrottle
from ninja_jwt.exceptions import TokenError
from ninja_jwt.tokens import RefreshToken
from pydantic import BaseModel, Field

from auditlog.models import AuditLog

logger = logging.getLogger(__name__)

router = Router(tags=["Auth"])

# Brute-force guard on the credential endpoints: 30 attempts/min per IP.
AUTH_THROTTLE = AnonRateThrottle("30/m")


class RegisterThrottle(AnonRateThrottle):
    """
    Dedicated slower bucket for account creation (12/min per IP).

    A distinct `scope` gives it its own throttle cache key, so a registration
    storm cannot starve legitimate login/refresh traffic (and vice versa).
    """

    scope = "anon-register"


REGISTER_THROTTLE = RegisterThrottle("12/m")

# Shape-only guardrails; the real strength checks are Django's
# AUTH_PASSWORD_VALIDATORS, run explicitly inside the register handler.
EMAIL_PATTERN = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
USERNAME_PATTERN = r"^[A-Za-z0-9._-]+$"


class TokenIn(BaseModel):
    """Credentials accepted by POST /auth/token."""

    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=128)


class TokenOut(BaseModel):
    """JWT pair returned on successful authentication."""

    access: str
    refresh: str


class RefreshIn(BaseModel):
    """Refresh token accepted by POST /auth/refresh."""

    refresh: str = Field(min_length=1)


class AccessOut(BaseModel):
    """Fresh access token returned by POST /auth/refresh."""

    access: str


@router.post("/token", response=TokenOut, auth=None, throttle=AUTH_THROTTLE)
def obtain_token(request, payload: TokenIn):
    """
    Validate credentials and mint an access + refresh JWT pair (200).

    401 with the identical body regardless of which field was wrong, so the
    endpoint cannot be used to enumerate usernames.
    """
    user = authenticate(username=payload.username, password=payload.password)
    if user is None or not user.is_active:
        logger.warning("auth.failed username=%s", payload.username)
        raise HttpError(401, "Invalid credentials.")
    # ninja-jwt's type stubs incorrectly model this classmethod's receiver.
    refresh: RefreshToken = RefreshToken.for_user(user)  # pyright: ignore[reportAttributeAccessIssue]
    logger.info("auth.token user=%s", user.pk)
    return TokenOut(access=str(refresh.access_token), refresh=str(refresh))


@router.post("/refresh", response=AccessOut, auth=None, throttle=AUTH_THROTTLE)
def refresh_access(request, payload: RefreshIn):
    """
    Exchange a valid refresh token for a fresh access token (200).

    401 when the refresh token is invalid, expired or blacklisted.
    """
    try:
        refresh = RefreshToken(payload.refresh)
        access = str(refresh.access_token)
    except TokenError as exc:
        logger.warning("auth.refresh_failed reason=%s", exc)
        raise HttpError(401, "Invalid or expired refresh token.") from exc
    logger.info("auth.refresh ok")
    return AccessOut(access=access)


class RegisterIn(BaseModel):
    """Account-creation payload accepted by POST /auth/register."""

    username: str = Field(min_length=3, max_length=150, pattern=USERNAME_PATTERN)
    email: str = Field(min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(min_length=8, max_length=128)


class RegisterOut(BaseModel):
    """JWT pair + username returned after successful account creation."""

    access: str
    refresh: str
    username: str


@router.post(
    "/register",
    response={201: RegisterOut},
    auth=None,
    throttle=REGISTER_THROTTLE,
)
def register_account(request, payload: RegisterIn):
    """
    Create an account and sign the caller in immediately (201 + JWT pair).

    The SAME generic 409 is returned whether the username or the email is
    taken, so the endpoint cannot be used to enumerate either. Django's
    AUTH_PASSWORD_VALIDATORS are applied explicitly: weak/common/similar
    passwords are rejected with 422. Every registration emits an info-level
    audit row so account creation shows up in the telemetry feed.
    """
    User = get_user_model()
    username = payload.username.strip()
    email = payload.email.strip().lower()

    # One generic probe result for both identity collisions (anti-enumeration).
    if (
        User.objects.filter(username__iexact=username).exists()
        or User.objects.filter(email__iexact=email).exists()
    ):
        logger.warning("auth.register_exists username=%s", username)
        raise HttpError(409, "Account already exists.")

    candidate = User(username=username, email=email, is_active=True)
    try:
        password_validation.validate_password(payload.password, user=candidate)
    except DjangoValidationError as exc:
        raise HttpError(422, "; ".join(exc.messages)) from exc

    try:
        user = User.objects.create_user(
            username=username, email=email, password=payload.password
        )
    except IntegrityError as exc:  # lost the race on the unique username index
        logger.warning("auth.register_integrity username=%s", username)
        raise HttpError(409, "Account already exists.") from exc

    AuditLog.emit(
        user=user,
        action="register",
        target_id=user.pk,
        message=f"Account registered: {username}",
    )

    # ninja-jwt's type stubs incorrectly model this classmethod's receiver.
    refresh: RefreshToken = RefreshToken.for_user(user)  # pyright: ignore[reportAttributeAccessIssue]
    logger.info("auth.register user=%s", user.pk)
    return Status(
        201,
        RegisterOut(
            access=str(refresh.access_token),
            refresh=str(refresh),
            username=user.username,
        ),
    )
