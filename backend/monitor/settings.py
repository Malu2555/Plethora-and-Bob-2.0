"""
Settings for the Sentinel Monitor backend.

Covers:
  * secrets/flags from backend/.env (SENTINEL_* variables, dev fallbacks)
  * database engine switch: SQLite (dev) <-> PostgreSQL (prod)
  * CORS for the Vite dev server on :5173
  * Ninja throttling defaults (NINJA_DEFAULT_THROTTLE_RATES)
  * JWT lifetimes (NINJA_JWT)
  * structured logging to console + backend/logs/sentinel.log

Fresh-clone bootstrap: `python manage.py runserver` — backend/.env optional
for dev; production sets real environment variables.
"""

import logging
import os
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Secrets/flags live in backend/.env (gitignored — the single source of
# truth for local dev). Real environment variables (prod containers, CI)
# take precedence: load_dotenv never overrides variables already set.
load_dotenv(BASE_DIR / ".env")


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# The value comes from backend/.env (local dev) or the real environment
# (prod). The fallback below exists ONLY so a fresh clone boots without
# setup; never rely on it anywhere real (see .env.example).
SECRET_KEY = os.environ.get(
    "SENTINEL_SECRET_KEY", "django-insecure-dev-only-sentinel-9f3a2b1c"
)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("SENTINEL_DEBUG", "1") == "1"

_ALLOWED_HOSTS = os.environ.get("SENTINEL_ALLOWED_HOSTS")
ALLOWED_HOSTS = (
    _ALLOWED_HOSTS.split(",") if _ALLOWED_HOSTS else ["localhost", "127.0.0.1"]
)

# Render injects RENDER_EXTERNAL_HOSTNAME into every deployed process (free
# tier included). Append it so a fresh deploy is reachable without having to
# hand-copy the generated *.onrender.com hostname into SENTINEL_ALLOWED_HOSTS.
_RENDER_HOST = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "").strip()
if _RENDER_HOST and _RENDER_HOST not in ALLOWED_HOSTS:
    ALLOWED_HOSTS = [*ALLOWED_HOSTS, _RENDER_HOST]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # --- third-party ---
    'corsheaders',          # CORS allow-list for the Vite dev server
    'ninja',                # django-ninja framework app (checks, etc.)
    'ninja_extra',          # ninja-extra helpers used by django-ninja-jwt routers
    # --- sentinel domains ---
    'vault.apps.VaultConfig',
    'auditlog.apps.AuditlogConfig',
    'security.apps.SecurityConfig',
]

MIDDLEWARE = [
    # CorsMiddleware must sit as high as possible (it must see OPTIONS
    # preflight requests before CommonMiddleware can interfere).
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'monitor.urls'

# Explicit PK type for every app in this codebase (Django 3.2+ convention).
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'monitor.wsgi.application'


# Database
# https://docs.djangoproject.com/en/6.1/ref/settings/#databases
#
# Engine switching is driven by SENTINEL_DB_ENGINE:
#   sqlite     -> local/dev + tests (zero-config, backend/db.sqlite3)
#   postgresql -> production (psycopg 3, persistent pooled connections)
#
# PostgreSQL credentials come from SENTINEL_DB_NAME / SENTINEL_DB_USER /
# SENTINEL_DB_PASSWORD / SENTINEL_DB_HOST / SENTINEL_DB_PORT — none of
# them may ever sit in the repo (they live in backend/.env, gitignored).
DB_ENGINE = os.environ.get("SENTINEL_DB_ENGINE", "sqlite").strip().lower()

if DB_ENGINE == "postgresql":
    try:
        import psycopg  # noqa: F401  (Django 6.x talks to Postgres via psycopg 3)
    except ImportError as exc:
        raise ImproperlyConfigured(
            "SENTINEL_DB_ENGINE=postgresql but psycopg is not installed. "
            "Run: pip install 'psycopg[binary]>=3.2,<4.0'"
        ) from exc

    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("SENTINEL_DB_NAME", "sentinel"),
            "USER": os.environ.get("SENTINEL_DB_USER", "sentinel"),
            "PASSWORD": os.environ.get("SENTINEL_DB_PASSWORD", ""),
            "HOST": os.environ.get("SENTINEL_DB_HOST", "127.0.0.1"),
            "PORT": os.environ.get("SENTINEL_DB_PORT", "5432"),
            # Persistent connections skip the TCP+TLS handshake on repeat
            # queries; CONN_HEALTH_CHECKS makes psycopg re-validate them.
            "CONN_MAX_AGE": int(os.environ.get("SENTINEL_DB_CONN_MAX_AGE", "60")),
            "CONN_HEALTH_CHECKS": True,
        }
    }
else:  # default & explicit fallback: SQLite for local development and tests
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }


# Password validation
# https://docs.djangoproject.com/en/6.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.1/howto/static-files/

STATIC_URL = 'static/'


# --------------------------------------------------------------------------
# Cross-Origin Resource Sharing (dev: Vite frontend on :5173)
# --------------------------------------------------------------------------
_CORS = os.environ.get(
    "SENTINEL_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
)
CORS_ALLOWED_ORIGINS = [o.strip() for o in _CORS.split(",") if o.strip()]

# --------------------------------------------------------------------------
# Rate limiting (consumed by ninja.throttling.SimpleRateThrottle subclasses)
# --------------------------------------------------------------------------
# NOTE: rate strings must use the short unit form ("120/m"), NOT "120/min" —
# ninja's parser matches the shortest unit suffix first, so "/min" would die
# on "int('mi')" and raise "Invalid rate format".
NINJA_DEFAULT_THROTTLE_RATES = {
    "anon": "60/m",    # unauthenticated clients, keyed by IP
    "user": "120/m",   # authenticated users, keyed by user id
    "auth": "120/m",   # any authenticated principal (ninja `request.auth`)
    # Account creation gets its own, stricter bucket so registration spam
    # cannot starve login/refresh traffic (see RegisterThrottle in auth_api).
    "anon-register": "12/m",
}

# --------------------------------------------------------------------------
# JWT (django-ninja-jwt)
# --------------------------------------------------------------------------
NINJA_JWT = {
    # Access tokens are short-lived; the frontend refreshes them via
    # POST /api/v1/auth/refresh before the window closes.
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=2),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# --------------------------------------------------------------------------
# Cache (throttle history lives here; LocMem is fine for dev)
# --------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "sentinel-dev",
    }
}

# --------------------------------------------------------------------------
# Logging: console + rotating file under backend/logs/
# --------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} | {levelname:<8} | {name} | {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": BASE_DIR / "logs" / "sentinel.log",
            "maxBytes": 1024 * 1024,   # 1 MiB per file
            "backupCount": 5,          # keep at most 5 rotations
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "DEBUG" if DEBUG else "INFO",
    },
}

logger.info("Sentinel settings loaded DEBUG=%s DB=%s", DEBUG, DB_ENGINE)

# Email
# https://docs.djangoproject.com/en/6.1/topics/email/#topic-email-configuration

MAILERS = {
    'default': {
        'BACKEND': 'django.core.mail.backends.console.EmailBackend',
    },
}
