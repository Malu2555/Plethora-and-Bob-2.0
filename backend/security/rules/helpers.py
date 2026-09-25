"""Shared helpers for the scanner rules (router registry + file walk)."""

import inspect
import logging
from pathlib import Path

from ninja.constants import NOT_SET

logger = logging.getLogger(__name__)

# Canonical route registry. The scanner trusts the LIVE ninja routers rather
# than grepping decorators, so a rename or re-mount here moves the route
# surface every rule sees. Kept lazy so unit tests never import Django.
_SCAN_DIRS = ("monitor", "vault", "auditlog", "security")

# Never walk these subtrees: tests fixtures use deliberately broken patterns,
# migrations are historical, and the scanner's own machinery is the
# instrument, not the measured surface.
EXCLUDED_DIR_PARTS = {
    "tests",
    "migrations",
    "management",
    "rules",
    "__pycache__",
    "logs",
    ".venv",
}

# Detector definition files are excluded from the source-heuristic rules so
# the instrument cannot flag itself.
EXCLUDED_FILES = {
    "security/scanner.py",
    "security/weights.py",
    "security/models.py",
    "security/schemas.py",
}

# Public routes allowed to run without auth BY DESIGN (credential endpoints).
PUBLIC_PATH_WHITELIST = {
    ("auth", "/token"),
    ("auth", "/refresh"),
    ("auth", "/register"),
}


def default_routers():
    """
    Lazy [(prefix, Router)] manifest mirroring monitor/urls.py.

    Imported on demand: `security.scanner` is imported by `security.api` at
    request time, and this in turn imports `security.api` -- safe because the
    module is fully loaded by then.
    """
    from auditlog.api import router as audit_router
    from monitor.auth_api import router as auth_router
    from security.api import router as security_router
    from vault.api import router as vault_router

    return [
        ("auth", auth_router),
        ("vault", vault_router),
        ("audit", audit_router),
        ("security", security_router),
    ]


def iter_source_files(root: Path):
    """
    Yield (rel_path, source_text) for every scannable Python file under
    backend/{monitor,vault,auditlog,security}, excluding tests, migrations,
    the scanner itself and any management commands.
    """
    for dirname in _SCAN_DIRS:
        base = root / dirname
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            rel = path.resolve().relative_to(root.resolve())
            parts = rel.parts
            if any(part in EXCLUDED_DIR_PARTS for part in parts[:-1]):
                continue
            if rel.as_posix() in EXCLUDED_FILES or rel.name in EXCLUDED_FILES:
                continue
            try:
                yield rel.as_posix(), path.read_text(encoding="utf-8")
            except UnicodeDecodeError:  # pragma: no cover - binary edge case
                logger.warning("scanner skipped non-utf8 file %s", rel)


def view_location(view_func):
    """
    Resolve (rel_path, line_no) for a router handler using inspect.

    `rel_path` is relative to backend/ (posix separators) so findings stay
    portable across checkouts and operating systems.
    """
    try:
        source_file = inspect.getsourcefile(view_func)
        _, start_line = inspect.getsourcelines(view_func)
    except (OSError, TypeError):  # pragma: no cover - defensive fallback
        return "", None
    if not source_file:
        return "", None
    path = Path(source_file).resolve()
    parts = path.parts
    if "backend" in parts:
        idx = parts.index("backend")
        rel = "/".join(parts[idx + 1 :])
    else:
        rel = path.name
    return rel, start_line


def effective_auth(operation, router):
    """
    The authenticator an operation actually runs with: explicit per-operation
    value first, otherwise the router default (NOT_SET -> None = public).
    """
    if operation.auth_param is not NOT_SET:
        return operation.auth_param
    if router.auth is not NOT_SET:
        return router.auth
    return None
