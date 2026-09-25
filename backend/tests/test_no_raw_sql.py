"""
Static guard: the Sentinel backend must never use raw SQL.

Django offers everything this project needs through the ORM, so any
`raw(...)` / `extra(...)` / cursor usage would be a regression that reopens
the project to SQL injection. This test scans the source tree and fails
loudly if it finds those constructs.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCANNED_DIRS = ("vault", "auditlog", "security", "monitor")

FORBIDDEN = (
    ".raw(",
    ".extra(",
    "RawSQL(",
    "connection.cursor",
    "connections[",
)


def test_no_raw_sql_in_backend_source():
    """Fail if any Sentinel source module uses raw SQL primitives."""
    offending = []
    for dirname in SCANNED_DIRS:
        for path in (BACKEND_ROOT / dirname).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for pattern in FORBIDDEN:
                if pattern in text:
                    offending.append(f"{path.relative_to(BACKEND_ROOT)} uses `{pattern}`")
    assert not offending, "Raw SQL detected:\n  " + "\n  ".join(sorted(offending))
