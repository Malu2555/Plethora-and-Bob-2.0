"""R5 absent_tests -- flag a missing or uncollectable test suite."""

import logging
import subprocess
import sys

logger = logging.getLogger(__name__)

COLLECT_TIMEOUT_S = 180


def check(*, root, routers, options):
    """
    Two gates, in order of severity:

      1. critical -- backend/tests/ is absent or holds no test_*.py modules.
      2. warning  -- `pytest --collect-only` fails in that tree (only when
         the `collect_tests` option is enabled; unit tests run it off so the
         suite never re-runs itself, the CLI/default scan runs it on).
    """
    del routers  # filesystem rule: router registry unused
    collect_tests = bool(options.get("collect_tests"))
    tests_dir = root / "tests"
    files = (
        sorted(p for p in tests_dir.rglob("test_*.py") if p.is_file())
        if tests_dir.exists()
        else []
    )
    findings = []

    if not files:
        findings.append(
            {
                "rule_id": "absent_tests",
                "severity": "critical",
                "file_path": "tests/",
                "line_no": None,
                "message": (
                    "no test suite present under backend/tests/ -- "
                    "the regression net is absent"
                ),
            }
        )
        return findings

    if collect_tests:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "--collect-only", "-q"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=COLLECT_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover
            logger.warning("absent_tests collect failed: %s", exc)
            findings.append(
                {
                    "rule_id": "absent_tests",
                    "severity": "warning",
                    "file_path": "tests/",
                    "line_no": None,
                    "message": f"test collection could not run: {exc}",
                }
            )
            return findings
        if result.returncode != 0:
            tail = (result.stderr or result.stdout or "").strip().splitlines()
            hint = tail[-1] if tail else "unknown collection error"
            findings.append(
                {
                    "rule_id": "absent_tests",
                    "severity": "warning",
                    "file_path": "tests/",
                    "line_no": None,
                    "message": f"test collection failed: {hint}",
                }
            )
    return findings
