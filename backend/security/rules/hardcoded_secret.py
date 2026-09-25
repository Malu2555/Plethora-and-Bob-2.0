"""R3 hardcoded_secret -- flag credential-shaped literals in source files."""

import logging
import re
from pathlib import Path

from security.rules.helpers import EXCLUDED_DIR_PARTS, EXCLUDED_FILES

logger = logging.getLogger(__name__)

# `key = "value"` assignments (yml-prototype `key: "value"` also matches the
# separator class). The value must look credentials-shaped to skip constants
# like window sizes or file names.
SECRET_NAME = r"(secret(?:_key)?|api[_ ]?key|apikey|password|passwd|token|access[_ ]?key)"
ASSIGNMENT_RE = re.compile(
    r"\b" + SECRET_NAME + r"\b\s*[:=]\s*[\"']([^\"']{16,64})[\"']", re.IGNORECASE
)

# Files ending in these suffixes are treated as config-shaped and scanned too.
CONFIG_SUFFIXES = (".env.example", ".env.sample", ".toml", ".json", ".yaml", ".yml")

MAX_FINDINGS = 50


def _looks_secret(value: str) -> bool:
    """Minimal entropy heuristic: mixed case + digits, 16+ chars."""
    return (
        len(value) >= 16
        and any(ch.isupper() for ch in value)
        and any(ch.islower() for ch in value)
        and any(ch.isdigit() for ch in value)
    )


def _iter_config_files(root: Path):
    for suffix in CONFIG_SUFFIXES:
        for path in sorted(root.rglob(f"*{suffix}")):
            if path.name == ".env":
                continue  # the real env file is gitignored; ignore leftovers
            rel = path.resolve().relative_to(root.resolve())
            if any(part in EXCLUDED_DIR_PARTS for part in rel.parts[:-1]):
                continue
            if rel.as_posix() in EXCLUDED_FILES:
                continue
            yield rel.as_posix(), path.read_text(encoding="utf-8", errors="replace")


def check(*, root, routers, options):
    """
    Scan source AND config-shaped files for literal credentials.

    Two filters keep the clean tree green: scripted `gets from the environment
    carry no quoted literal after the separator, and low-entropy fallbacks
    (all-lowercase dev placeholders) are rejected by the entropy heuristic.
    """
    del routers, options  # source-heuristic rule: router registry unused
    findings = []
    scanned = [("source", *item) for item in _iter_py(root)]
    scanned += [("config", *item) for item in _iter_config_files(root)]
    for kind, rel_path, source in scanned:
        lines = source.splitlines()
        for match in ASSIGNMENT_RE.finditer(source):
            value = match.group(2).strip()  # group 1 is the key NAME, 2 the value
            if not _looks_secret(value):
                continue
            line_no = source.count("\n", 0, match.start()) + 1
            # Redact the secret text itself: findings are evidence, not leaks.
            line = lines[line_no - 1].split("=", 1)[0].split(":", 1)[0].strip()
            findings.append(
                {
                    "rule_id": "hardcoded_secret",
                    "severity": "critical",
                    "file_path": rel_path,
                    "line_no": line_no,
                    "message": (
                        f"{kind} file assigns a credential-shaped literal to "
                        f"'{match.group(0).split()[0].rstrip(':= ')}' (value redacted)"
                    ),
                }
            )
            if len(findings) >= MAX_FINDINGS:
                logger.warning("hardcoded_secret cap hit; truncating at %d", MAX_FINDINGS)
                return findings
    return findings


def _iter_py(root: Path):
    """Yield (rel_path, source) for scannable Python files under backend/."""
    from security.rules.helpers import iter_source_files

    return iter_source_files(root)
