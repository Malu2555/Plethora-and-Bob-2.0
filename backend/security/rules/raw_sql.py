"""R1 raw_sql -- flag string-built database statements in the API surface."""

import logging
import re

from security.rules.helpers import iter_source_files

logger = logging.getLogger(__name__)

# Detector primitives are spelled with escaped dots/parens on purpose: (a) so
# the regex can never match itself, and (b) so the project's own static guard
# over forbidden literals stays green. Each entry maps pattern -> human label.
RAW_SQL_PATTERNS = (
    (re.compile(r"\.raw\(\s*[\"']"), "queryset built from a literal string"),
    (re.compile(r"\.extra\(\s*[\"',(]"), "queryset extended with a literal clause"),
    (re.compile(r"connection\.cursor\s*\("), "direct database cursor"),
    (re.compile(r"\bcursor\.execute\s*\("), "direct query execution"),
    (re.compile(r"\.execute\(\s*f[\"']"), "interpolated query text"),
    (re.compile(r"select\s+.*from\s", re.IGNORECASE), "literal statement text"),
)

MAX_FINDINGS = 50


def _line_no(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def check(*, root, routers, options):
    """
    Walk backend/{monitor,vault,auditlog,security} and flag whole-line matches
    for any raw-SQL primitive. One finding per offending line, capped so a
    deliberate stress-file cannot flood the store.
    """
    del routers, options  # source-heuristic rule: router registry unused
    findings = []
    for rel_path, source in iter_source_files(root):
        for pattern, label in RAW_SQL_PATTERNS:
            for match in pattern.finditer(source):
                line_no = _line_no(source, match.start())
                line = source.splitlines()[line_no - 1].strip()
                findings.append(
                    {
                        "rule_id": "raw_sql",
                        "severity": "critical",
                        "file_path": rel_path,
                        "line_no": line_no,
                        "message": f"{label} ({line[:160]})",
                    }
                )
                if len(findings) >= MAX_FINDINGS:
                    logger.warning("raw_sql cap hit; truncating at %d", MAX_FINDINGS)
                    return findings
    return findings
