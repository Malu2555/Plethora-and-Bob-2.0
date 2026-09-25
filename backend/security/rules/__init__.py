"""
Rule package for the security scanner.

Each rule module exposes the SAME contract:

    check(*, root, routers, options) -> list[dict]

with every dict shaped as:

    {
        "rule_id":  "registry key from security.weights",
        "severity": "critical|high|warning|info",
        "file_path": "location relative to backend/ ('' for runtime probes)",
        "line_no":  1-based source line (None when not textual),
        "message":  one-line evidence summary (secrets always redacted),
    }

ALL_RULES preserves the presentation order defined in security.weights so the
scanner, the API and the dashboard agree on tile ordering.
"""

import logging

from security.rules import (  # noqa: F401  (re-exported for the scanner)
    absent_tests,
    hardcoded_secret,
    missing_auth,
    missing_pydantic,
    missing_rate_limit,
    n_plus_one,
    raw_sql,
)
from security.weights import RULE_IDS

logger = logging.getLogger(__name__)

ALL_RULES = {
    "raw_sql": raw_sql.check,
    "missing_auth": missing_auth.check,
    "hardcoded_secret": hardcoded_secret.check,
    "missing_rate_limit": missing_rate_limit.check,
    "absent_tests": absent_tests.check,
    "n_plus_one": n_plus_one.check,
    "missing_pydantic": missing_pydantic.check,
}

# Keep honest: the registry and the rule map must describe the same universe.
assert set(ALL_RULES) == set(RULE_IDS), "rule map diverged from weights registry"

logger.debug("security scanner: %d rules registered", len(ALL_RULES))
