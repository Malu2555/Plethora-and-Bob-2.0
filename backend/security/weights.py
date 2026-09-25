"""
Rule registry for the security scanner.

Single source of truth consumed by three layers:

    * the scanner   (backend/security/scanner.py)  -- severity + weight per finding
    * the API       (backend/security/api.py)      -- posture deduction + aggregation
    * the dashboard (SecurityFindingsTiles.vue)    -- labels + prose guidance

Every entry carries two prose blocks -- `why` and `recommended` -- that the
dashboard renders VERBATIM. They are deliberately prose-only: the dashboard
observes the codebase, it never edits it, so no snippets are shipped here.
"""

import logging

logger = logging.getLogger(__name__)

# Order matters: it is the presentation order on the dashboard tiles.
RULE_IDS = (
    "raw_sql",
    "missing_auth",
    "hardcoded_secret",
    "missing_rate_limit",
    "absent_tests",
    "n_plus_one",
    "missing_pydantic",
)

# Posture deduction per single finding of each rule (tuned so one severe rule
# cannot instantly zero an otherwise healthy tree).
RULE_WEIGHTS = {
    "raw_sql": 25,
    "missing_auth": 25,
    "hardcoded_secret": 25,
    "missing_rate_limit": 15,
    "absent_tests": 15,
    "n_plus_one": 10,
    "missing_pydantic": 10,
}

# The findings deduction is capped so a noisy scanner never dominates the
# 0..100 posture score by itself.
FINDINGS_DEDUCTION_CAP = 80

# Severity ladder stored on each Finding row (independent of auditlog's ladder;
# findings are a static code-state fact, not a runtime event).
RULE_SEVERITY = {
    "raw_sql": "critical",
    "missing_auth": "critical",
    "hardcoded_secret": "critical",
    "missing_rate_limit": "high",
    "absent_tests": "high",
    "n_plus_one": "warning",
    "missing_pydantic": "warning",
}

RULE_LABELS = {
    "raw_sql": "Raw SQL",
    "missing_auth": "Missing Auth",
    "hardcoded_secret": "Hardcoded Secrets",
    "missing_rate_limit": "Missing Rate Limit",
    "absent_tests": "Absent Test Suite",
    "n_plus_one": "N+1 Queries",
    "missing_pydantic": "Missing Schema Validation",
}

RULE_WHY = {
    "raw_sql": (
        "String-built SQL lets attacker-controlled input escape the query "
        "grammar entirely. One interpolated search field is enough to read "
        "every row in the database; prepared statements make that class of "
        "bug structurally impossible."
    ),
    "missing_auth": (
        "An endpoint without an effective authentication layer is reachable "
        "by anyone who can guess the URL. Every route outside the credential "
        "endpoints must resolve a real authenticator, either per-operation or "
        "at the router level."
    ),
    "hardcoded_secret": (
        "A literal credential committed to source is leaked to every clone, "
        "fork, log and build artifact -- forever. Rotating it means changing "
        "code, not configuration. Secrets belong in the environment, with a "
        "placeholder in any committed example file."
    ),
    "missing_rate_limit": (
        "Mutating and credential endpoints without throttling can be brute-"
        "forced or flooded at whatever speed the attacker's connection "
        "allows. A per-client ceiling turns credential stuffing and spray "
        "attacks into a waiting game instead of a race."
    ),
    "absent_tests": (
        "An empty or missing test directory means no regression net exists: "
        "every refactor is an un-witnessed change and every security fix can "
        "be silently reverted. A suite that cannot even be collected is "
        "equivalent to having no suite at all."
    ),
    "n_plus_one": (
        "A list endpoint that issues one extra query per row scales badly and "
        "turns a single request into a cascade of database round-trips. "
        "Grepping for loops over lazily-evaluated querysets keeps this class "
        "of bottleneck out of the hot paths."
    ),
    "missing_pydantic": (
        "Untyped handler bodies skip validation entirely, so malformed or "
        "malicious payloads reach business logic untouched. Declaring a "
        "pydantic model per mutating endpoint restores strict shape and type "
        "guarantees at the API boundary."
    ),
}

RULE_RECOMMENDED = {
    "raw_sql": (
        "Express every read and write through the ORM's structured query "
        "builders so parameters are bound and quoted by the database driver. "
        "If a raw statement is truly unavoidable, pass values exclusively "
        "through bound placeholders. Never concatenate a parameter into the "
        "statement text."
    ),
    "missing_auth": (
        "Attach an authenticator to the endpoint directly, or rely on a "
        "router-level default that covers it. Keep the public surface limited "
        "to the credential endpoints that must remain anonymous, and re-"
        "evaluate every addition against that whitelist."
    ),
    "hardcoded_secret": (
        "Move the value into the environment and reference it through the "
        "settings layer, then rotate the compromised credential because it "
        "has already left the machine. All example files ship placeholders "
        "only, never usable values."
    ),
    "missing_rate_limit": (
        "Add a per-client throttle to every state-changing or credential-"
        "handling operation, sized to match real usage but low enough to "
        "slow down automated abuse. Public credential endpoints deserve the "
        "strictest buckets."
    ),
    "absent_tests": (
        "Restore a discoverable test package that the runner can collect, "
        "and gate merges on a green suite. Start with one contract test per "
        "endpoint; a small living suite beats a large unmaintained one."
    ),
    "n_plus_one": (
        "Preload the related rows a list endpoint serializes, so each joined "
        "foreign key resolves with a single query rather than one per row. "
        "Verify the fan-out stays flat by asserting the query count when "
        "records exist in plural."
    ),
    "missing_pydantic": (
        "Give every mutating handler an explicitly typed pydantic payload "
        "with field-level constraints; the framework then rejects wrong "
        "shapes before they reach domain logic. Handlers that only read "
        "query or path inputs are exempt."
    ),
}

# Maps rule_id -> 'why'/'recommended' prose for the API aggregation layer.
RULE_GUIDANCE = {
    rule_id: {"why": RULE_WHY[rule_id], "recommended": RULE_RECOMMENDED[rule_id]}
    for rule_id in RULE_IDS
}

logger.debug("security scanner registry: %d rules", len(RULE_IDS))
