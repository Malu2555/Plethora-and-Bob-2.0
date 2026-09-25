"""R6 n_plus_one -- runtime probe: query fan-out on populated list routes."""

import logging

logger = logging.getLogger(__name__)

# (method, path, query budget). Budgets assume the clean tree's join strategy
# (one SELECT for the rows, one for the joined owner). Anything above reveals
# per-row query fan-out on a populated dataset. Margin of one for defence.
PROBES = (
    ("GET", "/vault/", 3),
    ("GET", "/audit/", 3),
)

POPULATE_ROWS = 20  # plural enough that per-row fan-out is unmistakable


def check(*, root, routers, options):
    """
    Populate rows for a throwaway user INSIDE a rollback-only transaction,
    hit each list route with an authenticated client and count queries with
    Django's query capture. Everything -- user, rows, audit events -- is
    rolled back at the end, so the probe leaves zero traces.

    Skipped when `runtime_probe` is off (pure static scans / unit tests that
    do not want database traffic).
    """
    del root, routers  # probe rule: talks to the API, not the registry
    if not options.get("runtime_probe"):
        return []

    # Imports stay local so importing this module never requires Django DB.
    from django.contrib.auth import get_user_model
    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext
    from ninja.testing import TestClient
    from ninja_jwt.tokens import RefreshToken

    from monitor.urls import api
    from vault.models import VaultRecord

    findings = []
    User = get_user_model()
    client = TestClient(api)
    try:
        with transaction.atomic():
            probe_user = User.objects.create_user(
                username="__scanner_probe__",
                password="sentinel-scanner-probe-only",
            )
            # ninja-jwt's type stubs incorrectly model this classmethod.
            token: RefreshToken = RefreshToken.for_user(probe_user)  # pyright: ignore[reportAttributeAccessIssue]
            client.headers = {"Authorization": f"Bearer {token.access_token}"}

            for i in range(POPULATE_ROWS):
                VaultRecord.objects.create(
                    owner=probe_user,
                    title=f"scanner-probe-{i:02d}",
                    secret_data="probe-payload",
                )

            for method, path, budget in PROBES:
                with CaptureQueriesContext(connection) as ctx:
                    response = getattr(client, method.lower())(path)
                queries = len(ctx.captured_queries)
                if response.status_code != 200:
                    logger.warning(
                        "n_plus_one probe %s %s -> %d", method, path, response.status_code
                    )
                    continue
                if queries > budget:
                    findings.append(
                        {
                            "rule_id": "n_plus_one",
                            "severity": "warning",
                            "file_path": path,
                            "line_no": None,
                            "message": (
                                f"{method} {path} executed {queries} queries on "
                                f"{POPULATE_ROWS} rows (budget {budget}) -- "
                                "probable per-row query fan-out"
                            ),
                        }
                    )
            # Nothing from this synthetic fixture may survive the probe.
            transaction.set_rollback(True)
    except Exception:  # pragma: no cover - probe must never kill a scan
        logger.exception("n_plus_one probe raised; rolling back")
        try:
            transaction.set_rollback(True)
        except Exception:  # pragma: no cover
            logger.exception("rollback failed")
    return findings
