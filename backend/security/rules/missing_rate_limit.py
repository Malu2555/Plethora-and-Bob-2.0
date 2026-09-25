"""R4 missing_rate_limit -- flag mutating endpoints without a throttle."""

import logging

from security.rules.helpers import view_location

logger = logging.getLogger(__name__)

# Read-only (GET-only) operations are exempt: they are authenticated, bounded
# and do not change state, so throttling them adds friction without closing a
# real attack path. Everything else -- create, update, delete, credential
# issuance -- must carry an explicit per-operation throttle.
MUTATING_METHODS = {"POST", "PATCH", "PUT", "DELETE"}


def check(*, root, routers, options):
    """Flag operations with mutating methods and zero throttle objects."""
    del root, options  # registry-only rule
    findings = []
    for prefix, router in routers:
        for path, path_view in router.path_operations.items():
            for operation in path_view.operations:
                if not (MUTATING_METHODS & set(operation.methods)):
                    continue
                if operation.throttle_objects:
                    continue
                file_path, line_no = view_location(operation.view_func)
                display = f"/{prefix}{path}".replace("//", "/")
                findings.append(
                    {
                        "rule_id": "missing_rate_limit",
                        "severity": "high",
                        "file_path": file_path,
                        "line_no": line_no,
                        "message": (
                            f"mutating endpoint {display} "
                            f"({','.join(sorted(operation.methods))}) has no rate-limit throttle"
                        ),
                    }
                )
    return findings
