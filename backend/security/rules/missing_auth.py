"""R2 missing_auth -- flag routes with no effective authenticator."""

import logging

from security.rules.helpers import (
    PUBLIC_PATH_WHITELIST,
    effective_auth,
    view_location,
)

logger = logging.getLogger(__name__)


def check(*, root, routers, options):
    """
    Inspect every operation on the mounted routers. A route is flagged when:

      * its (prefix, path) is not on the PUBLIC_PATH_WHITELIST, AND
      * neither the operation nor its router resolves an authenticator.

    The whitelist exists because the credential endpoints must stay anonymous
    or no client could ever log in; everything else must be protected.
    """
    del root, options  # registry-only rule
    findings = []
    for prefix, router in routers:
        for path, path_view in router.path_operations.items():
            for operation in path_view.operations:
                if (prefix, path) in PUBLIC_PATH_WHITELIST:
                    continue
                auth = effective_auth(operation, router)
                if auth is not None:
                    continue
                file_path, line_no = view_location(operation.view_func)
                display = f"/{prefix}{path}".replace("//", "/")
                findings.append(
                    {
                        "rule_id": "missing_auth",
                        "severity": "critical",
                        "file_path": file_path,
                        "line_no": line_no,
                        "message": (
                            f"endpoint {display} ({','.join(operation.methods)}) "
                            "runs with no effective authenticator"
                        ),
                    }
                )
    return findings
