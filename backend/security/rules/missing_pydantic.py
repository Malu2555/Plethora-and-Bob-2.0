"""R7 missing_pydantic -- mutating handlers must declare a pydantic body."""

import inspect
import logging

from pydantic import BaseModel

from security.rules.helpers import view_location

logger = logging.getLogger(__name__)

# DELETE handlers take no body by design (REST id-based removal); they are
# exempt. Every POST/PATCH/PUT handler must accept a pydantic-typed payload.
MUTATING_METHODS = {"POST", "PATCH", "PUT"}


def _has_pydantic_body(operation) -> bool:
    """
    True when the handler signature carries a parameter annotated with a
    pydantic BaseModel subclass (the framework's body-binding convention).
    """
    try:
        signature = inspect.signature(operation.view_func)
    except (TypeError, ValueError):  # pragma: no cover - exotic callables
        return False
    for name, parameter in signature.parameters.items():
        if name == "request":
            continue
        annotation = parameter.annotation
        if annotation is inspect.Parameter.empty:
            continue
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return True
    return False


def check(*, root, routers, options):
    """Flag mutating operations whose handler has no pydantic body parameter."""
    del root, options  # registry-only rule
    findings = []
    for prefix, router in routers:
        for path, path_view in router.path_operations.items():
            for operation in path_view.operations:
                if not (MUTATING_METHODS & set(operation.methods)):
                    continue
                if _has_pydantic_body(operation):
                    continue
                file_path, line_no = view_location(operation.view_func)
                display = f"/{prefix}{path}".replace("//", "/")
                findings.append(
                    {
                        "rule_id": "missing_pydantic",
                        "severity": "warning",
                        "file_path": file_path,
                        "line_no": line_no,
                        "message": (
                            f"mutating endpoint {display} binds no pydantic "
                            "payload -- request body reaches logic unvalidated"
                        ),
                    }
                )
    return findings
