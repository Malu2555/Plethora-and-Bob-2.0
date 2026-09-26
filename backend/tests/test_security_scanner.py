"""
Scanner rule suite: positive + negative contracts per rule, plus the two
project-level guarantees the dashboard depends on:

    * the CLEAN tree scans to exactly zero findings (any regression here is a
      false positive shipped to the dashboard), and
    * persisted runs are idempotent per fingerprint and drive the exit code.

Static rules (R1, R3, R5) are exercised against synthetic tmp trees so the
flake patterns never pollute the real source; registry rules (R2, R4, R7)
are exercised against tiny synthetic ninja routers AND the real manifest.
"""

import logging
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command
from ninja import Router
from pydantic import BaseModel

from security import scanner as scanner_module
from security.models import Finding
from security.rules import (
    absent_tests,
    hardcoded_secret,
    missing_auth,
    missing_pydantic,
    missing_rate_limit,
    n_plus_one,
    raw_sql,
)
from security.rules.helpers import default_routers

logger = logging.getLogger(__name__)

NO_OPTIONS = {}


def _backends_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_tree(root: Path, files: dict):
    """Create a fake backend tree from {rel_path: text} (POSIX separators)."""
    for rel, text in files.items():
        path = Path(root) / Path(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _router_with(router, path, methods, auth=None, handler=None):
    def _handler(request):
        return {"ok": True}

    handle = handler or _handler
    if "GET" in methods:
        router.get(path, auth=auth)(handle)
    else:
        router.post(path, auth=auth)(handle)
    return router


# --------------------------------------------------------------------------
# R1 raw_sql
# --------------------------------------------------------------------------

RAW_SQL_FLAKE = '''\ndef search_vault(request):\n    """Search endpoint (flawed branch)."""\n    cur = connection.cursor()\n    cur.execute("SELECT title FROM vault_vaultrecord WHERE title LIKE %s" % request.GET.get("q"))\n    return cur.fetchall()\n'''


def test_raw_sql_flags_interpolated_statement(tmp_path):
    _write_tree(tmp_path, {"vault/search_api.py": RAW_SQL_FLAKE})
    findings = raw_sql.check(root=Path(tmp_path), routers=[], options=NO_OPTIONS)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["file_path"] == "vault/search_api.py"


def test_raw_sql_ignores_pure_orm(tmp_path):
    _write_tree(
        tmp_path,
        {
            "vault/search_api.py": (
                "def search_vault(request):\n"
                '    return VaultRecord.visible_to(request.auth).filter(title__icontains=request.GET.get("q"))\n'
            )
        },
    )
    assert raw_sql.check(root=Path(tmp_path), routers=[], options=NO_OPTIONS) == []


def test_raw_sql_clean_on_real_tree():
    findings = raw_sql.check(root=_backends_root(), routers=[], options=NO_OPTIONS)
    assert findings == [], [f["message"] for f in findings]


# --------------------------------------------------------------------------
# R2 missing_auth
# --------------------------------------------------------------------------


def test_missing_auth_flags_unprotected_endpoint():
    router = _router_with(Router(), "/stats", ["GET"], auth=None)
    findings = missing_auth.check(
        root=_backends_root(), routers=[("monitor", router)], options=NO_OPTIONS
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "no effective authenticator" in findings[0]["message"]


def test_missing_auth_accepts_router_level_default():
    router = Router(auth=lambda request: True)  # router-level default
    router.get("/stats")(lambda request: {"ok": True})  # no per-op auth
    findings = missing_auth.check(
        root=_backends_root(), routers=[("monitor", router)], options=NO_OPTIONS
    )
    assert findings == []


def test_missing_auth_whitelists_credential_endpoints():
    router = _router_with(Router(), "/token", ["POST"], auth=None)
    findings = missing_auth.check(
        root=_backends_root(), routers=[("auth", router)], options=NO_OPTIONS
    )
    assert findings == []


def test_missing_auth_clean_on_real_manifest():
    findings = missing_auth.check(
        root=_backends_root(), routers=default_routers(), options=NO_OPTIONS
    )
    assert findings == [], [f["message"] for f in findings]


# --------------------------------------------------------------------------
# R4 missing_rate_limit
# --------------------------------------------------------------------------


def test_rate_limit_flags_unthrottled_mutation():
    router = _router_with(Router(), "/import", ["POST"])
    findings = missing_rate_limit.check(
        root=_backends_root(), routers=[("vault", router)], options=NO_OPTIONS
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_rate_limit_exempts_read_only_gets():
    router = _router_with(Router(), "/feed", ["GET"])
    findings = missing_rate_limit.check(
        root=_backends_root(), routers=[("audit", router)], options=NO_OPTIONS
    )
    assert findings == []


def test_rate_limit_clean_on_real_manifest():
    findings = missing_rate_limit.check(
        root=_backends_root(), routers=default_routers(), options=NO_OPTIONS
    )
    assert findings == [], [f["message"] for f in findings]


# --------------------------------------------------------------------------
# R7 missing_pydantic
# --------------------------------------------------------------------------


def test_pydantic_flags_untyped_payload():
    def _untyped(request, payload):
        return {"ok": True}

    router = Router()
    router.post("/ingest")(_untyped)
    findings = missing_pydantic.check(
        root=_backends_root(), routers=[("vault", router)], options=NO_OPTIONS
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "warning"


def test_pydantic_accepts_typed_payload():
    class IngestIn(BaseModel):
        title: str

    def _typed(request, payload: IngestIn):
        return {"ok": True}

    router = Router()
    router.post("/ingest")(_typed)
    findings = missing_pydantic.check(
        root=_backends_root(), routers=[("vault", router)], options=NO_OPTIONS
    )
    assert findings == []


def test_pydantic_clean_on_real_manifest():
    findings = missing_pydantic.check(
        root=_backends_root(), routers=default_routers(), options=NO_OPTIONS
    )
    assert findings == [], [f["message"] for f in findings]


# --------------------------------------------------------------------------
# R3 hardcoded_secret
# --------------------------------------------------------------------------


def test_secret_flags_credential_shaped_literal(tmp_path):
    _write_tree(tmp_path, {"monitor/conf.py": 'API_KEY = "AbCdEf1234567890_xyz"\n'})
    findings = hardcoded_secret.check(
        root=Path(tmp_path), routers=[], options=NO_OPTIONS
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "redacted" in findings[0]["message"].lower()


def test_secret_ignores_low_entropy_placeholders(tmp_path):
    _write_tree(
        tmp_path,
        {
            "monitor/conf.py": 'API_KEY = "changeme"\nDEBUG_FLAG = "some-static-text"\n',
            ".env.example": "SENTINEL_SECRET_KEY=replace-with-a-real-secret\n",
        },
    )
    findings = hardcoded_secret.check(
        root=Path(tmp_path), routers=[], options=NO_OPTIONS
    )
    assert findings == []


def test_secret_clean_on_real_tree():
    findings = hardcoded_secret.check(
        root=_backends_root(), routers=[], options=NO_OPTIONS
    )
    assert findings == [], [f["message"] for f in findings]


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows-only")
def test_secret_config_walk_survives_escaping_junction(tmp_path):
    """A .venv junction must not drag the config walk into the OTHER checkout."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "creds.json").write_text(
        '{"api_key": "Abc123Def456Ghi7890"}\n', encoding="utf-8"
    )
    root = tmp_path / "backend"
    (root / "vault").mkdir(parents=True)
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / ".venv"), str(outside)],
        capture_output=True,
        text=True,
    )
    if made.returncode != 0:  # pragma: no cover - restricted environment
        pytest.skip("junction creation not permitted here")

    findings = hardcoded_secret.check(root=root, routers=[], options=NO_OPTIONS)
    assert findings == []  # .venv pruned; the outside file is never scanned


# --------------------------------------------------------------------------
# R5 absent_tests
# --------------------------------------------------------------------------


def test_absent_tests_flags_missing_suite(tmp_path):
    (Path(tmp_path) / "monitor").mkdir(parents=True)  # code, but no tests/
    findings = absent_tests.check(
        root=Path(tmp_path), routers=[], options={"collect_tests": False}
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_absent_tests_accepts_discoverable_suite(tmp_path):
    _write_tree(tmp_path, {"tests/test_dummy.py": "def test_dummy():\n    pass\n"})
    findings = absent_tests.check(
        root=Path(tmp_path), routers=[], options={"collect_tests": False}
    )
    assert findings == []


def test_absent_tests_clean_on_real_tree():
    findings = absent_tests.check(
        root=_backends_root(), routers=[], options={"collect_tests": False}
    )
    assert findings == [], [f["message"] for f in findings]


# --------------------------------------------------------------------------
# R6 n_plus_one (runtime probe on the real clean API)
# --------------------------------------------------------------------------


def test_n_plus_one_probe_is_clean_and_leaves_no_rows(db):
    from django.contrib.auth import get_user_model

    findings = n_plus_one.check(
        root=_backends_root(), routers=[], options={"runtime_probe": True}
    )
    assert findings == [], [f["message"] for f in findings]
    # Rollback guarantee: the synthetic user and records must be gone.
    assert not get_user_model().objects.filter(username="__scanner_probe__").exists()


def test_n_plus_one_skipped_without_runtime_probe(db):
    got = n_plus_one.check(
        root=_backends_root(), routers=[], options={"runtime_probe": False}
    )
    assert got == []


# --------------------------------------------------------------------------
# Scanner entry point: persistence, idempotency, exit-code contract
# --------------------------------------------------------------------------


def test_run_scan_and_store_clean_tree(db):
    run = scanner_module.run_scan_and_store(
        branch="unit", trigger="test", runtime_probe=False, collect_tests=False
    )
    assert run.exit_code == 0
    assert run.findings_total == 0
    assert run.finished_at is not None
    assert Finding.objects.filter(scan_run=run).count() == 0


def test_no_rule_errors_on_clean_tree(db):
    """Zero findings AND zero rule exceptions -- no silent scanning gaps."""
    drafts, per_rule_log = scanner_module.collect_findings(
        root=_backends_root(), runtime_probe=False, collect_tests=False
    )
    assert per_rule_log == {}
    assert drafts == []


def test_run_scan_and_store_persists_findings_and_fingerprints(db, tmp_path, monkeypatch):
    _write_tree(
        tmp_path,
        {"vault/flaky.py": 'def f(request):\n    return model.objects.raw("SELECT 1")\n'},
    )
    monkeypatch.setattr(scanner_module, "BACKEND_ROOT", Path(tmp_path))

    first = scanner_module.run_scan_and_store(
        branch="unit", trigger="test", runtime_probe=False, collect_tests=False
    )
    second = scanner_module.run_scan_and_store(
        branch="unit", trigger="test", runtime_probe=False, collect_tests=False
    )

    assert first.exit_code == 1  # a critical finding flips the CI gate
    assert first.findings_total >= 1
    first_rows = list(Finding.objects.filter(scan_run=first))
    second_rows = list(Finding.objects.filter(scan_run=second))
    # Each run stores its own snapshot; fingerprints dedupe within one run.
    assert first_rows and len(second_rows) == len(first_rows)
    fingerprints = [f.fingerprint for f in first_rows]
    assert len(set(fingerprints)) == len(fingerprints)  # keys are unique


def test_run_scan_and_store_respects_explicit_root_override(db, tmp_path):
    """--root parity: source rules follow the target tree, not this checkout."""
    _write_tree(
        tmp_path,
        {"vault/flaky.py": 'def f(request):\n    return model.objects.raw("SELECT 1")\n'},
    )

    run = scanner_module.run_scan_and_store(
        root=tmp_path,
        branch="demo-start",
        trigger="test",
        runtime_probe=False,
        collect_tests=False,
    )

    assert run.exit_code == 1  # critical findings in the TARGET tree
    rows = list(Finding.objects.filter(scan_run=run))
    # Both source-side rules followed the override: R1 saw the target's bad
    # line, R5 saw the target's missing suite -- nothing from this checkout.
    by_rule = {row.rule_id for row in rows}
    assert by_rule == {"raw_sql", "absent_tests"}
    flake = [row for row in rows if row.rule_id == "raw_sql"]
    assert len(flake) == 1 and flake[0].file_path == "vault/flaky.py"


def test_security_scan_command_root_override_reports_target_findings(db, tmp_path):
    """`manage.py security_scan --root`: findings come from the target tree."""
    _write_tree(
        tmp_path,
        {"vault/flaky.py": 'def f(request):\n    return model.objects.raw("SELECT 1")\n'},
    )
    out = StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command(
            "security_scan",
            "--dry-run",
            "--rule",
            "raw_sql",
            "--root",
            str(tmp_path),
            stdout=out,
        )
    assert exc.value.code == 1  # critical finding -> CI gate trips
    rendered = out.getvalue()
    assert "raw_sql" in rendered and "vault/flaky.py" in rendered


def test_security_scan_command_root_override_clean_target(db, tmp_path):
    """An empty target tree scans clean and exits 0 -- the sibling-branch smoke."""
    out = StringIO()
    call_command(
        "security_scan",
        "--dry-run",
        "--rule",
        "raw_sql",
        "--root",
        str(tmp_path),
        stdout=out,
    )
    assert "0 findings" in out.getvalue()


def test_scanner_rule_failure_is_contained(db, monkeypatch):
    """One raising rule may not sink a scan: other rules still run."""

    def _boom(*, root, routers, options):
        raise RuntimeError("synthetic rule failure")

    import security.rules as rules_pkg

    monkeypatch.setitem(rules_pkg.ALL_RULES, "raw_sql", _boom)
    drafts, per_rule_log = scanner_module.collect_findings(
        root=_backends_root(), runtime_probe=False, collect_tests=False
    )
    assert per_rule_log.get("raw_sql")
    assert isinstance(drafts, list)


def test_selected_rules_validates_ids():
    with pytest.raises(ValueError):
        scanner_module.selected_rules(["not_a_rule"])
    assert set(scanner_module.selected_rules(None)) == {
        "raw_sql",
        "missing_auth",
        "hardcoded_secret",
        "missing_rate_limit",
        "absent_tests",
        "n_plus_one",
        "missing_pydantic",
    }
