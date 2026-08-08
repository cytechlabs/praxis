"""PRA-371 - import-time invariants must survive an optimized interpreter.

``report_catalog`` and ``compliance_labels`` both enforce a fail-closed
invariant while the module is imported: the report catalog must match the
enforced report-kind vocabulary, and no static product-facing compliance label
may contain an internal token. Both used ``assert``, which ``python -O`` /
``PYTHONOPTIMIZE`` strips, so the guarantee evaporated in an optimized
deployment.

These tests pin the explicit-raise behavior under the normal interpreter and
run the same validation logic in a real optimized subprocess.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import app
from app.services import compliance_labels, report_catalog
from app.services import report_run_service as rrs

CATALOG_DRIFT_MESSAGE = (
    "report_catalog and report_run_service.VALID_REPORT_KINDS are out of sync"
)


def _catalog_kinds() -> list:
    return [entry["report_kind"] for entry in report_catalog.list_catalog()]


# ---------------------------------------------------------------------------
# Report catalog invariant
# ---------------------------------------------------------------------------


def test_shipped_catalog_matches_valid_report_kinds():
    kinds = _catalog_kinds()
    assert sorted(kinds) == sorted(rrs.VALID_REPORT_KINDS)
    # The shipped data must pass the same check the import path runs.
    report_catalog._validate_catalog_kinds(kinds, rrs.VALID_REPORT_KINDS)


def test_missing_catalog_kind_raises_runtime_error():
    kinds = _catalog_kinds()
    with pytest.raises(RuntimeError) as exc:
        report_catalog._validate_catalog_kinds(kinds[1:], rrs.VALID_REPORT_KINDS)
    assert str(exc.value) == CATALOG_DRIFT_MESSAGE


def test_duplicate_catalog_kind_raises_runtime_error():
    kinds = _catalog_kinds()
    with pytest.raises(RuntimeError) as exc:
        report_catalog._validate_catalog_kinds(
            kinds + [kinds[0]], rrs.VALID_REPORT_KINDS
        )
    assert str(exc.value) == CATALOG_DRIFT_MESSAGE


def test_unknown_catalog_kind_raises_runtime_error():
    kinds = _catalog_kinds()
    drifted = ["not_a_registered_report_kind"] + kinds[1:]
    with pytest.raises(RuntimeError) as exc:
        report_catalog._validate_catalog_kinds(drifted, rrs.VALID_REPORT_KINDS)
    assert str(exc.value) == CATALOG_DRIFT_MESSAGE


def test_catalog_public_api_unchanged_for_valid_data():
    catalog = report_catalog.list_catalog()
    assert catalog and catalog is not report_catalog.list_catalog()
    descriptor = report_catalog.get_descriptor(rrs.REPORT_KIND_PACKAGE_OUTDATED)
    assert descriptor["report_kind"] == rrs.REPORT_KIND_PACKAGE_OUTDATED
    with pytest.raises(KeyError):
        report_catalog.get_descriptor("not_a_registered_report_kind")


# ---------------------------------------------------------------------------
# Compliance label invariant
# ---------------------------------------------------------------------------


def test_shipped_label_tables_pass_the_leak_check():
    compliance_labels._check_no_leak(compliance_labels._LABEL_TABLES)


@pytest.mark.parametrize(
    "leaky",
    [
        "Deferred to pra166",
        "Fact key not in slice 2 schema",
        "Evaluated in slice_1",
    ],
)
def test_leaky_static_label_raises_runtime_error(leaky):
    with pytest.raises(RuntimeError) as exc:
        compliance_labels._check_no_leak(({"some_reason": leaky},))
    assert str(exc.value) == f"leaky compliance label: {leaky!r}"


def test_clean_static_label_table_passes():
    compliance_labels._check_no_leak(
        ({"some_reason": "No host facts collected yet, run a scan on this host."},)
    )


def test_label_public_api_unchanged():
    assert compliance_labels.runner_label("deferred_to_pra166") == "Host probe (SSH)"
    assert (
        compliance_labels.verdict_reason_label("deferred_to_something_internal")
        == "Not evaluated (see raw reason in export)."
    )
    assert (
        compliance_labels.evidence_status("error", "no_host_facts_row")
        == compliance_labels.STATUS_AWAITING_SCAN
    )


# ---------------------------------------------------------------------------
# Optimized-interpreter regression
# ---------------------------------------------------------------------------

_OPTIMIZED_SNIPPET = """
if __debug__:
    raise SystemExit("assertions are still enabled; this check proves nothing")

# Importing both modules must still succeed for the shipped, valid data.
from app.services import compliance_labels, report_catalog

report_catalog.list_catalog()
compliance_labels.runner_label("deferred_to_pra166")

failures = []

try:
    report_catalog._validate_catalog_kinds(["only_one_kind"], ["a", "b"])
except RuntimeError as exc:
    if "out of sync" not in str(exc):
        failures.append("unexpected catalog message: %s" % exc)
else:
    failures.append("catalog drift did not raise")

try:
    compliance_labels._check_no_leak(({"some_reason": "Deferred to pra166"},))
except RuntimeError as exc:
    if "leaky compliance label" not in str(exc):
        failures.append("unexpected label message: %s" % exc)
else:
    failures.append("leaky label did not raise")

if failures:
    raise SystemExit("; ".join(failures))

print("OPTIMIZED_INVARIANTS_OK")
"""


def _run_optimized():
    backend_root = Path(app.__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(backend_root), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    return subprocess.run(
        [sys.executable, "-O", "-c", _OPTIMIZED_SNIPPET],
        cwd=str(backend_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_invariants_still_raise_under_optimized_python():
    result = _run_optimized()
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "OPTIMIZED_INVARIANTS_OK" in result.stdout


def test_optimized_subprocess_really_strips_assertions():
    """Guards the regression test itself: -O must disable assertions."""
    backend_root = Path(app.__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-O", "-c", "assert False, 'stripped'; print(__debug__)"],
        cwd=str(backend_root),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
