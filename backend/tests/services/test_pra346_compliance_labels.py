"""PRA-346 — operator-facing compliance humanization.

Covers the readiness audit fixes:

* the ``compliance_labels`` humanizer maps every internal enum to a
  product-facing label with NO leaky ticket/slice/schema token;
* the evidence ``status`` classifier splits the single ``error`` verdict into
  distinguishable, actionable states (error / coverage_pending / awaiting_scan
  / unsupported);
* evidence / check / starter-pack reads carry the humanized sibling fields
  while the raw internal enums stay stable;
* a policy can be evaluated and re-evaluated with the verdict flipping as facts
  change (the path that had no direct coverage before).
"""

from __future__ import annotations

import re
from datetime import datetime

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    Credential,
    Group,
    HostFacts,
    Package,
    System,
)
from app.services import (
    compliance_evaluation_service,
    compliance_labels,
    compliance_service,
)
from app.services.compliance_evaluation_service import (
    REASON_DEFERRED_PRA166,
    REASON_FACT_KEY_UNMAPPED,
    REASON_FACT_VALUE_NULL,
    REASON_NO_HOST_FACTS,
    REASON_PACKAGE_INSTALLED,
    REASON_PACKAGE_NOT_INSTALLED,
    REASON_VERSION_MISMATCH,
    REASON_VERSION_UNPARSEABLE,
    evidence_export_row,
)
from app.services.compliance_service import (
    RUNNER_OWNER_PRA166,
    RUNNER_OWNER_SLICE_2,
    RUNNER_STATUS_NOT_IMPLEMENTED,
    check_read_envelope,
    starter_pack_preview,
)

# The forbidden internal patterns that must never appear in a product label.
_LEAK_RE = re.compile(r"pra\d|slice|schema|deferred_to", re.IGNORECASE)


def _assert_clean(label):
    assert label is None or not _LEAK_RE.search(
        label
    ), f"label leaks an internal token: {label!r}"


# ---------------------------------------------------------------------------
# Fixtures / harness (mirrors the PRA-165 evaluation-service test helpers)
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra346-eval", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra346-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra346-host.example.com",
        ip_address="10.0.0.61",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _make_policy(db, admin_user, slug, **overrides):
    return compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug=slug, name=slug.upper(), **overrides
    )


def _add_check(db, admin_user, policy, slug, kind, definition, **overrides):
    return compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=slug,
        title=slug,
        kind=kind,
        definition=definition,
        **overrides,
    )


def _install_package(db, system_id, name, version="1.0"):
    db.add(
        Package(
            system_id=system_id,
            name=name,
            installed_version=version,
            package_type="apt",
        )
    )
    db.flush()


def _evaluate(db, policy, host):
    return compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )


def _rows(db, policy, host):
    return (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == host.id,
        )
        .order_by(CompliancePolicyEvidence.id.asc())
        .all()
    )


# ---------------------------------------------------------------------------
# Humanizer unit tests
# ---------------------------------------------------------------------------


def test_runner_label_maps_families():
    assert compliance_labels.runner_label(RUNNER_OWNER_SLICE_2) == (
        "Package & fact evaluation"
    )
    assert compliance_labels.runner_label(RUNNER_OWNER_PRA166) == "Host probe (SSH)"
    assert compliance_labels.runner_label("unknown") == "Unsupported check"
    for owner in (RUNNER_OWNER_SLICE_2, RUNNER_OWNER_PRA166, "unknown"):
        _assert_clean(compliance_labels.runner_label(owner))


def test_no_verdict_reason_label_leaks_internal_tokens():
    reasons = [
        REASON_NO_HOST_FACTS,
        REASON_FACT_KEY_UNMAPPED,
        REASON_FACT_VALUE_NULL,
        REASON_PACKAGE_NOT_INSTALLED,
        REASON_PACKAGE_INSTALLED,
        REASON_VERSION_MISMATCH,
        REASON_VERSION_UNPARSEABLE,
        REASON_DEFERRED_PRA166,
        # dynamic / defensive reasons — the internal suffix must never echo.
        "unknown_kind:command_exit_code",
        f"unknown_runner_owner:{RUNNER_OWNER_PRA166}",
        "missing_runner_for_kind:file_exists",
        "unsupported_probe_kind:foo",
        # probe reasons
        "file_not_found",
        "ssh_transport_failure",
        "sha256_mismatch",
    ]
    for reason in reasons:
        label = compliance_labels.verdict_reason_label(reason)
        assert label is not None
        _assert_clean(label)
    # None reason -> None label (plain pass/fail).
    assert compliance_labels.verdict_reason_label(None) is None


def test_dynamic_reason_never_echoes_internal_suffix():
    # The most dangerous case: the suffix is itself an internal owner string.
    label = compliance_labels.verdict_reason_label(
        f"unknown_runner_owner:{RUNNER_OWNER_PRA166}"
    )
    assert "deferred_to_pra166" not in label
    _assert_clean(label)


def test_evidence_status_classification():
    S = compliance_labels
    assert S.evidence_status("pass", None) == S.STATUS_PASS
    assert S.evidence_status("fail", "package_not_installed") == S.STATUS_FAIL
    assert (
        S.evidence_status("error", REASON_FACT_KEY_UNMAPPED)
        == S.STATUS_COVERAGE_PENDING
    )
    assert S.evidence_status("error", REASON_NO_HOST_FACTS) == S.STATUS_AWAITING_SCAN
    assert S.evidence_status("error", REASON_FACT_VALUE_NULL) == S.STATUS_AWAITING_SCAN
    assert S.evidence_status("error", "file_not_found") == S.STATUS_ERROR
    assert S.evidence_status("error", "unknown_kind:foo") == S.STATUS_UNSUPPORTED
    assert S.evidence_status("error", REASON_DEFERRED_PRA166) == S.STATUS_UNSUPPORTED
    # Every status has a label.
    for code in (
        S.STATUS_PASS,
        S.STATUS_FAIL,
        S.STATUS_ERROR,
        S.STATUS_COVERAGE_PENDING,
        S.STATUS_AWAITING_SCAN,
        S.STATUS_UNSUPPORTED,
    ):
        _assert_clean(S.status_label(code))


# ---------------------------------------------------------------------------
# Evidence read integration
# ---------------------------------------------------------------------------


def test_evidence_export_row_has_humanized_fields_pass_and_fail(db, admin_user, host):
    policy = _make_policy(db, admin_user, "pra346-pkg")
    _add_check(
        db, admin_user, policy, "nginx", "package_installed", {"package": "nginx"}
    )
    _install_package(db, host.id, "nginx")
    _evaluate(db, policy, host)
    row = evidence_export_row(_rows(db, policy, host)[0])
    # Raw enums stay stable.
    assert row["verdict"] == "pass"
    assert row["runner_owner"] == RUNNER_OWNER_SLICE_2
    # Humanized siblings present + clean.
    assert row["status"] == "pass"
    assert row["status_label"] == "Pass"
    assert row["runner_label"] == "Package & fact evaluation"
    _assert_clean(row["runner_label"])
    _assert_clean(row["status_label"])


def test_unmapped_fact_is_coverage_pending(db, admin_user, host):
    policy = _make_policy(db, admin_user, "pra346-unmapped")
    _add_check(
        db,
        admin_user,
        policy,
        "future-key",
        "fact_equals",
        # PRA-359 mapped the SSH/sysctl keys; a genuinely uncollected future key
        # still exercises the coverage_pending path.
        {"fact_key": "future.not.collected.yet", "expected": "no"},
    )
    _evaluate(db, policy, host)
    row = evidence_export_row(_rows(db, policy, host)[0])
    assert row["verdict"] == "error"
    assert row["verdict_reason"] == REASON_FACT_KEY_UNMAPPED  # raw stays stable
    assert row["status"] == "coverage_pending"
    assert row["status_label"] == "Coverage pending"
    _assert_clean(row["verdict_reason_label"])
    assert "schema" not in (row["verdict_reason_label"] or "")


def test_missing_facts_is_awaiting_scan(db, admin_user, host):
    policy = _make_policy(db, admin_user, "pra346-missing")
    _add_check(
        db,
        admin_user,
        policy,
        "kver",
        "fact_equals",
        {"fact_key": "host.kernel_version", "expected": "6.0.0"},
    )
    _evaluate(db, policy, host)  # no HostFacts row seeded
    row = evidence_export_row(_rows(db, policy, host)[0])
    assert row["verdict"] == "error"
    assert row["verdict_reason"] == REASON_NO_HOST_FACTS
    assert row["status"] == "awaiting_scan"
    assert row["status_label"] == "Awaiting host scan"


def test_reevaluate_after_package_install_flips_verdict(db, admin_user, host):
    policy = _make_policy(db, admin_user, "pra346-reeval")
    _add_check(
        db, admin_user, policy, "auditd", "package_installed", {"package": "auditd"}
    )
    # First pass: package absent -> fail.
    _evaluate(db, policy, host)
    row1 = evidence_export_row(_rows(db, policy, host)[0])
    assert row1["verdict"] == "fail"
    assert row1["status_label"] == "Fail"

    # Install the package and re-evaluate. Evidence is append-only history, so
    # the newest row (highest id) carries the re-evaluated verdict.
    _install_package(db, host.id, "auditd")
    _evaluate(db, policy, host)
    row2 = evidence_export_row(_rows(db, policy, host)[-1])
    assert row2["verdict"] == "pass"
    assert row2["status_label"] == "Pass"


# ---------------------------------------------------------------------------
# Check-read + starter-pack reads
# ---------------------------------------------------------------------------


def test_check_read_envelope_has_labels(db, admin_user, host):
    policy = _make_policy(db, admin_user, "pra346-check")
    check = _add_check(
        db, admin_user, policy, "sshd", "file_exists", {"path": "/etc/ssh/sshd_config"}
    )
    env = check_read_envelope(check)
    # Raw stale value stays; humanized sibling is truthful + clean.
    assert env["runner_status"] == RUNNER_STATUS_NOT_IMPLEMENTED
    assert env["runner_label"] == "Host probe (SSH)"
    _assert_clean(env["runner_status_label"])
    _assert_clean(env["runner_label"])


def test_starter_pack_preview_coverage_flags():
    entries = {e["slug"]: e for e in starter_pack_preview()}
    # PRA-359: the SSH + kernel-sysctl fact keys are now mapped/collected, so
    # every starter-pack fact key resolves — no pack shows coverage pending.
    for slug in ("ssh-baseline", "kernel-baseline", "package-hygiene"):
        assert entries[slug]["has_coverage_pending"] is False, slug
        assert entries[slug]["coverage_pending_count"] == 0, slug
    # runner_labels present + clean.
    for e in entries.values():
        assert e["runner_labels"]
        for label in e["runner_labels"]:
            _assert_clean(label)
