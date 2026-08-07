"""PRA-165 Slice 3 — read service + export streaming tests.

Covers:

* Paginated evidence list with all four filters.
* ``policy_summary``: per-check + per-host counts, ``latest_run_at``
  as absolute UTC ``Z`` string, empty-no-runs case.
* ``fleet_summary``: counts per-policy / per-severity / per-host,
  ``stale`` flag honors the 2x schedule_interval_hours rule.
* ``iter_evidence_for_export`` window validation + ordered output.
* ``evidence_export_row`` carries ``runner_owner`` even after the
  source check is deleted (denormalization survives).
* ``emit_export_requested_audit`` goes through ``safe_emit`` with no
  ``db=``.
* UTC ``Z`` suffix on every wire timestamp.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import CompliancePolicyEvidence, Credential, Group, Package, System
from app.services import compliance_evaluation_service, compliance_service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class AuditCapture:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_evaluation_service, "safe_emit", cap)
    return cap


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra165-s3", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra165-s3-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="s3-host.example.com",
        ip_address="10.0.0.55",
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
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug.upper(),
        **overrides,
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


def _install_package(db, system_id, name, version="1.0.0"):
    pkg = Package(
        system_id=system_id,
        name=name,
        installed_version=version,
        package_type="apt",
    )
    db.add(pkg)
    db.flush()
    return pkg


def _evaluate(db, policy, host):
    return compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )


# ---------------------------------------------------------------------------
# Paginated evidence list
# ---------------------------------------------------------------------------


def test_list_evidence_paginated_filters_by_policy(db, admin_user, host):
    p1 = _make_policy(db, admin_user, "list-p1")
    p2 = _make_policy(db, admin_user, "list-p2")
    _add_check(
        db, admin_user, p1, "c1", "package_installed", {"package": "openssh-server"}
    )
    _add_check(db, admin_user, p2, "c2", "package_installed", {"package": "auditd"})
    _install_package(db, host.id, "openssh-server")
    _install_package(db, host.id, "auditd")
    _evaluate(db, p1, host)
    _evaluate(db, p2, host)

    rows, total = compliance_evaluation_service.list_evidence_paginated(
        db, policy_id=p1.id
    )
    assert total == 1
    assert rows[0].policy_id == p1.id


def test_list_evidence_paginated_filters_by_verdict(db, admin_user, host):
    p = _make_policy(db, admin_user, "verdict-filter")
    _add_check(
        db, admin_user, p, "ok", "package_installed", {"package": "openssh-server"}
    )
    _add_check(
        db, admin_user, p, "miss", "package_installed", {"package": "missing-pkg"}
    )
    _install_package(db, host.id, "openssh-server")
    _evaluate(db, p, host)
    pass_rows, pass_total = compliance_evaluation_service.list_evidence_paginated(
        db, policy_id=p.id, verdict="pass"
    )
    fail_rows, fail_total = compliance_evaluation_service.list_evidence_paginated(
        db, policy_id=p.id, verdict="fail"
    )
    assert pass_total == 1 and pass_rows[0].verdict == "pass"
    assert fail_total == 1 and fail_rows[0].verdict == "fail"


def test_list_evidence_filters_by_window(db, admin_user, host):
    p = _make_policy(db, admin_user, "window")
    _add_check(
        db, admin_user, p, "c", "package_installed", {"package": "openssh-server"}
    )
    old = datetime.utcnow() - timedelta(days=10)
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=p.id, system_id=host.id, now=old
    )
    _evaluate(db, p, host)

    rows, total = compliance_evaluation_service.list_evidence_paginated(
        db,
        policy_id=p.id,
        evaluated_after=datetime.utcnow() - timedelta(days=1),
    )
    assert total == 1
    assert (datetime.utcnow() - rows[0].evaluated_at) < timedelta(days=1)


def test_list_evidence_rejects_unknown_verdict(db, admin_user, host):
    p = _make_policy(db, admin_user, "bad-verdict")
    with pytest.raises(compliance_service.ComplianceError):
        compliance_evaluation_service.list_evidence_paginated(
            db, policy_id=p.id, verdict="amazing"
        )


def test_list_evidence_caps_limit(db, admin_user):
    with pytest.raises(compliance_service.ComplianceError):
        compliance_evaluation_service.list_evidence_paginated(db, limit=10_000)


# ---------------------------------------------------------------------------
# policy_summary
# ---------------------------------------------------------------------------


def test_policy_summary_empty_for_never_run_policy(db, admin_user):
    p = _make_policy(db, admin_user, "never-run")
    summary = compliance_evaluation_service.policy_summary(db, policy_id=p.id)
    assert summary["latest_run_id"] is None
    assert summary["latest_run_at"] is None
    assert summary["per_check"] == []
    assert summary["per_host"] == []
    assert summary["pass_count"] == 0


def test_policy_summary_counts_latest_run(db, admin_user, host):
    # NOTE: the test DB shares schema with the dev praxis DB which
    # may carry pre-existing System rows. ``policy_summary`` anchors
    # on ``policy.last_run_at`` — set explicitly here so the per-host
    # evaluation against the test fixture host alone counts as the
    # "latest run". This sidesteps the fleet evaluator picking up
    # external hosts and lets the assertion stay precise (1 pass +
    # 1 fail for the two checks on this one host).
    p = _make_policy(db, admin_user, "summary-ok")
    _add_check(
        db, admin_user, p, "c1", "package_installed", {"package": "openssh-server"}
    )
    _add_check(db, admin_user, p, "c2", "package_installed", {"package": "auditd"})
    _install_package(db, host.id, "openssh-server")
    summary_call = compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=p.id, system_id=host.id
    )
    p.last_run_at = summary_call.evaluated_at
    db.flush()

    summary = compliance_evaluation_service.policy_summary(db, policy_id=p.id)
    assert summary["pass_count"] == 1
    assert summary["fail_count"] == 1
    assert summary["error_count"] == 0
    assert summary["latest_run_at"].endswith("Z")
    assert {c["check_slug"] for c in summary["per_check"]} == {"c1", "c2"}
    assert any(h["system_id"] == host.id for h in summary["per_host"])


def test_policy_summary_404_for_missing(db):
    with pytest.raises(compliance_service.ComplianceError):
        compliance_evaluation_service.policy_summary(db, policy_id=999_999)


# ---------------------------------------------------------------------------
# fleet_summary + stale flag
# ---------------------------------------------------------------------------


def test_fleet_summary_with_no_evidence(db, admin_user):
    p = _make_policy(db, admin_user, "empty-fleet")
    summary = compliance_evaluation_service.fleet_summary(db)
    assert summary["policy_count"] >= 1
    assert summary["per_policy"][0]["stale"] is True
    assert summary["pass_count"] == 0
    assert summary["generated_at"].endswith("Z")


def test_fleet_summary_counts(db, admin_user, host):
    # Run host-scoped to avoid the fleet evaluator pulling in
    # external dev-DB hosts; stamp last_run_at by hand so the
    # fleet summary's latest-run anchor matches our row.
    p = _make_policy(db, admin_user, "fleet-counts", severity="high")
    _add_check(
        db, admin_user, p, "c", "package_installed", {"package": "openssh-server"}
    )
    _install_package(db, host.id, "openssh-server")
    s = compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=p.id, system_id=host.id
    )
    p.last_run_at = s.evaluated_at
    db.flush()

    summary = compliance_evaluation_service.fleet_summary(db)
    target = next(
        x for x in summary["per_policy"] if x["policy_slug"] == "fleet-counts"
    )
    assert target["pass_count"] >= 1
    assert target["last_run_at"].endswith("Z")
    assert target["stale"] is False
    sev = next(sv for sv in summary["per_severity"] if sv["severity"] == "high")
    assert sev["pass_count"] >= 1


def test_fleet_summary_stale_when_overdue(db, admin_user, host):
    p = _make_policy(db, admin_user, "stale-test", schedule_interval_hours=1)
    _add_check(
        db, admin_user, p, "c", "package_installed", {"package": "openssh-server"}
    )
    very_old = datetime.utcnow() - timedelta(hours=48)
    compliance_evaluation_service.evaluate_policy_for_fleet(
        db, policy_id=p.id, now=very_old
    )
    summary = compliance_evaluation_service.fleet_summary(db)
    target = next(x for x in summary["per_policy"] if x["policy_slug"] == "stale-test")
    assert target["stale"] is True


# ---------------------------------------------------------------------------
# Export iterator + row shape
# ---------------------------------------------------------------------------


def test_iter_evidence_rejects_inverted_window(db):
    now = datetime.utcnow()
    with pytest.raises(compliance_service.ComplianceError):
        list(
            compliance_evaluation_service.iter_evidence_for_export(
                db, evaluated_after=now, evaluated_before=now
            )
        )


def test_iter_evidence_rejects_oversize_window(db):
    now = datetime.utcnow()
    with pytest.raises(compliance_service.ComplianceError):
        list(
            compliance_evaluation_service.iter_evidence_for_export(
                db,
                evaluated_after=now - timedelta(days=10_000),
                evaluated_before=now,
            )
        )


def test_iter_evidence_yields_in_evaluated_at_order(db, admin_user, host):
    p = _make_policy(db, admin_user, "iter-order")
    _add_check(
        db, admin_user, p, "c", "package_installed", {"package": "openssh-server"}
    )
    t1 = datetime.utcnow() - timedelta(hours=2)
    t2 = datetime.utcnow() - timedelta(hours=1)
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=p.id, system_id=host.id, now=t1
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=p.id, system_id=host.id, now=t2
    )
    rows = list(
        compliance_evaluation_service.iter_evidence_for_export(
            db,
            evaluated_after=t1 - timedelta(minutes=1),
            evaluated_before=t2 + timedelta(minutes=1),
        )
    )
    assert [r.evaluated_at for r in rows] == sorted(r.evaluated_at for r in rows)


def test_export_row_carries_runner_status_for_executed_kinds(db, admin_user, host):
    """Slice 3 P2 fix (updated for PRA-166): evidence export row MUST
    surface a stable ``runner_status`` field. Package/fact rows carry
    ``runner_executed``; file/command rows now also carry
    ``runner_executed`` because PRA-166's probe runner records actual
    runs (success and failure paths). Legacy PRA-165 deferred rows
    are covered by the dedicated test below.
    """
    p = _make_policy(db, admin_user, "status-exec")
    _add_check(
        db, admin_user, p, "c", "package_installed", {"package": "openssh-server"}
    )
    _install_package(db, host.id, "openssh-server")
    _evaluate(db, p, host)
    rows = (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.policy_id == p.id)
        .all()
    )
    assert rows
    payload = compliance_evaluation_service.evidence_export_row(rows[0])
    assert payload["runner_status"] == "runner_executed"


def test_export_row_preserves_runner_deferred_for_legacy_rows(db, admin_user, host):
    """Pre-PRA-166 evidence rows carried the stable
    ``runner_owner_deferred_pra166`` reason. After PRA-166 the export
    helper inspects ``verdict_reason`` so those legacy rows continue
    to read as ``runner_deferred``; a re-export of historical
    evidence does not retroactively claim execution.
    """
    p = _make_policy(db, admin_user, "status-deferred-legacy")
    check = _add_check(db, admin_user, p, "f", "file_exists", {"path": "/etc/passwd"})
    # Materialize a legacy row directly so we don't need to roll back
    # the new probe-runner wiring just to assert on the old reason.
    legacy = CompliancePolicyEvidence(
        policy_id=p.id,
        check_id=check.id,
        system_id=host.id,
        policy_slug=p.slug,
        policy_version=p.version,
        check_slug=check.slug,
        check_kind=check.kind,
        verdict="error",
        verdict_reason="runner_owner_deferred_pra166",
        observed_value=None,
        expected_value="file_exists",
        severity=p.severity,
        evaluation_run_id="legacy-run",
        evaluated_at=datetime.utcnow(),
    )
    db.add(legacy)
    db.flush()
    payload = compliance_evaluation_service.evidence_export_row(legacy)
    assert payload["runner_status"] == "runner_deferred"
    assert payload["runner_owner"] == "deferred_to_pra166"


def test_export_csv_columns_include_runner_status():
    assert "runner_status" in compliance_evaluation_service.EXPORT_CSV_COLUMNS
    # Adjacent to runner_owner so deferral signals land together.
    cols = list(compliance_evaluation_service.EXPORT_CSV_COLUMNS)
    assert (
        cols.index("runner_status") - cols.index("runner_owner") == 1
    ), "runner_status must immediately follow runner_owner in CSV header"


def test_export_row_carries_runner_owner_after_check_delete(
    db, admin_user, host, monkeypatch
):
    # PRA-166 routes file_exists through the probe runner; stub it so
    # this read-surface test doesn't depend on a live SSH host.
    from app.services import compliance_probe_runner_service

    monkeypatch.setitem(
        compliance_probe_runner_service._PROBES,
        "file_exists",
        lambda db, system_id, definition: compliance_probe_runner_service.ProbeOutcome(
            verdict="pass",
            observed_value="exists",
            expected_value=definition["path"],
        ),
    )

    p = _make_policy(db, admin_user, "runner-owner-survives")
    check = _add_check(
        db,
        admin_user,
        p,
        "file-check",
        "file_exists",
        {"path": "/etc/passwd"},
    )
    _evaluate(db, p, host)
    compliance_service.delete_check(db, check.id, actor_user_id=admin_user.id)
    rows = (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.policy_id == p.id)
        .all()
    )
    assert rows
    payload = compliance_evaluation_service.evidence_export_row(rows[0])
    assert payload["runner_owner"] == "deferred_to_pra166"
    assert payload["evaluated_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Export audit emission — session-boundary lock
# ---------------------------------------------------------------------------


def test_export_audit_uses_session_boundary(capture_audit):
    compliance_evaluation_service.emit_export_requested_audit(
        actor_user_id=1,
        actor_username="admin",
        actor_ip="10.0.0.1",
        export_format="jsonl",
        filters={"policy_id": 42},
        row_count=7,
    )
    calls = capture_audit.by_action("compliance_export.requested")
    assert len(calls) == 1
    call = calls[0]
    assert call["outcome"] == "success"
    assert call["context"]["format"] == "jsonl"
    assert call["context"]["row_count"] == 7
    # Session-boundary lock: safe_emit is invoked WITHOUT db= so it
    # opens its own SessionLocal.
    assert "db" not in call


# ---------------------------------------------------------------------------
# UTC wire shape on export row
# ---------------------------------------------------------------------------


def test_export_row_timestamps_are_z(db, admin_user, host):
    p = _make_policy(db, admin_user, "z-shape")
    _add_check(
        db, admin_user, p, "c", "package_installed", {"package": "openssh-server"}
    )
    _install_package(db, host.id, "openssh-server")
    _evaluate(db, p, host)
    row = (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.policy_id == p.id)
        .first()
    )
    payload = compliance_evaluation_service.evidence_export_row(row)
    for key in ("evaluated_at", "created_at", "updated_at"):
        assert payload[key].endswith("Z"), key
