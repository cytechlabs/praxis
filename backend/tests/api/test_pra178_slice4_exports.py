"""PRA-178 Slice 4 — broader CSV/JSON export route tests.

Covers all 5 new export classes:

* ``GET /patch/update-plans/export``
* ``GET /patch/update-executions/{execution_id}/reboots/export``
* ``GET /patch/update-executions/{execution_id}/rollback/export``
* ``GET /compliance/exports/remediation-plans``
* ``GET /compliance/exports/remediation-executions``

For each: one JSON shape assertion, one CSV header assertion, one
auditor denial (admin/maintainer-only RBAC), and one Slice 2
``report_runs`` persistence assertion through the shared
``safe_record_completed_run`` hook.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta

import pytest

from app.db.models import (
    ComplianceRemediationExecutionAttempt,
    ComplianceRemediationPlan,
    Credential,
    Group,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionReboot,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    ReportRun,
    System,
)
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_execution_export_service,
    compliance_remediation_plan_export_service,
    compliance_service,
    patch_plans_export_service,
    patch_reboots_export_service,
    patch_rollbacks_export_service,
)


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Shared host + policy + plan + execution fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro) -> System:
    g = Group(name="pra178-s4-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra178-s4-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    h = System(
        hostname="pra178-s4.example.com",
        ip_address="10.0.0.184",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(h)
    db.flush()
    return h


@pytest.fixture
def patch_plan(db, admin_user) -> PatchUpdatePlan:
    pol = PatchPolicy(
        slug="pra178-s4-pol",
        name="PRA-178 S4 policy",
        scope_kind="full",
        reboot_policy="if_required",
        rollout_cadence="immediate",
        failure_policy="continue",
        requires_approval=False,
        created_by=admin_user.id,
    )
    db.add(pol)
    db.flush()
    plan = PatchUpdatePlan(
        policy_id=pol.id,
        name="PRA-178 S4 plan",
        state="approved",
        policy_snapshot={"slug": "pra178-s4-pol", "name": "S4", "version": 1},
        request_snapshot={},
        block_reasons=[],
        ring_sequence_snapshot=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    return plan


# ---------------------------------------------------------------------------
# Patch update plans export
# ---------------------------------------------------------------------------


def test_patch_plans_export_json(authed_client, db, admin_user, patch_plan):
    db.commit()
    res = authed_client.get("/patch/update-plans/export", params={"format": "json"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert isinstance(body, list)
    matching = [r for r in body if r["id"] == patch_plan.id]
    assert matching, body
    row = matching[0]
    assert row["name"] == "PRA-178 S4 plan"
    assert row["policy_slug_snapshot"] == "pra178-s4-pol"
    assert row["state"] == "approved"
    assert row["created_by_user_id"] == admin_user.id
    assert row["created_by_username"] == admin_user.username
    assert row["created_at"].endswith("Z")


def test_patch_plans_export_csv_header_order(authed_client, db, patch_plan):
    db.commit()
    res = authed_client.get("/patch/update-plans/export", params={"format": "csv"})
    assert res.status_code == 200
    reader = csv.reader(io.StringIO(res.text))
    rows = list(reader)
    assert tuple(rows[0]) == patch_plans_export_service.EXPORT_CSV_COLUMNS


def test_patch_plans_export_auditor_denied(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get(
        "/patch/update-plans/export",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code in (401, 403)


def test_patch_plans_export_persists_report_run(
    authed_client, db, admin_user, patch_plan
):
    db.commit()
    res = authed_client.get("/patch/update-plans/export", params={"format": "csv"})
    assert res.status_code == 200
    latest = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "patch_update_plans")
        .filter(ReportRun.triggered_by_user_id == admin_user.id)
        .order_by(ReportRun.id.desc())
        .first()
    )
    assert latest is not None
    assert latest.state == "succeeded"
    assert latest.format == "csv"
    assert (latest.row_count or 0) >= 1


def test_patch_plans_export_rejects_inverted_window(authed_client):
    after = (datetime.utcnow() - timedelta(days=1)).isoformat()
    before = (datetime.utcnow() - timedelta(days=2)).isoformat()
    res = authed_client.get(
        "/patch/update-plans/export",
        params={"format": "json", "created_after": after, "created_before": before},
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Per-execution reboot queue + rollback exports
# ---------------------------------------------------------------------------


@pytest.fixture
def patch_execution(db, admin_user, patch_plan) -> PatchUpdateExecution:
    exe = PatchUpdateExecution(
        plan_id=patch_plan.id,
        state="succeeded",
        started_by=admin_user.id,
        started_at=datetime.utcnow() - timedelta(hours=2),
        completed_at=datetime.utcnow() - timedelta(hours=1),
        max_parallel_per_wave=5,
        failure_threshold_percent=10,
        plan_state_snapshot="approved",
        policy_snapshot={"slug": "pra178-s4-pol"},
        execution_config_snapshot={},
        progress_summary={
            "host_count": 1,
            "host_counts_by_state": {"succeeded": 1},
        },
    )
    db.add(exe)
    db.flush()
    return exe


@pytest.fixture
def patch_execution_host(db, patch_execution):
    # The reboot + rollback fixtures FK to patch_update_execution_hosts;
    # we need a minimal plan-host and execution-host row to satisfy the
    # FK without driving the full PRA-171 substrate.
    plan_host = PatchUpdatePlanHost(
        plan_id=patch_execution.plan_id,
        system_id=None,
        system_hostname_snapshot="pra178-s4-host.example.com",
        policy_id_snapshot=None,
        policy_slug_snapshot=None,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=0,
        content_profile_state="no_profile",
        state="planned",
        block_reasons=[],
    )
    db.add(plan_host)
    db.flush()
    eh = __import__(
        "app.db.models", fromlist=["PatchUpdateExecutionHost"]
    ).PatchUpdateExecutionHost(
        execution_id=patch_execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=99,
        system_hostname_snapshot="pra178-s4-host.example.com",
        wave_index=0,
        state="succeeded",
        selected_package_count=0,
    )
    db.add(eh)
    db.flush()
    return eh


@pytest.fixture
def patch_reboot(
    db, patch_execution, patch_execution_host
) -> PatchUpdateExecutionReboot:
    row = PatchUpdateExecutionReboot(
        execution_id=patch_execution.id,
        execution_host_id=patch_execution_host.id,
        plan_id_snapshot=patch_execution.plan_id,
        system_id_snapshot=99,
        system_hostname_snapshot="pra178-s4-host.example.com",
        wave_index=0,
        state="healthy",
        reboot_policy_snapshot="if_required",
        reboot_required_fact=True,
        decision_code="required_reboot",
        decision_details={},
    )
    db.add(row)
    db.flush()
    return row


def test_patch_reboots_export_json(
    authed_client, db, admin_user, patch_execution, patch_reboot
):
    db.commit()
    res = authed_client.get(
        f"/patch/update-executions/{patch_execution.id}/reboots/export",
        params={"format": "json"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["id"] == patch_reboot.id
    assert body[0]["execution_id"] == patch_execution.id
    assert body[0]["system_hostname_snapshot"] == "pra178-s4-host.example.com"


def test_patch_reboots_export_csv_header_order(
    authed_client, db, patch_execution, patch_reboot
):
    db.commit()
    res = authed_client.get(
        f"/patch/update-executions/{patch_execution.id}/reboots/export",
        params={"format": "csv"},
    )
    assert res.status_code == 200
    reader = csv.reader(io.StringIO(res.text))
    header = next(reader)
    assert tuple(header) == patch_reboots_export_service.EXPORT_CSV_COLUMNS


def test_patch_reboots_export_auditor_denied(client, auditor_user, db, patch_execution):
    db.commit()
    token = _login(client, auditor_user)
    res = client.get(
        f"/patch/update-executions/{patch_execution.id}/reboots/export",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code in (401, 403)


def test_patch_reboots_export_persists_report_run(
    authed_client, db, admin_user, patch_execution, patch_reboot
):
    db.commit()
    res = authed_client.get(
        f"/patch/update-executions/{patch_execution.id}/reboots/export",
        params={"format": "json"},
    )
    assert res.status_code == 200
    latest = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "patch_reboot_queues")
        .filter(ReportRun.triggered_by_user_id == admin_user.id)
        .order_by(ReportRun.id.desc())
        .first()
    )
    assert latest is not None
    assert latest.state == "succeeded"
    assert (latest.filters_snapshot or {}).get("execution_id") == patch_execution.id


# ---------- rollback export ----------


def test_patch_rollback_export_json_empty_for_no_run(
    authed_client, db, patch_execution
):
    """The rollback export returns an empty list when an execution has
    no rollback rows. Wiring + audit + report_runs still fires."""
    db.commit()
    res = authed_client.get(
        f"/patch/update-executions/{patch_execution.id}/rollback/export",
        params={"format": "json"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert isinstance(body, list)
    assert body == []


def test_patch_rollback_export_csv_header_order(authed_client, db, patch_execution):
    """Even with no rollback rows, the CSV response carries the pinned
    header so external auditor scripts can rely on the column order."""
    db.commit()
    res = authed_client.get(
        f"/patch/update-executions/{patch_execution.id}/rollback/export",
        params={"format": "csv"},
    )
    assert res.status_code == 200
    reader = csv.reader(io.StringIO(res.text))
    header = next(reader)
    assert tuple(header) == patch_rollbacks_export_service.EXPORT_CSV_COLUMNS


def test_patch_rollback_export_auditor_denied(
    client, auditor_user, db, patch_execution
):
    db.commit()
    token = _login(client, auditor_user)
    res = client.get(
        f"/patch/update-executions/{patch_execution.id}/rollback/export",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code in (401, 403)


def test_patch_rollback_export_persists_report_run(
    authed_client, db, admin_user, patch_execution
):
    db.commit()
    res = authed_client.get(
        f"/patch/update-executions/{patch_execution.id}/rollback/export",
        params={"format": "json"},
    )
    assert res.status_code == 200
    latest = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "patch_rollback_runs")
        .filter(ReportRun.triggered_by_user_id == admin_user.id)
        .order_by(ReportRun.id.desc())
        .first()
    )
    assert latest is not None
    assert latest.state == "succeeded"


# ---------- Slice 4a fix: 404 on unknown execution_id ----------


def test_patch_reboots_export_unknown_execution_returns_404(authed_client, db):
    """Nonexistent execution_id must 404 rather than emit a 200/empty
    + ``report_runs`` row for a typoed id.
    """
    db.commit()
    res = authed_client.get(
        "/patch/update-executions/9999999/reboots/export",
        params={"format": "json"},
    )
    assert res.status_code == 404
    # And no report_runs row was persisted for the bogus id.
    assert (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "patch_reboot_queues")
        .filter(ReportRun.filters_snapshot["execution_id"].as_integer() == 9999999)
        .count()
        == 0
    )


def test_patch_rollback_export_unknown_execution_returns_404(authed_client, db):
    db.commit()
    res = authed_client.get(
        "/patch/update-executions/9999999/rollback/export",
        params={"format": "json"},
    )
    assert res.status_code == 404
    assert (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "patch_rollback_runs")
        .filter(ReportRun.filters_snapshot["execution_id"].as_integer() == 9999999)
        .count()
        == 0
    )


# ---------------------------------------------------------------------------
# Compliance remediation plans + execution attempts exports
# ---------------------------------------------------------------------------


@pytest.fixture
def failing_evidence(db, admin_user, host):
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="pra178-s4-rem-policy",
        name="PRA-178 S4 Remediation",
        remediation_guidance="run the playbook",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="pra178-s4-missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "definitely-not-installed-pkg"},
        remediation_guidance="apt-get install -y missing-pkg",
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    from app.db.models import CompliancePolicyEvidence

    return (
        db.query(CompliancePolicyEvidence)
        .filter_by(policy_id=policy.id, system_id=host.id, verdict="fail")
        .one()
    )


@pytest.fixture
def remediation_plan(db, admin_user, failing_evidence) -> ComplianceRemediationPlan:
    from app.services import compliance_remediation_service

    req = compliance_remediation_service.create_request(
        db,
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        actor_ip="127.0.0.1",
        evidence_id=failing_evidence.id,
        justification="open per finding",
    )
    plan = ComplianceRemediationPlan(
        request_id=req.id,
        policy_id=req.policy_id,
        check_id=req.check_id,
        system_id=req.system_id,
        policy_slug=req.policy_slug,
        policy_version=req.policy_version,
        check_slug=req.check_slug,
        check_kind=req.check_kind,
        severity_snapshot=req.severity_snapshot,
        state="planned",
        plan_kind="package_install_preview",
        plan_steps=[{"action_intent": "install", "target": {"package": "x"}}],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    return plan


def test_remediation_plans_export_json(authed_client, db, admin_user, remediation_plan):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-plans", params={"format": "json"}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    matching = [r for r in body if r["id"] == remediation_plan.id]
    assert matching, body
    row = matching[0]
    assert row["policy_slug"] == remediation_plan.policy_slug
    assert row["state"] == "planned"
    assert row["plan_kind"] == "package_install_preview"
    assert row["is_current"] is True


def test_remediation_plans_export_csv_header_order(authed_client, db, remediation_plan):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-plans", params={"format": "csv"}
    )
    assert res.status_code == 200
    reader = csv.reader(io.StringIO(res.text))
    header = next(reader)
    assert (
        tuple(header) == compliance_remediation_plan_export_service.EXPORT_CSV_COLUMNS
    )


def test_remediation_plans_export_auditor_denied(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get(
        "/compliance/exports/remediation-plans",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code in (401, 403)


def test_remediation_plans_export_persists_report_run(
    authed_client, db, admin_user, remediation_plan
):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-plans", params={"format": "csv"}
    )
    assert res.status_code == 200
    latest = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "compliance_remediation_plans")
        .filter(ReportRun.triggered_by_user_id == admin_user.id)
        .order_by(ReportRun.id.desc())
        .first()
    )
    assert latest is not None
    assert latest.state == "succeeded"


# ---------- remediation execution attempts export ----------


@pytest.fixture
def remediation_attempt(
    db, admin_user, remediation_plan
) -> ComplianceRemediationExecutionAttempt:
    attempt = ComplianceRemediationExecutionAttempt(
        request_id=remediation_plan.request_id,
        plan_id=remediation_plan.id,
        policy_id=remediation_plan.policy_id,
        check_id=remediation_plan.check_id,
        system_id=remediation_plan.system_id,
        policy_slug=remediation_plan.policy_slug,
        policy_version=remediation_plan.policy_version,
        check_slug=remediation_plan.check_slug,
        check_kind=remediation_plan.check_kind,
        severity_snapshot=remediation_plan.severity_snapshot,
        plan_kind_snapshot=remediation_plan.plan_kind,
        package_name="x",
        state="pending",
        created_by=admin_user.id,
    )
    db.add(attempt)
    db.flush()
    return attempt


def test_remediation_executions_export_json(
    authed_client, db, admin_user, remediation_attempt
):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-executions", params={"format": "json"}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    matching = [r for r in body if r["id"] == remediation_attempt.id]
    assert matching, body
    row = matching[0]
    assert row["state"] == "pending"
    assert row["plan_id"] == remediation_attempt.plan_id
    assert row["package_name"] == "x"


def test_remediation_executions_export_csv_header_order(
    authed_client, db, remediation_attempt
):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-executions", params={"format": "csv"}
    )
    assert res.status_code == 200
    reader = csv.reader(io.StringIO(res.text))
    header = next(reader)
    assert (
        tuple(header)
        == compliance_remediation_execution_export_service.EXPORT_CSV_COLUMNS
    )


def test_remediation_executions_export_auditor_denied(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get(
        "/compliance/exports/remediation-executions",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code in (401, 403)


def test_remediation_executions_export_persists_report_run(
    authed_client, db, admin_user, remediation_attempt
):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-executions", params={"format": "csv"}
    )
    assert res.status_code == 200
    latest = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "compliance_remediation_executions")
        .filter(ReportRun.triggered_by_user_id == admin_user.id)
        .order_by(ReportRun.id.desc())
        .first()
    )
    assert latest is not None
    assert latest.state == "succeeded"
