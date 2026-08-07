"""PRA-178 Slice 2 — report-run substrate route + service tests.

Covers:

* Service lifecycle (``start_run`` → ``complete_run`` /
  ``fail_run``) including state-machine refusal of double-completion.
* Service ``record_completed_run`` (single-shot) shape.
* Route GET ``/reports/runs`` filtering, pagination, RBAC, and bad
  filter validation.
* Manual Slice 1 export hook persists a ``report_runs`` row with the
  filters / format / row_count, without changing the Slice 1
  response shape.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdatePlan,
    ReportRun,
    System,
)
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_service,
    compliance_service,
    report_run_service,
)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


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
# Service-level lifecycle tests
# ---------------------------------------------------------------------------


def test_record_completed_run_persists_row(db, admin_user):
    row = report_run_service.record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        triggered_by=report_run_service.TRIGGERED_BY_USER,
        triggered_by_user_id=admin_user.id,
        triggered_by_username=admin_user.username,
        format="csv",
        filters_snapshot={"plan_id": 7, "state": None},
        row_count=42,
    )
    assert row.id is not None
    assert row.state == report_run_service.STATE_SUCCEEDED
    assert row.report_kind == "patch_executions"
    assert row.triggered_by == "user"
    assert row.triggered_by_user_id == admin_user.id
    assert row.triggered_by_username == admin_user.username
    assert row.format == "csv"
    assert row.row_count == 42
    assert row.filters_snapshot == {"plan_id": 7, "state": None}
    assert row.started_at is not None
    assert row.completed_at is not None


def test_lifecycle_start_then_complete(db, admin_user):
    started = report_run_service.start_run(
        db,
        report_kind=report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
        triggered_by_user_id=admin_user.id,
        triggered_by_username=admin_user.username,
        format="json",
        filters_snapshot={"policy_id": 3},
    )
    assert started.state == report_run_service.STATE_STARTED
    assert started.completed_at is None

    completed = report_run_service.complete_run(db, run_id=started.id, row_count=11)
    assert completed.state == report_run_service.STATE_SUCCEEDED
    assert completed.row_count == 11
    assert completed.completed_at is not None


def test_lifecycle_fail_run_bounds_error_message(db, admin_user):
    started = report_run_service.start_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        triggered_by_user_id=admin_user.id,
    )
    overlong = "x" * (report_run_service.MAX_ERROR_MESSAGE_CHARS + 256)
    failed = report_run_service.fail_run(db, run_id=started.id, error_message=overlong)
    assert failed.state == report_run_service.STATE_FAILED
    assert failed.error_message is not None
    assert len(failed.error_message) == report_run_service.MAX_ERROR_MESSAGE_CHARS


def test_complete_run_refuses_non_started_state(db, admin_user):
    row = report_run_service.record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        triggered_by_user_id=admin_user.id,
        row_count=0,
    )
    with pytest.raises(report_run_service.ReportRunError):
        report_run_service.complete_run(db, run_id=row.id, row_count=1)


def test_record_completed_run_rejects_bad_kind(db, admin_user):
    with pytest.raises(report_run_service.ReportRunError):
        report_run_service.record_completed_run(
            db,
            report_kind="not_a_real_kind",
            triggered_by_user_id=admin_user.id,
            row_count=0,
        )


def test_record_completed_run_rejects_oversized_filters(db, admin_user):
    huge = {"junk": "x" * (report_run_service.MAX_FILTERS_SNAPSHOT_BYTES + 100)}
    with pytest.raises(report_run_service.ReportRunError):
        report_run_service.record_completed_run(
            db,
            report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
            triggered_by_user_id=admin_user.id,
            filters_snapshot=huge,
            row_count=0,
        )


# ---------------------------------------------------------------------------
# GET /reports/runs route tests
# ---------------------------------------------------------------------------


def _seed_runs(db, admin_user) -> dict:
    """Seed a small mix of report-run rows across kinds and states."""
    rows = {}
    rows["patch_csv"] = report_run_service.record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        triggered_by_user_id=admin_user.id,
        triggered_by_username=admin_user.username,
        format="csv",
        filters_snapshot={"plan_id": 1},
        row_count=5,
    )
    rows["patch_json"] = report_run_service.record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        triggered_by_user_id=admin_user.id,
        triggered_by_username=admin_user.username,
        format="json",
        filters_snapshot={"plan_id": 2},
        row_count=3,
    )
    rows["remediation_csv"] = report_run_service.record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
        triggered_by_user_id=admin_user.id,
        triggered_by_username=admin_user.username,
        format="csv",
        filters_snapshot={"state": "requested"},
        row_count=7,
    )
    db.commit()
    return rows


def test_list_runs_route_returns_all_kinds(authed_client, db, admin_user):
    seeded = _seed_runs(db, admin_user)
    res = authed_client.get("/reports/runs")
    assert res.status_code == 200, res.text
    body = res.json()
    ids = [r["id"] for r in body["items"]]
    for row in seeded.values():
        assert row.id in ids
    assert body["total"] >= 3
    assert body["offset"] == 0
    # Most-recent first ordering.
    if len(body["items"]) >= 2:
        assert body["items"][0]["started_at"] >= body["items"][1]["started_at"]


def test_list_runs_route_filters_by_kind(authed_client, db, admin_user):
    seeded = _seed_runs(db, admin_user)
    res = authed_client.get(
        "/reports/runs",
        params={"report_kind": "patch_executions"},
    )
    assert res.status_code == 200
    body = res.json()
    assert all(r["report_kind"] == "patch_executions" for r in body["items"])
    assert seeded["remediation_csv"].id not in [r["id"] for r in body["items"]]


def test_list_runs_route_filter_by_state(authed_client, db, admin_user):
    started = report_run_service.start_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        triggered_by_user_id=admin_user.id,
    )
    db.commit()
    res = authed_client.get("/reports/runs", params={"state": "started"})
    assert res.status_code == 200
    body = res.json()
    assert all(r["state"] == "started" for r in body["items"])
    assert started.id in [r["id"] for r in body["items"]]


def test_list_runs_route_rejects_bad_kind(authed_client):
    res = authed_client.get("/reports/runs", params={"report_kind": "not_a_real_kind"})
    assert res.status_code == 422
    assert "report_kind" in res.json()["detail"]


def test_list_runs_route_rejects_bad_state(authed_client):
    res = authed_client.get("/reports/runs", params={"state": "weird"})
    assert res.status_code == 422


def test_list_runs_route_pagination_next_offset(authed_client, db, admin_user):
    _seed_runs(db, admin_user)
    res = authed_client.get("/reports/runs", params={"limit": 1})
    assert res.status_code == 200
    body = res.json()
    assert len(body["items"]) == 1
    assert body["limit"] == 1
    if body["total"] > 1:
        assert body["next_offset"] == 1


def test_list_runs_route_auditor_can_read(client, auditor_user, db, admin_user):
    _seed_runs(db, admin_user)
    db.commit()
    token = _login(client, auditor_user)
    res = client.get("/reports/runs", headers=_bearer(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert isinstance(body["items"], list)


def test_list_runs_route_requires_auth(client):
    res = client.get("/reports/runs")
    assert res.status_code in (401, 403)


def test_list_runs_route_viewer_denied(client, db, seed_roles):
    """Viewer (read-only) role is intentionally NOT one of the three
    that may read report-run history. Slice 2a fix to the P1
    review finding: ``GET /reports/runs`` enforces
    ``require_role("admin", "maintainer", "auditor")`` instead of
    accepting any authenticated user.
    """
    from app.core.auth import get_password_hash
    from app.db.models import User

    viewer = User(
        username="viewertest",
        email="viewertest@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    viewer.roles.append(seed_roles["viewer"])
    db.add(viewer)
    db.commit()

    token = _login(client, viewer)
    res = client.get("/reports/runs", headers=_bearer(token))
    assert res.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Slice 1 export hook tests — each successful manual export should
# leave a report_runs row with the right kind / format / row_count.
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro) -> System:
    g = Group(name="pra178-s2-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra178-s2-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    h = System(
        hostname="pra178-s2.example.com",
        ip_address="10.0.0.179",
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
        slug="pra178-s2-pol",
        name="PRA-178 S2 policy",
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
        name="PRA-178 S2 plan",
        state="approved",
        policy_snapshot={"slug": "pra178-s2-pol", "name": "S2", "version": 1},
        request_snapshot={},
        block_reasons=[],
        ring_sequence_snapshot=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    return plan


def test_patch_export_hook_persists_report_run(
    authed_client, db, admin_user, patch_plan
):
    exec_row = PatchUpdateExecution(
        plan_id=patch_plan.id,
        state="succeeded",
        started_by=admin_user.id,
        started_at=datetime.utcnow() - timedelta(hours=1),
        completed_at=datetime.utcnow(),
        max_parallel_per_wave=5,
        failure_threshold_percent=10,
        plan_state_snapshot="approved",
        policy_snapshot={"slug": "pra178-s2-pol"},
        execution_config_snapshot={},
        progress_summary={
            "host_count": 1,
            "host_counts_by_state": {"succeeded": 1},
            "package_outcome_counts": {"succeeded": 2},
        },
    )
    db.add(exec_row)
    db.commit()

    res = authed_client.get(
        "/patch/update-executions/export",
        params={"format": "json", "plan_id": patch_plan.id},
    )
    assert res.status_code == 200, res.text
    assert isinstance(res.json(), list)
    assert len(res.json()) == 1

    # The hook shares the request's session (Slice 2 wires
    # safe_record_completed_run with db=request_session), so the row
    # is visible through the test session inside the same savepoint.
    latest = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "patch_executions")
        .filter(ReportRun.triggered_by_user_id == admin_user.id)
        .order_by(ReportRun.id.desc())
        .first()
    )
    assert latest is not None, "expected hook to persist a report-run row"
    assert latest.row_count == 1
    assert latest.format == "json"
    assert latest.state == "succeeded"
    assert latest.triggered_by == "user"
    assert (latest.filters_snapshot or {}).get("plan_id") == patch_plan.id


@pytest.fixture
def failing_evidence(db, admin_user, host):
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="pra178-s2-rem-policy",
        name="PRA-178 S2 Remediation",
        remediation_guidance="run the playbook",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="pra178-s2-missing-pkg",
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


def test_remediation_export_hook_persists_report_run(
    authed_client, db, admin_user, failing_evidence
):
    compliance_remediation_service.create_request(
        db,
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        actor_ip="127.0.0.1",
        evidence_id=failing_evidence.id,
        justification="open per finding",
    )
    db.commit()

    res = authed_client.get(
        "/compliance/exports/remediation-requests",
        params={"format": "csv"},
    )
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")

    latest = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "compliance_remediation_requests")
        .filter(ReportRun.triggered_by_user_id == admin_user.id)
        .order_by(ReportRun.id.desc())
        .first()
    )
    assert latest is not None
    assert latest.format == "csv"
    assert latest.state == "succeeded"
    assert latest.triggered_by == "user"
    assert (latest.row_count or 0) >= 1
