"""PRA-178 Slice 1 — manual reporting/export route tests.

Covers the bounded review-period exports added in Slice 1:

* ``GET /patch/update-executions/export`` — patch execution review
  report; CSV and JSON output paths plus the auth gate.
* ``GET /compliance/exports/remediation-requests`` — compliance
  remediation request review report; CSV and JSON output paths plus
  the auth gate.

The tests assert wire-shape stability, bounded review-window
validation, the optional filter set, and that auditor cannot
trigger either export (matches the admin/maintainer RBAC in the
route layer).
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdatePlan,
    System,
)
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_export_service,
    compliance_remediation_service,
    compliance_service,
    patch_reports_service,
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
# Shared host + policy + plan fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro) -> System:
    g = Group(name="pra178-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra178-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    h = System(
        hostname="pra178-host.example.com",
        ip_address="10.0.0.178",
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
    """Minimal ``PatchUpdatePlan`` row sufficient for the export
    join. The export reads ``name`` and ``policy_snapshot['slug']``
    on the plan — no execution-pipeline state is required.
    """
    pol = PatchPolicy(
        slug="pra178-pol",
        name="PRA-178 policy",
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
        name="PRA-178 plan",
        state="approved",
        policy_snapshot={
            "slug": "pra178-pol",
            "name": "PRA-178 policy",
            "version": 1,
        },
        request_snapshot={},
        block_reasons=[],
        ring_sequence_snapshot=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    return plan


def _seed_execution(
    db,
    *,
    plan: PatchUpdatePlan,
    admin_user_id: int,
    started_at: datetime,
    state: str = "succeeded",
    progress: dict | None = None,
) -> PatchUpdateExecution:
    exec_row = PatchUpdateExecution(
        plan_id=plan.id,
        state=state,
        started_by=admin_user_id,
        started_at=started_at,
        completed_at=(
            started_at + timedelta(minutes=5) if state == "succeeded" else None
        ),
        max_parallel_per_wave=5,
        failure_threshold_percent=10,
        plan_state_snapshot="approved",
        policy_snapshot={"slug": "pra178-pol"},
        execution_config_snapshot={},
        progress_summary=progress
        or {
            "host_count": 3,
            "host_counts_by_state": {
                "succeeded": 3,
                "failed": 0,
                "skipped": 0,
                "canceled": 0,
            },
            "package_outcome_counts": {
                "succeeded": 7,
                "failed": 0,
                "skipped": 1,
            },
        },
    )
    db.add(exec_row)
    db.flush()
    return exec_row


# ---------------------------------------------------------------------------
# Patch execution export — JSON
# ---------------------------------------------------------------------------


def test_patch_execution_export_json_returns_rows_for_window(
    authed_client, db, admin_user, patch_plan
):
    now = datetime.utcnow()
    inside = now - timedelta(days=2)
    outside = now - timedelta(days=200)
    _seed_execution(db, plan=patch_plan, admin_user_id=admin_user.id, started_at=inside)
    _seed_execution(
        db,
        plan=patch_plan,
        admin_user_id=admin_user.id,
        started_at=outside,
    )
    db.commit()

    # Filter by plan_id so the assertion is robust against unrelated
    # patch executions that other tests may have committed earlier in
    # the session.
    res = authed_client.get(
        "/patch/update-executions/export",
        params={"format": "json", "plan_id": patch_plan.id},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert isinstance(body, list)
    # Default window is 30 days; only the row inside the window should
    # appear (the 200-days-ago row is filtered out).
    assert len(body) == 1
    row = body[0]
    assert row["plan_id"] == patch_plan.id
    assert row["plan_name_snapshot"] == "PRA-178 plan"
    assert row["policy_slug_snapshot"] == "pra178-pol"
    assert row["state"] == "succeeded"
    assert row["plan_state_snapshot"] == "approved"
    assert row["host_count"] == 3
    assert row["host_succeeded"] == 3
    assert row["package_succeeded"] == 7
    assert row["started_by_user_id"] == admin_user.id
    assert row["started_by_username"] == admin_user.username
    assert row["started_at"].endswith("Z")
    assert row["completed_at"].endswith("Z")


def test_patch_execution_export_csv_pinned_header_order(
    authed_client, db, admin_user, patch_plan
):
    _seed_execution(
        db,
        plan=patch_plan,
        admin_user_id=admin_user.id,
        started_at=datetime.utcnow() - timedelta(hours=1),
    )
    db.commit()

    res = authed_client.get(
        "/patch/update-executions/export",
        params={"format": "csv", "plan_id": patch_plan.id},
    )
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers.get("content-disposition", "")
    reader = csv.reader(io.StringIO(res.text))
    rows = list(reader)
    # Header order must match the pinned EXPORT_CSV_COLUMNS tuple so
    # downstream auditor scripts stay stable.
    assert tuple(rows[0]) == patch_reports_service.EXPORT_CSV_COLUMNS
    assert len(rows) == 2  # header + 1 data row


def test_patch_execution_export_rejects_inverted_window(authed_client):
    after = (datetime.utcnow() - timedelta(days=1)).isoformat()
    before = (datetime.utcnow() - timedelta(days=2)).isoformat()
    res = authed_client.get(
        "/patch/update-executions/export",
        params={
            "format": "json",
            "started_after": after,
            "started_before": before,
        },
    )
    assert res.status_code == 422
    assert "strictly greater" in res.json()["detail"]


def test_patch_execution_export_rejects_oversized_window(authed_client):
    after = (datetime.utcnow() - timedelta(days=500)).isoformat()
    before = datetime.utcnow().isoformat()
    res = authed_client.get(
        "/patch/update-executions/export",
        params={
            "format": "json",
            "started_after": after,
            "started_before": before,
        },
    )
    assert res.status_code == 422
    assert "export window" in res.json()["detail"]


def test_patch_execution_export_rejects_bad_state(authed_client):
    res = authed_client.get(
        "/patch/update-executions/export",
        params={"format": "json", "state": "not-a-real-state"},
    )
    assert res.status_code == 422


def test_patch_execution_export_rejects_bad_format(authed_client):
    res = authed_client.get(
        "/patch/update-executions/export",
        params={"format": "xml"},
    )
    assert res.status_code == 422


def test_patch_execution_export_auditor_denied(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get(
        "/patch/update-executions/export",
        headers=_bearer(token),
        params={"format": "json"},
    )
    # require_role denies auditor for admin/maintainer-only routes;
    # the gate may return 401 or 403 depending on the dependency path.
    assert res.status_code in (401, 403)


def test_patch_execution_export_maintainer_allowed(
    client, maintainer_user, db, admin_user, patch_plan
):
    _seed_execution(
        db,
        plan=patch_plan,
        admin_user_id=admin_user.id,
        started_at=datetime.utcnow() - timedelta(hours=2),
    )
    db.commit()
    token = _login(client, maintainer_user)
    res = client.get(
        "/patch/update-executions/export",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code == 200, res.text
    assert isinstance(res.json(), list)


# ---------------------------------------------------------------------------
# Compliance remediation export — fixture: a failing-evidence policy +
# one open remediation request created via the existing service path.
# ---------------------------------------------------------------------------


@pytest.fixture
def failing_evidence(db, admin_user, host):
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="pra178-rem-policy",
        name="PRA-178 Remediation",
        remediation_guidance="run the playbook",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="pra178-missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "definitely-not-installed-pkg"},
        remediation_guidance="apt-get install -y missing-pkg",
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    return (
        db.query(
            __import__(
                "app.db.models", fromlist=["CompliancePolicyEvidence"]
            ).CompliancePolicyEvidence
        )
        .filter_by(policy_id=policy.id, system_id=host.id, verdict="fail")
        .one()
    )


@pytest.fixture
def remediation_request(db, admin_user, failing_evidence):
    return compliance_remediation_service.create_request(
        db,
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        actor_ip="127.0.0.1",
        evidence_id=failing_evidence.id,
        justification="open per finding",
    )


def test_compliance_remediation_export_json_returns_request(
    authed_client, db, admin_user, host, remediation_request
):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-requests",
        params={"format": "json"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert isinstance(body, list)
    assert len(body) >= 1
    matching = [r for r in body if r["id"] == remediation_request.id]
    assert matching, body
    row = matching[0]
    assert row["state"] == "requested"
    assert row["policy_slug"] == remediation_request.policy_slug
    assert row["check_kind"] == remediation_request.check_kind
    assert row["verdict_snapshot"] == "fail"
    assert row["system_id"] == host.id
    assert row["system_hostname"] == host.hostname
    assert row["requested_by_user_id"] == admin_user.id
    assert row["requested_by_username"] == admin_user.username
    assert row["created_at"].endswith("Z")
    assert row["updated_at"].endswith("Z")
    assert row["decided_at"] is None  # request is still pending


def test_compliance_remediation_export_csv_pinned_header_order(
    authed_client, db, remediation_request
):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-requests",
        params={"format": "csv"},
    )
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    reader = csv.reader(io.StringIO(res.text))
    rows = list(reader)
    assert tuple(rows[0]) == compliance_remediation_export_service.EXPORT_CSV_COLUMNS
    # header + at least the one request seeded by the fixture
    assert len(rows) >= 2


def test_compliance_remediation_export_state_filter_excludes_other_states(
    authed_client, db, remediation_request
):
    db.commit()
    res = authed_client.get(
        "/compliance/exports/remediation-requests",
        params={"format": "json", "state": "approved"},
    )
    assert res.status_code == 200
    body = res.json()
    assert all(r["state"] == "approved" for r in body)
    # The requested-state row from the fixture must NOT leak through.
    assert all(r["id"] != remediation_request.id for r in body)


def test_compliance_remediation_export_rejects_inverted_window(authed_client):
    after = (datetime.utcnow() - timedelta(days=1)).isoformat()
    before = (datetime.utcnow() - timedelta(days=2)).isoformat()
    res = authed_client.get(
        "/compliance/exports/remediation-requests",
        params={
            "format": "json",
            "created_after": after,
            "created_before": before,
        },
    )
    assert res.status_code == 422


def test_compliance_remediation_export_rejects_oversized_window(authed_client):
    after = (datetime.utcnow() - timedelta(days=500)).isoformat()
    before = datetime.utcnow().isoformat()
    res = authed_client.get(
        "/compliance/exports/remediation-requests",
        params={
            "format": "json",
            "created_after": after,
            "created_before": before,
        },
    )
    assert res.status_code == 422


def test_compliance_remediation_export_auditor_denied(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get(
        "/compliance/exports/remediation-requests",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code in (401, 403)


def test_compliance_remediation_export_maintainer_allowed(client, maintainer_user):
    token = _login(client, maintainer_user)
    res = client.get(
        "/compliance/exports/remediation-requests",
        headers=_bearer(token),
        params={"format": "json"},
    )
    assert res.status_code == 200, res.text
    assert isinstance(res.json(), list)
