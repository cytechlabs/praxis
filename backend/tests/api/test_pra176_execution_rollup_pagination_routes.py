"""PRA-176 Slice 4 — paginated rollup route tests.

Covers:

* GET /compliance/remediation-requests/{id}/executions accepts
  bounded ``offset`` + ``limit`` query parameters.
* First / middle / last / beyond-end page semantics on the wire.
* Whole-request totals stay byte-equal across pages; page-local
  counts shift to match each page's slice.
* Negative offset / zero limit / oversized limit return HTTP 422
  via FastAPI's Query constraints.
* 404 path unchanged for missing request id.
* Auditor read access on paginated rollup still works.
* Default call (no offset/limit) preserves Slice-3-style first page
  shape.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import CompliancePolicyEvidence, HostFacts
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_execution_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
)
from app.services.compliance_remediation_execution_service import MAX_BATCH_SIZE
from app.services.patch_execution_dispatch_service import (
    ERROR_CODE_PACKAGE_MANAGER_FAILED,
    DispatchResult,
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


@pytest.fixture(autouse=True)
def _pra281_grant_scope(db, host, maintainer_user, auditor_user):
    """PRA-281: compliance routes are now fleet-scoped. These pre-scope tests
    drive the compliance flow as a maintainer/auditor, so grant those non-admin
    actors access to this file's single host (admin stays tenant-wide)."""
    from app.db.access_models import AccessGrant, FleetRole

    role = FleetRole(
        name=f"pra281-legacy-scope-{host.id}",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    for u in (maintainer_user, auditor_user):
        db.add(
            AccessGrant(
                user_id=u.id,
                system_id=host.id,
                fleet_role_id=role.id,
                login=u.username,
            )
        )
    db.flush()


@pytest.fixture
def host(db, seed_distro):
    from app.db.models import Credential, Group, System

    g = Group(name="pra176p-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra176p-routes-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176p-routes.example.com",
        ip_address="10.0.0.183",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.add(
        HostFacts(
            system_id=sys_row.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="agent",
            distro_id_facts="ubuntu",
            package_manager="apt",
        )
    )
    db.flush()
    return sys_row


@pytest.fixture
def request_with_dispatched_attempts(db, admin_user, maintainer_user, host):
    """Build a request, create 5 pending attempts, then dispatch them
    with a mix of outcomes (3 succeeded, 2 failed). Returns the
    request id."""

    class _FakeDispatch:
        def __init__(self, results):
            self.results = list(results)

        def __call__(self, db, system, cmd):
            if not self.results:
                return DispatchResult(exit_code=0, transport_name="fake")
            return self.results.pop(0)

    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="pg-routes", name="Pg Routes"
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "missing-pg-route"},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    evidence = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "fail",
        )
        .one()
    )
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    for _ in range(5):
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )

    fake = _FakeDispatch(
        [
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
            DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
        ]
    )
    # The batch dispatch helper accepts a ``DispatchCallable`` arg, so
    # we wire the fake directly through that path — no monkeypatching
    # of the module-level ``default_dispatch`` symbol is needed for
    # the route to render the rollup later.

    class _ServiceDispatchAdapter:
        """Wrap the (db, system, cmd) -> result fake into the service's
        (system, cmd) -> result signature."""

        def __init__(self, inner):
            self.inner = inner

        def __call__(self, system, cmd):
            return self.inner(db, system, cmd)

    compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ServiceDispatchAdapter(fake),
    )

    return req.id


# ---------------------------------------------------------------------------
# Pagination over the wire
# ---------------------------------------------------------------------------


def test_rollup_route_default_call_returns_first_page(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions",
        headers=_bearer(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["offset"] == 0
    assert body["limit"] == MAX_BATCH_SIZE
    assert body["returned_count"] == 5
    assert body["total_attempts"] == 5
    assert body["has_more"] is False
    assert body["next_offset"] is None


def test_rollup_route_first_and_second_page_agree_on_whole_request_counts(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    page1 = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?offset=0&limit=2",
        headers=_bearer(token),
    ).json()
    page2 = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?offset=2&limit=2",
        headers=_bearer(token),
    ).json()
    # Whole-request totals are byte-equal across pages.
    assert page1["total_attempts"] == 5
    assert page1["total_attempts"] == page2["total_attempts"]
    assert page1["counts_by_state"] == page2["counts_by_state"]
    assert page1["counts_by_failure_reason"] == page2["counts_by_failure_reason"]
    # Page-local counts differ because each page sees a different slice.
    assert page1["returned_count"] == 2
    assert page2["returned_count"] == 2
    assert page1["offset"] == 0 and page1["next_offset"] == 2
    assert page2["offset"] == 2 and page2["next_offset"] == 4
    assert page1["has_more"] is True
    assert page2["has_more"] is True


def test_rollup_route_last_page_has_no_more(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?offset=4&limit=2",
        headers=_bearer(token),
    )
    assert res.status_code == 200
    body = res.json()
    assert body["returned_count"] == 1
    assert body["has_more"] is False
    assert body["next_offset"] is None


def test_rollup_route_beyond_end_page_returns_empty_envelope(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?offset=99&limit=10",
        headers=_bearer(token),
    )
    assert res.status_code == 200
    body = res.json()
    assert body["returned_count"] == 0
    assert body["attempts"] == []
    assert body["total_attempts"] == 5
    assert body["counts_by_state"]["succeeded"] == 3
    assert body["counts_by_state"]["failed"] == 2
    assert body["page_counts_by_state"]["succeeded"] == 0
    assert body["page_counts_by_state"]["failed"] == 0


def test_rollup_route_whole_request_counts_by_failure_reason(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    body = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions",
        headers=_bearer(token),
    ).json()
    assert body["counts_by_failure_reason"] == {
        ERROR_CODE_PACKAGE_MANAGER_FAILED: 2,
    }


# ---------------------------------------------------------------------------
# Invalid pagination
# ---------------------------------------------------------------------------


def test_rollup_route_rejects_negative_offset(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?offset=-1",
        headers=_bearer(token),
    )
    assert res.status_code == 422


def test_rollup_route_rejects_zero_limit(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?limit=0",
        headers=_bearer(token),
    )
    assert res.status_code == 422


def test_rollup_route_rejects_overlimit(
    client, admin_user, request_with_dispatched_attempts
):
    token = _login(client, admin_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?limit={MAX_BATCH_SIZE + 1}",
        headers=_bearer(token),
    )
    assert res.status_code == 422


def test_rollup_route_unknown_request_returns_404(client, admin_user):
    token = _login(client, admin_user)
    res = client.get(
        "/compliance/remediation-requests/999999/executions",
        headers=_bearer(token),
    )
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# RBAC — auditor read access on paginated route
# ---------------------------------------------------------------------------


def test_rollup_route_auditor_paginated_read(
    client, auditor_user, request_with_dispatched_attempts
):
    token = _login(client, auditor_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_dispatched_attempts}/executions?offset=0&limit=2",
        headers=_bearer(token),
    )
    assert res.status_code == 200
    body = res.json()
    assert body["offset"] == 0
    assert body["limit"] == 2
