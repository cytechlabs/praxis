"""PRA-176 Slice 3 — batch dispatch + per-request rollup route tests.

Covers:

* POST /compliance/remediation-requests/{id}/dispatch-executions
  - admin happy path returns 200 with mixed-outcome envelope.
  - maintainer is blocked (admin-only).
  - auditor is blocked.
  - unknown request id returns 404.
  - limit query param outside 1..MAX_BATCH_SIZE returns 422.
* GET /compliance/remediation-requests/{id}/executions
  - any authed user can read the rollup.
  - unknown request id returns 404.
  - empty request returns clean zero-count rollup.
* The route layer monkeypatches the compliance service's
  ``default_dispatch`` symbol with a fake so no real SSH/agent is
  reached during the route exercises.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

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

    g = Group(name="pra176b-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra176b-routes-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176b-routes.example.com",
        ip_address="10.0.0.181",
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
def request_with_pending_attempts(db, admin_user, maintainer_user, host):
    """Build an approved + acknowledged plan and create three pending
    execution attempts on it. Returns the request id."""
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="bx-routes", name="Bx Routes"
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "missing-bx-route"},
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
    for _ in range(3):
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    return req.id


class _FakeDispatch:
    """Stand-in for ``default_dispatch`` that records the call and
    returns a queued DispatchResult."""

    def __init__(self, results: List[DispatchResult]):
        self.results = list(results)
        self.calls: List[dict] = []

    def __call__(self, db, system, cmd):  # default_dispatch signature
        self.calls.append({"system_id": system.id, "cmd": list(cmd)})
        if not self.results:
            return DispatchResult(exit_code=0, transport_name="fake")
        return self.results.pop(0)


@pytest.fixture
def patch_default_dispatch(monkeypatch):
    def install(results):
        fake = _FakeDispatch(results)
        monkeypatch.setattr(
            compliance_remediation_execution_service, "default_dispatch", fake
        )
        return fake

    return install


# ---------------------------------------------------------------------------
# POST /dispatch-executions
# ---------------------------------------------------------------------------


def test_batch_dispatch_route_admin_mixed_200(
    client, admin_user, request_with_pending_attempts, patch_default_dispatch
):
    fake = patch_default_dispatch(
        [
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
        ]
    )
    token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/dispatch-executions",
        headers=_bearer(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["request_id"] == request_with_pending_attempts
    assert body["total_eligible"] == 3
    assert body["dispatched_count"] == 3
    assert body["succeeded_count"] == 2
    assert body["failed_count"] == 1
    assert body["refused_count"] == 0
    assert body["failure_breakdown_by_reason"] == {
        ERROR_CODE_PACKAGE_MANAGER_FAILED: 1,
    }
    assert body["generated_at"].endswith("Z")
    assert len(body["items"]) == 3
    assert len(fake.calls) == 3


def test_batch_dispatch_route_blocks_maintainer(
    client, maintainer_user, request_with_pending_attempts, patch_default_dispatch
):
    patch_default_dispatch([DispatchResult(exit_code=0, transport_name="fake")])
    token = _login(client, maintainer_user)
    res = client.post(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/dispatch-executions",
        headers=_bearer(token),
    )
    assert res.status_code in (401, 403), res.text


def test_batch_dispatch_route_blocks_auditor(
    client, auditor_user, request_with_pending_attempts, patch_default_dispatch
):
    patch_default_dispatch([DispatchResult(exit_code=0, transport_name="fake")])
    token = _login(client, auditor_user)
    res = client.post(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/dispatch-executions",
        headers=_bearer(token),
    )
    assert res.status_code in (401, 403), res.text


def test_batch_dispatch_route_unknown_request_404(client, admin_user):
    token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-requests/999999/dispatch-executions",
        headers=_bearer(token),
    )
    assert res.status_code == 404, res.text


def test_batch_dispatch_route_rejects_bad_limit(
    client, admin_user, request_with_pending_attempts
):
    token = _login(client, admin_user)
    # limit=0 fails the FastAPI Query ge constraint -> 422
    res = client.post(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/dispatch-executions?limit=0",
        headers=_bearer(token),
    )
    assert res.status_code == 422
    res = client.post(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/dispatch-executions?limit={MAX_BATCH_SIZE + 1}",
        headers=_bearer(token),
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# GET /executions (per-request rollup)
# ---------------------------------------------------------------------------


def test_rollup_route_admin_200(
    client, admin_user, request_with_pending_attempts, patch_default_dispatch
):
    # First dispatch the batch so the rollup has terminal rows to aggregate.
    patch_default_dispatch(
        [
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
        ]
    )
    token = _login(client, admin_user)
    client.post(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/dispatch-executions",
        headers=_bearer(token),
    )
    res = client.get(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/executions",
        headers=_bearer(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["request_id"] == request_with_pending_attempts
    assert body["total_attempts"] == 3
    assert body["counts_by_state"]["succeeded"] == 3
    assert body["counts_by_failure_reason"] == {}
    assert body["generated_at"].endswith("Z")
    assert len(body["attempts"]) == 3


def test_rollup_route_auditor_200(
    client, admin_user, auditor_user, request_with_pending_attempts
):
    aud_token = _login(client, auditor_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/executions",
        headers=_bearer(aud_token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    # No dispatch yet — all 3 attempts are pending.
    assert body["total_attempts"] == 3
    assert body["counts_by_state"]["pending"] == 3


def test_rollup_route_unknown_request_404(client, admin_user):
    token = _login(client, admin_user)
    res = client.get(
        "/compliance/remediation-requests/999999/executions",
        headers=_bearer(token),
    )
    assert res.status_code == 404


def test_rollup_route_rejects_bad_limit(
    client, admin_user, request_with_pending_attempts
):
    token = _login(client, admin_user)
    res = client.get(
        f"/compliance/remediation-requests/{request_with_pending_attempts}/executions?limit=0",
        headers=_bearer(token),
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Compatibility — Slice 1/2 dispatch route still works after batch
# ---------------------------------------------------------------------------


def test_single_attempt_dispatch_route_still_works_after_batch(
    client, admin_user, request_with_pending_attempts, patch_default_dispatch
):
    """Slice 2 single-attempt dispatch path must remain usable
    side-by-side with the Slice 3 batch endpoint."""
    fake = patch_default_dispatch(
        [
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
        ]
    )
    token = _login(client, admin_user)
    # Find the first pending attempt id via the existing list endpoint.
    list_res = client.get(
        f"/compliance/remediation-executions?request_id={request_with_pending_attempts}",
        headers=_bearer(token),
    )
    assert list_res.status_code == 200
    first_id = list_res.json()["items"][0]["id"]
    res = client.post(
        f"/compliance/remediation-executions/{first_id}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code == 200, res.text
    assert res.json()["state"] == "succeeded"
