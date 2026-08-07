"""PRA-176 Slice 2 — dispatch route tests.

Covers:

* POST /compliance/remediation-executions/{id}/dispatch
  - admin happy path returns 200 + terminal succeeded envelope.
  - maintainer is blocked (admin-only).
  - auditor is blocked.
  - unknown attempt id returns 404.
  - non-`pending` attempt returns 422 with the service error.
  - readiness-gate failure (e.g. plan superseded between create and
    dispatch) returns 422.
* The route does not invoke the real ``default_dispatch``; tests
  monkeypatch the service module's ``default_dispatch`` symbol with a
  fake that records the (system, cmd) call, so the route layer can be
  exercised without touching SSH/agent.
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
from app.services.patch_execution_dispatch_service import DispatchResult


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def host(db, seed_distro):
    from app.db.models import Credential, Group, System

    g = Group(name="pra176d-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra176d-routes-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176d-routes.example.com",
        ip_address="10.0.0.179",
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
def pending_attempt(db, admin_user, maintainer_user, host):
    """Build the full PRA-167 chain + Slice 1 attempt creation.
    Returns the attempt id ready for a Slice 2 dispatch route test.
    """
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="disp-routes",
        name="Disp Routes",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "missing-disp-pkg"},
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
    attempt = compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    return attempt.id


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
    """Patch ``compliance_remediation_execution_service.default_dispatch``
    so the route layer never reaches the real transport factory."""
    fakes: List[_FakeDispatch] = []

    def install(results):
        fake = _FakeDispatch(results)
        monkeypatch.setattr(
            compliance_remediation_execution_service, "default_dispatch", fake
        )
        fakes.append(fake)
        return fake

    return install


# ---------------------------------------------------------------------------
# Happy path + RBAC
# ---------------------------------------------------------------------------


def test_dispatch_route_admin_200_succeeded(
    client, admin_user, pending_attempt, patch_default_dispatch
):
    fake = patch_default_dispatch(
        [
            DispatchResult(
                exit_code=0,
                stdout="installed\n",
                stderr="",
                duration_ms=77,
                transport_name="ssh",
            )
        ]
    )
    token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-executions/{pending_attempt}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["id"] == pending_attempt
    assert body["state"] == "succeeded"
    assert body["transport"] == "ssh"
    assert body["exit_code"] == 0
    assert body["duration_ms"] == 77
    assert body["stdout_summary"] == "installed\n"
    assert body["dispatched_at"].endswith("Z")
    assert body["completed_at"].endswith("Z")
    assert len(fake.calls) == 1
    assert fake.calls[0]["cmd"][:2] == ["apt-get", "install"]


def test_dispatch_route_records_package_manager_failure_as_422_no(
    client, admin_user, pending_attempt, patch_default_dispatch
):
    """A nonzero package-manager exit is a recorded ``failed`` outcome,
    NOT a route-layer validation refusal — the route still returns 200
    with the failed envelope. Validation refusals (readiness/lineage)
    return 422; transport/package failures return 200 with state=failed.
    """
    patch_default_dispatch(
        [
            DispatchResult(
                exit_code=100,
                stderr="E: Unable to locate package missing-disp-pkg\n",
                transport_name="ssh",
            )
        ]
    )
    token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-executions/{pending_attempt}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"] == "failed"
    assert body["failure_reason"] == "package_manager_failed"
    assert body["exit_code"] == 100


def test_dispatch_route_blocks_maintainer(
    client, maintainer_user, pending_attempt, patch_default_dispatch
):
    patch_default_dispatch([DispatchResult(exit_code=0, transport_name="fake")])
    token = _login(client, maintainer_user)
    res = client.post(
        f"/compliance/remediation-executions/{pending_attempt}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code in (401, 403), res.text


def test_dispatch_route_blocks_auditor(
    client, auditor_user, pending_attempt, patch_default_dispatch
):
    patch_default_dispatch([DispatchResult(exit_code=0, transport_name="fake")])
    token = _login(client, auditor_user)
    res = client.post(
        f"/compliance/remediation-executions/{pending_attempt}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code in (401, 403), res.text


def test_dispatch_route_unknown_attempt_404(client, admin_user):
    token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-executions/999999/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code == 404, res.text


def test_dispatch_route_refuses_non_pending_attempt(
    client, admin_user, pending_attempt, patch_default_dispatch
):
    patch_default_dispatch([DispatchResult(exit_code=0, transport_name="fake")])
    token = _login(client, admin_user)
    # First call: succeed.
    res = client.post(
        f"/compliance/remediation-executions/{pending_attempt}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code == 200
    # Patch a fresh fake for the second call (the first one already ran).
    patch_default_dispatch([DispatchResult(exit_code=0, transport_name="fake")])
    # Second call must refuse with 422.
    res = client.post(
        f"/compliance/remediation-executions/{pending_attempt}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code == 422, res.text
    assert "'pending'" in res.json()["detail"]


def test_dispatch_route_refuses_superseded_plan_422(
    client,
    db,
    admin_user,
    maintainer_user,
    host,
    pending_attempt,
    patch_default_dispatch,
):
    """Edit the live check + rebuild the plan AFTER the attempt is
    created — Slice 1 readiness re-checked at dispatch time must
    refuse with 422.
    """
    # Look up the plan tied to the attempt and supersede it via a
    # check definition mutation + rebuild.
    attempt = compliance_remediation_execution_service.get_attempt(db, pending_attempt)
    plan = compliance_remediation_plan_service.get_plan(db, attempt.plan_id)
    from app.db.models import CompliancePolicyCheck

    check = (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.id == plan.check_id)
        .first()
    )
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "different-pkg"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=plan.request_id, actor_user_id=admin_user.id
    )

    patch_default_dispatch([DispatchResult(exit_code=0, transport_name="fake")])
    token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-executions/{pending_attempt}/dispatch",
        headers=_bearer(token),
    )
    assert res.status_code == 422, res.text
    detail = res.json()["detail"]
    assert "superseded" in detail or "stale" in detail
