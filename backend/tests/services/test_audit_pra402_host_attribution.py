"""PRA-402: per-host attribution of audit events at emission time.

The per-host audit query matches ``audit_events.target_system_id``, and the
automated change families that know their affected hosts never filled it in. A
host patched under an approved plan therefore returned a history with the patch
missing from it.

These tests pin the emission half of the repair from both directions:

* an event about exactly one host names that host in ``target_system_id``, the
  column the query already reads; and
* an event spanning a set of hosts names none of them as its target and records
  every one of them as an ``AuditEventSystem`` link instead, so it is reachable
  from each host's history without any single host being asserted as the target.

They also pin what must not regress while that attribution is added: an audit
row is the source of truth and has to persist even when the host reference the
caller supplied no longer resolves.

The compliance cases below record the scope classification this work depends on.
The per-host evaluation path already supplies its host; the fleet-wide path
supplies none and must not be given one.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.db.access_models import AuditEvent, AuditEventSystem
from app.db.models import (
    Credential,
    Group,
    Package,
    PackageUpdate,
    PatchPolicy,
    PatchUpdateExecutionHost,
    System,
)
from app.services import audit_event_service as aes
from app.services import (
    compliance_evaluation_service,
    compliance_service,
    patch_execution_dispatch_service,
    patch_execution_service,
    patch_policy_service,
    patch_scope,
    patch_update_plan_service,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class AuditCapture:
    """Stand in for ``safe_emit`` and record the kwargs each call passes."""

    def __init__(self):
        self.calls: List[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def by_action(self, action: str) -> List[dict]:
        return [c for c in self.calls if c["action"] == action]

    def related_for(self, action: str) -> set:
        related = set()
        for call in self.by_action(action):
            related.update(call.get("related_system_ids") or set())
        return related


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra402-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra402-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host_factory(db, seed_distro, static_group, credentials):
    counter = {"n": 0}

    def make() -> System:
        counter["n"] += 1
        s = System(
            hostname=f"pra402-host-{counter['n']}.example.com",
            ip_address=f"10.0.42.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        return s

    return make


def _missing_system_id(db) -> int:
    """An id no ``systems`` row holds, standing in for a removed host."""
    highest = db.query(System.id).order_by(System.id.desc()).first()
    return (highest[0] if highest else 0) + 5000


def _links(db, event_id: int) -> set:
    return {
        row.system_id
        for row in db.query(AuditEventSystem).filter(
            AuditEventSystem.event_id == event_id
        )
    }


def _make_policy(db, admin_user, slug: str, **overrides) -> PatchPolicy:
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind=overrides.pop("scope_kind", "full"),
        rollout_cadence="immediate",
        **overrides,
    )


def _bind(db, admin_user, policy, host) -> None:
    patch_policy_service.bind_host(
        db, policy_id=policy.id, system_id=host.id, actor_user_id=admin_user.id
    )


def _seed_host_with_update(db, host_factory) -> System:
    """A host with a pending package update, so plan selection produces work."""
    host = host_factory()
    package = Package(
        system_id=host.id,
        name=f"pkg-{host.id}",
        installed_version="1.0",
        package_type="apt",
    )
    db.add(package)
    db.flush()
    db.add(
        PackageUpdate(
            package_id=package.id,
            system_id=host.id,
            available_version="1.1",
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
    db.flush()
    return host


def _plan_over(db, admin_user, policy, hosts, name="pra402-plan"):
    return patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=name,
        target_system_ids=[h.id for h in hosts],
    )


# ---------------------------------------------------------------------------
# emit(): recording the hosts an event affects
# ---------------------------------------------------------------------------


def test_related_hosts_are_recorded_for_an_event_with_no_single_target(
    db, host_factory
):
    first, second = host_factory(), host_factory()

    row = aes.emit(
        db,
        action="patch_update_plan.created",
        target_kind="patch_update_plan",
        target_id="17",
        related_system_ids={first.id, second.id},
    )

    assert row.target_system_id is None, "a multi-host event claims no single host"
    assert _links(db, row.id) == {first.id, second.id}


def test_the_target_host_is_not_repeated_as_a_link(db, host_factory):
    subject, other = host_factory(), host_factory()

    row = aes.emit(
        db,
        action="patch_update_execution.host_succeeded",
        target_system_id=subject.id,
        target_kind="patch_update_execution_host",
        target_id="3",
        related_system_ids={subject.id, other.id},
    )

    assert row.target_system_id == subject.id
    assert _links(db, row.id) == {other.id}


def test_a_removed_host_does_not_cost_the_event_its_other_links(db, host_factory):
    """A host that no longer exists is settled before anything is written.

    Callers name hosts from run snapshots, which outlive the host row. Resolving
    that away up front is what keeps the write itself able to fail only for real
    database reasons."""
    live = host_factory()
    removed = _missing_system_id(db)

    row = aes.emit(
        db,
        action="patch_update_execution.completed",
        target_kind="patch_update_execution",
        target_id="9",
        related_system_ids={live.id, removed},
    )

    assert _links(db, row.id) == {live.id}


def test_the_event_survives_a_target_host_that_no_longer_exists(db):
    """Audit rows are the source of truth; a stale reference must not drop one."""
    removed = _missing_system_id(db)

    row = aes.emit(
        db,
        action="patch_update_execution.host_failed",
        target_system_id=removed,
        target_kind="patch_update_execution_host",
        target_id="4",
        context={"system_id": removed, "system_hostname": "retired.example.com"},
    )

    persisted = db.query(AuditEvent).filter(AuditEvent.id == row.id).first()
    assert persisted is not None
    assert persisted.target_system_id is None
    assert aes.event_to_dict(persisted)["context"]["system_id"] == removed


def test_an_event_and_its_attribution_are_committed_together(db, host_factory):
    """The links are in the event's own transaction, not a later best-effort pass."""
    first, second = host_factory(), host_factory()

    row = aes.emit(
        db,
        action="patch_update_execution.started",
        target_kind="patch_update_execution",
        target_id="55",
        related_system_ids={first.id, second.id},
    )

    # One commit put both there: the event is durable and already attributed.
    assert db.query(AuditEvent).filter(AuditEvent.id == row.id).count() == 1
    assert _links(db, row.id) == {first.id, second.id}


def test_an_unwritable_link_takes_the_event_with_it(db, host_factory, monkeypatch):
    """A database failure recording valid attribution must not be swallowed.

    An event that reached the log without the links that make it findable would
    answer a per-host query with exactly the confident, incomplete history this
    attribution exists to prevent. Losing the write outright is the lesser
    failure, and it is the one the caller gets told about.
    """
    host = host_factory()
    marker = "pra402-atomicity-probe"
    before = db.query(AuditEvent).count()

    real_link = aes.AuditEventSystem

    def _unwritable_link(*, event_id, system_id):
        # A host that genuinely exists, so this is valid attribution the database
        # refuses to record, not a stale id the resolver should have filtered.
        assert system_id == host.id
        return real_link(event_id=event_id, system_id=None)  # system_id is NOT NULL

    monkeypatch.setattr(aes, "AuditEventSystem", _unwritable_link)

    with pytest.raises(SQLAlchemyError):
        aes.emit(
            db,
            action="patch_update_plan.created",
            target_kind="patch_update_plan",
            target_id=marker,
            related_system_ids={host.id},
        )

    monkeypatch.undo()
    assert (
        db.query(AuditEvent).filter(AuditEvent.target_id == marker).count() == 0
    ), "an event was committed without the attribution that makes it findable"
    assert db.query(AuditEvent).count() == before

    # The session came back usable, so a caller that shared one with this emit
    # is not left with an aborted transaction.
    recovered = aes.emit(
        db, action="session.open", target_kind="session", target_id="1"
    )
    assert db.query(AuditEvent).filter(AuditEvent.id == recovered.id).count() == 1


def test_no_links_are_written_when_no_related_hosts_are_given(db, host_factory):
    host = host_factory()
    row = aes.emit(
        db,
        action="host_facts.collected",
        target_system_id=host.id,
        target_kind="system",
        target_id=str(host.id),
    )
    assert _links(db, row.id) == set()


# ---------------------------------------------------------------------------
# Patch plan events
# ---------------------------------------------------------------------------


def test_plan_events_name_every_host_the_plan_targets(
    db, admin_user, host_factory, monkeypatch
):
    capture = AuditCapture()
    monkeypatch.setattr(patch_update_plan_service, "safe_emit", capture)

    policy = _make_policy(db, admin_user, "pra402-plan-multi")
    first = _seed_host_with_update(db, host_factory)
    second = _seed_host_with_update(db, host_factory)
    _bind(db, admin_user, policy, first)
    _bind(db, admin_user, policy, second)

    approved = _plan_over(db, admin_user, policy, [first, second], name="pra402-ok")
    patch_update_plan_service.approve_directly(
        db, approved.id, actor_user_id=admin_user.id
    )
    # A cancel only leaves a draft, so it needs a plan of its own.
    canceled = _plan_over(db, admin_user, policy, [first, second], name="pra402-cancel")
    patch_update_plan_service.cancel_plan(db, canceled.id, actor_user_id=admin_user.id)

    expected = {first.id, second.id}
    for action in (
        patch_update_plan_service.AUDIT_PLAN_CREATED,
        patch_update_plan_service.AUDIT_PLAN_SELECTION_RECOMPUTED,
        patch_update_plan_service.AUDIT_PLAN_PREFLIGHT_RECOMPUTED,
        patch_update_plan_service.AUDIT_PLAN_APPROVED,
        patch_update_plan_service.AUDIT_PLAN_CANCELED,
    ):
        assert capture.by_action(action), f"{action} was not emitted"
        assert capture.related_for(action) == expected, action

    # The plan is the target; no host is claimed as one.
    for call in capture.calls:
        assert call.get("target_system_id") is None
        assert "db" not in call


def test_a_single_host_plan_is_reachable_from_that_host(
    db, admin_user, host_factory, monkeypatch
):
    capture = AuditCapture()
    monkeypatch.setattr(patch_update_plan_service, "safe_emit", capture)

    policy = _make_policy(db, admin_user, "pra402-plan-single")
    host = _seed_host_with_update(db, host_factory)
    _bind(db, admin_user, policy, host)

    _plan_over(db, admin_user, policy, [host])

    assert capture.related_for(patch_update_plan_service.AUDIT_PLAN_CREATED) == {
        host.id
    }


def test_deleting_a_plan_still_attributes_the_event_to_its_hosts(
    db, admin_user, host_factory, monkeypatch
):
    """The host rows go with the plan, so they are read before the delete."""
    capture = AuditCapture()
    monkeypatch.setattr(patch_update_plan_service, "safe_emit", capture)

    policy = _make_policy(db, admin_user, "pra402-plan-delete")
    host = _seed_host_with_update(db, host_factory)
    _bind(db, admin_user, policy, host)
    plan = _plan_over(db, admin_user, policy, [host])

    patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)

    assert capture.related_for(patch_update_plan_service.AUDIT_PLAN_DELETED) == {
        host.id
    }


# ---------------------------------------------------------------------------
# Patch execution events
# ---------------------------------------------------------------------------


def test_execution_lifecycle_events_name_every_target_host(
    db, admin_user, host_factory, monkeypatch
):
    capture = AuditCapture()
    monkeypatch.setattr(patch_execution_service, "safe_emit", capture)

    policy = _make_policy(db, admin_user, "pra402-exec-multi")
    first = _seed_host_with_update(db, host_factory)
    second = _seed_host_with_update(db, host_factory)
    _bind(db, admin_user, policy, first)
    _bind(db, admin_user, policy, second)
    plan = _plan_over(db, admin_user, policy, [first, second], name="pra402-exec-plan")
    patch_update_plan_service.approve_directly(db, plan.id, actor_user_id=admin_user.id)

    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    patch_execution_service.pause_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    patch_execution_service.resume_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    expected = {first.id, second.id}
    for action in (
        patch_execution_service.AUDIT_EXECUTION_STARTED,
        patch_execution_service.AUDIT_EXECUTION_PAUSED,
        patch_execution_service.AUDIT_EXECUTION_RESUMED,
        patch_execution_service.AUDIT_EXECUTION_CANCELED,
    ):
        assert capture.by_action(action), f"{action} was not emitted"
        assert capture.related_for(action) == expected, action
        for call in capture.by_action(action):
            assert call.get("target_system_id") is None
            assert "db" not in call


def test_a_host_outcome_event_names_its_own_host(
    db, admin_user, host_factory, monkeypatch
):
    """host_started / host_succeeded / host_failed are about one host each."""
    capture = AuditCapture()
    monkeypatch.setattr(patch_execution_dispatch_service, "safe_emit", capture)

    policy = _make_policy(db, admin_user, "pra402-exec-host")
    host = _seed_host_with_update(db, host_factory)
    _bind(db, admin_user, policy, host)
    plan = _plan_over(db, admin_user, policy, [host], name="pra402-host-plan")
    patch_update_plan_service.approve_directly(db, plan.id, actor_user_id=admin_user.id)
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    execution_host = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution.id)
        .first()
    )

    patch_execution_dispatch_service._emit_host_audit(
        action=patch_execution_dispatch_service.AUDIT_EXECUTION_HOST_SUCCEEDED,
        execution=execution,
        execution_host=execution_host,
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        actor_ip=None,
    )

    call = capture.by_action(
        patch_execution_dispatch_service.AUDIT_EXECUTION_HOST_SUCCEEDED
    )[0]
    assert call["target_system_id"] == host.id
    assert execution_host.system_id_snapshot == host.id


def test_a_wave_event_covers_only_the_hosts_in_that_wave(
    db, admin_user, host_factory, monkeypatch
):
    """Attributing a wave to the whole execution would file it under hosts it
    never touched."""
    policy = _make_policy(db, admin_user, "pra402-wave")
    first = _seed_host_with_update(db, host_factory)
    second = _seed_host_with_update(db, host_factory)
    _bind(db, admin_user, policy, first)
    _bind(db, admin_user, policy, second)
    plan = _plan_over(db, admin_user, policy, [first, second], name="pra402-wave-plan")
    patch_update_plan_service.approve_directly(db, plan.id, actor_user_id=admin_user.id)
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )

    # Split the materialized hosts across two waves.
    rows = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution.id)
        .order_by(PatchUpdateExecutionHost.id.asc())
        .all()
    )
    assert len(rows) == 2
    rows[0].wave_index = 0
    rows[1].wave_index = 1
    db.flush()

    assert patch_scope.execution_wave_target_system_ids(db, execution.id, 0) == {
        rows[0].system_id_snapshot
    }
    assert patch_scope.execution_wave_target_system_ids(db, execution.id, 1) == {
        rows[1].system_id_snapshot
    }
    assert patch_scope.execution_target_system_ids(db, execution.id) == {
        first.id,
        second.id,
    }


# ---------------------------------------------------------------------------
# Compliance scope classification
#
# The observed defect counted 50 compliance evaluation events with no host on
# any of them. These two tests are what tells the two paths apart: only the
# fleet-wide one omits the host, so an event set with none of them is a
# fleet-wide set.
# ---------------------------------------------------------------------------


@pytest.fixture
def compliance_host(db, seed_distro, static_group, credentials) -> System:
    s = System(
        hostname="pra402-compliance.example.com",
        ip_address="10.0.43.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.flush()
    return s


def _compliance_policy_with_check(db, admin_user, slug: str):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug=slug, name=slug.upper()
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="pkg-present",
        title="pkg-present",
        kind="package_installed",
        definition={"package": "openssl"},
    )
    return policy


def test_a_per_host_compliance_event_names_its_host(
    db, admin_user, compliance_host, monkeypatch
):
    capture = AuditCapture()
    monkeypatch.setattr(compliance_evaluation_service, "safe_emit", capture)
    policy = _compliance_policy_with_check(db, admin_user, "pra402-per-host")

    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=compliance_host.id
    )

    runs = capture.by_action(
        compliance_evaluation_service.AUDIT_COMPLIANCE_EVALUATION_RUN
    )
    assert runs, "the per-host evaluation must emit a run event"
    for call in runs:
        assert call["target_system_id"] == compliance_host.id
        assert call["context"]["scope"] == "per_host"


def test_a_fleet_compliance_event_names_no_single_host(
    db, admin_user, compliance_host, monkeypatch
):
    capture = AuditCapture()
    monkeypatch.setattr(compliance_evaluation_service, "safe_emit", capture)
    policy = _compliance_policy_with_check(db, admin_user, "pra402-fleet")

    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)

    runs = capture.by_action(
        compliance_evaluation_service.AUDIT_COMPLIANCE_EVALUATION_RUN
    )
    assert runs, "the fleet evaluation must emit a run event"
    for call in runs:
        assert call.get("target_system_id") is None
        assert call["context"]["scope"] == "per_fleet"
        assert call["context"]["run_id"]
