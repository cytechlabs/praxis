"""PRA-402: the per-host audit query returns a complete host history.

``GET /audit/events?system_id=`` matched ``audit_events.target_system_id`` and
nothing else. Patch plan, execution, and fleet-wide compliance events are written
against a plan, an execution, or a policy and carry no host in that column, so a
host that was patched under an approved plan came back with a single facts event
and no indication that the rest of its history had been dropped.

The filter now reads the affected-host links alongside the column. These tests
hold it to both halves of the contract: everything that concerns the host comes
back, in order, across every family; and nothing that belongs only to another
host comes with it.

The shape of the historical case is the one the defect was reported against: one
host inside a two-host plan and execution, with plan, approval, execution,
outcome, compliance, facts, and session activity all in its history.
"""

from __future__ import annotations

from typing import List, Optional

import pytest

from app.db.access_models import AuditEvent, AuditEventSystem
from app.db.models import Credential, Group, System
from app.services import audit_event_service as aes
from app.services import compliance_evaluation_service, compliance_service

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def host_builder(db, seed_distro):
    """Build hosts on demand, so a test can register one mid-scenario."""
    group = Group(name="pra402-api-group", description="t")
    db.add(group)
    db.flush()
    cred = Credential(
        name="pra402-api-cred", auth_method="password", username="root", vault_path="x"
    )
    db.add(cred)
    db.flush()
    counter = {"n": 0}

    def make() -> System:
        counter["n"] += 1
        row = System(
            hostname=f"pra402-api-host-{counter['n']}.example.com",
            ip_address=f"10.0.44.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=cred.id,
        )
        db.add(row)
        db.flush()
        return row

    return make


@pytest.fixture
def hosts(host_builder) -> List[System]:
    """Two hosts, so 'belongs only to the other host' is testable."""
    return [host_builder(), host_builder()]


@pytest.fixture
def viewer_user(db, seed_roles):
    """An authenticated user with no audit-read privilege."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    user = User(
        username="pra402viewer",
        email="pra402viewer@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    user.roles.append(seed_roles["viewer"])
    db.add(user)
    db.commit()
    return user


def _emit(
    db,
    action: str,
    *,
    target_kind: str,
    target_id: Optional[str] = None,
    target_system_id: Optional[int] = None,
    related_system_ids=None,
    context=None,
) -> AuditEvent:
    return aes.emit(
        db,
        action=action,
        target_kind=target_kind,
        target_id=target_id,
        target_system_id=target_system_id,
        related_system_ids=related_system_ids,
        context=context or {},
    )


def _events_for(client, system_id: int) -> dict:
    res = client.get(f"/audit/events?system_id={system_id}&limit=1000")
    assert res.status_code == 200, res.text
    return res.json()


def _uuids(payload: dict) -> List[str]:
    return [e["event_uuid"] for e in payload["events"]]


@pytest.fixture
def patched_host_history(db, hosts):
    """A two-host plan and execution, with one host's full history around it.

    Mirrors the reported case: only the facts event carries the host in
    ``target_system_id``; everything else is reachable only through the plan,
    execution, and fleet-evaluation links.
    """
    subject, other = hosts
    both = {subject.id, other.id}
    plan_id, execution_id = "501", "601"

    plan_events = [
        _emit(
            db,
            action,
            target_kind="patch_update_plan",
            target_id=plan_id,
            related_system_ids=both,
        )
        for action in (
            "patch_update_plan.created",
            "patch_update_plan.selection_recomputed",
            "patch_update_plan.preflight_recomputed",
            "patch_update_plan.approval_requested",
            "patch_update_plan.approved",
        )
    ]
    execution_events = [
        _emit(
            db,
            action,
            target_kind="patch_update_execution",
            target_id=execution_id,
            related_system_ids=both,
        )
        for action in (
            "patch_update_execution.started",
            "patch_update_execution.completed",
        )
    ]
    outcome_events = [
        _emit(
            db,
            action,
            target_kind="patch_update_execution_host",
            target_id="7001",
            target_system_id=subject.id,
            context={"system_id": subject.id, "execution_id": 601},
        )
        for action in (
            "patch_update_execution.host_started",
            "patch_update_execution.host_succeeded",
        )
    ]
    compliance_event = _emit(
        db,
        "compliance_evaluation.run",
        target_kind="compliance_policy",
        target_id="9",
        related_system_ids=both,
        context={"scope": "per_fleet", "run_id": "run-abc"},
    )
    facts_event = _emit(
        db,
        "host_facts.collected",
        target_kind="system",
        target_id=str(subject.id),
        target_system_id=subject.id,
    )
    session_event = _emit(
        db,
        "session.open",
        target_kind="system",
        target_id=str(subject.id),
        target_system_id=subject.id,
    )

    # Belongs only to the other host: must never appear in the subject's history.
    foreign_event = _emit(
        db,
        "host_facts.collected",
        target_kind="system",
        target_id=str(other.id),
        target_system_id=other.id,
    )

    expected = (
        plan_events
        + execution_events
        + outcome_events
        + [compliance_event, facts_event, session_event]
    )
    return {
        "subject": subject,
        "other": other,
        "expected": expected,
        "foreign": foreign_event,
    }


# ---------------------------------------------------------------------------
# The reported case
# ---------------------------------------------------------------------------


def test_a_patched_host_returns_its_whole_history_not_just_its_facts(
    authed_client, db, patched_host_history
):
    subject = patched_host_history["subject"]
    expected = patched_host_history["expected"]

    payload = _events_for(authed_client, subject.id)

    assert len(expected) >= 11, "the reported case is an 11-event history"
    assert set(_uuids(payload)) == {e.event_uuid for e in expected}
    assert payload["total"] == len(expected)


def test_the_history_covers_every_family_the_host_took_part_in(
    authed_client, db, patched_host_history
):
    payload = _events_for(authed_client, patched_host_history["subject"].id)
    actions = {e["action"] for e in payload["events"]}

    assert "patch_update_plan.created" in actions
    assert "patch_update_plan.approved" in actions
    assert "patch_update_execution.started" in actions
    assert "patch_update_execution.host_succeeded" in actions
    assert "compliance_evaluation.run" in actions
    assert "host_facts.collected" in actions
    assert "session.open" in actions


def test_only_the_facts_and_outcome_events_name_the_host_as_their_target(
    authed_client, db, patched_host_history
):
    """The plan, execution, and fleet events reach the host without claiming it."""
    subject = patched_host_history["subject"]
    payload = _events_for(authed_client, subject.id)

    by_target = {e["action"]: e["target"]["system_id"] for e in payload["events"]}
    assert by_target["host_facts.collected"] == subject.id
    assert by_target["patch_update_execution.host_succeeded"] == subject.id
    assert by_target["patch_update_plan.created"] is None
    assert by_target["patch_update_execution.started"] is None
    assert by_target["compliance_evaluation.run"] is None


def test_another_hosts_events_never_appear(authed_client, db, patched_host_history):
    subject = patched_host_history["subject"]
    other = patched_host_history["other"]
    foreign = patched_host_history["foreign"]

    payload = _events_for(authed_client, subject.id)
    assert foreign.event_uuid not in _uuids(payload)

    # The shared plan/execution/fleet events reach the other host too; its own
    # facts event does not cross back.
    other_payload = _events_for(authed_client, other.id)
    other_actions = {e["action"] for e in other_payload["events"]}
    assert "patch_update_plan.created" in other_actions
    assert "patch_update_execution.host_succeeded" not in other_actions


def test_the_history_is_returned_in_order(authed_client, db, patched_host_history):
    payload = _events_for(authed_client, patched_host_history["subject"].id)
    timestamps = [e["timestamp"] for e in payload["events"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_an_event_is_counted_once_however_many_hosts_it_affects(
    authed_client, db, hosts
):
    """A link per host must not multiply the event through the join."""
    subject, other = hosts
    event = _emit(
        db,
        "patch_update_plan.created",
        target_kind="patch_update_plan",
        target_id="777",
        related_system_ids={subject.id, other.id},
    )
    assert (
        db.query(AuditEventSystem).filter(AuditEventSystem.event_id == event.id).count()
        == 2
    )

    payload = _events_for(authed_client, subject.id)
    assert _uuids(payload).count(event.event_uuid) == 1
    assert payload["total"] == len(payload["events"])


# ---------------------------------------------------------------------------
# Fleet-wide compliance, emitted live
#
# A fleet evaluation has no single subject host, so it must reach every host it
# swept without any of them being recorded as its target. These drive the real
# evaluator rather than hand-written rows, so the emission and the retrieval are
# proved against each other.
# ---------------------------------------------------------------------------


COMPLIANCE_FLEET_ACTIONS = (
    "compliance_evaluation.run",
    "compliance_evidence.persisted",
)


@pytest.fixture
def emit_into_test_session(db, monkeypatch):
    """Route the evaluator's audit emission into this test's own transaction.

    ``safe_emit`` opens its own ``SessionLocal`` on purpose, so an audit write
    survives the caller's rollback. That second session cannot see rows this test
    has not committed, which would leave the evaluator resolving every fixture
    host as deleted. Only the session boundary is replaced here: the real
    ``emit`` still resolves the hosts, writes the links in the event's own
    transaction, and is what the assertions below read back.
    """

    def _emit(**kwargs):
        aes.emit(db, **kwargs)

    monkeypatch.setattr(compliance_evaluation_service, "safe_emit", _emit)


def _fleet_policy(db, admin_user, slug: str):
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


def _compliance_events(payload: dict) -> List[dict]:
    return [e for e in payload["events"] if e["action"] in COMPLIANCE_FLEET_ACTIONS]


def test_a_fleet_evaluation_reaches_every_host_it_swept(
    authed_client, db, admin_user, host_builder, emit_into_test_session
):
    swept = [host_builder(), host_builder(), host_builder()]
    policy = _fleet_policy(db, admin_user, "pra402-fleet-reach")

    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)

    for host in swept:
        actions = [
            e["action"] for e in _compliance_events(_events_for(authed_client, host.id))
        ]
        # Each event links all three hosts; a host must still see it once.
        assert actions.count("compliance_evaluation.run") == 1, host.hostname
        assert actions.count("compliance_evidence.persisted") == 1, host.hostname


def test_a_fleet_evaluation_claims_no_single_host_as_its_target(
    authed_client, db, admin_user, host_builder, emit_into_test_session
):
    host = host_builder()
    host_builder()
    policy = _fleet_policy(db, admin_user, "pra402-fleet-target")

    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)

    events = _compliance_events(_events_for(authed_client, host.id))
    assert len(events) == 2
    for event in events:
        assert event["target"]["system_id"] is None
        assert event["target"]["kind"] == "compliance_policy"
        assert event["context"]["scope"] == "per_fleet"


def test_a_host_registered_after_the_sweep_gets_neither_event(
    authed_client, db, admin_user, host_builder, emit_into_test_session
):
    swept = host_builder()
    policy = _fleet_policy(db, admin_user, "pra402-fleet-outsider")

    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)

    # Registered after the run, so it was never part of it.
    outsider = host_builder()

    assert len(_compliance_events(_events_for(authed_client, swept.id))) == 2
    assert _compliance_events(_events_for(authed_client, outsider.id)) == []


def test_a_fleet_evaluation_links_every_swept_host_to_each_event(
    authed_client, db, admin_user, host_builder, emit_into_test_session
):
    """The links are the mechanism; count them directly, not just their effect."""
    swept = [host_builder(), host_builder(), host_builder()]
    policy = _fleet_policy(db, admin_user, "pra402-fleet-links")

    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)

    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.action.in_(COMPLIANCE_FLEET_ACTIONS))
        .filter(AuditEvent.target_id == str(policy.id))
        .all()
    )
    assert {e.action for e in events} == set(COMPLIANCE_FLEET_ACTIONS)
    for event in events:
        linked = {
            row.system_id
            for row in db.query(AuditEventSystem).filter(
                AuditEventSystem.event_id == event.id
            )
        }
        assert linked == {h.id for h in swept}


# ---------------------------------------------------------------------------
# Filters and authorization keep working
# ---------------------------------------------------------------------------


def test_the_host_filter_still_combines_with_the_other_filters(
    authed_client, db, patched_host_history
):
    subject = patched_host_history["subject"]
    res = authed_client.get(
        f"/audit/events?system_id={subject.id}&action=patch_update_plan.approved"
    )
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["total"] == 1
    assert payload["events"][0]["action"] == "patch_update_plan.approved"


def test_an_unrelated_host_id_returns_nothing(authed_client, db, patched_host_history):
    highest = db.query(System.id).order_by(System.id.desc()).first()[0]
    payload = _events_for(authed_client, highest + 5000)
    assert payload["total"] == 0
    assert payload["events"] == []


def test_reading_the_host_history_still_needs_an_audit_role(
    client, db, viewer_user, patched_host_history
):
    res = client.post(
        "/auth/login",
        data={"username": viewer_user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    token = res.json()["access_token"]

    res = client.get(
        f"/audit/events?system_id={patched_host_history['subject'].id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403, res.text


def test_an_auditor_reads_the_same_complete_history(
    client, db, auditor_user, patched_host_history
):
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    token = res.json()["access_token"]

    subject = patched_host_history["subject"]
    res = client.get(
        f"/audit/events?system_id={subject.id}&limit=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    assert set(_uuids(res.json())) == {
        e.event_uuid for e in patched_host_history["expected"]
    }


def test_the_wire_format_is_unchanged(authed_client, db, patched_host_history):
    """Sinks and exports read this shape; attribution must not alter it."""
    payload = _events_for(authed_client, patched_host_history["subject"].id)
    event = payload["events"][0]
    assert set(event) == {
        "schema_version",
        "event_uuid",
        "timestamp",
        "action",
        "outcome",
        "actor",
        "target",
        "context",
    }
    assert set(event["target"]) == {"kind", "system_id", "id"}
    assert event["schema_version"] == aes.SCHEMA_VERSION
