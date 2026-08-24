"""PRA-402: the backfill that gives existing audit rows their affected hosts.

Emitters now record the hosts an event affects, but every event written before
that has no attribution at all, so an upgraded installation would still answer
"what happened to this host" with a partial history for everything already in the
database. The migration closes that gap from the relational associations the
database already holds.

The bar these tests hold it to is equivalence: a history backfilled from the old
rows must read exactly like one recorded by the new emitters. Each case strips
the attribution a real service call produced, runs the backfill, and compares the
result against what emission had written.

They also pin the limits. Rerunning changes nothing, a host that no longer exists
cannot break the run or forge a reference, and a fleet evaluation whose evidence
was pruned attributes to nothing rather than guessing.
"""

from __future__ import annotations

import importlib.util
import json
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import inspect, text

from app.db.access_models import AuditEvent, AuditEventSystem
from app.db.compliance_models import CompliancePolicyEvidence
from app.db.models import (
    Credential,
    Group,
    Package,
    PackageUpdate,
    PatchUpdateExecutionHost,
    System,
)
from app.services import audit_event_service as aes
from app.services import (
    patch_execution_service,
    patch_policy_service,
    patch_scope,
    patch_update_plan_service,
)

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "20260823_0001_audit_event_host_attribution.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "audit_event_host_attribution_migration", MIGRATION_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def migration():
    return _load_migration()


# ---------------------------------------------------------------------------
# Building history, then taking its attribution away
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra402-bf-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra402-bf-cred", auth_method="password", username="root", vault_path="x"
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
            hostname=f"pra402-bf-host-{counter['n']}.example.com",
            ip_address=f"10.0.45.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        package = Package(
            system_id=s.id,
            name=f"pkg-{s.id}",
            installed_version="1.0",
            package_type="apt",
        )
        db.add(package)
        db.flush()
        db.add(
            PackageUpdate(
                package_id=package.id,
                system_id=s.id,
                available_version="1.1",
                update_type="security",
                discovered_on=datetime.utcnow(),
            )
        )
        db.flush()
        return s

    return make


def _attribution(db) -> dict:
    """Every event's attribution: its target host plus its linked hosts."""
    links = {}
    for row in db.query(AuditEventSystem).all():
        links.setdefault(row.event_id, set()).add(row.system_id)
    return {
        event.id: (event.target_system_id, links.get(event.id, set()))
        for event in db.query(AuditEvent).all()
    }


def _strip_attribution(db) -> None:
    """Rewrite history into the shape it had before the emitters were fixed."""
    db.query(AuditEventSystem).delete(synchronize_session=False)
    db.query(AuditEvent).filter(
        AuditEvent.target_kind.in_(
            (
                "patch_update_plan",
                "patch_update_execution",
                "patch_update_execution_host",
                "patch_update_execution_reboot",
                "patch_rollback_dispatch_host",
                "compliance_policy",
            )
        )
    ).update({AuditEvent.target_system_id: None}, synchronize_session=False)
    db.flush()


def _historical_event(
    db,
    action: str,
    *,
    target_kind: str,
    target_id: str,
    target_system_id=None,
    context=None,
) -> AuditEvent:
    """An event in the shape the old emitters wrote: no host attribution."""
    event = AuditEvent(
        schema_version=1,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action=action,
        outcome="success",
        target_system_id=target_system_id,
        target_kind=target_kind,
        target_id=target_id,
        context_json=json.dumps(context or {}),
    )
    db.add(event)
    db.flush()
    return event


PLAN_ACTIONS = (
    "patch_update_plan.created",
    "patch_update_plan.selection_recomputed",
    "patch_update_plan.approved",
)
EXECUTION_ACTIONS = (
    "patch_update_execution.started",
    "patch_update_execution.completed",
)


def _patch_history(db, plan, execution, *, attributed: bool):
    """Write a plan and execution audit trail.

    ``attributed`` writes it the way the emitters do now, passing the plan's and
    execution's hosts; otherwise it writes the unattributed shape the backfill
    has to repair.
    """
    events = []
    for action in PLAN_ACTIONS:
        related = (
            patch_scope.plan_target_system_ids(db, plan.id) if attributed else None
        )
        events.append(
            aes.emit(
                db,
                action=action,
                target_kind="patch_update_plan",
                target_id=str(plan.id),
                related_system_ids=related,
            )
        )
    for action in EXECUTION_ACTIONS:
        related = (
            patch_scope.execution_target_system_ids(db, execution.id)
            if attributed
            else None
        )
        events.append(
            aes.emit(
                db,
                action=action,
                target_kind="patch_update_execution",
                target_id=str(execution.id),
                related_system_ids=related,
            )
        )
    return events


def _patched_fleet(db, admin_user, host_factory, slug: str, host_count: int = 2):
    """A real plan and execution over ``host_count`` hosts, with its audit trail."""
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
    )
    hosts = [host_factory() for _ in range(host_count)]
    for host in hosts:
        patch_policy_service.bind_host(
            db, policy_id=policy.id, system_id=host.id, actor_user_id=admin_user.id
        )
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=slug,
        target_system_ids=[h.id for h in hosts],
    )
    patch_update_plan_service.approve_directly(db, plan.id, actor_user_id=admin_user.id)
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    return policy, hosts, plan, execution


# ---------------------------------------------------------------------------
# Table shape
# ---------------------------------------------------------------------------


def test_the_migration_created_the_attribution_table(db):
    columns = {
        c["name"] for c in inspect(db.get_bind()).get_columns("audit_event_systems")
    }
    assert {"id", "event_id", "system_id", "created_at", "updated_at"} <= columns


def test_the_model_matches_the_table():
    assert AuditEventSystem.__tablename__ == "audit_event_systems"
    assert {"id", "event_id", "system_id", "created_at", "updated_at"} <= set(
        AuditEventSystem.__table__.columns.keys()
    )


def test_a_host_cannot_be_linked_to_the_same_event_twice(db, host_factory):
    from sqlalchemy.exc import IntegrityError

    host = host_factory()
    event = AuditEvent(
        schema_version=1,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action="patch_update_plan.created",
        outcome="success",
        context_json="{}",
    )
    db.add(event)
    db.commit()

    db.add(AuditEventSystem(event_id=event.id, system_id=host.id))
    db.commit()
    db.add(AuditEventSystem(event_id=event.id, system_id=host.id))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# ---------------------------------------------------------------------------
# Equivalence: backfilled history reads like emitted history
# ---------------------------------------------------------------------------


def test_backfilled_history_matches_what_emission_would_have_written(
    db, admin_user, host_factory, migration
):
    _, _, plan, execution = _patched_fleet(
        db, admin_user, host_factory, "pra402-bf-equiv"
    )
    _patch_history(db, plan, execution, attributed=True)
    db.flush()
    emitted = _attribution(db)
    assert any(links for _, links in emitted.values()), "emission must produce links"

    _strip_attribution(db)
    assert not db.query(AuditEventSystem).count()

    migration.backfill(db.connection())
    db.expire_all()

    assert _attribution(db) == emitted


def test_plan_and_execution_events_reach_every_host_they_spanned(
    db, admin_user, host_factory, migration
):
    _, hosts, plan, execution = _patched_fleet(
        db, admin_user, host_factory, "pra402-bf-span"
    )
    _patch_history(db, plan, execution, attributed=False)
    db.flush()
    migration.backfill(db.connection())
    db.expire_all()

    expected = {h.id for h in hosts}
    for target_kind, target_id in (
        ("patch_update_plan", str(plan.id)),
        ("patch_update_execution", str(execution.id)),
    ):
        events = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target_kind == target_kind,
                AuditEvent.target_id == target_id,
            )
            .all()
        )
        assert events, f"no {target_kind} events to attribute"
        for event in events:
            linked = {
                row.system_id
                for row in db.query(AuditEventSystem).filter(
                    AuditEventSystem.event_id == event.id
                )
            }
            assert linked == expected, event.action
            assert event.target_system_id is None


def test_a_host_outcome_event_regains_its_own_host(
    db, admin_user, host_factory, migration
):
    _, hosts, _, execution = _patched_fleet(
        db, admin_user, host_factory, "pra402-bf-outcome", host_count=1
    )
    execution_host = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution.id)
        .first()
    )
    event = AuditEvent(
        schema_version=1,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action="patch_update_execution.host_succeeded",
        outcome="success",
        target_kind="patch_update_execution_host",
        target_id=str(execution_host.id),
        context_json=json.dumps({"system_id": hosts[0].id}),
    )
    db.add(event)
    db.flush()

    migration.backfill(db.connection())
    db.expire_all()

    db.refresh(event)
    assert event.target_system_id == hosts[0].id
    # A single-host event needs no link; the column already carries it.
    assert (
        db.query(AuditEventSystem).filter(AuditEventSystem.event_id == event.id).count()
        == 0
    )


def test_a_wave_event_is_attributed_only_to_its_own_wave(
    db, admin_user, host_factory, migration
):
    _, _, _, execution = _patched_fleet(db, admin_user, host_factory, "pra402-bf-wave")
    rows = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution.id)
        .order_by(PatchUpdateExecutionHost.id.asc())
        .all()
    )
    rows[0].wave_index = 0
    rows[1].wave_index = 1
    db.flush()

    event = AuditEvent(
        schema_version=1,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action="patch_update_execution.wave_completed",
        outcome="success",
        target_kind="patch_update_execution",
        target_id=str(execution.id),
        context_json=json.dumps({"execution_id": execution.id, "wave_index": 1}),
    )
    db.add(event)
    db.flush()

    migration.backfill(db.connection())
    db.expire_all()

    linked = {
        row.system_id
        for row in db.query(AuditEventSystem).filter(
            AuditEventSystem.event_id == event.id
        )
    }
    assert linked == {rows[1].system_id_snapshot}
    assert rows[0].system_id_snapshot not in linked


# ---------------------------------------------------------------------------
# Fleet-wide compliance
# ---------------------------------------------------------------------------


def _fleet_compliance_history(db, admin_user, hosts, run_id: str):
    from app.services import compliance_service

    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug=f"pra402-bf-{run_id}", name="BF"
    )
    for host in hosts:
        db.add(
            CompliancePolicyEvidence(
                policy_id=policy.id,
                system_id=host.id,
                policy_slug=policy.slug,
                policy_version=policy.version,
                check_slug="c",
                check_kind="package_installed",
                verdict="pass",
                severity="medium",
                evaluation_run_id=run_id,
                evaluated_at=datetime.utcnow(),
            )
        )
    event = AuditEvent(
        schema_version=1,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action="compliance_evaluation.run",
        outcome="success",
        target_kind="compliance_policy",
        target_id=str(policy.id),
        context_json=json.dumps({"scope": "per_fleet", "run_id": run_id}),
    )
    db.add(event)
    db.flush()
    return policy, event


def test_a_fleet_evaluation_reaches_every_host_its_run_covered(
    db, admin_user, host_factory, migration
):
    hosts = [host_factory(), host_factory()]
    _, event = _fleet_compliance_history(db, admin_user, hosts, "run-covered")

    migration.backfill(db.connection())
    db.expire_all()

    db.refresh(event)
    linked = {
        row.system_id
        for row in db.query(AuditEventSystem).filter(
            AuditEventSystem.event_id == event.id
        )
    }
    assert linked == {h.id for h in hosts}
    assert event.target_system_id is None, "a fleet event names no single host"


def test_a_fleet_evaluation_whose_evidence_was_pruned_attributes_to_nothing(
    db, admin_user, host_factory, migration
):
    """Retention deleted the only record of which hosts the run covered."""
    hosts = [host_factory()]
    _, event = _fleet_compliance_history(db, admin_user, hosts, "run-pruned")
    db.query(CompliancePolicyEvidence).filter(
        CompliancePolicyEvidence.evaluation_run_id == "run-pruned"
    ).delete(synchronize_session=False)
    db.flush()

    migration.backfill(db.connection())
    db.expire_all()

    assert (
        db.query(AuditEventSystem).filter(AuditEventSystem.event_id == event.id).count()
        == 0
    )
    db.refresh(event)
    assert event.target_system_id is None


def test_a_per_host_compliance_event_keeps_the_host_it_already_had(
    db, admin_user, host_factory, migration
):
    host = host_factory()
    event = AuditEvent(
        schema_version=1,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action="compliance_evaluation.run",
        outcome="success",
        target_kind="compliance_policy",
        target_id="4242",
        target_system_id=host.id,
        context_json=json.dumps({"scope": "per_host", "run_id": "run-per-host"}),
    )
    db.add(event)
    db.flush()

    migration.backfill(db.connection())
    db.expire_all()

    db.refresh(event)
    assert event.target_system_id == host.id
    assert (
        db.query(AuditEventSystem).filter(AuditEventSystem.event_id == event.id).count()
        == 0
    )


# ---------------------------------------------------------------------------
# Rerunning, and references that no longer resolve
# ---------------------------------------------------------------------------


def test_running_the_backfill_again_changes_nothing(
    db, admin_user, host_factory, migration
):
    hosts = [host_factory(), host_factory()]
    _fleet_compliance_history(db, admin_user, hosts, "run-idempotent")
    _, _, plan, execution = _patched_fleet(
        db, admin_user, host_factory, "pra402-bf-again"
    )
    _patch_history(db, plan, execution, attributed=False)
    db.flush()

    migration.backfill(db.connection())
    db.expire_all()
    first = _attribution(db)
    first_link_ids = {row.id for row in db.query(AuditEventSystem).all()}

    migration.backfill(db.connection())
    db.expire_all()

    assert _attribution(db) == first
    assert {row.id for row in db.query(AuditEventSystem).all()} == first_link_ids


def test_a_host_that_no_longer_exists_is_never_linked(
    db, admin_user, host_factory, migration
):
    """Execution host rows keep a snapshot id, which outlives the host row."""
    _, _, plan, execution = _patched_fleet(
        db, admin_user, host_factory, "pra402-bf-gone"
    )
    _patch_history(db, plan, execution, attributed=False)
    db.flush()

    rows = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution.id)
        .order_by(PatchUpdateExecutionHost.id.asc())
        .all()
    )
    removed = db.query(System.id).order_by(System.id.desc()).first()[0] + 5000
    rows[0].system_id_snapshot = removed
    db.flush()

    migration.backfill(db.connection())
    db.expire_all()

    linked = {row.system_id for row in db.query(AuditEventSystem).all()}
    assert removed not in linked
    assert rows[1].system_id_snapshot in linked


def test_the_backfill_never_reaches_a_host_the_event_had_nothing_to_do_with(
    db, admin_user, host_factory, migration
):
    bystander = host_factory()
    _, hosts, plan, execution = _patched_fleet(
        db, admin_user, host_factory, "pra402-bf-iso"
    )
    _patch_history(db, plan, execution, attributed=False)
    db.flush()

    migration.backfill(db.connection())
    db.expire_all()

    plan_event_ids = [
        row.id
        for row in db.query(AuditEvent).filter(
            AuditEvent.target_kind == "patch_update_plan",
            AuditEvent.target_id == str(plan.id),
        )
    ]
    linked = {
        row.system_id
        for row in db.query(AuditEventSystem).filter(
            AuditEventSystem.event_id.in_(plan_event_ids)
        )
    }
    assert linked == {h.id for h in hosts}
    assert bystander.id not in linked


def test_the_attribution_table_is_indexed_for_the_per_host_lookup(db):
    """The host filter joins on system_id on every audit read."""
    indexes = inspect(db.get_bind()).get_indexes("audit_event_systems")
    indexed = {tuple(ix["column_names"]) for ix in indexes}
    assert ("system_id",) in indexed
    assert ("event_id",) in indexed


def test_links_follow_their_event_when_it_is_removed(db, host_factory):
    """Audit rows are retained, but a link must never outlive its event."""
    host = host_factory()
    event = AuditEvent(
        schema_version=1,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action="patch_update_plan.created",
        outcome="success",
        context_json="{}",
    )
    db.add(event)
    db.flush()
    db.add(AuditEventSystem(event_id=event.id, system_id=host.id))
    db.flush()

    db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": event.id})
    db.flush()
    assert (
        db.query(AuditEventSystem).filter(AuditEventSystem.event_id == event.id).count()
        == 0
    )
