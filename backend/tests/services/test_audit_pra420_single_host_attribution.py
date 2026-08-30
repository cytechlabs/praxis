"""PRA-420: single-host audit events name their host at emission time.

The per-host audit query is the union of ``audit_events.target_system_id`` and
the affected-host links. An event about exactly one managed system is therefore
findable only if it fills that column in, and several emitters described one
host in their target vocabulary and their context while leaving the column
empty. A host's history came back confident and short.

These tests cover the service-level sites: the content-profile apply outcome,
the advisory applicability recompute, and the revocation work reconcile. Both name one host and only one, so
the host belongs in ``target_system_id`` and not in the affected-host links,
which exist for events that span a set and have no single subject.

What must not move while that host is added is pinned alongside it: the action,
the target kind and id, the context, and the session the event is written on.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

import pytest

from app.db.access_models import AuditEvent, AuditEventSystem, RevocationWork
from app.db.models import (
    ContentProfile,
    Credential,
    Group,
    HostContentProfileSubscription,
    HostFacts,
    Package,
    System,
    SystemMetadata,
)
from app.services import (
    fleet_reconciliation_service,
    patch_advisory_service,
    revocation_service,
    ssh_service,
)
from app.services.content_profile_apply import apply_content_profile_to_host
from app.services.patch_advisory_service import (
    AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED,
    SOURCE_KIND_UBUNTU_USN,
    compute_host_applicability,
    normalize_ubuntu_usn,
)
from tests.conftest import unique_test_ip

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def group(db) -> Group:
    g = Group(name="pra420-svc-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra420-svc-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host_builder(db, seed_distro, group, credentials):
    """Build hosts on demand so 'belongs only to the other host' is testable."""
    counter = {"n": 0}

    def make(*, with_facts: bool = False) -> System:
        counter["n"] += 1
        row = System(
            hostname=f"pra420-svc-{counter['n']}.example.com",
            ip_address=unique_test_ip(),
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=credentials.id,
        )
        db.add(row)
        db.flush()
        if with_facts:
            db.add(
                HostFacts(
                    system_id=row.id,
                    schema_version=1,
                    collected_at=datetime.utcnow(),
                    source_transport="agent",
                    distro_id_facts="ubuntu",
                    distro_release="22.04",
                )
            )
            db.flush()
        db.commit()
        return row

    return make


def _events(db, action: str, system_id: Optional[int] = None):
    q = db.query(AuditEvent).filter(AuditEvent.action == action)
    if system_id is not None:
        q = q.filter(AuditEvent.target_system_id == system_id)
    return q.order_by(AuditEvent.id).all()


def _links(db, event: AuditEvent):
    return (
        db.query(AuditEventSystem).filter(AuditEventSystem.event_id == event.id).all()
    )


# ---------------------------------------------------------------------------
# Content profile apply
# ---------------------------------------------------------------------------


class _NoTransport:
    """Refusal outcomes must reach the audit without touching the host, so a
    transport that fails the test if it is used is the honest stand-in."""

    name = "ssh"

    async def run(self, *args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("refused apply must not reach the host")


@pytest.mark.asyncio
async def test_apply_refusal_names_the_applied_host(db, host_builder):
    host = host_builder()

    outcome = await apply_content_profile_to_host(db, host, _NoTransport())

    assert outcome.state == "refused_no_profile"
    rows = _events(db, "host_content_profile.refused")
    assert len(rows) == 1
    assert rows[0].target_system_id == host.id
    # The target vocabulary the event already published is unchanged.
    assert rows[0].target_kind == "system"
    assert rows[0].target_id == str(host.id)
    context = json.loads(rows[0].context_json)
    assert context["hostname"] == host.hostname
    assert context["outcome_state"] == "refused_no_profile"


@pytest.mark.asyncio
async def test_apply_outcome_is_a_single_host_event_not_a_spanning_one(
    db, host_builder
):
    """One host is the subject, so it belongs in the column. The affected-host
    links describe an event that spans a set and names no single subject, and
    adding one here would misreport this event as that kind."""
    host = host_builder()

    await apply_content_profile_to_host(db, host, _NoTransport())

    rows = _events(db, "host_content_profile.refused")
    assert len(rows) == 1
    assert _links(db, rows[0]) == []


@pytest.mark.asyncio
async def test_apply_outcome_stays_out_of_another_hosts_history(db, host_builder):
    host = host_builder()
    other = host_builder()

    await apply_content_profile_to_host(db, host, _NoTransport())

    assert len(_events(db, "host_content_profile.refused", system_id=host.id)) == 1
    assert _events(db, "host_content_profile.refused", system_id=other.id) == []


@pytest.mark.asyncio
async def test_apply_conflict_refusal_also_names_the_host(db, host_builder):
    """Every outcome state leaves through one emitter, so the conflict refusal
    is attributed the same way the no-profile refusal is."""
    host = host_builder()
    first = ContentProfile(slug="pra420-a", display_name="x", package_family="deb")
    second = ContentProfile(slug="pra420-b", display_name="x", package_family="deb")
    db.add_all([first, second])
    db.flush()
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=first.id))
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=second.id))
    db.commit()

    outcome = await apply_content_profile_to_host(db, host, _NoTransport())

    assert outcome.state == "refused_conflict"
    rows = _events(db, "host_content_profile.refused")
    assert len(rows) == 1
    assert rows[0].target_system_id == host.id


# ---------------------------------------------------------------------------
# Advisory applicability recompute
# ---------------------------------------------------------------------------


def _import_usn(db, admin_user, *, advisory_id: str, fixed_version: str):
    payload = normalize_ubuntu_usn(
        {
            "id": advisory_id,
            "title": f"{advisory_id} title",
            "summary": "test",
            "severity": "High",
            "release_packages": {
                "jammy": [{"name": "openssl", "version": fixed_version}],
            },
        }
    )
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )


@pytest.fixture
def capture_emit(monkeypatch):
    """``_emit_applicable_recomputed`` calls ``safe_emit`` with no ``db=``, so
    it writes on its own session and cannot see uncommitted fixture rows. The
    kwargs are the contract under test here; retrieval is covered in the API
    lane."""
    calls: list = []
    monkeypatch.setattr(
        patch_advisory_service, "safe_emit", lambda **kw: calls.append(kw)
    )
    return calls


def test_advisory_recompute_names_the_recomputed_host(
    db, admin_user, host_builder, capture_emit
):
    host = host_builder(with_facts=True)
    db.add(
        Package(
            system_id=host.id,
            name="openssl",
            installed_version="3.0.2-0ubuntu1.10",
            package_type="deb",
        )
    )
    db.commit()
    _import_usn(
        db, admin_user, advisory_id="USN-PRA420-1", fixed_version="3.0.2-0ubuntu1.15"
    )

    emitted = [
        c
        for c in capture_emit
        if c["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert len(emitted) == 1
    assert emitted[0]["target_system_id"] == host.id
    # The target vocabulary and the context the event already published stay
    # exactly as they were, and the event does not claim to span a set.
    assert emitted[0]["target_kind"] == "system"
    assert emitted[0]["target_id"] == str(host.id)
    assert "related_system_ids" not in emitted[0]
    assert emitted[0]["context"]["rows_added"] == 1


def test_advisory_recompute_names_only_the_host_it_recomputed(
    db, admin_user, host_builder, capture_emit
):
    host = host_builder(with_facts=True)
    other = host_builder(with_facts=True)
    db.add(
        Package(
            system_id=host.id,
            name="openssl",
            installed_version="3.0.2-0ubuntu1.10",
            package_type="deb",
        )
    )
    db.commit()
    _import_usn(
        db, admin_user, advisory_id="USN-PRA420-2", fixed_version="3.0.2-0ubuntu1.15"
    )
    capture_emit.clear()

    compute_host_applicability(db, other.id)

    emitted = [
        c
        for c in capture_emit
        if c["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert [c["target_system_id"] for c in emitted] == [other.id]


# ---------------------------------------------------------------------------
# Revocation work reconcile
# ---------------------------------------------------------------------------


@pytest.fixture
def capture_revocation_emit(monkeypatch):
    """``_emit_result`` calls ``safe_emit`` with no ``db=``, so it writes on its
    own session. The kwargs are the contract here; retrieval is covered in the
    API lane."""
    calls: list = []
    monkeypatch.setattr(revocation_service, "safe_emit", lambda **kw: calls.append(kw))
    return calls


@pytest.fixture(autouse=True)
def _isolate_drain(monkeypatch):
    """Keep the drain off SSH and off its privilege-reconcile tail. Neither is
    what these tests are about."""
    monkeypatch.setattr(
        fleet_reconciliation_service, "reconcile_pending_privilege", lambda db: None
    )
    monkeypatch.setattr(ssh_service, "is_host_cooling_down", lambda *a, **k: None)
    monkeypatch.setattr(
        fleet_reconciliation_service,
        "reconcile_system",
        lambda _db, _sid: {
            "provisioned": 0,
            "removed": 0,
            "errors": 0,
            "skipped": 0,
            "conflicts": 0,
            "manual_intervention": 0,
        },
    )


def _revocation_work(db, *, system_id, user_id=None, login=None):
    row = RevocationWork(
        reason="test",
        user_id=user_id,
        system_id=system_id,
        login=login,
        status="pending",
        attempt_count=0,
    )
    db.add(row)
    db.flush()
    return row


def test_host_scoped_revocation_names_its_host(
    db, host_builder, capture_revocation_emit
):
    host = host_builder()
    db.add(SystemMetadata(system_id=host.id))
    db.flush()
    _revocation_work(db, system_id=host.id, login="alice")

    revocation_service.drain(db, now=datetime.utcnow())

    emitted = [
        c for c in capture_revocation_emit if c["action"] == "revocation.reconcile"
    ]
    assert len(emitted) == 1
    assert emitted[0]["target_system_id"] == host.id
    # The target vocabulary and context the event already published are intact.
    assert emitted[0]["target_kind"] == "revocation_work"
    assert emitted[0]["context"]["system_id"] == host.id
    assert emitted[0]["context"]["login"] == "alice"


def test_session_only_revocation_stays_hostless(
    db, admin_user, capture_revocation_emit
):
    """A user-scoped sweep carries no ``system_id`` and touches no host, so it
    must not be attributed to one.

    This is a guard rather than a repair: it held before the host-scoped branch
    was attributed and has to keep holding after, so it reads the kwarg with
    ``get`` and fails only if a host ever appears here.
    """
    _revocation_work(db, system_id=None, user_id=admin_user.id)

    revocation_service.drain(db, now=datetime.utcnow())

    emitted = [
        c for c in capture_revocation_emit if c["action"] == "revocation.reconcile"
    ]
    assert len(emitted) == 1
    assert emitted[0].get("target_system_id") is None
    assert emitted[0]["context"]["system_id"] is None


def test_revocation_names_only_the_host_its_work_is_for(
    db, host_builder, capture_revocation_emit
):
    host = host_builder()
    other = host_builder()
    for system in (host, other):
        db.add(SystemMetadata(system_id=system.id))
    db.flush()
    _revocation_work(db, system_id=host.id, login="alice")

    revocation_service.drain(db, now=datetime.utcnow())

    emitted = [
        c for c in capture_revocation_emit if c["action"] == "revocation.reconcile"
    ]
    assert [c["target_system_id"] for c in emitted] == [host.id]
