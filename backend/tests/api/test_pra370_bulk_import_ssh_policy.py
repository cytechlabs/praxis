"""PRA-370: bulk-imported systems get the persisted Default SSH security policy.

Single-system registration already attaches the seeded ``Default`` policy, so
bulk import left systems with a NULL ``ssh_security_policy_id`` until the next
startup backfill ran. Correctness must not depend on a backend restart: these
tests pin the assignment at creation time, and pin that a missing default still
cannot degrade into permissive host-key acceptance.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import paramiko
import pytest

from app.db.models import Credential, Group, System
from app.db.ssh_security_models import SSHSecurityPolicy
from app.services.ssh_service import HostKeyPromptPolicy, configure_host_key_policy

_BULK = "/bulk"


@pytest.fixture(autouse=True)
def _stub_bulk_side_effects(monkeypatch):
    """Stub the fleet-operation service so the success path does not hit its own
    ``SessionLocal`` (which cannot see the test transaction's uncommitted rows ->
    FK violation). Mirrors the pattern in ``test_pra281_fleet_scope_authorization``.
    """
    import app.api.routes.bulk as bulk_routes
    from app.services import fleet_operation_service

    monkeypatch.setattr(fleet_operation_service, "start_operation", lambda **kw: 1)
    monkeypatch.setattr(fleet_operation_service, "record_result", lambda *a, **kw: None)
    monkeypatch.setattr(
        fleet_operation_service, "complete_operation", lambda *a, **kw: None
    )
    monkeypatch.setattr(bulk_routes, "create_notification", lambda *a, **kw: None)


@pytest.fixture
def import_targets(db):
    """Import requires a resolvable group + credential per row."""
    tag = uuid.uuid4().hex[:8]
    group = Group(name=f"pra370-grp-{tag}")
    cred = Credential(
        name=f"pra370-cred-{tag}", auth_method="password", username="root"
    )
    db.add_all([group, cred])
    db.flush()
    return group, cred


def _seed_default_policy(db, admin_user) -> SSHSecurityPolicy:
    """Seed (or reuse) the ``Default`` policy the startup seeder creates."""
    policy = (
        db.query(SSHSecurityPolicy).filter(SSHSecurityPolicy.name == "Default").first()
    )
    if not policy:
        policy = SSHSecurityPolicy(
            name="Default",
            description="Seeded default policy.",
            require_host_key_verification=True,
            created_by=admin_user.id,
        )
        db.add(policy)
        db.flush()
    return policy


def _import_body(seed_distro, import_targets, count: int = 1) -> dict:
    group, cred = import_targets
    tag = uuid.uuid4().hex[:8]
    return {
        "systems": [
            {
                "hostname": f"pra370-{tag}-{i}.example.com",
                "ip_address": f"10.37.0.{i + 1}",
                "distro": f"{seed_distro.name} {seed_distro.version}",
                "group": group.name,
                "credential": cred.name,
            }
            for i in range(count)
        ]
    }


def _created(db, body) -> list[System]:
    hostnames = [s["hostname"] for s in body["systems"]]
    rows = db.query(System).filter(System.hostname.in_(hostnames)).all()
    assert len(rows) == len(hostnames), f"expected {len(hostnames)} systems, got {rows}"
    return rows


def _install_policy(db, system):
    """Run the shared host-key helper against ``system`` and return the policy
    object it installed."""
    client = MagicMock()
    client.get_host_keys.return_value = MagicMock()
    configure_host_key_policy(client, db, system)
    return client.set_missing_host_key_policy.call_args[0][0]


def test_bulk_import_assigns_default_policy(
    authed_client, db, admin_user, seed_distro, import_targets
):
    policy = _seed_default_policy(db, admin_user)
    before = db.query(SSHSecurityPolicy).count()
    body = _import_body(seed_distro, import_targets, count=3)

    res = authed_client.post(f"{_BULK}/import", json=body)
    assert res.status_code == 201, res.text
    assert res.json()["created"] == 3, res.text

    db.expire_all()
    systems = _created(db, body)
    # Every imported row is attached to the SAME persisted Default policy: the
    # batch resolves it once and never creates one ad hoc.
    assert {s.ssh_security_policy_id for s in systems} == {policy.id}
    assert db.query(SSHSecurityPolicy).count() == before


def test_bulk_imported_system_requires_host_key_verification(
    authed_client, db, admin_user, seed_distro, import_targets
):
    """End to end: the policy attached at import actually drives the shared SSH
    host-key decision, and it is never AutoAddPolicy."""
    _seed_default_policy(db, admin_user)
    body = _import_body(seed_distro, import_targets)

    res = authed_client.post(f"{_BULK}/import", json=body)
    assert res.status_code == 201, res.text

    db.expire_all()
    system = _created(db, body)[0]
    assert system.ssh_security_policy is not None
    assert system.ssh_security_policy.require_host_key_verification is True

    installed = _install_policy(db, system)
    assert isinstance(installed, HostKeyPromptPolicy)
    assert not isinstance(installed, paramiko.AutoAddPolicy)


def test_bulk_import_without_default_policy_is_not_permissive(
    authed_client, db, seed_distro, import_targets
):
    """If the seeded Default policy is unexpectedly absent, import must not
    invent one or fail the request, and the resulting NULL-policy system must
    still fail closed in the shared host-key helper (PRA-370)."""
    db.query(SSHSecurityPolicy).filter(SSHSecurityPolicy.name == "Default").delete()
    db.flush()
    before = db.query(SSHSecurityPolicy).count()
    body = _import_body(seed_distro, import_targets)

    res = authed_client.post(f"{_BULK}/import", json=body)
    assert res.status_code == 201, res.text

    db.expire_all()
    system = _created(db, body)[0]
    assert system.ssh_security_policy_id is None
    # No policy row was fabricated by the route.
    assert db.query(SSHSecurityPolicy).count() == before

    installed = _install_policy(db, system)
    assert isinstance(installed, HostKeyPromptPolicy)
    assert not isinstance(installed, paramiko.AutoAddPolicy)


def test_bulk_import_dry_run_creates_nothing(
    authed_client, db, admin_user, seed_distro, import_targets
):
    _seed_default_policy(db, admin_user)
    body = {**_import_body(seed_distro, import_targets), "dry_run": True}

    res = authed_client.post(f"{_BULK}/import", json=body)
    assert res.status_code == 201, res.text
    assert res.json()["dry_run"] is True

    db.expire_all()
    hostnames = [s["hostname"] for s in body["systems"]]
    assert db.query(System).filter(System.hostname.in_(hostnames)).count() == 0
