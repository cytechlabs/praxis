"""PRA-312 follow-up: per-host compliance summary rows carry the hostname.

The dashboard/policy "By host" tables showed `#<system_id>` because the summary
`per_host` rows only had `system_id`. Both summary builders now join System and
include `hostname` (NULL-safe) so the UI can render the real hostname.
"""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, Package, System
from app.services import compliance_evaluation_service as evalsvc
from app.services import compliance_service


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra312-hn", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra312-hn-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra312-hostname.example.com",
        ip_address="10.0.0.91",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _policy_with_evidence(db, admin_user, host):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="hn", name="HN", enabled=True
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="hn-chk",
        title="openssl",
        kind="package_installed",
        definition={"package": "openssl"},
    )
    db.add(Package(system_id=host.id, name="openssl", installed_version="3.0.2"))
    db.flush()
    evalsvc.evaluate_policy_for_fleet(db, policy_id=policy.id)
    return policy


def test_policy_summary_per_host_includes_hostname(db, admin_user, host):
    policy = _policy_with_evidence(db, admin_user, host)
    summary = evalsvc.policy_summary(db, policy_id=policy.id)
    per_host = summary["per_host"]
    assert per_host, "expected a per-host row"
    row = next(r for r in per_host if r["system_id"] == host.id)
    assert row["hostname"] == "pra312-hostname.example.com"


def test_fleet_summary_per_host_includes_hostname(db, admin_user, host):
    _policy_with_evidence(db, admin_user, host)
    summary = evalsvc.fleet_summary(db)
    per_host = summary["per_host"]
    assert per_host, "expected a per-host row"
    row = next(r for r in per_host if r["system_id"] == host.id)
    assert row["hostname"] == "pra312-hostname.example.com"


def test_hostname_map_is_null_safe_for_missing_system(db):
    # No such system -> not in the map (UI falls back to #id).
    assert evalsvc._hostname_map(db, [999999]) == {}
    assert evalsvc._hostname_map(db, []) == {}
