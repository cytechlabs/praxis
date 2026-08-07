"""PRA-180 P2 Remediation (PRA-221): audit read authorization hardening.

AUDIT-05: the legacy ``SystemAudit`` read/export/feed surfaces previously used
only ``Depends(get_current_user)``, so any authenticated role (including a
low-privilege viewer) could read or export fleet-wide audit history. They are
now gated to the audit-read roles (admin/auditor), matching the unified
``/audit/events`` posture.

Covers:
- ``GET /audits`` (list), ``GET /audits/{system_id}``, ``GET /audits/filters/options``
- ``GET /export/audits``
- ``GET /activity/feed?source=audit`` (explicit) and the mixed feed (audit rows
  are dropped for lower-privilege roles rather than leaked).
"""

from datetime import datetime

import pytest

from app.db.models import Credential, Group, System, SystemAudit

# ── helpers / fixtures ─────────────────────────────────────────────────────


def _token(client, username: str) -> str:
    res = client.post(
        "/auth/login",
        data={"username": username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_user(db, seed_roles):
    """A plain authenticated user with no audit-read privilege."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    user = User(
        username="viewertest",
        email="viewertest@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    user.roles.append(seed_roles["viewer"])
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def audited_system(db, seed_distro) -> System:
    """A system with one SystemAudit row carrying old/new values."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    actor = User(
        username="pra221-actor",
        email="pra221-actor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    db.add(actor)
    db.flush()
    g = Group(name="pra221-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="pra221-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="pra221.example.com",
        ip_address="10.60.70.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    audit = SystemAudit(
        system_id=s.id,
        audit_type="status",
        changed_by=actor.id,
        changed_at=datetime.utcnow(),
        old_value="Active",
        new_value="Maintenance",
        operation="update",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(audit)
    db.commit()
    return s


# ── /audits read endpoints ─────────────────────────────────────────────────


AUDIT_LIST_PATHS = ["/audits", "/audits/filters/options"]


@pytest.mark.parametrize("path", AUDIT_LIST_PATHS)
def test_audits_read_allows_admin(client, admin_user, audited_system, path):
    res = client.get(path, headers=_hdr(_token(client, admin_user.username)))
    assert res.status_code == 200, res.text


@pytest.mark.parametrize("path", AUDIT_LIST_PATHS)
def test_audits_read_allows_auditor(client, auditor_user, audited_system, path):
    res = client.get(path, headers=_hdr(_token(client, auditor_user.username)))
    assert res.status_code == 200, res.text


@pytest.mark.parametrize("path", AUDIT_LIST_PATHS)
def test_audits_read_rejects_maintainer(client, maintainer_user, path):
    res = client.get(path, headers=_hdr(_token(client, maintainer_user.username)))
    assert res.status_code == 403, res.text


@pytest.mark.parametrize("path", AUDIT_LIST_PATHS)
def test_audits_read_rejects_viewer(client, viewer_user, path):
    res = client.get(path, headers=_hdr(_token(client, viewer_user.username)))
    assert res.status_code == 403, res.text


@pytest.mark.parametrize("path", AUDIT_LIST_PATHS)
def test_audits_read_rejects_unauthenticated(client, path):
    assert client.get(path).status_code == 401


def test_audits_for_system_allows_auditor(client, db, auditor_user, audited_system):
    # PRA-281: per-system audit reads are fleet-scoped — the auditor needs a grant
    # on the system in addition to the audit-read role. Without it the route
    # returns a non-disclosing 404 (covered by the PRA-281 suite).
    from app.db.access_models import AccessGrant, FleetRole

    role = FleetRole(
        name="pra221-auditor-role",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    db.add(
        AccessGrant(
            user_id=auditor_user.id,
            system_id=audited_system.id,
            fleet_role_id=role.id,
            login=auditor_user.username,
        )
    )
    db.commit()
    res = client.get(
        f"/audits/{audited_system.id}",
        headers=_hdr(_token(client, auditor_user.username)),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["items"], "auditor should see the seeded audit row"
    assert body["items"][0]["new_value"] == "Maintenance"


def test_audits_for_system_rejects_maintainer(client, maintainer_user, audited_system):
    # 403 from the role gate fires before the handler, regardless of the id.
    res = client.get(
        f"/audits/{audited_system.id}",
        headers=_hdr(_token(client, maintainer_user.username)),
    )
    assert res.status_code == 403, res.text


# ── /export/audits ─────────────────────────────────────────────────────────


def test_export_audits_allows_admin(client, admin_user, audited_system):
    res = client.get(
        "/export/audits", headers=_hdr(_token(client, admin_user.username))
    )
    assert res.status_code == 200, res.text


def test_export_audits_rejects_maintainer(client, maintainer_user):
    res = client.get(
        "/export/audits", headers=_hdr(_token(client, maintainer_user.username))
    )
    assert res.status_code == 403, res.text


def test_export_audits_rejects_viewer(client, viewer_user):
    res = client.get(
        "/export/audits", headers=_hdr(_token(client, viewer_user.username))
    )
    assert res.status_code == 403, res.text


def test_export_audits_rejects_unauthenticated(client):
    assert client.get("/export/audits").status_code == 401


def test_export_systems_still_open_to_authenticated(client, maintainer_user):
    """AUDIT-05 is scoped to the audit surface; non-audit exports keep their
    existing any-authenticated posture."""
    res = client.get(
        "/export/systems", headers=_hdr(_token(client, maintainer_user.username))
    )
    assert res.status_code == 200, res.text


# ── /activity/feed?source=audit ────────────────────────────────────────────


def test_activity_feed_audit_source_allows_auditor(
    client, auditor_user, audited_system
):
    res = client.get(
        "/activity/feed?source=audit",
        headers=_hdr(_token(client, auditor_user.username)),
    )
    assert res.status_code == 200, res.text
    sources = {item["source"] for item in res.json()["items"]}
    assert "audit" in sources


def test_activity_feed_audit_source_rejects_maintainer(client, maintainer_user):
    res = client.get(
        "/activity/feed?source=audit",
        headers=_hdr(_token(client, maintainer_user.username)),
    )
    assert res.status_code == 403, res.text


def test_activity_feed_audit_source_rejects_viewer(client, viewer_user):
    res = client.get(
        "/activity/feed?source=audit",
        headers=_hdr(_token(client, viewer_user.username)),
    )
    assert res.status_code == 403, res.text


def test_activity_feed_mixed_drops_audit_for_maintainer(
    client, maintainer_user, audited_system
):
    """The unfiltered feed still works for lower-privilege roles, but audit
    rows are excluded rather than leaked."""
    res = client.get(
        "/activity/feed",
        headers=_hdr(_token(client, maintainer_user.username)),
    )
    assert res.status_code == 200, res.text
    sources = {item["source"] for item in res.json()["items"]}
    assert "audit" not in sources


def test_activity_feed_mixed_includes_audit_for_auditor(
    client, auditor_user, audited_system
):
    res = client.get(
        "/activity/feed",
        headers=_hdr(_token(client, auditor_user.username)),
    )
    assert res.status_code == 200, res.text
    sources = {item["source"] for item in res.json()["items"]}
    assert "audit" in sources
