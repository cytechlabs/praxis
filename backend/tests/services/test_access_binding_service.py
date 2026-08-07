"""Tests for PRA-137 access_binding_service + host_user_provisioning_service.

Covers:
    - Built-in fleet role seeding
    - Binding CRUD + XOR validation
    - Grant computation for user/app-role subjects x group/smart-group scopes
    - Expired / disabled bindings produce no grants
    - Implicit admin rule
    - Role-account mode shared-login grants
    - Provisioning script generation (no SSH side effects)

Integration-level provisioning against a real Linux container is deferred
(see follow-up PRA for E1+E2 end-to-end).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.db.access_models import AccessBinding, AccessGrant, FleetRole
from app.db.models import Credential, Group, SmartGroup, SmartGroupMembership, System
from app.services import access_binding_service as abs_svc
from app.services import host_user_provisioning_service as prov

# --------------------------------------------------------------------- helpers


@pytest.fixture
def seed_default_group(db):
    """Reuse the standing 'Default' group to avoid PK-sequence collisions
    caused by migration-seeded rows in the test DB."""
    g = db.query(Group).filter_by(name="Default").first()
    if not g:
        g = Group(name="Default", description="test default")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def seed_cred(db):
    """Reuse an existing credential to avoid PK-sequence collisions from
    migration-seeded rows in the test DB."""
    c = db.query(Credential).first()
    if c is None:
        c = Credential(
            name="pra137-cred",
            auth_method="password",
            username="root",
            vault_path="vault/pra137",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.9.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _fleet_role(db, name: str) -> FleetRole:
    return db.query(FleetRole).filter(FleetRole.name == name).first()


# -------------------------------------------------------------- role seeding


def test_builtin_fleet_roles_seeded(db):
    """Migration seeds admin / maintainer / auditor."""
    names = {
        r.name for r in db.query(FleetRole).filter(FleetRole.is_builtin.is_(True)).all()
    }
    assert names == {"admin", "maintainer", "auditor"}


def test_builtin_roles_have_no_standing_sudo(db):
    """PRA-282: the 1.0 privilege baseline — no built-in fleet role carries a
    standing sudoers snippet or a privileged OS group."""
    for name in ("admin", "maintainer", "auditor"):
        role = _fleet_role(db, name)
        assert role.sudoers_snippet is None, f"{name} must have no sudoers snippet"
        groups = set(json.loads(role.os_groups_json or "[]"))
        assert not (
            groups & {"wheel", "sudo", "root", "admin"}
        ), f"{name} must not be in a privileged OS group"


def test_auditor_role_is_session_only(db):
    auditor = _fleet_role(db, "auditor")
    actions = json.loads(auditor.allowed_actions_json)
    assert actions == ["session_open"]
    assert auditor.sudoers_snippet is None


# ------------------------------------------------------------ binding shape


def test_subject_xor_enforced():
    with pytest.raises(abs_svc.BindingValidationError):
        abs_svc._validate_binding_shape(None, None, 1, None)
    with pytest.raises(abs_svc.BindingValidationError):
        abs_svc._validate_binding_shape(1, 1, 1, None)


def test_scope_xor_enforced():
    with pytest.raises(abs_svc.BindingValidationError):
        abs_svc._validate_binding_shape(1, None, None, None)
    with pytest.raises(abs_svc.BindingValidationError):
        abs_svc._validate_binding_shape(1, None, 1, 1)


def test_both_sides_valid():
    abs_svc._validate_binding_shape(1, None, 1, None)
    abs_svc._validate_binding_shape(None, 1, None, 1)


# ------------------------------------------------------------- grant compute


def test_user_subject_static_group_scope_creates_grant(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-h1")
    dev = _fleet_role(db, "maintainer")

    abs_svc.create_binding(
        db,
        fleet_role_id=dev.id,
        subject_user_id=admin_user.id,
        scope_group_id=seed_default_group.id,
    )

    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == admin_user.id,
            AccessGrant.system_id == s1.id,
            AccessGrant.fleet_role_id == dev.id,
        )
        .all()
    )
    assert len(grants) == 1
    assert grants[0].login == admin_user.username
    assert grants[0].is_implicit_admin is False


def test_app_role_subject_spreads_to_all_users_in_role(
    db,
    admin_user,
    maintainer_user,
    seed_roles,
    seed_distro,
    seed_default_group,
    seed_cred,
):
    """A binding whose subject is an app-role grants every user in that role."""
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-h2")
    maintainer_fleet = _fleet_role(db, "maintainer")

    abs_svc.create_binding(
        db,
        fleet_role_id=maintainer_fleet.id,
        subject_app_role_id=seed_roles["maintainer"].id,
        scope_group_id=seed_default_group.id,
    )

    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.system_id == s1.id,
            AccessGrant.fleet_role_id == maintainer_fleet.id,
        )
        .all()
    )
    user_ids = {g.user_id for g in grants}
    assert maintainer_user.id in user_ids
    assert admin_user.id not in user_ids  # not in maintainer role


def test_expired_binding_produces_no_grants(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-h3")
    dev = _fleet_role(db, "maintainer")
    abs_svc.create_binding(
        db,
        fleet_role_id=dev.id,
        subject_user_id=admin_user.id,
        scope_group_id=seed_default_group.id,
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )
    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == admin_user.id,
            AccessGrant.fleet_role_id == dev.id,
        )
        .all()
    )
    # implicit admin may still fire for admin_user, but no explicit grants via this binding
    assert all(g.is_implicit_admin for g in grants) or len(grants) == 0


def test_disabled_binding_produces_no_grants(
    db, auditor_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-h4")
    auditor = _fleet_role(db, "auditor")
    abs_svc.create_binding(
        db,
        fleet_role_id=auditor.id,
        subject_user_id=auditor_user.id,
        scope_group_id=seed_default_group.id,
        enabled=False,
    )
    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == auditor_user.id,
            AccessGrant.system_id == s.id,
        )
        .all()
    )
    assert grants == []


def test_implicit_admin_rule(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    """Users with app-role 'admin' get admin fleet role on every system."""
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-h5")
    abs_svc.recompute_grants(db)

    admin_fleet = _fleet_role(db, "admin")
    implicit = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == admin_user.id,
            AccessGrant.system_id == s1.id,
            AccessGrant.fleet_role_id == admin_fleet.id,
            AccessGrant.is_implicit_admin.is_(True),
        )
        .first()
    )
    assert implicit is not None
    assert implicit.via_binding_id is None
    assert implicit.login == admin_user.username


def test_smart_group_scope_drives_grants(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    """Grants follow cached smart-group membership."""
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-sg1")
    sg = SmartGroup(
        name="pra137-smart",
        rule_json=json.dumps({"field": "hostname", "op": "eq", "value": "pra137-sg1"}),
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=s1.id))
    db.commit()

    dev = _fleet_role(db, "maintainer")
    abs_svc.create_binding(
        db,
        fleet_role_id=dev.id,
        subject_user_id=admin_user.id,
        scope_smart_group_id=sg.id,
    )

    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == admin_user.id,
            AccessGrant.system_id == s1.id,
            AccessGrant.fleet_role_id == dev.id,
        )
        .all()
    )
    assert len(grants) == 1
    assert grants[0].via_binding_id is not None


def test_role_account_mode_shares_login(
    db,
    admin_user,
    maintainer_user,
    seed_roles,
    seed_distro,
    seed_default_group,
    seed_cred,
):
    """Multiple users with a role-account binding all use the same login."""
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-ra")
    ra_role = FleetRole(
        name="shared-dev",
        login_mode="role_account",
        role_account_name="developer",
        allowed_actions_json='["session_open", "command_exec"]',
        os_groups_json="[]",
    )
    db.add(ra_role)
    db.flush()

    abs_svc.create_binding(
        db,
        fleet_role_id=ra_role.id,
        subject_app_role_id=seed_roles["maintainer"].id,
        scope_group_id=seed_default_group.id,
    )

    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.system_id == s1.id,
            AccessGrant.fleet_role_id == ra_role.id,
        )
        .all()
    )
    logins = {g.login for g in grants}
    assert logins == {"developer"}  # everyone shares the role account
    assert maintainer_user.id in {g.user_id for g in grants}


# --------------------------------------------------- eligible_logins lookup


def test_eligible_logins_returns_matches(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s1 = _mk_system(db, seed_distro, seed_default_group, seed_cred, "pra137-el")
    dev = _fleet_role(db, "maintainer")
    abs_svc.create_binding(
        db,
        fleet_role_id=dev.id,
        subject_user_id=admin_user.id,
        scope_group_id=seed_default_group.id,
    )
    grants = abs_svc.eligible_logins(db, admin_user.id, s1.id)
    # admin also gets admin-role via implicit rule
    fleet_names = {
        db.query(FleetRole).filter(FleetRole.id == g.fleet_role_id).first().name
        for g in grants
    }
    assert {"admin", "maintainer"}.issubset(fleet_names)


# ---------------------------------------------------- provisioning scripts


def test_login_validation_rejects_shell_injection():
    with pytest.raises(prov.ProvisioningError):
        prov._validate_login("alice; rm -rf /")
    with pytest.raises(prov.ProvisioningError):
        prov._validate_login("Alice")  # uppercase not allowed
    with pytest.raises(prov.ProvisioningError):
        prov._validate_login("")
    prov._validate_login("alice")
    prov._validate_login("_svc-deploy")


def test_ensure_script_includes_useradd_and_principals():
    script = prov._ensure_script(
        login="alice",
        os_groups=["docker", "wheel"],
        principals=["alice"],
    )
    assert "useradd -m -s /bin/bash alice" in script
    # The group list now passes through a getent filter so missing groups on
    # cross-distro hosts don't fail provisioning. Both wanted groups still
    # appear in the iterated list, and the usermod call consumes the
    # filtered result.
    assert "for g in docker wheel" in script
    assert 'getent group "$g"' in script
    # PRA-282: provisioning never writes a sudoers drop-in — it always removes it.
    assert "rm -f /etc/sudoers.d/praxis-alice" in script
    assert "visudo" not in script
    assert 'usermod -G "$praxis_groups" alice' in script
    assert "/etc/praxis/principals.d/alice" in script


def test_ensure_script_empty_groups_clears_membership():
    script = prov._ensure_script(
        login="bob",
        os_groups=[],
        principals=["bob"],
    )
    # With no groups we still issue a clearing usermod
    assert "usermod -G '' bob" in script
    # No sudoers snippet => sudoers file should be removed, not written
    assert "rm -f /etc/sudoers.d/praxis-bob" in script
    assert "visudo" not in script


def test_remove_script_archives_home_and_deletes():
    script = prov._remove_script("alice")
    assert "mkdir -p /var/backups/praxis/homedirs" in script
    assert "tar czf /var/backups/praxis/homedirs/alice-" in script
    assert "userdel -r alice" in script
    assert "PRAXIS_ARCHIVE=" in script
