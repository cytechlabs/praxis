"""Tests for PRA-139: authorization, TOTP, and JIT access requests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pyotp
import pytest

from app.db.access_models import (
    AccessBinding,
    AccessGrant,
    AccessRequest,
    FleetRole,
    TotpChallenge,
)
from app.db.models import Credential, Group, System
from app.services import access_authorization_service as auth_svc
from app.services import access_binding_service as abs_svc
from app.services import access_request_service as ar_svc
from app.services import totp_service

# --------------------------------------------------------------- helpers


@pytest.fixture
def seed_default_group(db):
    g = db.query(Group).filter_by(name="Default").first()
    if not g:
        g = Group(name="Default")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def seed_cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(
            name="pra139-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra139",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.7.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


# ------------------------------------------------------- authorization


def test_authorize_denies_without_grant(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p139-noauth")
    with pytest.raises(auth_svc.PermissionDenied) as exc:
        auth_svc.authorize_action(db, maintainer_user, s, "session_open")
    assert exc.value.code == "forbidden"


def test_authorize_denies_action_not_in_role(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred, seed_roles
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p139-noxfer")
    auditor = db.query(FleetRole).filter(FleetRole.name == "auditor").first()
    abs_svc.create_binding(
        db,
        fleet_role_id=auditor.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=seed_default_group.id,
    )
    # auditor has only session_open
    with pytest.raises(auth_svc.PermissionDenied) as exc:
        auth_svc.authorize_action(db, maintainer_user, s, "file_transfer")
    assert exc.value.code == "action_not_allowed"


def test_authorize_passes_for_implicit_admin(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p139-admin")
    abs_svc.recompute_grants(db)
    result = auth_svc.authorize_action(db, admin_user, s, "session_open")
    assert result.grant is not None
    assert result.fleet_role.name == "admin"
    assert result.login == admin_user.username


def test_enforce_raises_totp_required_when_not_fresh(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred, seed_roles
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p139-totp")
    # Make a custom role that requires TOTP
    role = FleetRole(
        name="totp-needed",
        login_mode="per_user",
        allowed_actions_json=json.dumps(["session_open"]),
        totp_required=True,
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=seed_default_group.id,
    )
    with pytest.raises(auth_svc.PermissionDenied) as exc:
        auth_svc.enforce_action(db, maintainer_user, s, "session_open")
    assert exc.value.code == "totp_required"


def test_enforce_accepts_with_fresh_totp_challenge(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p139-totp-ok")
    role = FleetRole(
        name="totp-needed-2",
        login_mode="per_user",
        allowed_actions_json=json.dumps(["session_open"]),
        totp_required=True,
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=seed_default_group.id,
    )
    auth_svc.record_totp_challenge(db, maintainer_user.id, window_s=300)
    result = auth_svc.enforce_action(db, maintainer_user, s, "session_open")
    assert result.fleet_role.name == "totp-needed-2"


def test_enforce_raises_approval_required(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p139-appr")
    role = FleetRole(
        name="approval-needed",
        login_mode="per_user",
        allowed_actions_json=json.dumps(["session_open"]),
        session_requires_approval=True,
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=seed_default_group.id,
    )
    with pytest.raises(auth_svc.PermissionDenied) as exc:
        auth_svc.enforce_action(db, maintainer_user, s, "session_open")
    assert exc.value.code == "approval_required"


# ------------------------------------------------------------------- TOTP


def test_totp_enrollment_flow_end_to_end(db, admin_user):
    secret, uri = totp_service.begin_enrollment(db, admin_user)
    assert "otpauth://" in uri
    # Not enrolled until verify_enrollment succeeds
    assert not totp_service.is_enrolled(admin_user)
    code = pyotp.TOTP(secret).now()
    recovery = totp_service.verify_enrollment(db, admin_user, code)
    assert len(recovery) == 10
    assert totp_service.is_enrolled(admin_user)


def test_totp_enrollment_rejects_bad_code(db, admin_user):
    totp_service.begin_enrollment(db, admin_user)
    with pytest.raises(totp_service.TotpError):
        totp_service.verify_enrollment(db, admin_user, "000000")


def test_totp_step_up_mints_challenge(db, admin_user):
    secret, _ = totp_service.begin_enrollment(db, admin_user)
    totp_service.verify_enrollment(db, admin_user, pyotp.TOTP(secret).now())
    assert not auth_svc.has_fresh_totp(db, admin_user.id)
    ok = totp_service.verify_step_up(db, admin_user, pyotp.TOTP(secret).now())
    assert ok
    assert auth_svc.has_fresh_totp(db, admin_user.id)


def test_totp_recovery_code_burns_on_use(db, admin_user):
    secret, _ = totp_service.begin_enrollment(db, admin_user)
    codes = totp_service.verify_enrollment(db, admin_user, pyotp.TOTP(secret).now())
    # Use one recovery code
    ok = totp_service.verify_step_up(db, admin_user, codes[0])
    assert ok
    # That code is gone; reuse fails
    ok2 = totp_service.verify_step_up(db, admin_user, codes[0])
    assert not ok2
    # Remaining codes still work
    assert totp_service.remaining_recovery_codes(admin_user) == 9


def test_totp_disable_clears_state(db, admin_user):
    secret, _ = totp_service.begin_enrollment(db, admin_user)
    totp_service.verify_enrollment(db, admin_user, pyotp.TOTP(secret).now())
    totp_service.disable(db, admin_user)
    assert admin_user.totp_secret is None
    assert admin_user.totp_enrolled_at is None
    assert not totp_service.is_enrolled(admin_user)


# ------------------------------------------------------ access requests


def test_access_request_lifecycle_approve_creates_binding(
    db, maintainer_user, admin_user, seed_distro, seed_default_group, seed_cred
):
    role = db.query(FleetRole).filter(FleetRole.name == "maintainer").first()
    req = ar_svc.create_request(
        db,
        requested_by=maintainer_user.id,
        fleet_role_id=role.id,
        scope_group_id=seed_default_group.id,
        justification="need prod access for deploy",
        duration_seconds=1800,
    )
    assert req.status == "pending"

    ar_svc.approve(db, req.id, decider_id=admin_user.id, comment="ok")
    db.refresh(req)
    assert req.status == "approved"
    assert req.resulting_binding_id is not None
    binding = (
        db.query(AccessBinding)
        .filter(AccessBinding.id == req.resulting_binding_id)
        .first()
    )
    assert binding is not None
    assert binding.subject_user_id == maintainer_user.id
    # expires_at ~ 30 min from now
    delta = (binding.expires_at - datetime.utcnow()).total_seconds()
    assert 1700 < delta < 1900


def test_access_request_reject_sets_status(
    db, maintainer_user, admin_user, seed_default_group
):
    role = db.query(FleetRole).filter(FleetRole.name == "maintainer").first()
    req = ar_svc.create_request(
        db,
        requested_by=maintainer_user.id,
        fleet_role_id=role.id,
        scope_group_id=seed_default_group.id,
        duration_seconds=600,
    )
    ar_svc.reject(db, req.id, decider_id=admin_user.id, comment="denied")
    db.refresh(req)
    assert req.status == "rejected"
    assert req.resulting_binding_id is None


def test_access_request_validation_rejects_bad_duration(
    db, maintainer_user, seed_default_group
):
    role = db.query(FleetRole).filter(FleetRole.name == "maintainer").first()
    with pytest.raises(ar_svc.AccessRequestError):
        ar_svc.create_request(
            db,
            requested_by=maintainer_user.id,
            fleet_role_id=role.id,
            scope_group_id=seed_default_group.id,
            duration_seconds=10,  # below 5 min minimum
        )


def test_access_request_validation_requires_one_scope(
    db, maintainer_user, seed_default_group
):
    role = db.query(FleetRole).filter(FleetRole.name == "maintainer").first()
    with pytest.raises(ar_svc.AccessRequestError):
        ar_svc.create_request(
            db,
            requested_by=maintainer_user.id,
            fleet_role_id=role.id,
            # neither set
            duration_seconds=600,
        )


def test_access_request_revoke_deletes_binding(
    db, maintainer_user, admin_user, seed_default_group
):
    role = db.query(FleetRole).filter(FleetRole.name == "maintainer").first()
    req = ar_svc.create_request(
        db,
        requested_by=maintainer_user.id,
        fleet_role_id=role.id,
        scope_group_id=seed_default_group.id,
        duration_seconds=600,
    )
    ar_svc.approve(db, req.id, decider_id=admin_user.id)
    db.refresh(req)
    binding_id = req.resulting_binding_id

    ar_svc.revoke(db, req.id, revoker_id=admin_user.id)
    db.refresh(req)
    assert req.status == "revoked"
    assert (
        db.query(AccessBinding).filter(AccessBinding.id == binding_id).first() is None
    )
