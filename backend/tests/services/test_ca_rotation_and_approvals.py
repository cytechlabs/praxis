"""Tests for PRA-128 CA rotation + PRA-129 approval votes & expiration."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.db.models import (
    CARotation,
    CommandApproval,
    CommandApprovalVote,
    Credential,
    Group,
    SSHIdentitySettings,
    System,
)
from app.services import ca_rotation_service, command_approval_service

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def seed_default_group(db):
    g = db.query(Group).filter_by(name="Default").first()
    if not g:
        g = Group(name="Default", description="t")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def seed_cred(db):
    c = Credential(name="c", auth_method="password", username="root", vault_path="x")
    db.add(c)
    db.flush()
    return c


def _mk_system(db, distro, group, cred, hostname, ip, ca=False):
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
        ca_trust_deployed=ca,
    )
    db.add(s)
    db.flush()
    return s


# -- PRA-128 CA rotation ----------------------------------------------------


def test_rotate_ca_clears_flags_records_history(
    db, seed_distro, seed_default_group, seed_cred, admin_user, monkeypatch
):
    s = _mk_system(
        db, seed_distro, seed_default_group, seed_cred, "h1", "10.20.0.1", ca=True
    )
    db.commit()

    vs_mock = MagicMock()
    vs_mock.rotate_ssh_ca.return_value = "ssh-rsa NEWKEY test@praxis"
    monkeypatch.setattr(ca_rotation_service, "_drop_ssh_pool", lambda: None)

    result = ca_rotation_service.rotate_ca(
        db, performed_by=admin_user.id, vault_service=vs_mock
    )
    assert result["event_type"] == "rotate"
    assert result["systems_flagged_for_redeploy"] == 1
    assert result["ca_public_key"] == "ssh-rsa NEWKEY test@praxis"

    db.refresh(s)
    assert s.ca_trust_deployed is False

    history = db.query(CARotation).order_by(CARotation.id.desc()).first()
    assert history.event_type == "rotate"
    assert history.ca_identifier == result["ca_identifier"]

    settings = db.query(SSHIdentitySettings).first()
    assert settings.ca_identifier == result["ca_identifier"]


def test_revoke_user_certs_bumps_identifier_without_regen(db, admin_user, monkeypatch):
    monkeypatch.setattr(ca_rotation_service, "_drop_ssh_pool", lambda: None)
    result = ca_rotation_service.revoke_user_certs(db, performed_by=admin_user.id)
    assert result["event_type"] == "revoke"
    row = db.query(CARotation).filter_by(event_type="revoke").first()
    assert row.ca_identifier == result["ca_identifier"]
    assert row.ca_public_key is None


# -- PRA-129 approval voting -----------------------------------------------


def _mk_approval(db, user_id, system_id, required=1, expires_in=3600):
    a = CommandApproval(
        command="whoami",
        system_id=system_id,
        requested_by=user_id,
        status="pending",
        required_approvals=required,
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
    )
    db.add(a)
    db.flush()
    return a


def test_single_vote_approves_when_required_equals_one(
    db, seed_distro, seed_default_group, seed_cred, admin_user, monkeypatch
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "va", "10.21.0.1")
    approval = _mk_approval(db, admin_user.id, s.id, required=1)
    db.commit()
    # don't actually run the command
    monkeypatch.setattr(
        command_approval_service, "_execute_in_background", lambda _id: None
    )
    result = command_approval_service.record_vote(
        db, approval.id, admin_user.id, "approve", "ok"
    )
    assert result["status"] == "approved"
    db.refresh(approval)
    assert approval.status == "approved"


def test_multi_level_requires_N_distinct_approves(
    db,
    seed_distro,
    seed_default_group,
    seed_cred,
    admin_user,
    maintainer_user,
    monkeypatch,
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "vm", "10.22.0.1")
    approval = _mk_approval(db, admin_user.id, s.id, required=2)
    db.commit()
    monkeypatch.setattr(
        command_approval_service, "_execute_in_background", lambda _id: None
    )
    # first approve -> still pending
    r1 = command_approval_service.record_vote(db, approval.id, admin_user.id, "approve")
    assert r1["status"] == "pending" and r1["approves"] == 1
    # same user again -> error
    with pytest.raises(command_approval_service.ApprovalVoteError):
        command_approval_service.record_vote(db, approval.id, admin_user.id, "approve")
    # second distinct approver -> approved
    r2 = command_approval_service.record_vote(
        db, approval.id, maintainer_user.id, "approve"
    )
    assert r2["status"] == "approved"


def test_reject_short_circuits(
    db, seed_distro, seed_default_group, seed_cred, admin_user
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "vr", "10.23.0.1")
    approval = _mk_approval(db, admin_user.id, s.id, required=3)
    db.commit()
    result = command_approval_service.record_vote(
        db, approval.id, admin_user.id, "reject", "no"
    )
    assert result["status"] == "rejected"
    db.refresh(approval)
    assert approval.status == "rejected"


def test_expire_stale_marks_pending_past_expiry(
    db, seed_distro, seed_default_group, seed_cred, admin_user
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "ve", "10.24.0.1")
    stale = _mk_approval(db, admin_user.id, s.id, expires_in=-10)
    fresh = _mk_approval(db, admin_user.id, s.id, expires_in=3600)
    db.commit()
    n = command_approval_service.expire_stale(db)
    assert n == 1
    db.refresh(stale)
    db.refresh(fresh)
    assert stale.status == "expired"
    assert fresh.status == "pending"
