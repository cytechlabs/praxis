"""Tests for PRA-142 SFTP file transfer service.

Focuses on the parts we can cover without a live paramiko transport:
    - remote-path validation
    - authorization gate (no grant / forbidden action / TOTP required)
    - audit row open / finalize helpers
"""

from __future__ import annotations

import json

import pytest

from app.db.access_models import FleetRole
from app.db.models import Credential, Group, System
from app.services import access_binding_service as abs_svc
from app.services import file_transfer_service as fts


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
            name="pra142-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra142",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.4.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


# ------------------------------------------------------------- path validator


def test_validate_remote_path_accepts_absolute():
    fts.validate_remote_path("/")
    fts.validate_remote_path("/home/alice/file.txt")
    fts.validate_remote_path("/a" + "b" * 2000)


def test_validate_remote_path_rejects_relative():
    with pytest.raises(fts.FileTransferError):
        fts.validate_remote_path("home/alice")


def test_validate_remote_path_rejects_empty_or_wrong_type():
    with pytest.raises(fts.FileTransferError):
        fts.validate_remote_path("")
    with pytest.raises(fts.FileTransferError):
        fts.validate_remote_path(None)  # type: ignore[arg-type]


def test_validate_remote_path_rejects_control_chars():
    with pytest.raises(fts.FileTransferError):
        fts.validate_remote_path("/tmp/\x00foo")
    with pytest.raises(fts.FileTransferError):
        fts.validate_remote_path("/tmp/bad\nname")
    with pytest.raises(fts.FileTransferError):
        fts.validate_remote_path("/tmp/bad\rname")


def test_validate_remote_path_rejects_overlong():
    with pytest.raises(fts.FileTransferError):
        fts.validate_remote_path("/" + "a" * 5000)


# -------------------------------------------------------------- gate


def test_gate_rejects_missing_system(db, admin_user):
    with pytest.raises(fts.FileTransferError, match="not found"):
        fts._gate(db, admin_user, 9_999_999)


def test_gate_rejects_without_grant(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-nogrant")
    with pytest.raises(fts.FileTransferError, match="forbidden"):
        fts._gate(db, maintainer_user, s.id)


def test_gate_rejects_auditor_role_without_file_transfer_action(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred, seed_roles
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-auditor")
    auditor = db.query(FleetRole).filter(FleetRole.name == "auditor").first()
    abs_svc.create_binding(
        db,
        fleet_role_id=auditor.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=seed_default_group.id,
    )
    # auditor role only allows session_open, not file_transfer
    with pytest.raises(fts.FileTransferError, match="action_not_allowed"):
        fts._gate(db, maintainer_user, s.id)


def test_gate_admin_passes_via_implicit_grant(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-admin")
    abs_svc.recompute_grants(db)
    system, login = fts._gate(db, admin_user, s.id)
    assert system.id == s.id
    assert login == admin_user.username


def test_gate_rejects_totp_required_when_stale(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-totp")
    role = FleetRole(
        name="p142-totp-role",
        login_mode="per_user",
        allowed_actions_json=json.dumps(["session_open", "file_transfer"]),
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
    with pytest.raises(fts.FileTransferError, match="totp_required"):
        fts._gate(db, maintainer_user, s.id)


# ---------------------------------------------------------- audit helpers


def test_open_audit_inserts_in_progress_row(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-audit")
    row = fts._open_audit(
        db,
        user=admin_user,
        system=s,
        login="alice",
        direction="upload",
        remote_path="/tmp/file.bin",
        local_filename="file.bin",
        client_ip="10.0.0.5",
    )
    assert row.id is not None
    assert row.status == "in_progress"
    assert row.direction == "upload"
    assert row.size_bytes == 0
    assert row.ended_at is None


def test_finish_audit_marks_success(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-audit-end")
    row = fts._open_audit(
        db,
        user=admin_user,
        system=s,
        login="alice",
        direction="download",
        remote_path="/etc/hostname",
    )
    fts._finish_audit(db, row, status="success", size_bytes=18, sha256="deadbeef")
    db.refresh(row)
    assert row.status == "success"
    assert row.size_bytes == 18
    assert row.sha256 == "deadbeef"
    assert row.ended_at is not None


def test_finish_audit_marks_error(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-audit-err")
    row = fts._open_audit(
        db,
        user=admin_user,
        system=s,
        login="alice",
        direction="unlink",
        remote_path="/root/secret",
    )
    fts._finish_audit(db, row, status="error", error_message="Permission denied")
    db.refresh(row)
    assert row.status == "error"
    assert row.error_message == "Permission denied"


# ------------------------------------------------------------ listing query


def test_list_audits_filters(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p142-list")
    # Seed a couple audits
    for direction in ("upload", "download", "mkdir"):
        fts._open_audit(
            db,
            user=admin_user,
            system=s,
            login="alice",
            direction=direction,
            remote_path=f"/tmp/{direction}",
        )
    rows = fts.list_audits(db, user_id=admin_user.id, system_id=s.id)
    directions = {r.direction for r in rows}
    assert {"upload", "download", "mkdir"}.issubset(directions)
