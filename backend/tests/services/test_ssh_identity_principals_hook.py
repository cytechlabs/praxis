"""Tests for PRA-138 principals hook additions to ssh_identity_service.

Covers the deterministic parts:
    - Wrapper script content shape
    - sshd directives string format
    - ``deploy_principals_hook`` refuses to run without CA trust deployed
    - ``enroll_access_broker`` fails cleanly on a missing system

Full SSH-side behaviour (install + self-test + rollback) is covered by the
integration test in PRA-144 once a disposable Linux container is wired up.
"""

from __future__ import annotations

import pytest

from app.db.models import Credential, System
from app.services.ssh_identity_service import (
    PRINCIPALS_DIR,
    PRINCIPALS_SCRIPT_BODY,
    PRINCIPALS_SCRIPT_PATH,
    SSHD_PRINCIPALS_DIRECTIVES,
    SSHD_PRINCIPALS_MARKER,
    SSHIdentityError,
    SSHIdentityService,
)

# ------------------------------------------------------------- constants


def test_principals_script_is_posix_sh_not_bash():
    """Wrapper must use /bin/sh so it works on BusyBox / Alpine / minimal images."""
    assert PRINCIPALS_SCRIPT_BODY.startswith("#!/bin/sh")


def test_principals_script_reads_expected_path():
    assert "/etc/praxis/principals.d/$login" in PRINCIPALS_SCRIPT_BODY


def test_principals_script_never_fails_on_missing_file():
    """Non-existent file must emit nothing AND exit 0, not fail the SSH login."""
    # Script checks `-r` before cat, so a missing file is a no-op
    assert 'if [ -r "$file" ]' in PRINCIPALS_SCRIPT_BODY
    # We deliberately do NOT exit non-zero on missing file; sshd treats non-zero
    # as deny which would break legitimate logins for any login not managed by
    # Praxis (e.g. the bootstrap user pre-enrollment).
    assert "exit 1" not in PRINCIPALS_SCRIPT_BODY


def test_sshd_directives_include_command_and_user():
    assert "AuthorizedPrincipalsCommand" in SSHD_PRINCIPALS_DIRECTIVES
    assert "AuthorizedPrincipalsCommandUser nobody" in SSHD_PRINCIPALS_DIRECTIVES
    assert PRINCIPALS_SCRIPT_PATH in SSHD_PRINCIPALS_DIRECTIVES
    # %u placeholder is what sshd substitutes for the requested local login
    assert "%u" in SSHD_PRINCIPALS_DIRECTIVES


def test_principals_marker_unique_vs_pra44():
    """Marker must not clash with the PRA-44 CA trust marker so revoke sed
    commands don't accidentally strip each other's directives."""
    from app.services.ssh_identity_service import SSHD_CONFIG_MARKER

    assert SSHD_PRINCIPALS_MARKER != SSHD_CONFIG_MARKER
    assert "PRA-138" in SSHD_PRINCIPALS_MARKER


def test_principals_directory_is_etc_praxis():
    assert PRINCIPALS_DIR == "/etc/praxis/principals.d"


# --------------------------------------------------------------- guards


def _mk_system(db, seed_distro, hostname, ca_deployed=False):
    """Minimal system with an empty bootstrap credential for guard tests."""
    cred = db.query(Credential).first()
    if cred is None:
        cred = Credential(
            name="pra138-cred",
            auth_method="password",
            username="ubuntu",
            vault_path="vault/pra138",
        )
        db.add(cred)
        db.flush()
    grp = None
    from app.db.models import Group

    grp = db.query(Group).filter_by(name="Default").first()
    if grp is None:
        grp = Group(name="Default")
        db.add(grp)
        db.flush()
    s = System(
        hostname=hostname,
        ip_address="10.8.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
        ca_trust_deployed=ca_deployed,
    )
    db.add(s)
    db.flush()
    return s


def test_deploy_principals_hook_requires_ca_trust(db, seed_distro):
    s = _mk_system(db, seed_distro, "pra138-noca", ca_deployed=False)
    svc = SSHIdentityService(db)
    with pytest.raises(SSHIdentityError, match="CA trust not deployed"):
        svc.deploy_principals_hook(s.id)


def test_deploy_principals_hook_rejects_missing_system(db):
    svc = SSHIdentityService(db)
    with pytest.raises(SSHIdentityError, match="not found"):
        svc.deploy_principals_hook(999999)


def test_enroll_access_broker_rejects_missing_system(db):
    svc = SSHIdentityService(db)
    with pytest.raises(SSHIdentityError, match="not found"):
        svc.enroll_access_broker(999999)


def test_self_test_rejects_missing_system(db):
    svc = SSHIdentityService(db)
    with pytest.raises(SSHIdentityError, match="not found"):
        svc.self_test_cert_auth(999999)
