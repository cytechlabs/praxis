"""PRA-144: end-to-end provisioning smoke test.

Full round-trip against a disposable Ubuntu 22.04 container:

1. Enroll the target (CA trust + principals hook via PRA-138).
2. Create an AccessBinding for user ``alice`` (admin fleet role, per_user).
3. Reconcile — assert the account + principals file exist and that NO sudoers
   drop-in is written (PRA-282: no standing user sudo in 1.0)
   and that a Vault-signed cert for ``alice`` can log in via cert auth.
4. Delete the binding, reconcile again — assert the home-dir archive exists,
   the account and config files are gone, and HostUserState is ``removed``.

Gated on ``PRAXIS_E2E=1`` + a mounted docker socket + reachable Vault
(see ``integration/conftest.py``).
"""

from __future__ import annotations

import os
import uuid

import paramiko
import pytest


def _e2e_skip_reason() -> str:
    if os.environ.get("PRAXIS_E2E", "").lower() not in ("1", "true", "yes"):
        return "PRAXIS_E2E not set"
    if not os.path.exists("/var/run/docker.sock"):
        return "/var/run/docker.sock not mounted"
    if not os.environ.get("VAULT_ADDR"):
        return "VAULT_ADDR not set"
    return ""


_skip = _e2e_skip_reason()
pytestmark = pytest.mark.skipif(bool(_skip), reason=f"e2e skipped: {_skip}")

from app.core.auth import get_password_hash  # noqa: E402
from app.db.access_models import AccessBinding, AccessGrant, FleetRole, HostUserState
from app.db.models import Credential, Distro, Group, Role, System, User
from app.db.session import SessionLocal
from app.services.access_authorization_service import cert_principal_for_user
from app.services.access_binding_service import (
    create_binding,
    delete_binding,
    recompute_grants,
)
from app.services.fleet_reconciliation_service import reconcile_system
from app.services.ssh_identity_service import SSHIdentityService
from app.services.vault_service import VaultService

from ._harness import ensure_vault_config
from ._harness import mint_user_cert as _mint_user_cert
from ._harness import retire_target_system


def _seed_fixtures(db, ssh_target) -> dict:
    """Create user, credential (with vault-stored password), and System row."""
    # Rerun-safety: retire any leftover System for this hostname (unique constraint)
    # from a previously aborted run before recreating it.
    retire_target_system(db, ssh_target["hostname"])
    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if not distro:
        from datetime import date

        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()

    group = db.query(Group).filter_by(name="e2e-targets").first()
    if not group:
        group = Group(name="e2e-targets")
        db.add(group)
        db.flush()

    admin_role = db.query(Role).filter_by(name="admin").first()
    if not admin_role:
        admin_role = Role(name="admin", description="admin")
        db.add(admin_role)
        db.flush()

    # Regular user "alice" — gets the binding, NOT an app-admin (so implicit
    # admin rule doesn't short-circuit the binding under test).
    alice = db.query(User).filter_by(username="alice").first()
    if not alice:
        alice = User(
            username="alice",
            email="alice@e2e.example.com",
            hashed_password=get_password_hash("unused-in-e2e"),
            is_active=True,
        )
        db.add(alice)
        db.flush()

    # Rerun-safety: clear any stale bindings/grants for the reused test user so the
    # single-grant assertion holds on a rerun.
    db.query(AccessBinding).filter(AccessBinding.subject_user_id == alice.id).delete(
        synchronize_session=False
    )
    db.query(AccessGrant).filter(AccessGrant.user_id == alice.id).delete(
        synchronize_session=False
    )
    db.flush()

    # A fresh test DB has no active Vault config; seed one so VaultService can auth.
    ensure_vault_config(db)
    # VaultService requires the production ``praxis/`` KV prefix (do not loosen it).
    vault_path = f"praxis/ssh/e2e-{uuid.uuid4().hex[:8]}"
    VaultService(db).write_secret(vault_path, {"password": ssh_target["password"]})

    cred = Credential(
        name=f"e2e-cred-{uuid.uuid4().hex[:6]}",
        auth_method="password",
        username="root",
        vault_path=vault_path,
    )
    db.add(cred)
    db.flush()

    system = System(
        hostname=ssh_target["hostname"],
        ip_address=ssh_target["ip"],
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.commit()
    db.refresh(system)
    return {"system": system, "alice": alice, "cred": cred, "vault_path": vault_path}


@pytest.fixture(scope="module")
def session():
    """Module-scoped real DB session. Caller is responsible for its own cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def fixtures(session, ssh_target):
    created = _seed_fixtures(session, ssh_target)
    try:
        yield created
    finally:
        # Best-effort cleanup — never crash on a teardown FK/error.
        try:
            system = created["system"]
            sys_id = system.id
            alice_id = created["alice"].id
            session.query(AccessGrant).filter(
                (AccessGrant.system_id == sys_id) | (AccessGrant.user_id == alice_id)
            ).delete(synchronize_session=False)
            session.query(HostUserState).filter(
                HostUserState.system_id == sys_id
            ).delete(synchronize_session=False)
            session.query(AccessBinding).filter(
                AccessBinding.subject_user_id == alice_id
            ).delete(synchronize_session=False)
            # Retire (rename), never delete, the System — audit tables FK-reference it
            # without ON DELETE CASCADE.
            system.hostname = f"{system.hostname}-retired-{uuid.uuid4().hex[:8]}"
            system.status = "Retired"
            session.commit()
        except Exception:  # pylint: disable=broad-except
            session.rollback()


def test_end_to_end_provisioning(session, ssh_target, fixtures):
    db = session
    system = fixtures["system"]
    alice = fixtures["alice"]
    target = ssh_target

    # ------------------------------------------------------------- 1. Enroll
    SSHIdentityService(db).enroll_access_broker(system.id)
    db.refresh(system)
    assert system.ca_trust_deployed is True
    assert system.principals_hook_deployed is True

    # ------------------------------------------------------- 2. Bind + grant
    admin_fleet_role = (
        db.query(FleetRole).filter_by(name="admin", is_builtin=True).first()
    )
    assert admin_fleet_role is not None, "admin fleet role seed missing"

    binding = create_binding(
        db,
        fleet_role_id=admin_fleet_role.id,
        subject_user_id=alice.id,
        scope_group_id=system.group_id,
    )
    recompute_grants(db)

    grants = (
        db.query(AccessGrant)
        .filter_by(user_id=alice.id, system_id=system.id, login="alice")
        .all()
    )
    assert len(grants) == 1, f"expected 1 grant, got {grants!r}"

    # ---------------------------------------------------------- 3. Reconcile
    counts = reconcile_system(db, system.id)
    assert counts["errors"] == 0, f"reconcile reported errors: {counts}"
    assert counts["provisioned"] >= 1

    state = (
        db.query(HostUserState).filter_by(system_id=system.id, login="alice").first()
    )
    assert state is not None and state.state == "provisioned", state

    container = target["container"]

    def _in_target(cmd: str) -> tuple[int, str]:
        code, out = container.exec_run(["bash", "-lc", cmd])
        return code, out.decode("utf-8", errors="replace")

    code, _ = _in_target("id alice")
    assert code == 0, "alice account should exist"

    code, out = _in_target("getent passwd alice | awk -F: '{print $7}'")
    assert code == 0 and out.strip() == "/bin/bash", out

    code, _ = _in_target("test -d /home/alice")
    assert code == 0

    # PRA-282: user-facing managed accounts get NO standing sudoers drop-in in
    # Praxis 1.0. Provisioning must not have written one.
    code, _ = _in_target("test -e /etc/sudoers.d/praxis-alice")
    assert code != 0, "no sudoers drop-in should be written for a 1.0 fleet role"

    # PRA-288: the principals file authorizes the IMMUTABLE cert principal
    # (praxis-user-<id>), NEVER the mutable Linux username.
    principal = cert_principal_for_user(alice)
    code, out = _in_target("cat /etc/praxis/principals.d/alice")
    assert (
        code == 0 and principal in out
    ), f"principals file missing immutable principal {principal!r}: {out!r}"
    assert alice.username not in out, "principals file must not carry the username"

    # ------------------- 4. Cert-auth SSH login as alice (immutable principal)
    # The certificate principal is praxis-user-<id>; the SSH username is the Linux
    # login (alice). A cert signed for the old mutable username must NOT authenticate.
    stale = paramiko.RSAKey.generate(2048)
    _mint_user_cert(db, stale, principal=alice.username, ttl=300)
    stale_client = paramiko.SSHClient()
    stale_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with pytest.raises(paramiko.AuthenticationException):
        stale_client.connect(
            hostname=target["ip"],
            port=target["port"],
            username="alice",
            pkey=stale,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
        )
    stale_client.close()

    pkey = paramiko.RSAKey.generate(2048)
    _mint_user_cert(db, pkey, principal=principal, ttl=300)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=target["ip"],
        port=target["port"],
        username="alice",
        pkey=pkey,
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
    )
    try:
        _, stdout, _ = client.exec_command("whoami")
        assert stdout.read().decode().strip() == "alice"
        # PRA-282: no standing user sudo. Passwordless sudo must NOT work for a
        # 1.0 fleet-role account (the account has no password either, so an
        # interactive sudo prompt is unusable — root is out-of-band).
        _, stdout, _ = client.exec_command("sudo -n whoami")
        assert (
            stdout.read().decode().strip() != "root"
        ), "no NOPASSWD sudo should exist for a 1.0 fleet-role account"
    finally:
        client.close()

    # ------------------------------------------ 5. Delete binding + reconcile
    assert delete_binding(db, binding.id) is True
    recompute_grants(db)
    assert (
        db.query(AccessGrant).filter_by(user_id=alice.id, system_id=system.id).count()
        == 0
    )

    counts = reconcile_system(db, system.id)
    assert counts["errors"] == 0, counts
    assert counts["removed"] >= 1

    # --------------------------------------------------- 6. Assert teardown
    code, _ = _in_target("id alice")
    assert code != 0, "alice account should be gone after reconcile"

    code, _ = _in_target("test -f /etc/sudoers.d/praxis-alice")
    assert code != 0, "sudoers drop-in should be gone"

    code, _ = _in_target("test -f /etc/praxis/principals.d/alice")
    assert code != 0, "principals file should be gone"

    code, out = _in_target("ls /var/backups/praxis/homedirs/ 2>/dev/null")
    assert code == 0 and "alice-" in out, f"no archive found: {out!r}"
    archive = [ln for ln in out.split() if ln.startswith("alice-")][0]
    code, out = _in_target(f"tar tzf /var/backups/praxis/homedirs/{archive}")
    assert code == 0, f"archive not readable: {out}"

    db.refresh(state)
    assert state.state == "removed"
    assert state.home_archive_path and state.home_archive_path.startswith(
        "/var/backups/praxis/homedirs/alice-"
    )
