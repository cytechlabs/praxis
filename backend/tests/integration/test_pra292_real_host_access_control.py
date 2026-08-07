"""PRA-292: real-host access-control regression suite (critical CI-safe subset).

Proves the locked 1.0 access-control contract against a DISPOSABLE Ubuntu target
with real ``sshd``, ``sudo``, users, groups, ``/etc/praxis/principals.d`` files, and
OpenSSH certificate authentication — not mocks. Slice 1 covers the highest-risk
paths; the slower/extended matrix is documented in
``docs/dev-notes/real-host-access-control-matrix.md``.

Gated on ``PRAXIS_E2E=1`` + a mounted docker socket + reachable Vault (see
``integration/conftest.py``). In normal CI (no ``PRAXIS_E2E``) the whole module is
COLLECTED and SKIPPED with an explicit reason; the release checklist requires one
successful real-host run before shipping.

Every test asserts the post-PRA-288 identity model: the SSH connection uses the
Linux login as the username while the certificate principal is the immutable
``cert_principal_for_user(user)`` (``praxis-user-<id>``).
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import date, datetime, timedelta

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
from app.db.access_models import (  # noqa: E402
    AccessBinding,
    AccessGrant,
    FleetRole,
    HostUserState,
)
from app.db.models import Credential, Distro, Group, System, User  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.services.access_authorization_service import (  # noqa: E402
    PermissionDenied,
    authorize_action,
    cert_principal_for_user,
)
from app.services.access_binding_service import (  # noqa: E402
    create_binding,
    delete_binding,
    recompute_grants,
)
from app.services.fleet_reconciliation_service import reconcile_system  # noqa: E402
from app.services.ssh_identity_service import SSHIdentityService  # noqa: E402
from app.services.vault_service import VaultService  # noqa: E402

from ._harness import (  # noqa: E402
    cert_key_for,
    cert_login,
    ensure_vault_config,
    retire_target_system,
    run_in_target,
)

# --------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _purge_p292(db):
    """Remove leftover p292-* users/roles/bindings/grants from a prior aborted run
    (system-independent), so setup does not collide on unique usernames/role names.
    Best-effort — a failure here must not abort setup/teardown."""
    try:
        user_ids = [
            u.id for u in db.query(User).filter(User.username.like("p292-%")).all()
        ]
        if user_ids:
            db.query(AccessGrant).filter(AccessGrant.user_id.in_(user_ids)).delete(
                synchronize_session=False
            )
            db.query(AccessBinding).filter(
                AccessBinding.subject_user_id.in_(user_ids)
            ).delete(synchronize_session=False)
            db.query(User).filter(User.id.in_(user_ids)).delete(
                synchronize_session=False
            )
        db.query(FleetRole).filter(FleetRole.name.like("p292-%")).delete(
            synchronize_session=False
        )
        db.commit()
    except Exception:  # pylint: disable=broad-except
        db.rollback()


@pytest.fixture(scope="module")
def env(db_session, ssh_target):
    """One enrolled target + system for the module; per-test logins are distinct."""
    db = db_session
    # Rerun-safety: retire any leftover target System + clear stale p292 rows.
    retire_target_system(db, ssh_target["hostname"])
    _purge_p292(db)
    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if not distro:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()

    group = db.query(Group).filter_by(name="p292-targets").first()
    if not group:
        group = Group(name="p292-targets")
        db.add(group)
        db.flush()

    # A fresh test DB has no active Vault config; seed one so VaultService can auth.
    ensure_vault_config(db)
    # VaultService requires the production ``praxis/`` KV prefix (do not loosen it).
    vault_path = f"praxis/ssh/p292-{uuid.uuid4().hex[:8]}"
    VaultService(db).write_secret(vault_path, {"password": ssh_target["password"]})
    cred = Credential(
        name=f"p292-cred-{uuid.uuid4().hex[:6]}",
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

    # Enroll CA trust + principals hook so sshd honours cert principals.
    SSHIdentityService(db).enroll_access_broker(system.id)

    try:
        yield {
            "db": db,
            "system": system,
            "container": ssh_target["container"],
            "target": ssh_target,
        }
    finally:
        # Best-effort cleanup — never crash the module on a teardown FK/error.
        try:
            sys_id = system.id
            db.query(AccessGrant).filter(AccessGrant.system_id == sys_id).delete(
                synchronize_session=False
            )
            db.query(HostUserState).filter(HostUserState.system_id == sys_id).delete(
                synchronize_session=False
            )
            _purge_p292(db)
            # Retire (rename), never delete, the System — audit tables FK-reference it
            # without ON DELETE CASCADE, so a hard delete would fail.
            system.hostname = f"{system.hostname}-retired-{uuid.uuid4().hex[:8]}"
            system.status = "Retired"
            db.commit()
        except Exception:  # pylint: disable=broad-except
            db.rollback()


# Per-run token: users/roles carry a unique suffix so a rerun never collides on the
# unique username/email/role-name constraints. We cannot reliably DELETE these rows
# between runs — audit tables (ssh_security_logs, audit_events, …) FK-reference
# users/systems without ON DELETE CASCADE — so unique-per-run names, not cleanup, are
# what makes the suite rerun-safe. (Tests reference user.username / role.name
# dynamically, so the suffix is transparent; role_account_name stays fixed — it is
# the Linux login on the always-fresh target container.)
_RUN = uuid.uuid4().hex[:8]


def _mk_user(db, username):
    u = User(
        username=f"{username}-{_RUN}",
        email=f"{username}-{_RUN}@e2e.example.com",
        hashed_password=get_password_hash("unused-in-e2e"),
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _mk_role(
    db,
    name,
    *,
    login_mode="per_user",
    role_account_name=None,
    actions=("session_open", "command_exec", "file_transfer"),
    os_groups=(),
):
    r = FleetRole(
        name=f"{name}-{_RUN}",
        login_mode=login_mode,
        role_account_name=role_account_name,
        allowed_actions_json=json.dumps(list(actions)),
        os_groups_json=json.dumps(list(os_groups)),
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _bind(db, role, user, group_id, *, expires_at=None):
    b = create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=user.id,
        scope_group_id=group_id,
        expires_at=expires_at,
    )
    recompute_grants(db)
    return b


def _auth_fails(target, username, pkey):
    """Assert cert auth is rejected by real sshd (principal not authorized)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        with pytest.raises(paramiko.AuthenticationException):
            client.connect(
                hostname=target["ip"],
                port=target["port"],
                username=username,
                pkey=pkey,
                allow_agent=False,
                look_for_keys=False,
                timeout=10,
            )
    finally:
        client.close()


def _no_root_sudo(client):
    _, stdout, _ = client.exec_command("sudo -n whoami")
    assert (
        stdout.read().decode().strip() != "root"
    ), "managed account must not NOPASSWD-sudo to root"


# ---------------------------------------------------------- per-user cert login


def test_per_user_cert_login_uses_immutable_principal(env):
    db, system, container, target = (
        env["db"],
        env["system"],
        env["container"],
        env["target"],
    )
    alice = _mk_user(db, "p292-alice")
    role = _mk_role(db, "p292-per-user")
    _bind(db, role, alice, system.group_id)

    counts = reconcile_system(db, system.id)
    assert counts["errors"] == 0 and counts["provisioned"] >= 1, counts

    principal = cert_principal_for_user(alice)
    code, out = run_in_target(
        container, f"cat /etc/praxis/principals.d/{alice.username}"
    )
    assert code == 0 and principal in out, f"principals missing {principal!r}: {out!r}"
    assert (
        alice.username not in out
    ), "principals file must not carry the mutable username"

    # No sudoers drop-in for a 1.0 managed user account.
    code, _ = run_in_target(
        container, f"test -e /etc/sudoers.d/praxis-{alice.username}"
    )
    assert code != 0, "no sudoers drop-in for a 1.0 fleet-role account"

    # Cert for the immutable principal logs in as the Linux login; no root sudo.
    key = cert_key_for(db, principal)
    client = cert_login(target["ip"], target["port"], alice.username, key)
    try:
        _, stdout, _ = client.exec_command("whoami")
        assert stdout.read().decode().strip() == alice.username
        _no_root_sudo(client)
    finally:
        client.close()

    # A cert for the OLD mutable username must NOT authenticate.
    _auth_fails(target, alice.username, cert_key_for(db, alice.username))


# ------------------------------------------------------ shared role-account login


def test_shared_role_account_login_per_user_principals(env):
    db, system, container, target = (
        env["db"],
        env["system"],
        env["container"],
        env["target"],
    )
    bob = _mk_user(db, "p292-bob")
    carol = _mk_user(db, "p292-carol")
    login = "p292svc"
    role = _mk_role(db, "p292-svc", login_mode="role_account", role_account_name=login)
    _bind(db, role, bob, system.group_id)
    _bind(db, role, carol, system.group_id)

    counts = reconcile_system(db, system.id)
    assert counts["errors"] == 0, counts

    # The shared login's principals file lists BOTH users' immutable principals.
    code, out = run_in_target(container, f"cat /etc/praxis/principals.d/{login}")
    assert code == 0
    for u in (bob, carol):
        assert (
            cert_principal_for_user(u) in out
        ), f"missing principal for {u.username}: {out!r}"
    assert login not in out, "the shared Linux login is never itself a principal"

    # Each user's own immutable cert lands as the shared Linux login; no root sudo.
    for u in (bob, carol):
        key = cert_key_for(db, cert_principal_for_user(u))
        client = cert_login(target["ip"], target["port"], login, key)
        try:
            _, stdout, _ = client.exec_command("whoami")
            assert stdout.read().decode().strip() == login
            _no_root_sudo(client)
        finally:
            client.close()

    code, _ = run_in_target(container, f"test -e /etc/sudoers.d/praxis-{login}")
    assert code != 0, "no sudoers drop-in for a shared role account"


# --------------------------------------------------------------------- expiry


def test_grant_expiry_denies_new_auth(env):
    db, system, container, target = (
        env["db"],
        env["system"],
        env["container"],
        env["target"],
    )
    dave = _mk_user(db, "p292-dave")
    role = _mk_role(db, "p292-exp")
    expiry = datetime.utcnow() + timedelta(hours=1)
    b = _bind(db, role, dave, system.group_id, expires_at=expiry)

    reconcile_system(db, system.id)
    principal = cert_principal_for_user(dave)
    # Active now: authz allows and the cert logs in.
    assert (
        authorize_action(db, dave, system, "session_open", login=dave.username).login
        == dave.username
    )
    cert_login(
        target["ip"], target["port"], dave.username, cert_key_for(db, principal)
    ).close()

    # PRA-284: once the materialized grant's expiry passes, authorization denies
    # SYNCHRONOUSLY at the decision — no recompute, no unrelated mutation.
    with pytest.raises(PermissionDenied):
        authorize_action(
            db,
            dave,
            system,
            "session_open",
            login=dave.username,
            now=expiry + timedelta(seconds=1),
        )

    # Expire the binding + recompute: the grant drops and reconcile removes the host
    # principal/account, so even a directly-minted cert is rejected by real sshd.
    b.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    recompute_grants(db)
    assert (
        db.query(AccessGrant).filter_by(user_id=dave.id, system_id=system.id).count()
        == 0
    )
    reconcile_system(db, system.id)
    _auth_fails(target, dave.username, cert_key_for(db, principal))


# ------------------------------------------------------------------ revocation


def test_binding_revocation_prevents_auth_and_reconciles_host(env):
    db, system, container, target = (
        env["db"],
        env["system"],
        env["container"],
        env["target"],
    )
    frank = _mk_user(db, "p292-frank")
    role = _mk_role(db, "p292-rev")
    b = _bind(db, role, frank, system.group_id)
    reconcile_system(db, system.id)

    principal = cert_principal_for_user(frank)
    cert_login(
        target["ip"], target["port"], frank.username, cert_key_for(db, principal)
    ).close()

    # Revoke: delete the binding + recompute -> no grant -> reconcile removes the
    # principal + account (home archived) and marks HostUserState removed.
    assert delete_binding(db, b.id) is True
    recompute_grants(db)
    assert (
        db.query(AccessGrant).filter_by(user_id=frank.id, system_id=system.id).count()
        == 0
    )
    counts = reconcile_system(db, system.id)
    assert counts["removed"] >= 1, counts

    code, out = run_in_target(
        container, f"cat /etc/praxis/principals.d/{frank.username} 2>/dev/null"
    )
    assert (
        principal not in out
    ), "revoked principal must be removed from host desired state"
    state = (
        db.query(HostUserState)
        .filter_by(system_id=system.id, login=frank.username)
        .first()
    )
    assert state is not None and state.state == "removed", state
    _auth_fails(target, frank.username, cert_key_for(db, principal))


# ------------------------------------------------ unmanaged collision fails closed


def test_unmanaged_username_collision_fails_closed(env):
    db, system, container, target = (
        env["db"],
        env["system"],
        env["container"],
        env["target"],
    )
    # The Praxis user's per_user login IS its (run-unique) username; pre-create a
    # LOCAL account with that exact name and NO Praxis ownership marker so reconcile
    # hits a genuine unmanaged collision.
    erin = _mk_user(db, "p292coll")
    login = erin.username
    code, _ = run_in_target(container, f"useradd -m -s /bin/bash {login}")
    assert code == 0, "could not seed the unmanaged collision account"

    role = _mk_role(db, "p292-coll")
    _bind(db, role, erin, system.group_id)

    counts = reconcile_system(db, system.id)
    assert counts["errors"] >= 1, f"unmanaged collision must fail closed: {counts}"

    state = db.query(HostUserState).filter_by(system_id=system.id, login=login).first()
    assert state is not None and state.state == "error", state
    assert "not Praxis-managed" in (state.last_error or ""), state.last_error

    # The unmanaged account is neither adopted (no marker/principals) nor deleted.
    code, _ = run_in_target(container, f"id {login}")
    assert code == 0, "unmanaged account must NOT be deleted"
    code, _ = run_in_target(
        container, f"test -e /etc/praxis/managed-users/{login}.json"
    )
    assert code != 0, "no ownership marker may be written for an unmanaged collision"
    code, _ = run_in_target(container, f"test -e /etc/praxis/principals.d/{login}")
    assert code != 0, "no principals file for an unadopted account"


# --------------------------------------------- shared-login conflict fails closed


def test_shared_login_conflict_skips_convergence(env):
    db, system, container, target = (
        env["db"],
        env["system"],
        env["container"],
        env["target"],
    )
    fran = _mk_user(db, "p292-fran")
    gwen = _mk_user(db, "p292-gwen")
    login = "p292shared"
    # Two role_account roles for the SAME shared login with DIFFERENT os_groups ->
    # PRA-287 account-shape conflict.
    role_a = _mk_role(
        db,
        "p292-conf-a",
        login_mode="role_account",
        role_account_name=login,
        os_groups=["users"],
    )
    role_b = _mk_role(
        db,
        "p292-conf-b",
        login_mode="role_account",
        role_account_name=login,
        os_groups=["staff"],
    )
    _bind(db, role_a, fran, system.group_id)
    _bind(db, role_b, gwen, system.group_id)

    counts = reconcile_system(db, system.id)
    assert counts["conflicts"] >= 1, f"shared-login conflict must be surfaced: {counts}"

    # The ambiguous account is never converged: no host account, no principals file.
    code, _ = run_in_target(container, f"id {login}")
    assert code != 0, "conflicted shared login must not be provisioned"
    code, _ = run_in_target(container, f"test -e /etc/praxis/principals.d/{login}")
    assert code != 0, "no principals file for a conflicted shared login"
