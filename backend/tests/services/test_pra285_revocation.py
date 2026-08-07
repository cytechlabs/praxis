"""PRA-285: common access-revocation orchestration.

Proves every revocation trigger flows through the shared path: new auth is denied
synchronously, a persisted RevocationWork item is enqueued (outbox), reachable
sessions close, the guarded drain reconciles hosts / closes DB-only sessions /
retries offline failures, work is idempotent, and — critically — the drain
re-derives desired state so access restored before it runs is NOT torn down.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.auth import get_password_hash
from app.db.access_models import AccessGrant, FleetRole, RevocationWork
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System, User
from app.services import access_authorization_service as authz
from app.services import access_binding_service as abs_svc
from app.services import fleet_reconciliation_service as frs
from app.services import identity_access_service as ias
from app.services import revocation_service as rev
from app.services import session_lock_service

# --------------------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra285-grp").first()
    if not g:
        g = Group(name="pra285-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra285-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


@pytest.fixture(autouse=True)
def _reconcile_ok(monkeypatch):
    """Default: host reconcile succeeds (no real SSH). Tests override for failure."""
    monkeypatch.setattr(
        frs,
        "reconcile_system",
        lambda db, sid: {"provisioned": 0, "removed": 1, "errors": 0, "skipped": 0},
    )
    # No privilege-baseline rows in a fresh test DB, but keep the drain's tail cheap.
    monkeypatch.setattr(
        frs, "reconcile_pending_privilege", lambda db: {"hosts": 0}, raising=True
    )


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.85.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _user(db, seed_roles, username, roles=("maintainer",)):
    u = User(
        username=username,
        email=f"{username}@pra285.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    for rn in roles:
        u.roles.append(seed_roles[rn])
    db.add(u)
    db.flush()
    return u


def _maintainer_fleet(db):
    return db.query(FleetRole).filter_by(name="maintainer").first()


def _bind(db, user, group, expires_at=None):
    return abs_svc.create_binding(
        db,
        fleet_role_id=_maintainer_fleet(db).id,
        subject_user_id=user.id,
        scope_group_id=group.id,
        expires_at=expires_at,
    )


def _session_row(db, user, system, login=None):
    row = SessionRow(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=_maintainer_fleet(db).id,
        login=login or user.username,
        status="active",
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(row)
    db.flush()
    return row


def _work(db):
    return db.query(RevocationWork).filter(RevocationWork.status != "completed").all()


# ----------------------------------------------------- trigger -> common path


def test_binding_delete_denies_sync_and_enqueues_one_item(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p285-del")
    user = _user(db, seed_roles, "p285-del-user")
    binding = _bind(db, user, group)
    assert authz.scoped_system_ids(db, user) == {system.id}

    abs_svc.delete_binding(db, binding.id)

    # New auth denied synchronously.
    assert authz.scoped_system_ids(db, user) == set()
    with pytest.raises(authz.PermissionDenied):
        authz.authorize_action(db, user, system, "session_open")
    # Exactly one outstanding work item for the revoked scope.
    work = _work(db)
    assert len(work) == 1
    w = work[0]
    assert (w.user_id, w.system_id, w.login) == (user.id, system.id, user.username)
    assert w.status == "pending" and w.reason == "binding_delete"


def test_binding_delete_closes_reachable_session_synchronously(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p285-sess")
    user = _user(db, seed_roles, "p285-sess-user")
    binding = _bind(db, user, group)
    sess = _session_row(db, user, system)

    abs_svc.delete_binding(db, binding.id)

    db.refresh(sess)
    assert sess.status == "closed"


def test_jit_revoke_and_expiry_use_common_path(
    db, seed_roles, seed_distro, group, cred
):
    from app.services import access_request_service as ar

    system = _system(db, seed_distro, group, cred, "p285-jit")
    admin = _user(db, seed_roles, "p285-jit-admin", roles=("admin",))
    user = _user(db, seed_roles, "p285-jit-user")
    req = ar.create_request(
        db,
        requested_by=user.id,
        fleet_role_id=_maintainer_fleet(db).id,
        scope_group_id=group.id,
        duration_seconds=3600,
    )
    ar.approve(db, req.id, decider_id=admin.id)
    assert system.id in (authz.scoped_system_ids(db, user) or set())

    ar.revoke(db, req.id, revoker_id=admin.id)
    assert authz.scoped_system_ids(db, user) == set()
    work = [w for w in _work(db) if w.reason == "jit_revoke"]
    assert len(work) == 1


def test_jit_expiry_realized_by_sweep(db, seed_roles, seed_distro, group, cred):
    from app.services import access_request_service as ar

    system = _system(db, seed_distro, group, cred, "p285-exp")
    admin = _user(db, seed_roles, "p285-exp-admin", roles=("admin",))
    user = _user(db, seed_roles, "p285-exp-user")
    req = ar.create_request(
        db,
        requested_by=user.id,
        fleet_role_id=_maintainer_fleet(db).id,
        scope_group_id=group.id,
        duration_seconds=3600,
    )
    ar.approve(db, req.id, decider_id=admin.id)
    grant = (
        db.query(AccessGrant)
        .filter(AccessGrant.user_id == user.id, AccessGrant.system_id == system.id)
        .first()
    )
    assert grant is not None
    # Push the binding's expiry into the past, then run the expiry sweep.
    from app.db.access_models import AccessBinding

    db.query(AccessBinding).filter(AccessBinding.id == req.resulting_binding_id).update(
        {AccessBinding.expires_at: datetime.utcnow() - timedelta(minutes=1)}
    )
    db.commit()

    triggered = rev.sweep_expiry(db)
    assert triggered is True
    # Grant row dropped and reconcile work enqueued via the outbox.
    assert (
        db.query(AccessGrant)
        .filter(AccessGrant.user_id == user.id, AccessGrant.system_id == system.id)
        .first()
        is None
    )
    assert any(w.reason == "jit_expiry" for w in _work(db))
    db.refresh(req)
    assert req.status == "expired"


def test_deactivation_uses_common_path(
    db, seed_roles, seed_distro, group, cred, admin_user
):
    system = _system(db, seed_distro, group, cred, "p285-deact")
    user = _user(db, seed_roles, "p285-deact-user")
    _bind(db, user, group)

    ias.deactivate_user(db, user, actor=admin_user)

    assert authz.scoped_system_ids(db, user) == set()
    # A host-reconcile item (deactivation) AND a session-sweep item (lock) exist.
    reasons = {w.reason for w in _work(db)}
    assert "user_deactivation" in reasons
    assert "session_lock" in reasons


def test_access_review_revoke_uses_common_path(
    db, seed_roles, seed_distro, group, cred, admin_user
):
    from app.services import access_review_service as ars

    system = _system(db, seed_distro, group, cred, "p285-review")
    user = _user(db, seed_roles, "p285-review-user")
    binding = _bind(db, user, group)
    # Minimal access-review with one item for this binding.
    from app.db.access_models import AccessReview, AccessReviewItem

    review = AccessReview(
        scope="all", state="pending", due_at=datetime.utcnow() + timedelta(days=7)
    )
    db.add(review)
    db.flush()
    item = AccessReviewItem(
        review_id=review.id,
        binding_id=binding.id,
        binding_snapshot_json="{}",
        action="pending",
    )
    db.add(item)
    db.flush()

    ars.revoke_item(db, item_id=item.id, reviewer=admin_user)

    assert authz.scoped_system_ids(db, user) == set()
    assert any(w.reason == "access_review_revoke" for w in _work(db))


def test_emergency_lock_enqueues_session_sweep(
    db, seed_roles, seed_distro, group, cred, admin_user
):
    user = _user(db, seed_roles, "p285-lock-user")
    session_lock_service.create_lock(
        db, creator=admin_user, reason="emergency", subject_user_id=user.id
    )
    sweep = [w for w in _work(db) if w.reason == "session_lock"]
    assert len(sweep) == 1 and sweep[0].system_id is None


# --------------------------------------------------------------- drain behavior


def test_drain_completes_on_reconcile_success(db, seed_roles, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "p285-drain-ok")
    user = _user(db, seed_roles, "p285-drain-ok-user")
    sess = _session_row(db, user, system)
    rev.enqueue(
        db,
        reason="binding_delete",
        user_id=user.id,
        system_id=system.id,
        login=user.username,
    )
    db.commit()

    rev.drain(db)

    w = db.query(RevocationWork).first()
    assert w.status == "completed" and w.completed_at is not None
    db.refresh(sess)
    assert sess.status == "closed"  # DB-only close by the drain


def test_drain_marks_error_and_retry_on_unreachable_host(
    db, seed_roles, seed_distro, group, cred, monkeypatch
):
    monkeypatch.setattr(
        frs,
        "reconcile_system",
        lambda db, sid: {"provisioned": 0, "removed": 0, "errors": 1, "skipped": 0},
    )
    system = _system(db, seed_distro, group, cred, "p285-offline")
    user = _user(db, seed_roles, "p285-offline-user")
    rev.enqueue(
        db,
        reason="binding_delete",
        user_id=user.id,
        system_id=system.id,
        login=user.username,
    )
    db.commit()

    rev.drain(db)

    w = db.query(RevocationWork).first()
    # Offline host stays visible: error status, retry metadata, no completion.
    assert w.status == "error"
    assert w.attempt_count == 1
    assert w.next_retry_at is not None
    assert w.last_error and "system" in w.last_error
    assert w.completed_at is None


def test_enqueue_is_idempotent(db, seed_roles, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "p285-idem")
    user = _user(db, seed_roles, "p285-idem-user")
    for _ in range(3):
        rev.enqueue(
            db,
            reason="binding_delete",
            user_id=user.id,
            system_id=system.id,
            login=user.username,
        )
    db.commit()
    assert db.query(RevocationWork).count() == 1


def test_stale_work_does_not_tear_down_restored_access(
    db, seed_roles, seed_distro, group, cred
):
    """The guardrail: remove access + enqueue work, RESTORE access before the drain
    runs, then drain — restored access must remain desired and its session must NOT
    be closed (the drain re-derives; a work item is a signal, not a replay)."""
    system = _system(db, seed_distro, group, cred, "p285-stale")
    user = _user(db, seed_roles, "p285-stale-user")
    binding = _bind(db, user, group)
    sess = _session_row(db, user, system)

    # Remove access (enqueues work + closes the session synchronously).
    abs_svc.delete_binding(db, binding.id)
    db.refresh(sess)
    assert sess.status == "closed"
    assert len(_work(db)) == 1

    # Restore access with a fresh valid grant BEFORE the drain runs.
    _bind(db, user, group)
    assert authz.scoped_system_ids(db, user) == {system.id}
    # Simulate a new live session under the restored grant.
    sess2 = _session_row(db, user, system)

    rev.drain(db)

    # Restored access is still desired, and its live session is untouched.
    assert user.username in authz.resolve_desired_login_roles(db, system.id)
    db.refresh(sess2)
    assert sess2.status == "active", "restored-access session must not be torn down"


def test_revocation_status_reports_counts_and_hosts(
    db, seed_roles, seed_distro, group, cred, monkeypatch
):
    monkeypatch.setattr(
        frs,
        "reconcile_system",
        lambda db, sid: {"provisioned": 0, "removed": 0, "errors": 1, "skipped": 0},
    )
    system = _system(db, seed_distro, group, cred, "p285-status")
    user = _user(db, seed_roles, "p285-status-user")
    rev.enqueue(
        db,
        reason="binding_delete",
        user_id=user.id,
        system_id=system.id,
        login=user.username,
    )
    db.commit()
    rev.drain(db)

    status = rev.revocation_status(db)
    assert status["counts"]["error"] == 1
    assert system.id in status["pending_systems"]
    assert status["outstanding"][0]["system_id"] == system.id
    assert status["outstanding"][0]["last_error"]


def test_cert_principal_removed_for_revoked_user(
    db, seed_roles, seed_distro, group, cred
):
    """1.0 cert-residual enforcement: after revocation the host desired principals
    for the login no longer include the revoked user, so sshd's
    AuthorizedPrincipalsCommand rejects their cert on that host once reconcile
    lands (verified at the desired-state layer that reconcile writes)."""
    from app.services import host_user_provisioning_service as prov

    system = _system(db, seed_distro, group, cred, "p285-princ")
    user = _user(db, seed_roles, "p285-princ-user")
    binding = _bind(db, user, group)
    # PRA-288: the desired principal is the immutable Praxis user principal, not the
    # username.
    from app.services.access_authorization_service import cert_principal_for_user

    assert cert_principal_for_user(user) in prov._principals_for(
        db, system.id, user.username
    )

    abs_svc.delete_binding(db, binding.id)

    # Desired principals no longer authorize the revoked cert principal.
    assert prov._principals_for(db, system.id, user.username) == []


# ----------------------------------------------- fix-pass: fail-closed outbox


def test_recompute_failure_leaves_no_narrowed_source_or_stale_grants(
    db, seed_roles, seed_distro, group, cred, monkeypatch
):
    """Blocking fix 1: a narrowing mutation must NOT pre-commit source state. If the
    outbox enqueue (inside recompute) fails, the whole transaction rolls back — the
    binding stays enabled, its grant survives, and no orphan work exists."""
    system = _system(db, seed_distro, group, cred, "p285-failclosed")
    user = _user(db, seed_roles, "p285-fc-user")
    binding = _bind(db, user, group)
    assert authz.scoped_system_ids(db, user) == {system.id}

    def _boom(*a, **k):
        raise RuntimeError("outbox enqueue failed")

    monkeypatch.setattr(rev, "enqueue_grant_removals", _boom)

    # update_binding(disable) narrows access -> recompute -> enqueue raises.
    with pytest.raises(RuntimeError):
        abs_svc.update_binding(db, binding.id, enabled=False)

    db.refresh(binding)
    assert binding.enabled is True, "source state must not be pre-committed"
    assert authz.scoped_system_ids(db, user) == {system.id}, "grant must survive"
    assert db.query(RevocationWork).count() == 0, "no orphan outbox work"


def test_delete_binding_failure_does_not_orphan_delete(
    db, seed_roles, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "p285-del-fc")
    user = _user(db, seed_roles, "p285-del-fc-user")
    binding = _bind(db, user, group)

    def _boom(*a, **k):
        raise RuntimeError("outbox enqueue failed")

    monkeypatch.setattr(rev, "enqueue_grant_removals", _boom)

    with pytest.raises(RuntimeError):
        abs_svc.delete_binding(db, binding.id)

    from app.db.access_models import AccessBinding

    still = db.query(AccessBinding).filter(AccessBinding.id == binding.id).first()
    assert still is not None and still.enabled is True, "binding not hard-deleted"
    assert authz.scoped_system_ids(db, user) == {system.id}
    assert db.query(RevocationWork).count() == 0


# ------------------------------------------ fix-pass: per-(user,system,login)


def _role_account_fleet(db, name, account):
    import json

    r = FleetRole(
        name=name,
        login_mode="role_account",
        role_account_name=account,
        allowed_actions_json=json.dumps(["session_open"]),
        os_groups_json="[]",
    )
    db.add(r)
    db.flush()
    return r


def test_drain_closes_only_revoked_login_on_shared_system(
    db, seed_roles, seed_distro, group, cred
):
    """Blocking fix 2: losing login=A must not close a still-valid login=B session on
    the same system."""
    system = _system(db, seed_distro, group, cred, "p285-twologin")
    user = _user(db, seed_roles, "p285-twologin-user")
    # login A: per-user (login == username) via the maintainer binding.
    _bind(db, user, group)
    # login B: a role-account fleet role (login == "svcacct").
    ra = _role_account_fleet(db, "p285-svc", "svcacct")
    abs_svc.create_binding(
        db, fleet_role_id=ra.id, subject_user_id=user.id, scope_group_id=group.id
    )
    sess_user = _session_row(db, user, system, login=user.username)
    sess_svc = _session_row(db, user, system, login="svcacct")

    # Revoke ONLY the role-account binding -> login "svcacct" loses access; the
    # per-user login is untouched.
    ra_binding = (
        db.query(
            __import__("app.db.access_models", fromlist=["AccessBinding"]).AccessBinding
        )
        .filter_by(fleet_role_id=ra.id)
        .first()
    )
    abs_svc.delete_binding(db, ra_binding.id)
    # per-user session was already closed synchronously? No — only svcacct scope was
    # removed, so the per-user session stays open. Reopen if the sync close touched it.
    db.refresh(sess_user)
    db.refresh(sess_svc)

    rev.drain(db)

    db.refresh(sess_user)
    db.refresh(sess_svc)
    assert sess_svc.status == "closed", "revoked-login session must close"
    assert sess_user.status == "active", "still-valid login session must survive"


# --------------------------------------------- fix-pass: role-subject lock sweep


def test_role_lock_sweeps_db_only_sessions_via_drain(
    db, seed_roles, seed_distro, group, cred, admin_user
):
    """Blocking fix 3: a role-subject lock enqueues a user-scoped sweep for each role
    member, so the guarded drain closes their DB-only/cross-worker sessions."""
    system = _system(db, seed_distro, group, cred, "p285-rolelock")
    role = seed_roles["viewer"]
    u1 = _user(db, seed_roles, "p285-rl-u1", roles=("viewer",))
    u2 = _user(db, seed_roles, "p285-rl-u2", roles=("viewer",))

    session_lock_service.create_lock(
        db, creator=admin_user, reason="emergency", subject_app_role_id=role.id
    )
    sweeps = [w for w in _work(db) if w.reason == "session_lock"]
    assert {w.user_id for w in sweeps} == {u1.id, u2.id}

    # A DB-only session appears for each member (e.g. opened in another worker).
    s1 = _session_row(db, u1, system)
    s2 = _session_row(db, u2, system)

    rev.drain(db)

    db.refresh(s1)
    db.refresh(s2)
    assert s1.status == "closed" and s2.status == "closed"
