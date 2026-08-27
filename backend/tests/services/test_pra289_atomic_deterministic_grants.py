"""PRA-289: atomic + deterministic access-grant recomputation.

Proves:
- recompute is a single-transaction swap (no transient empty/partial grant table);
- an injected failure mid-rebuild preserves the previous valid grant set;
- concurrent recomputes serialize via a transaction-scoped advisory lock (Postgres);
- recompute is idempotent/deterministic;
- overlap between grants is resolved by an explicit, primary-key-independent policy
  shared by authorization and reconciliation — authorization evaluates every
  applicable grant and preserves the conservative approval/TOTP requirement.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import event
from sqlalchemy.exc import OperationalError

from app.db.access_models import AccessGrant, FleetRole
from app.db.models import Credential, Group, System
from app.services import access_authorization_service as authz
from app.services import access_binding_service as abs_svc
from app.services import fleet_reconciliation_service as frs
from tests.conftest import unique_test_ip

# --------------------------------------------------------------------- helpers


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra289-grp").first()
    if not g:
        g = Group(name="pra289-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra289-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address=unique_test_ip(),
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _role(db, name, actions, *, approval=False, totp=False, login_mode="per_user"):
    r = FleetRole(
        name=name,
        login_mode=login_mode,
        allowed_actions_json=json.dumps(actions),
        session_requires_approval=approval,
        totp_required=totp,
        os_groups_json="[]",
    )
    db.add(r)
    db.flush()
    return r


def _grant_ids(db):
    return {
        (g.user_id, g.system_id, g.fleet_role_id, g.login)
        for g in db.query(AccessGrant).all()
    }


# --------------------------------------------------------------- atomic recompute


def test_recompute_is_single_transaction(
    db, maintainer_user, seed_distro, group, cred, monkeypatch
):
    """A single commit — never a delete-then-commit that exposes an empty table."""
    _system(db, seed_distro, group, cred, "p289-atomic")
    role = _role(db, "p289-atomic-role", ["session_open"])
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=group.id,
    )

    calls = {"commits": 0}
    orig_commit = db.commit

    def _counting_commit():
        calls["commits"] += 1
        return orig_commit()

    monkeypatch.setattr(db, "commit", _counting_commit)
    abs_svc.recompute_grants(db)
    assert calls["commits"] == 1, "recompute must commit exactly once (atomic swap)"


def test_injected_failure_preserves_previous_grants(
    db, maintainer_user, seed_distro, group, cred, monkeypatch
):
    _system(db, seed_distro, group, cred, "p289-fail")
    role = _role(db, "p289-fail-role", ["session_open"])
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=group.id,
    )
    before = _grant_ids(db)
    assert before, "precondition: some grants exist"

    # Fail AFTER the delete, during the rebuild.
    def _boom(*args, **kwargs):
        raise RuntimeError("injected rebuild failure")

    monkeypatch.setattr(abs_svc, "_resolve_scope_systems", _boom)

    with pytest.raises(RuntimeError):
        abs_svc.recompute_grants(db)

    # The transaction rolled back, so the previous valid grant set survives —
    # readers never end up with an empty/stale grant table.
    assert _grant_ids(db) == before


def test_recompute_serializes_with_advisory_lock(
    db, maintainer_user, seed_distro, group, cred
):
    _system(db, seed_distro, group, cred, "p289-lock")
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        pytest.skip("advisory lock is Postgres-only")

    statements = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(bind, "before_cursor_execute", _capture)
    try:
        abs_svc.recompute_grants(db)
    finally:
        event.remove(bind, "before_cursor_execute", _capture)

    assert any(
        "pg_advisory_xact_lock" in s for s in statements
    ), "recompute must take the serialization advisory lock on Postgres"


def test_advisory_lock_failure_aborts_recompute(
    db, maintainer_user, seed_distro, group, cred, monkeypatch
):
    """Fail-closed: if the Postgres advisory lock can't be taken, recompute must
    raise and preserve the previous grants — never continue unlocked."""
    if db.get_bind().dialect.name != "postgresql":
        pytest.skip("advisory lock is Postgres-only")
    _system(db, seed_distro, group, cred, "p289-lockfail")
    role = _role(db, "p289-lockfail-role", ["session_open"])
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=group.id,
    )
    before = _grant_ids(db)
    assert before, "precondition: some grants exist"

    # Simulate the advisory-lock statement failing (only that statement).
    orig_execute = db.execute

    def _fail_lock(statement, *args, **kwargs):
        if "pg_advisory_xact_lock" in str(statement):
            raise OperationalError("simulated advisory-lock failure", None, Exception())
        return orig_execute(statement, *args, **kwargs)

    monkeypatch.setattr(db, "execute", _fail_lock)

    with pytest.raises(OperationalError):
        abs_svc.recompute_grants(db)

    # The lock failed before the delete ran, and recompute rolled back, so the
    # previous grant set is intact — serialization failed closed, not open.
    monkeypatch.undo()
    assert _grant_ids(db) == before


def test_recompute_is_idempotent(db, maintainer_user, seed_distro, group, cred):
    _system(db, seed_distro, group, cred, "p289-idem")
    role = _role(db, "p289-idem-role", ["session_open"])
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=group.id,
    )
    first = _grant_ids(db)
    abs_svc.recompute_grants(db)
    second = _grant_ids(db)
    assert first == second and first


# --------------------------------------------------------- deterministic resolver


def test_role_sort_key_ignores_primary_key():
    """Precedence is (more-actions-first, then name) — never the PK."""
    strong = FleetRole(
        name="a-strong",
        allowed_actions_json=json.dumps(
            ["session_open", "command_exec", "file_transfer"]
        ),
        os_groups_json="[]",
    )
    weak = FleetRole(
        name="z-weak",
        allowed_actions_json=json.dumps(["session_open"]),
        os_groups_json="[]",
    )
    # Strong (3 actions) sorts before weak (1 action) regardless of id.
    assert authz.role_sort_key(strong) < authz.role_sort_key(weak)


def test_authorize_evaluates_all_grants_not_pk_winner(
    db, maintainer_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p289-evalall")
    # Lower-id role (created first) does NOT allow file_transfer; higher-id role
    # (created later) DOES. The old PK-order resolver would pick the lower-id role
    # and wrongly deny.
    low = _role(db, "z-low", ["session_open"])  # weaker + sorts last by name
    high = _role(
        db, "a-high", ["session_open", "command_exec", "file_transfer"]
    )  # stronger
    assert low.id < high.id
    for r in (low, high):
        abs_svc.create_binding(
            db,
            fleet_role_id=r.id,
            subject_user_id=maintainer_user.id,
            scope_group_id=group.id,
        )

    result = authz.authorize_action(db, maintainer_user, s, "file_transfer")
    assert result.fleet_role.name == "a-high"  # explicit policy picked the allower


def test_authorize_denies_when_no_role_allows(
    db, maintainer_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p289-none")
    r = _role(db, "p289-sessiononly", ["session_open"])
    abs_svc.create_binding(
        db,
        fleet_role_id=r.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=group.id,
    )
    with pytest.raises(authz.PermissionDenied) as exc:
        authz.authorize_action(db, maintainer_user, s, "file_transfer")
    assert exc.value.code == "action_not_allowed"


def test_opposite_insertion_order_same_decision(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    """Equivalent bindings created in opposite DB insertion orders resolve the
    same. Two shared roles (same action count → tie broken by name)."""
    s1 = _system(db, seed_distro, group, cred, "p289-order1")
    s2 = _system(db, seed_distro, group, cred, "p289-order2")
    role_a = _role(db, "a-tie", ["session_open", "command_exec"])
    role_m = _role(db, "m-tie", ["session_open", "command_exec"])

    # user1 on s1: bind a then m; user2 on s2: bind m then a (opposite order).
    for r in (role_a, role_m):
        abs_svc.create_binding(
            db,
            fleet_role_id=r.id,
            subject_user_id=maintainer_user.id,
            scope_group_id=group.id,
        )
    for r in (role_m, role_a):
        abs_svc.create_binding(
            db,
            fleet_role_id=r.id,
            subject_user_id=auditor_user.id,
            scope_group_id=group.id,
        )

    r1 = authz.authorize_action(db, maintainer_user, s1, "command_exec")
    r2 = authz.authorize_action(db, auditor_user, s2, "command_exec")
    # Tie on action count → name asc wins ("a-tie") for both, independent of order.
    assert r1.fleet_role.name == r2.fleet_role.name == "a-tie"


def test_conservative_approval_requirement_not_bypassed(
    db, maintainer_user, seed_distro, group, cred
):
    """A looser overlapping role must not bypass a stricter role's approval need."""
    s = _system(db, seed_distro, group, cred, "p289-appr")
    loose = _role(db, "p289-loose", ["command_exec"], approval=False)
    strict = _role(db, "p289-strict", ["command_exec"], approval=True)
    for r in (loose, strict):
        abs_svc.create_binding(
            db,
            fleet_role_id=r.id,
            subject_user_id=maintainer_user.id,
            scope_group_id=group.id,
        )
    result = authz.authorize_action(db, maintainer_user, s, "command_exec")
    assert result.requires_approval is True
    with pytest.raises(authz.PermissionDenied) as exc:
        authz.enforce_action(db, maintainer_user, s, "command_exec")
    assert exc.value.code == "approval_required"


def test_conservative_totp_requirement_not_bypassed(
    db, maintainer_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p289-totp")
    loose = _role(db, "p289-nototp", ["command_exec"], totp=False)
    strict = _role(db, "p289-totp", ["command_exec"], totp=True)
    for r in (loose, strict):
        abs_svc.create_binding(
            db,
            fleet_role_id=r.id,
            subject_user_id=maintainer_user.id,
            scope_group_id=group.id,
        )
    result = authz.authorize_action(db, maintainer_user, s, "command_exec")
    assert result.requires_totp is True


# --------------------------------------------- reconciliation shares the resolver


def test_reconcile_resolver_matches_authorization(
    db, maintainer_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p289-recon")
    # Lower-id role is weaker; higher-id role is stronger. Both per_user => same
    # login (username). The winner for the account shape must be the stronger
    # role by the shared precedence, NOT the lower fleet_role_id.
    weak = _role(db, "z-recon-weak", ["session_open"])
    strong = _role(
        db, "a-recon-strong", ["session_open", "command_exec", "file_transfer"]
    )
    assert weak.id < strong.id
    for r in (weak, strong):
        abs_svc.create_binding(
            db,
            fleet_role_id=r.id,
            subject_user_id=maintainer_user.id,
            scope_group_id=group.id,
        )

    desired = authz.resolve_desired_login_roles(db, s.id)
    login = maintainer_user.username
    assert desired[login].name == "a-recon-strong"
    # Reconciliation's _desired_logins delegates to the same resolver.
    assert frs._desired_logins(db, s.id)[login].name == "a-recon-strong"
