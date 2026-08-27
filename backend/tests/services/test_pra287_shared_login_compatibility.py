"""PRA-287: shared-login compatibility gate.

Multiple fleet roles can resolve to the SAME ``(system, login)`` — a shared Linux
role account, or one user holding several roles. Praxis 1.0 must not silently merge
incompatible account/session policy into that one login. This suite proves the
single shared resolver used by BOTH authorization and reconciliation:

  * ACCOUNT-SHAPE differences (login_mode / role_account_name / os_groups /
    sudoers_snippet) are hard CONFLICTS — authorization fails closed and
    reconciliation refuses to converge (and does not destructively remove) host
    state, independent of fleet-role creation / primary-key order;
  * SESSION-POLICY differences (approval / TOTP / idle_timeout / max_session /
    recording_retention) are NOT conflicts — they are resolved CONSERVATIVELY
    (strictest wins) at authorization so no lower-control role can bypass a stricter
    one, while the identically shaped account still provisions.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.db.access_models import AccessGrant, FleetRole, HostUserState
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System
from app.services import access_authorization_service as authz
from app.services import fleet_reconciliation_service as frs
from app.services import recording_service
from tests.conftest import unique_test_ip

# --------------------------------------------------------------------- helpers


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra287-grp").first()
    if not g:
        g = Group(name="pra287-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra287-cred", auth_method="ssh_key", username="root")
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


def _role(
    db,
    name,
    *,
    actions=("session_open", "command_exec"),
    login_mode="role_account",
    role_account_name="svc",
    os_groups=("docker",),
    sudoers=None,
    approval=False,
    totp=False,
    idle_timeout_s=900,
    max_session_s=3600,
    recording_retention_days=90,
):
    r = FleetRole(
        name=name,
        login_mode=login_mode,
        role_account_name=role_account_name,
        allowed_actions_json=json.dumps(list(actions)),
        os_groups_json=json.dumps(list(os_groups)),
        sudoers_snippet=sudoers,
        session_requires_approval=approval,
        totp_required=totp,
        idle_timeout_s=idle_timeout_s,
        max_session_s=max_session_s,
        recording_retention_days=recording_retention_days,
    )
    db.add(r)
    db.flush()
    return r


def _grant(db, user, system, role, login):
    g = AccessGrant(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=role.id,
        login=login,
    )
    db.add(g)
    db.flush()
    return g


class _FakeState:
    def __init__(self, state):
        self.state = state
        self.mode = "role_account"


def _patch_prov(monkeypatch):
    """Record ensure_user / remove_user calls without touching a host."""
    calls = {"ensure": [], "remove": []}
    monkeypatch.setattr(
        frs,
        "ensure_user",
        lambda db, system, login, role: (
            calls["ensure"].append(login) or _FakeState("provisioned")
        ),
    )
    monkeypatch.setattr(
        frs,
        "remove_user",
        lambda db, system, login, mode: (
            calls["remove"].append(login) or _FakeState("removed")
        ),
    )
    return calls


# --------------------------------------------------------- compatible acceptance


def test_identical_role_account_roles_accepted_deterministically(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    """Two role-account roles with the same account shape (identical login_mode /
    role_account_name / os_groups / sudoers) — differing only in name/actions — are
    compatible; the deterministic winner is used regardless of creation order."""
    s = _system(db, seed_distro, group, cred, "p287-ok")
    weak = _role(db, "z-weak", actions=["session_open"])
    strong = _role(db, "a-strong", actions=["session_open", "command_exec"])
    assert weak.id < strong.id  # creation/PK order is the opposite of strength
    _grant(db, maintainer_user, s, weak, "svc")
    _grant(db, auditor_user, s, strong, "svc")

    res = authz.resolve_login_resolution(db, s.id, "svc")
    assert not res.is_conflict
    # Strongest-by-actions wins, NOT the lower primary key.
    assert res.role.name == "a-strong"
    assert authz.resolve_desired_login_roles(db, s.id)["svc"].name == "a-strong"


def test_creation_order_does_not_change_winner(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p287-order")
    # Create the strong role FIRST this time (opposite of the test above).
    strong = _role(db, "a-strong2", actions=["session_open", "command_exec"])
    weak = _role(db, "z-weak2", actions=["session_open"])
    assert strong.id < weak.id
    _grant(db, maintainer_user, s, strong, "svc")
    _grant(db, auditor_user, s, weak, "svc")
    assert authz.resolve_login_resolution(db, s.id, "svc").role.name == "a-strong2"


# --------------------------------------------------- account-shape hard conflicts


def test_different_os_groups_is_conflict(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p287-groups")
    a = _role(db, "grp-a", os_groups=["docker"])
    b = _role(db, "grp-b", os_groups=["docker", "wheel"])
    _grant(db, maintainer_user, s, a, "svc")
    _grant(db, auditor_user, s, b, "svc")

    res = authz.resolve_login_resolution(db, s.id, "svc")
    assert res.is_conflict
    assert res.role is None
    assert "os_groups" in res.conflict["differing_fields"]
    assert res.conflict["role_names"] == ["grp-a", "grp-b"]
    # Excluded from the reconcile desired map (no arbitrary winner).
    assert "svc" not in authz.resolve_desired_login_roles(db, s.id)


def test_login_mode_mismatch_is_conflict(db, maintainer_user, seed_distro, group, cred):
    s = _system(db, seed_distro, group, cred, "p287-mode")
    per_user = _role(db, "pu", login_mode="per_user", role_account_name=None)
    role_acct = _role(db, "ra", login_mode="role_account", role_account_name="svc")
    # Same login string, incompatible modes.
    _grant(db, maintainer_user, s, per_user, "shared")
    _grant(db, maintainer_user, s, role_acct, "shared")
    res = authz.resolve_login_resolution(db, s.id, "shared")
    assert res.is_conflict
    assert "login_mode" in res.conflict["differing_fields"]


def test_role_account_name_mismatch_is_conflict(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p287-acct")
    a = _role(db, "acct-a", role_account_name="svc-a")
    b = _role(db, "acct-b", role_account_name="svc-b")
    _grant(db, maintainer_user, s, a, "svc")
    _grant(db, auditor_user, s, b, "svc")
    res = authz.resolve_login_resolution(db, s.id, "svc")
    assert res.is_conflict
    assert "role_account_name" in res.conflict["differing_fields"]


def test_sudoers_snippet_mismatch_is_conflict(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    """1.0 should keep sudoers NULL post-PRA-282, but a stray value must never
    silently merge — it is still compared and surfaces as a conflict."""
    s = _system(db, seed_distro, group, cred, "p287-sudo")
    clean = _role(db, "sudo-null", sudoers=None)
    stray = _role(db, "sudo-set", sudoers="%svc ALL=(ALL) NOPASSWD: ALL")
    _grant(db, maintainer_user, s, clean, "svc")
    _grant(db, auditor_user, s, stray, "svc")
    res = authz.resolve_login_resolution(db, s.id, "svc")
    assert res.is_conflict
    assert "sudoers_snippet" in res.conflict["differing_fields"]


# ---------------------------------------- session-policy conservative enforcement


def test_approval_difference_is_not_a_conflict_but_enforced(
    db, maintainer_user, seed_distro, group, cred
):
    """Same account shape, different approval -> NOT a conflict (account still
    provisions); authorization conservatively requires approval (no bypass)."""
    s = _system(db, seed_distro, group, cred, "p287-appr")
    loose = _role(db, "appr-loose", actions=["command_exec"], approval=False)
    strict = _role(db, "appr-strict", actions=["command_exec"], approval=True)
    _grant(db, maintainer_user, s, loose, "svc")
    _grant(db, maintainer_user, s, strict, "svc")

    assert not authz.resolve_login_resolution(db, s.id, "svc").is_conflict
    result = authz.authorize_action(db, maintainer_user, s, "command_exec")
    assert result.requires_approval is True


def test_totp_difference_is_not_a_conflict_but_enforced(
    db, maintainer_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p287-totp")
    loose = _role(db, "totp-loose", actions=["command_exec"], totp=False)
    strict = _role(db, "totp-strict", actions=["command_exec"], totp=True)
    _grant(db, maintainer_user, s, loose, "svc")
    _grant(db, maintainer_user, s, strict, "svc")
    assert not authz.resolve_login_resolution(db, s.id, "svc").is_conflict
    result = authz.authorize_action(db, maintainer_user, s, "command_exec")
    assert result.requires_totp is True


def test_session_timeouts_and_recording_resolved_strictest(
    db, maintainer_user, seed_distro, group, cred
):
    """Shortest idle/max session and longest recording retention win — a looser
    role cannot lengthen a session or shorten recording via a shared login."""
    s = _system(db, seed_distro, group, cred, "p287-ttl")
    loose = _role(
        db,
        "ttl-loose",
        actions=["session_open"],
        idle_timeout_s=1800,
        max_session_s=7200,
        recording_retention_days=30,
    )
    strict = _role(
        db,
        "ttl-strict",
        actions=["session_open"],
        idle_timeout_s=300,
        max_session_s=900,
        recording_retention_days=365,
    )
    _grant(db, maintainer_user, s, loose, "svc")
    _grant(db, maintainer_user, s, strict, "svc")

    assert not authz.resolve_login_resolution(db, s.id, "svc").is_conflict
    result = authz.authorize_action(db, maintainer_user, s, "session_open")
    assert result.idle_timeout_s == 300
    assert result.max_session_s == 900  # the looser 7200 must NOT be inherited
    assert result.recording_retention_days == 365


# ---------------------------------------- authorization fails closed on conflict


def test_authorize_fails_closed_on_conflicted_login(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p287-authz")
    a = _role(db, "az-a", actions=["command_exec"], os_groups=["docker"])
    b = _role(db, "az-b", actions=["command_exec"], os_groups=["wheel"])
    _grant(db, maintainer_user, s, a, "svc")
    _grant(db, auditor_user, s, b, "svc")

    # Explicit login request -> deny.
    with pytest.raises(authz.PermissionDenied) as exc:
        authz.authorize_action(db, maintainer_user, s, "command_exec", login="svc")
    assert exc.value.code == "login_conflict"

    # Unspecified login where the only applicable login is conflicted -> deny.
    with pytest.raises(authz.PermissionDenied) as exc2:
        authz.authorize_action(db, maintainer_user, s, "command_exec")
    assert exc2.value.code == "login_conflict"


def test_lower_privilege_cannot_inherit_groups_via_shared_login(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    """The whole point: a principal bound to a low-group role on a shared login must
    not gain a higher-group role's OS groups. Incompatible groups fail closed for
    BOTH principals rather than merging."""
    s = _system(db, seed_distro, group, cred, "p287-inherit")
    low = _role(db, "low", actions=["command_exec"], os_groups=["app"])
    high = _role(db, "high", actions=["command_exec"], os_groups=["app", "sudo"])
    _grant(db, maintainer_user, s, low, "svc")
    _grant(db, auditor_user, s, high, "svc")

    for u in (maintainer_user, auditor_user):
        with pytest.raises(authz.PermissionDenied) as exc:
            authz.authorize_action(db, u, s, "command_exec", login="svc")
        assert exc.value.code == "login_conflict"


def test_unrelated_compatible_login_still_authorizes(
    db, maintainer_user, seed_distro, group, cred
):
    """A conflict on one login must not deny access via a different, compatible
    login the same user holds."""
    s = _system(db, seed_distro, group, cred, "p287-mixed")
    # Conflicted shared login.
    a = _role(db, "mix-a", actions=["command_exec"], os_groups=["docker"])
    b = _role(db, "mix-b", actions=["command_exec"], os_groups=["wheel"])
    _grant(db, maintainer_user, s, a, "svc")
    _grant(db, maintainer_user, s, b, "svc")
    # Clean per-user login for the same user.
    clean = _role(
        db,
        "mix-clean",
        actions=["command_exec"],
        login_mode="per_user",
        role_account_name=None,
        os_groups=["app"],
    )
    _grant(db, maintainer_user, s, clean, "alice")

    result = authz.authorize_action(
        db, maintainer_user, s, "command_exec", login="alice"
    )
    assert result.login == "alice"


# ------------------------------------------------- reconciliation shares resolver


def test_reconcile_skips_conflicted_login_no_ensure(
    db, maintainer_user, auditor_user, seed_distro, group, cred, monkeypatch
):
    s = _system(db, seed_distro, group, cred, "p287-recon")
    a = _role(db, "rc-a", os_groups=["docker"])
    b = _role(db, "rc-b", os_groups=["wheel"])
    _grant(db, maintainer_user, s, a, "svc")
    _grant(db, auditor_user, s, b, "svc")

    calls = _patch_prov(monkeypatch)
    counts = frs.reconcile_system(db, s.id)
    assert "svc" not in calls["ensure"], "conflicted login must not be provisioned"
    assert counts["conflicts"] == 1
    assert counts["provisioned"] == 0


def test_reconcile_conflict_does_not_remove_existing_state(
    db, maintainer_user, auditor_user, seed_distro, group, cred, monkeypatch
):
    """A conflict prevents unsafe convergence — it must NOT trigger destructive
    removal of a previously provisioned account (that routes through PRA-285)."""
    s = _system(db, seed_distro, group, cred, "p287-noremove")
    a = _role(db, "nr-a", os_groups=["docker"])
    b = _role(db, "nr-b", os_groups=["wheel"])
    _grant(db, maintainer_user, s, a, "svc")
    _grant(db, auditor_user, s, b, "svc")
    # An existing provisioned ledger row for the now-conflicted login.
    db.add(
        HostUserState(
            system_id=s.id, login="svc", mode="role_account", state="provisioned"
        )
    )
    db.flush()

    calls = _patch_prov(monkeypatch)
    counts = frs.reconcile_system(db, s.id)
    assert "svc" not in calls["remove"], "conflict must not delete existing account"
    assert counts["removed"] == 0
    assert counts["conflicts"] == 1


def test_authorization_and_reconciliation_agree(
    db, maintainer_user, auditor_user, seed_distro, group, cred, monkeypatch
):
    """Compatible login: authz allows AND reconcile provisions. Conflicted login:
    authz denies AND reconcile skips. Same resolver, same verdict."""
    ok = _system(db, seed_distro, group, cred, "p287-agree-ok")
    good = _role(db, "ag-ok", actions=["command_exec"], os_groups=["docker"])
    _grant(db, maintainer_user, ok, good, "svc")

    bad = _system(db, seed_distro, group, cred, "p287-agree-bad")
    b1 = _role(db, "ag-b1", actions=["command_exec"], os_groups=["docker"])
    b2 = _role(db, "ag-b2", actions=["command_exec"], os_groups=["wheel"])
    _grant(db, maintainer_user, bad, b1, "svc")
    _grant(db, auditor_user, bad, b2, "svc")

    calls = _patch_prov(monkeypatch)
    ok_counts = frs.reconcile_system(db, ok.id)
    bad_counts = frs.reconcile_system(db, bad.id)

    # Compatible: authorized + provisioned.
    assert authz.authorize_action(db, maintainer_user, ok, "command_exec", login="svc")
    assert "svc" in calls["ensure"]
    assert ok_counts["conflicts"] == 0

    # Conflicted: denied + not provisioned.
    with pytest.raises(authz.PermissionDenied):
        authz.authorize_action(db, maintainer_user, bad, "command_exec", login="svc")
    assert bad_counts["conflicts"] == 1


# ------------------------------------------------------- operator visibility


def _session_row(db, user, system, *, fleet_role_id, retention):
    row = SessionRow(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=fleet_role_id,
        login="svc",
        status="active",
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
        recording_retention_days=retention,
    )
    db.add(row)
    db.flush()
    return row


def test_recording_retention_enforces_conservative_not_representative(
    db, maintainer_user, seed_distro, group, cred
):
    """The fix-pass guarantee: when one principal holds a 30-day and a 365-day role
    on a shared login, the session must record at 365 days even though the 30-day
    role wins as the representative ``fleet_role_id``. Authorization resolves the
    conservative (longest) retention AND recording enforces the value persisted on
    the session — not the representative role's."""
    s = _system(db, seed_distro, group, cred, "p287-rec")
    # ``short`` wins as representative (more allowed actions -> stronger by
    # role_sort_key) but carries the SHORTER retention; ``long`` carries the longest.
    short = _role(
        db,
        "rec-short",
        actions=["session_open", "command_exec"],
        recording_retention_days=30,
    )
    long = _role(db, "rec-long", actions=["session_open"], recording_retention_days=365)
    _grant(db, maintainer_user, s, short, "svc")
    _grant(db, maintainer_user, s, long, "svc")

    # Same account shape (retention is session-policy, not account-shape) -> no
    # conflict; the representative is the SHORTER-retention role, yet authorization
    # resolves the LONGEST retention.
    result = authz.authorize_action(db, maintainer_user, s, "session_open", login="svc")
    assert result.fleet_role.name == "rec-short"  # representative is the 30-day role
    assert result.recording_retention_days == 365  # conservative resolves to 365

    # A session persists that conservative value even though its representative role
    # (fleet_role_id) is the 30-day one -> recording enforces 365, not 30.
    row = _session_row(
        db, maintainer_user, s, fleet_role_id=result.fleet_role.id, retention=365
    )
    assert recording_service._retention_days_for(db, row.id) == 365


def test_recording_retention_legacy_row_falls_back_to_role(
    db, maintainer_user, seed_distro, group, cred
):
    """Rows created before PRA-287 have NULL recording_retention_days; recording
    falls back to the representative role's value (no behavior change for them)."""
    s = _system(db, seed_distro, group, cred, "p287-rec-legacy")
    short = _role(
        db, "rec-legacy", actions=["session_open"], recording_retention_days=30
    )
    _grant(db, maintainer_user, s, short, "svc")
    row = _session_row(db, maintainer_user, s, fleet_role_id=short.id, retention=None)
    assert recording_service._retention_days_for(db, row.id) == 30


def test_shared_login_conflicts_lists_structured_details(
    db, maintainer_user, auditor_user, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p287-visible")
    a = _role(db, "vis-a", os_groups=["docker"])
    b = _role(db, "vis-b", os_groups=["wheel"])
    _grant(db, maintainer_user, s, a, "svc")
    _grant(db, auditor_user, s, b, "svc")

    conflicts = authz.shared_login_conflicts(db, system_ids=[s.id])
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["system_id"] == s.id
    assert c["login"] == "svc"
    assert "os_groups" in c["differing_fields"]
    assert set(c["role_names"]) == {"vis-a", "vis-b"}
