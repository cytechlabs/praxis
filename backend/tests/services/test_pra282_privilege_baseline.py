"""PRA-282: the Praxis 1.0 privilege baseline (service + data layer).

Proves:
- the privilege-baseline repair clears every fleet role's raw sudoers snippet,
  strips privileged OS groups (keeping non-privileged ones), and flags live host
  accounts for on-host drop-in removal without silently preserving the old
  ``ALL=(ALL) NOPASSWD:ALL`` posture;
- provisioning never writes a sudoers drop-in (always removes it);
- a successful converge clears the reconcile marker; the reconcile queue drain and
  status helpers behave.
"""

from __future__ import annotations

import json

import pytest

from app.db.access_models import FleetRole, HostUserState
from app.db.models import Credential, Group, System
from app.services import fleet_reconciliation_service as frs
from app.services import host_user_provisioning_service as prov
from app.services.privilege_baseline_service import (
    PRIVILEGED_OS_GROUPS,
    enforce_privilege_baseline,
)


def _role(db, name, snippet, groups, builtin=False):
    r = FleetRole(
        name=name,
        description="x",
        login_mode="per_user",
        allowed_actions_json='["session_open"]',
        os_groups_json=json.dumps(groups),
        sudoers_snippet=snippet,
        is_builtin=builtin,
    )
    db.add(r)
    db.flush()
    return r


@pytest.fixture
def system(db, seed_distro):
    g = db.query(Group).filter_by(name="pra282-grp").first()
    if not g:
        g = Group(name="pra282-grp", description="x")
        db.add(g)
        db.flush()
    c = Credential(name="pra282-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    s = System(
        hostname="pra282-host",
        ip_address="10.82.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=c.id,
    )
    db.add(s)
    db.flush()
    return s


def _hus(db, system_id, login, state, pending):
    row = HostUserState(
        system_id=system_id,
        login=login,
        mode="per_user",
        state=state,
        privilege_reconcile_pending=pending,
    )
    db.add(row)
    db.flush()
    return row


# --------------------------------------------------------------- enforce baseline


def test_enforce_nulls_snippets_strips_privileged_groups_flags_hosts(db, system):
    # A custom role seeded exactly like the launch-incompatible PRA-137 posture.
    role = _role(db, "legacy-root", "ALL=(ALL) NOPASSWD:ALL", ["wheel", "docker"])
    keep = _role(db, "docker-only", None, ["docker"])
    prov_row = _hus(db, system.id, "alice", "provisioned", False)
    gone = _hus(db, system.id, "bob", "removed", False)

    summary = enforce_privilege_baseline(db)
    db.expire_all()

    role = db.query(FleetRole).filter_by(name="legacy-root").first()
    assert role.sudoers_snippet is None
    # Privileged group stripped, non-privileged preserved.
    assert json.loads(role.os_groups_json) == ["docker"]
    # A role that was already clean is untouched.
    keep = db.query(FleetRole).filter_by(name="docker-only").first()
    assert json.loads(keep.os_groups_json) == ["docker"]

    # Live account flagged for on-host drop-in removal; removed account is not.
    assert db.query(HostUserState).get(prov_row.id).privilege_reconcile_pending is True
    assert db.query(HostUserState).get(gone.id).privilege_reconcile_pending is False

    # Operator-facing summary reports names/counts, never raw sudoers text.
    assert "legacy-root" in summary["roles_sudoers_cleared"]
    assert "legacy-root" in summary["roles_groups_stripped"]
    assert summary["host_states_flagged"] >= 1
    assert "NOPASSWD" not in json.dumps(summary)


def test_enforce_is_idempotent(db, system):
    _role(db, "legacy-root", "ALL=(ALL) NOPASSWD:ALL", ["wheel"])
    enforce_privilege_baseline(db)
    second = enforce_privilege_baseline(db)
    # Nothing left to clear on the second pass.
    assert "legacy-root" not in second["roles_sudoers_cleared"]


def test_privileged_group_set_covers_wheel_and_sudo():
    assert {"wheel", "sudo", "root", "admin"} <= set(PRIVILEGED_OS_GROUPS)


# --------------------------------------------------------------- provisioning


def test_ensure_script_never_writes_sudoers():
    script = prov._ensure_script(
        login="carol", os_groups=["docker"], principals=["carol"]
    )
    assert "rm -f /etc/sudoers.d/praxis-carol" in script
    assert "visudo" not in script
    assert "NOPASSWD" not in script


def test_upsert_state_clears_marker_on_success(db, system):
    _hus(db, system.id, "dave", "provisioned", True)
    row = prov._upsert_state(
        db,
        system_id=system.id,
        login="dave",
        mode="per_user",
        state="provisioned",
        clear_privilege_pending=True,
    )
    assert row.privilege_reconcile_pending is False


def test_upsert_state_error_leaves_marker_set(db, system):
    _hus(db, system.id, "erin", "provisioned", True)
    row = prov._upsert_state(
        db,
        system_id=system.id,
        login="erin",
        mode="per_user",
        state="error",
        last_error="ssh: unreachable",
    )
    # An unreachable host stays flagged and visibly errored.
    assert row.privilege_reconcile_pending is True
    assert row.state == "error"


# --------------------------------------------------------------- reconcile queue


def test_count_and_status_report_pending(db, system):
    _hus(db, system.id, "f1", "provisioned", True)
    _hus(db, system.id, "f2", "error", True)
    _hus(db, system.id, "f3", "provisioned", False)

    assert frs.count_pending_privilege_reconcile(db) == 2
    status = frs.privilege_reconcile_status(db)
    assert status["pending_accounts"] == 2
    assert status["pending_systems"] == 1
    entry = status["systems"][0]
    assert set(entry["pending_logins"]) == {"f1", "f2"}
    assert entry["errored"] is True  # f2 errored


def test_reconcile_pending_privilege_drains_only_flagged_systems(
    db, system, monkeypatch
):
    _hus(db, system.id, "g1", "provisioned", True)

    calls = []

    def _fake_reconcile(session, sid):
        calls.append(sid)
        # Simulate a successful host reconcile clearing the marker.
        for r in session.query(HostUserState).filter_by(system_id=sid).all():
            r.privilege_reconcile_pending = False
        session.flush()
        return {"provisioned": 1, "removed": 0, "errors": 0, "skipped": 0}

    monkeypatch.setattr(frs, "reconcile_system", _fake_reconcile)

    totals = frs.reconcile_pending_privilege(db)
    assert calls == [system.id]
    assert totals["hosts"] == 1
    assert totals["still_pending"] == 0
