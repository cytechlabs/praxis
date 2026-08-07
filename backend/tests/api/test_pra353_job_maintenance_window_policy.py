"""PRA-353: scheduled-job maintenance-window policy by job type.

For 1.0 the maintenance window is enforced by JOB-TYPE profiling instead of a
broad ignore-window toggle:

- ``update`` / ``security_update`` mutate hosts -> still window-governed on a
  scheduled run (skipped outside a window).
- ``package_scan`` / ``audit`` are read/refresh (SSH-read inventory, never mutate
  a host) -> run any time.
- Manual "Run now" (``ignore_maintenance_window=True``) still bypasses windows
  for every type.
"""

import json

import pytest

from app.db.models import Credential, Group, Job, System
from app.services import maintenance_window_service as mws
from app.services.job_service import JobService, job_type_respects_maintenance_window

# --------------------------------------------------------------- fixtures


@pytest.fixture
def cred(db):
    c = Credential(name="pra353-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def group(db):
    g = Group(name="pra353-grp", description="x")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def system(db, seed_distro, group, cred):
    s = System(
        hostname="pra353-a",
        ip_address="10.53.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _mk_job(db, user, job_type, system):
    job = Job(
        name=f"pra353-{job_type}",
        job_type=job_type,
        status="scheduled",
        target_type="system",
        target_ids=json.dumps([system.id]),
        created_by=user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


@pytest.fixture
def outside_window(monkeypatch):
    """Force every system to be OUTSIDE any maintenance window."""
    monkeypatch.setattr(
        mws, "is_in_maintenance_window", lambda _db, _sid: (False, {"window_name": "x"})
    )
    monkeypatch.setattr(mws, "get_next_window", lambda _db, _sid: None)


def _run(db, user, system, job_type, *, ignore):
    job = _mk_job(db, user, job_type, system)
    return JobService(db).run_job(
        job.id, user_id=user.id, ignore_maintenance_window=ignore
    )


# --------------------------------------------------------------- policy unit


def test_policy_classifies_job_types():
    assert job_type_respects_maintenance_window("update") is True
    assert job_type_respects_maintenance_window("security_update") is True
    assert job_type_respects_maintenance_window("package_scan") is False
    assert job_type_respects_maintenance_window("audit") is False


def test_policy_fails_closed_for_unknown_job_type():
    # An unknown/future job type stays window-governed (explicit read/refresh
    # allowlist), never silently bypassing enforcement.
    assert job_type_respects_maintenance_window("some_future_type") is True
    assert job_type_respects_maintenance_window("") is True


# --------------------------------------------------------------- run_job behavior


@pytest.mark.parametrize("job_type", ["update", "security_update"])
def test_mutating_scheduled_job_is_maintenance_skipped(
    db, admin_user, system, outside_window, job_type
):
    res = _run(db, admin_user, system, job_type, ignore=False)
    # Mutating job types stay window-governed: skipped outside a window.
    assert "outside maintenance window" in res["message"]


@pytest.mark.parametrize("job_type", ["package_scan", "audit"])
def test_read_refresh_scheduled_job_runs_outside_window(
    db, admin_user, system, outside_window, job_type
):
    res = _run(db, admin_user, system, job_type, ignore=False)
    # Read/refresh job types are never maintenance-skipped, even outside a window.
    assert "outside maintenance window" not in res["message"]


def test_manual_run_bypass_unchanged(db, admin_user, system, outside_window):
    # Manual/on-demand run of a mutating job still bypasses the window.
    res = _run(db, admin_user, system, "update", ignore=True)
    assert "outside maintenance window" not in res["message"]
