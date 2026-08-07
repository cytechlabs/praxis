"""Tests for PRA-127 drift detection."""

import json
from datetime import datetime, timedelta

import pytest

from app.db.models import Baseline, BaselineCheck, Credential, Group, Package, System
from app.services import drift_service


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
    c = Credential(
        name="t-cred", auth_method="password", username="root", vault_path="x"
    )
    db.add(c)
    db.flush()
    return c


def _mk_system(db, distro, group, cred, hostname, ip):
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


# --- Validator -------------------------------------------------------------


def test_validate_empty_rules_rejected():
    with pytest.raises(drift_service.BaselineRuleError):
        drift_service.validate_rules({"packages": [], "services": []})


def test_validate_package_requires_name_and_check():
    with pytest.raises(drift_service.BaselineRuleError):
        drift_service.validate_rules({"packages": [{"name": "", "check": "required"}]})
    with pytest.raises(drift_service.BaselineRuleError):
        drift_service.validate_rules({"packages": [{"name": "x", "check": "nope"}]})


def test_validate_version_pin_requires_version():
    with pytest.raises(drift_service.BaselineRuleError):
        drift_service.validate_rules(
            {"packages": [{"name": "nginx", "check": "version_pin"}]}
        )


def test_validate_ok():
    drift_service.validate_rules(
        {
            "packages": [
                {"name": "openssh-server", "check": "required"},
                {"name": "telnet", "check": "forbidden"},
                {"name": "nginx", "check": "version_pin", "version": "1.24.0"},
            ],
            "services": [
                {"name": "sshd", "check": "running"},
                {"name": "cups", "check": "disabled"},
            ],
        }
    )


# --- Diff engine -----------------------------------------------------------


def test_diff_required_missing():
    drift = drift_service._diff_packages(
        [{"name": "openssh-server", "check": "required"}], {}
    )
    assert len(drift) == 1 and drift[0]["reason"] == "not installed"


def test_diff_forbidden_installed():
    drift = drift_service._diff_packages(
        [{"name": "telnet", "check": "forbidden"}], {"telnet": "0.17"}
    )
    assert len(drift) == 1 and "0.17" in drift[0]["reason"]


def test_diff_version_pin_mismatch():
    drift = drift_service._diff_packages(
        [{"name": "nginx", "check": "version_pin", "version": "1.24.0"}],
        {"nginx": "1.22.0"},
    )
    assert len(drift) == 1 and "1.22.0" in drift[0]["reason"]


def test_diff_compliant_when_matched():
    drift = drift_service._diff_packages(
        [{"name": "openssh-server", "check": "required"}],
        {"openssh-server": "9.0"},
    )
    assert drift == []


def test_diff_service_running_vs_stopped():
    state = {"sshd": {"active": "active", "enabled": "enabled"}}
    assert (
        drift_service._diff_services([{"name": "sshd", "check": "running"}], state)
        == []
    )
    drift = drift_service._diff_services([{"name": "sshd", "check": "stopped"}], state)
    assert len(drift) == 1 and drift[0]["reason"] == "running"


def test_diff_service_enabled_missing():
    state = {"ufw": {"active": "active", "enabled": "disabled"}}
    drift = drift_service._diff_services([{"name": "ufw", "check": "enabled"}], state)
    assert len(drift) == 1 and "disabled" in drift[0]["reason"]


# --- run_baseline end-to-end ----------------------------------------------


class _StubSSH:
    def __init__(self, responses):
        self._responses = responses

    def execute_command(self, system_id, command, timeout=None):  # noqa: D401
        return self._responses.get(
            system_id, {"exit_code": 0, "stdout": "", "stderr": ""}
        )


def test_run_baseline_records_compliant_and_drifted(
    db, seed_distro, seed_default_group, seed_cred
):
    s_ok = _mk_system(db, seed_distro, seed_default_group, seed_cred, "ok", "10.9.0.1")
    s_bad = _mk_system(
        db, seed_distro, seed_default_group, seed_cred, "bad", "10.9.0.2"
    )
    # good system has package, bad one doesn't
    db.add(Package(system_id=s_ok.id, name="openssh-server", installed_version="9.0"))
    db.commit()

    b = Baseline(
        name="bl",
        rules_json=json.dumps(
            {
                "packages": [{"name": "openssh-server", "check": "required"}],
                "services": [],
            }
        ),
        enabled=True,
        schedule_interval_hours=24,
    )
    db.add(b)
    db.commit()
    db.refresh(b)

    counts = drift_service.run_baseline(db, b.id, ssh_service=_StubSSH({}))
    assert counts["compliant"] == 1 and counts["drifted"] == 1

    checks = db.query(BaselineCheck).filter_by(baseline_id=b.id).all()
    by_system = {c.system_id: c for c in checks}
    assert by_system[s_ok.id].status == "compliant"
    assert by_system[s_bad.id].status == "drifted"
    assert by_system[s_bad.id].drift_details_json


def test_run_all_due_respects_interval(db, seed_distro, seed_default_group, seed_cred):
    _mk_system(db, seed_distro, seed_default_group, seed_cred, "h", "10.10.0.1")
    b = Baseline(
        name="due-test",
        rules_json=json.dumps(
            {"packages": [{"name": "x", "check": "required"}], "services": []}
        ),
        enabled=True,
        schedule_interval_hours=24,
        last_run_at=datetime.utcnow() - timedelta(minutes=5),  # not due
    )
    db.add(b)
    db.commit()
    stats = drift_service.run_all_due(db)
    assert b.id not in stats


def test_purge_old_checks(db, seed_distro, seed_default_group, seed_cred):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p", "10.11.0.1")
    b = Baseline(
        name="purge",
        rules_json=json.dumps(
            {"packages": [{"name": "x", "check": "required"}], "services": []}
        ),
        enabled=True,
    )
    db.add(b)
    db.commit()
    old = BaselineCheck(
        baseline_id=b.id,
        system_id=s.id,
        run_at=datetime.utcnow() - timedelta(days=91),
        status="compliant",
    )
    new = BaselineCheck(
        baseline_id=b.id,
        system_id=s.id,
        run_at=datetime.utcnow() - timedelta(days=10),
        status="compliant",
    )
    db.add_all([old, new])
    db.commit()

    removed = drift_service.purge_old_checks(db, days=90)
    assert removed == 1
    remaining = db.query(BaselineCheck).filter_by(baseline_id=b.id).all()
    assert len(remaining) == 1 and remaining[0].id == new.id
