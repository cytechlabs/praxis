"""PRA-286: host-side ownership markers — no adoption/deletion of unmanaged accounts.

Three layers:
  * the ownership-verify shell function is exercised directly via ``bash`` (real
    stat/grep/find) against controlled marker files — no root/useradd needed;
  * the generated ensure/remove scripts contain the ownership gate and drop the
    unsafe ``|| true`` around archive/userdel;
  * ``ensure_user``/``remove_user`` translate the script's exit codes into the
    right ``HostUserState`` (fail-closed on unverifiable accounts), with the
    PRA-282 privilege marker only cleared on a proven-owned success.
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from app.db.access_models import HostUserState
from app.db.models import Credential, Group, System
from app.services import host_user_provisioning_service as prov
from app.services.ssh_service import SSHService
from tests.conftest import unique_test_ip

# ---------------------------------------------------- fixtures / helpers


@pytest.fixture
def system(db, seed_distro):
    g = db.query(Group).filter_by(name="pra286-grp").first()
    if not g:
        g = Group(name="pra286-grp", description="x")
        db.add(g)
        db.flush()
    c = Credential(name="pra286-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    s = System(
        hostname="pra286-host",
        ip_address=unique_test_ip(),
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=c.id,
    )
    db.add(s)
    db.flush()
    return s


def _fleet(db):
    from app.db.access_models import FleetRole

    return db.query(FleetRole).filter_by(name="maintainer").first()


def _mock_ssh(monkeypatch, result):
    def _m(self, system_id, command, timeout=60):
        return result

    monkeypatch.setattr(SSHService, "execute_privileged_command", _m)


def _run_verify(login, path, owner):
    fn = prov.marker_verify_function_sh()
    return subprocess.run(
        ["bash", "-c", f'{fn}\npraxis_verify_marker {login} "{path}" {owner}'],
        capture_output=True,
    ).returncode


# ----------------------------------------------- ownership verify function


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(prov.build_marker_json("alice", 5), id="canonical"),
        # Production writes the marker with a trailing newline (printf '%s\n').
        pytest.param(prov.build_marker_json("alice", 5) + "\n", id="trailing-newline"),
        # system_id may be null when not locally known.
        pytest.param(prov.build_marker_json("alice", None), id="null-system-id"),
    ],
)
def test_verify_marker_accepts_valid_marker(tmp_path, content):
    m = tmp_path / "alice.json"
    m.write_text(content)
    m.chmod(0o600)
    assert _run_verify("alice", str(m), os.getuid()) == 0


def _tampered_false():
    return json.dumps(
        {"marker_version": 1, "praxis_managed": False, "login": "alice"},
        separators=(",", ":"),
    )


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda p: None, id="missing"),
        pytest.param(
            lambda p: (p.write_text("{not json"), p.chmod(0o600)), id="malformed"
        ),
        pytest.param(
            lambda p: (p.write_text(_tampered_false()), p.chmod(0o600)),
            id="tampered-managed-false",
        ),
        pytest.param(
            lambda p: (
                p.write_text(prov.build_marker_json("alice", 5)),
                p.chmod(0o666),
            ),
            id="world-writable",
        ),
        # PRA-286 fix-pass: strings that merely CONTAIN the sentinels must fail —
        # the check is a strict anchored whole-file structural match, not substring.
        pytest.param(
            lambda p: (
                p.write_text(prov.build_marker_json("alice", 5) + " GARBAGE"),
                p.chmod(0o600),
            ),
            id="trailing-garbage",
        ),
        pytest.param(
            lambda p: (
                p.write_text(prov.build_marker_json("alice", 5) + "\nEVIL"),
                p.chmod(0o600),
            ),
            id="multiline-extra",
        ),
        pytest.param(
            lambda p: (
                p.write_text(
                    '{"x":"{\\"marker_version\\":1,\\"praxis_managed\\":true,'
                    '\\"login\\":\\"alice\\"}"}'
                ),
                p.chmod(0o600),
            ),
            id="embedded-sentinels",
        ),
        pytest.param(
            lambda p: (
                p.write_text(
                    json.dumps(
                        {
                            "praxis_managed": True,
                            "marker_version": 1,
                            "login": "alice",
                            "system_id": 5,
                            "created_at": "2026Z",
                        },
                        separators=(",", ":"),
                    )
                ),
                p.chmod(0o600),
            ),
            id="reordered-fields",
        ),
        pytest.param(
            lambda p: (
                p.write_text(
                    '{"marker_version":1,"praxis_managed":true,"login":"alice",'
                    '"system_id":5,"created_at":"2026Z","evil":1}'
                ),
                p.chmod(0o600),
            ),
            id="extra-field",
        ),
    ],
)
def test_verify_marker_fails_closed(tmp_path, make):
    m = tmp_path / "alice.json"
    make(m)
    assert _run_verify("alice", str(m), os.getuid()) != 0


def test_verify_marker_rejects_login_mismatch(tmp_path):
    m = tmp_path / "alice.json"
    m.write_text(prov.build_marker_json("alice", 5))
    m.chmod(0o600)
    assert _run_verify("bob", str(m), os.getuid()) != 0


def test_verify_marker_rejects_wrong_owner(tmp_path):
    m = tmp_path / "alice.json"
    m.write_text(prov.build_marker_json("alice", 5))
    m.chmod(0o600)
    # File is owned by us, but require owner 0 (root) -> fail closed.
    assert _run_verify("alice", str(m), 0) != 0


# ----------------------------------------------------- generated scripts


def test_ensure_script_has_ownership_gate_and_marker():
    s = prov._ensure_script(
        login="alice", os_groups=["docker"], principals=["alice"], system_id=7
    )
    assert "praxis_verify_marker" in s
    assert "PRAXIS_OWNERSHIP_ERROR" in s and "exit 3" in s
    # useradd only in the account-missing (else) branch, before marker write.
    assert "useradd -m -s /bin/bash alice" in s
    assert "printf" in s and '"$MARKER"' in s
    assert 'chmod 600 "$MARKER"' in s
    assert "PRAXIS_MARKER_ERROR" in s and "exit 4" in s
    assert prov.MANAGED_USERS_DIR in s


def test_remove_script_gates_delete_and_has_no_soft_failures():
    s = prov._remove_script("alice")
    assert "praxis_verify_marker" in s
    assert "PRAXIS_OWNERSHIP_ERROR" in s and "exit 3" in s
    # Archive + userdel must NOT be softened with `|| true`.
    assert "tar czf" in s and "tar czf" in s.replace("|| true", "")
    assert "|| true" not in s, "no || true anywhere in the removal script"
    assert "userdel -r alice" in s
    # Praxis-namespaced artifacts are still removed (safe, not adoption).
    assert "rm -f /etc/sudoers.d/praxis-alice" in s
    assert "rm -f /etc/praxis/principals.d/alice" in s


# --------------------------------------------- ensure_user state mapping


def test_ensure_refuses_unmanaged_collision(db, system, monkeypatch):
    _mock_ssh(
        monkeypatch,
        {
            "exit_code": 3,
            "stderr": "PRAXIS_OWNERSHIP_ERROR: account alice exists but is not "
            "Praxis-managed (no valid ownership marker); refusing to modify",
            "stdout": "",
        },
    )
    state = prov.ensure_user(db, system, "alice", _fleet(db))
    assert state.state == "error"
    assert "not Praxis-managed" in state.last_error


def test_ensure_success_marks_provisioned_and_clears_privilege_pending(
    db, system, monkeypatch
):
    # Seed a pending privilege marker; a proven-owned success clears it.
    row = HostUserState(
        system_id=system.id,
        login="alice",
        mode="per_user",
        state="pending",
        privilege_reconcile_pending=True,
    )
    db.add(row)
    db.flush()
    _mock_ssh(monkeypatch, {"exit_code": 0, "stdout": "", "stderr": ""})
    state = prov.ensure_user(db, system, "alice", _fleet(db))
    assert state.state == "provisioned"
    assert state.privilege_reconcile_pending is False


def test_ensure_error_leaves_privilege_pending_set(db, system, monkeypatch):
    """PRA-282 sudoers cleanup stays pending/error for an unverifiable account."""
    row = HostUserState(
        system_id=system.id,
        login="alice",
        mode="per_user",
        state="provisioned",
        privilege_reconcile_pending=True,
    )
    db.add(row)
    db.flush()
    _mock_ssh(
        monkeypatch,
        {"exit_code": 3, "stderr": "PRAXIS_OWNERSHIP_ERROR: ...", "stdout": ""},
    )
    state = prov.ensure_user(db, system, "alice", _fleet(db))
    assert state.state == "error"
    assert state.privilege_reconcile_pending is True, "marker must stay pending"


# --------------------------------------------- remove_user state mapping


def test_remove_refuses_unowned_delete_even_with_ledger_row(db, system, monkeypatch):
    """Old ledger rows alone must not authorize destructive deletion — the host-side
    marker is the authority."""
    row = HostUserState(
        system_id=system.id, login="alice", mode="per_user", state="provisioned"
    )
    db.add(row)
    db.flush()
    _mock_ssh(
        monkeypatch,
        {
            "exit_code": 3,
            "stderr": "PRAXIS_OWNERSHIP_ERROR: account alice is not Praxis-managed "
            "(no valid ownership marker); refusing to delete account/home",
            "stdout": "",
        },
    )
    state = prov.remove_user(db, system, "alice", "per_user")
    assert state.state == "error"
    assert "refusing to delete" in state.last_error


def test_remove_archive_or_userdel_failure_is_error(db, system, monkeypatch):
    _mock_ssh(
        monkeypatch,
        {
            "exit_code": 1,
            "stderr": "tar: /home/alice: Cannot open: Permission denied",
            "stdout": "",
        },
    )
    state = prov.remove_user(db, system, "alice", "per_user")
    assert state.state == "error"
    assert "tar" in state.last_error


def test_remove_success_marks_removed(db, system, monkeypatch):
    _mock_ssh(
        monkeypatch,
        {
            "exit_code": 0,
            "stdout": "PRAXIS_ARCHIVE=/var/backups/praxis/homedirs/alice-x.tar.gz",
            "stderr": "",
        },
    )
    state = prov.remove_user(db, system, "alice", "per_user")
    assert state.state == "removed"
    assert state.home_archive_path.endswith("alice-x.tar.gz")
