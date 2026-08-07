"""PRA-234 — API contract for the sshd allow-list compatibility check.

Asserts that ``POST /ssh-identity/systems/{id}/check-allowlist`` surfaces a
specific, actionable allow-list denial for a provisioned login that host sshd
policy blocks — rather than a generic success — and that CA/principals health
does not hide it. Uses a fake bootstrap SSH client so no real host is touched.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.db.access_models import HostUserState
from app.db.models import Credential, Group, System


class _FakeStd:
    def __init__(self, out: str = "", code: int = 0):
        self._out = out.encode()
        self.channel = MagicMock()
        self.channel.recv_exit_status.return_value = code

    def read(self):
        return self._out


class _FakeClient:
    def __init__(self, responses):
        self.responses = responses

    def exec_command(self, command, timeout=None):  # noqa: ARG002
        for substr, out, code in self.responses:
            if substr in command:
                return (MagicMock(), _FakeStd(out, code), _FakeStd("", 0))
        return (MagicMock(), _FakeStd("", 1), _FakeStd("", 1))


@pytest.fixture
def _system(db, seed_distro):
    grp = db.query(Group).filter_by(name="Default").first()
    if not grp:
        grp = Group(name="Default")
        db.add(grp)
        db.flush()
    cred = Credential(
        name="pra234-route-cred",
        auth_method="password",
        username="praxis",
        vault_path="v/pra234route",
    )
    db.add(cred)
    db.flush()
    s = System(
        hostname="pra234-route-host",
        ip_address="10.9.0.2",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
        ca_trust_deployed=True,
        principals_hook_deployed=True,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def test_check_allowlist_route_surfaces_denial(
    authed_client, db, _system, mock_vault, monkeypatch
):
    db.add(
        HostUserState(
            system_id=_system.id, login="operator", mode="per_user", state="provisioned"
        )
    )
    db.commit()

    fake = _FakeClient(
        [
            ("sshd -T", "allowusers praxis\n", 0),
            ("id -nG", "users\n", 0),
            ("grep", "/etc/ssh/sshd_config.d/90-hardening.conf\n", 0),
        ]
    )
    # Patch the SSHService connection factory so no real SSH happens.
    monkeypatch.setattr(
        "app.services.ssh_service.SSHService.get_connection",
        lambda self, *a, **k: (fake, True),
    )

    res = authed_client.post(f"/ssh-identity/systems/{_system.id}/check-allowlist")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["checked"] is True
    assert body["blocked_logins"] == ["operator"]
    result = next(r for r in body["results"] if r["login"] == "operator")
    assert result["blocked"] is True
    assert result["kind"] == "allow_users"
    assert "AllowUsers" in result["reason"]
    assert "operator" in result["reason"]
    assert result["source_file"] == "/etc/ssh/sshd_config.d/90-hardening.conf"
    assert result["remediation"]


def test_check_allowlist_route_requires_admin(client, _system):
    """Unauthenticated callers must not reach the probe."""
    res = client.post(f"/ssh-identity/systems/{_system.id}/check-allowlist")
    assert res.status_code in (401, 403)


def test_enroll_response_surfaces_blocked_logins(
    authed_client, db, _system, mock_vault, monkeypatch
):
    """Enrollment must return the proactive allow-list result so the UI can warn
    instead of unconditionally reporting success (regression: the enroll handler
    previously discarded this, hiding blocked provisioned logins)."""
    db.add(
        HostUserState(
            system_id=_system.id, login="operator", mode="per_user", state="provisioned"
        )
    )
    db.commit()

    fake = _FakeClient(
        [
            ("sshd -T", "allowusers praxis\n", 0),
            ("id -nG", "users\n", 0),
            ("grep", "/etc/ssh/sshd_config.d/90-hardening.conf\n", 0),
        ]
    )
    monkeypatch.setattr(
        "app.services.ssh_service.SSHService.get_connection",
        lambda self, *a, **k: (fake, True),
    )

    # _system already has ca_trust_deployed + principals_hook_deployed, so
    # enroll_access_broker skips the deploy steps and only runs the check.
    res = authed_client.post(f"/ssh-identity/systems/{_system.id}/enroll-access-broker")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "enrolled"
    assert body["allowlist_blocked_logins"] == ["operator"]
    assert body["allowlist"]["blocked_logins"] == ["operator"]
    blocked = next(r for r in body["allowlist"]["results"] if r["login"] == "operator")
    assert blocked["blocked"] is True
    assert "AllowUsers" in blocked["reason"]
