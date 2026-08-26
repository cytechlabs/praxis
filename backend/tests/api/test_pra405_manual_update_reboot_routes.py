"""PRA-405: the package-update routes carry the reboot state through.

The service observes the host; these tests prove the two direct-update
endpoints hand that observation to the caller unchanged, so the operator UI
has something to render.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services.package_service import PackageService

UPDATE_OK = {"status": "success", "exit_code": 0, "stdout": "done", "stderr": ""}


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra405-route-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra405-route-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.commit()
    return c


@pytest.fixture
def host(db, seed_distro, static_group, credentials) -> System:
    s = System(
        hostname="pra405-route-1.example.com",
        ip_address="10.0.99.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.commit()
    pkg = Package(
        system_id=s.id,
        name="openssl",
        installed_version="1.0",
        package_type="apt",
    )
    db.add(pkg)
    db.commit()
    db.add(
        PackageUpdate(
            package_id=pkg.id,
            system_id=s.id,
            available_version="1.1",
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
    db.commit()
    return s


class _FakeSSH:
    def __init__(self, db, probe_result: Dict[str, Any]):
        self.probe_result = probe_result
        self.commands: List[str] = []

    def execute_privileged_command(
        self, system_id: int, command: str, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        self.commands.append(command)
        if "PRAXIS_REBOOT_PROBE" in command:
            return self.probe_result
        return dict(UPDATE_OK)

    def close_all_connections(self) -> None:  # pragma: no cover
        pass


def _stub_transport(
    monkeypatch,
    probe_result: Dict[str, Any],
    *,
    versions_change: bool = True,
) -> None:
    """Replace the package service's SSH layer and post-update rescan so the
    route runs the real service without reaching a host.

    ``versions_change`` models what a real rescan would find. With it set the
    rescan advances each package's installed version, which is what makes the
    service's post-update verification count a package as actually updated.
    With it clear the command still exits zero but nothing moved, so no reboot
    observation is taken.
    """
    import app.services.package_service as package_service_module

    monkeypatch.setattr(
        package_service_module,
        "SSHService",
        lambda db: _FakeSSH(db, probe_result),
    )

    def _rescan(self, system_id):
        if versions_change:
            for upd in (
                self.db.query(PackageUpdate)
                .filter(PackageUpdate.system_id == system_id)
                .all()
            ):
                upd.package.installed_version = upd.available_version
            self.db.flush()
        return {"status": "success"}

    monkeypatch.setattr(PackageService, "scan_packages", _rescan)


PROBE_POSITIVE = {
    "status": "success",
    "exit_code": 0,
    "stdout": "PRAXIS_REBOOT_PROBE=true",
    "stderr": "",
}
PROBE_NEGATIVE = {
    "status": "success",
    "exit_code": 0,
    "stdout": "PRAXIS_REBOOT_PROBE=false",
    "stderr": "",
}
PROBE_UNSUPPORTED = {
    "status": "success",
    "exit_code": 0,
    "stdout": "PRAXIS_REBOOT_PROBE=unsupported",
    "stderr": "",
}
PROBE_FAILED = {
    "status": "warning",
    "exit_code": 127,
    "stdout": "",
    "stderr": "sh: needs-restarting: not found",
}


@pytest.mark.parametrize(
    "probe,expected_required,expected_outcome",
    [
        (PROBE_POSITIVE, True, "success"),
        (PROBE_NEGATIVE, False, "success"),
        (PROBE_UNSUPPORTED, None, "unsupported"),
        (PROBE_FAILED, None, "probe_failed"),
    ],
)
def test_update_route_returns_reboot_state(
    authed_client, host, monkeypatch, probe, expected_required, expected_outcome
):
    _stub_transport(monkeypatch, probe)

    res = authed_client.post(
        f"/packages/{host.id}/update", json={"package_names": ["openssl"]}
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "success"
    assert body["packages_updated"] == 1
    assert body["reboot_required"] is expected_required
    assert body["reboot_evidence"]["outcome"] == expected_outcome
    assert body["reboot_evidence"]["collected_at"].endswith("Z")


@pytest.mark.parametrize(
    "probe,expected_required,expected_outcome",
    [
        (PROBE_POSITIVE, True, "success"),
        (PROBE_NEGATIVE, False, "success"),
        (PROBE_UNSUPPORTED, None, "unsupported"),
        (PROBE_FAILED, None, "probe_failed"),
    ],
)
def test_security_update_route_returns_reboot_state(
    authed_client, host, monkeypatch, probe, expected_required, expected_outcome
):
    _stub_transport(monkeypatch, probe)

    res = authed_client.post(f"/packages/{host.id}/update-security")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "success"
    assert body["packages_updated"] == 1
    assert body["reboot_required"] is expected_required
    assert body["reboot_evidence"]["outcome"] == expected_outcome


def test_update_route_does_not_leak_probe_secrets(authed_client, host, monkeypatch):
    _stub_transport(
        monkeypatch,
        {
            "status": "warning",
            "exit_code": 1,
            "stdout": "",
            "stderr": "auth failed for password=hunter2trombone",
        },
    )

    res = authed_client.post(
        f"/packages/{host.id}/update", json={"package_names": ["openssl"]}
    )

    assert res.status_code == 200, res.text
    assert "hunter2trombone" not in res.text
    assert res.json()["reboot_evidence"]["outcome"] == "probe_failed"


@pytest.mark.parametrize(
    "endpoint,body",
    [
        ("update", {"package_names": ["openssl"]}),
        ("update-security", None),
    ],
)
def test_routes_omit_reboot_state_when_nothing_was_verified_changed(
    authed_client, host, monkeypatch, endpoint, body
):
    """The package-manager command exited zero but no installed version
    moved, so nothing was mutated and there is no reboot answer to give."""
    _stub_transport(monkeypatch, PROBE_POSITIVE, versions_change=False)

    res = authed_client.post(
        f"/packages/{host.id}/{endpoint}", json=body if body is not None else None
    )

    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["status"] == "success"
    assert payload["packages_updated"] == 0
    assert "reboot_required" not in payload
    assert "reboot_evidence" not in payload
