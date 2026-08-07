"""PRA-373: the legacy raw SSH execute endpoint is gone, not merely discouraged.

`POST /ssh/execute/{system_id}` used to hand an arbitrary command straight to
`SSHService.execute_command()`, skipping command validation, risk classification
and approvals. The supported contract is `POST /command-execution/execute`.

These tests pin the removal at the HTTP boundary rather than by grepping source:
the path is absent from the OpenAPI document, a real authenticated request to it
404s, and that request reaches neither SSH nor the execution-history table. The
canonical route is asserted alive in the same module so a future refactor cannot
delete both and still look green.
"""

from __future__ import annotations

import uuid

import pytest

from app.db.command_execution_models import CommandExecutionResult
from app.db.models import Credential, Group, System
from app.services import ssh_service as ssh_service_module

_LEGACY_PATH_TEMPLATE = "/ssh/execute/{system_id}"
_CANONICAL_PATH = "/command-execution/execute"


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


@pytest.fixture
def system(db, seed_distro):
    tag = uuid.uuid4().hex[:8]
    group = Group(name=f"pra373-grp-{tag}")
    cred = Credential(
        name=f"pra373-cred-{tag}", auth_method="password", username="root"
    )
    db.add_all([group, cred])
    db.flush()
    row = System(
        hostname=f"pra373-{tag}.example.com",
        ip_address="10.73.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def ssh_execute_spy(monkeypatch):
    """Trip-wire on the transport primitive.

    `SSHService.execute_command()` stays as an internal primitive for package,
    facts, drift and repository work, so the proof is that no HTTP request can
    reach it, not that it stopped existing.
    """
    calls = []

    def _boom(self, *args, **kwargs):  # pragma: no cover - must never run
        calls.append((args, kwargs))
        raise AssertionError("SSHService.execute_command reached over HTTP")

    monkeypatch.setattr(ssh_service_module.SSHService, "execute_command", _boom)
    return calls


# ------------------------------------------------------------ removed surface


def test_legacy_execute_path_absent_from_openapi(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert _LEGACY_PATH_TEMPLATE not in paths
    # Nothing else re-exposes an SSH execute contract under a different shape.
    assert not [p for p in paths if p.startswith("/ssh/execute")]


def test_ssh_router_keeps_its_connection_lifecycle_routes(client):
    """The removal took the execute route and nothing else.

    A subset check on purpose: the security invariant is the absence of an
    execute prefix, which
    ``test_legacy_execute_path_absent_from_openapi`` owns. Freezing the whole
    ``/ssh/`` set here would turn any future unrelated SSH route into a failure
    in a test about a removed endpoint.
    """
    ssh_paths = {
        p for p in client.get("/openapi.json").json()["paths"] if p.startswith("/ssh/")
    }
    assert {
        "/ssh/test/{system_id}",
        "/ssh/test-all",
        "/ssh/close/{system_id}",
        "/ssh/close-all",
    } <= ssh_paths


@pytest.mark.parametrize("method", ["post", "get", "put", "delete"])
def test_legacy_execute_path_is_not_routable(
    client, db, admin_user, system, ssh_execute_spy, method
):
    _login(client, admin_user)
    res = getattr(client, method)(f"/ssh/execute/{system.id}", params={"command": "id"})
    assert res.status_code == 404, res.text
    assert ssh_execute_spy == []


def test_legacy_request_creates_no_execution_history(
    client, db, admin_user, system, ssh_execute_spy
):
    before = db.query(CommandExecutionResult).count()
    _login(client, admin_user)
    res = client.post(f"/ssh/execute/{system.id}", params={"command": "rm -rf /"})
    assert res.status_code == 404

    db.expire_all()
    # No SSH, and no audit/history row attributing the attempt to a real run.
    assert ssh_execute_spy == []
    assert db.query(CommandExecutionResult).count() == before


def test_legacy_path_is_gone_for_every_caller_that_previously_had_it(
    client, db, maintainer_user, system, ssh_execute_spy
):
    # Anonymous callers are stopped by authentication before routing, so the
    # removed path does not even disclose its own absence.
    assert client.post(f"/ssh/execute/{system.id}").status_code == 401
    # A maintainer previously had access to this route; now there is no route.
    _login(client, maintainer_user)
    assert client.post(f"/ssh/execute/{system.id}").status_code == 404
    assert ssh_execute_spy == []


# --------------------------------------------------------- canonical surface


def test_canonical_command_execution_route_remains_registered(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert _CANONICAL_PATH in paths
    assert "post" in paths[_CANONICAL_PATH]


def test_canonical_route_still_enforces_authentication(client, db, system):
    # A payload that satisfies CommandExecutionRequest, so the rejection below is
    # authentication and cannot be a 422 from a malformed body. The canonical
    # route is its own governed contract, not a redirect target for the removed
    # path, and it still refuses anonymous callers.
    res = client.post(_CANONICAL_PATH, json={"system_id": system.id, "command": "id"})
    assert res.status_code in (401, 403), res.text
