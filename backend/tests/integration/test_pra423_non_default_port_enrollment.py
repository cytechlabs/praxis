"""PRA-423: guided onboarding to managed reconnection against real EL targets
on a non-default SSH port, with a default-port control.

The pre-tag integration run enrolled two identical AlmaLinux hosts through the
same wizard and the same credential. The one on port 22 reconnected; the one on
2222 failed afterwards with ``Server '[address]:2222' not found in
known_hosts``, because the approved key was preloaded under the bare address
while paramiko looks a non-default-port endpoint up as ``[address]:port``.

This suite reproduces that arc end to end against disposable containers running
real ``sshd``: the wizard's own routes, the real credential in Vault, the
production host-key path, an ordinary managed-host reconnection, and a rotated
host key that must fail closed. Nothing here bypasses the credential or
host-key path, and no test relaxes verification.

Gated on ``PRAXIS_E2E=1`` plus a mounted docker socket and reachable Vault, the
same way the other real-host suites are. Without them the module is collected
and skipped.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import date
from typing import Dict, Iterator, Tuple

import paramiko
import pytest


def _e2e_skip_reason() -> str:
    if os.environ.get("PRAXIS_E2E", "").lower() not in ("1", "true", "yes"):
        return "PRAXIS_E2E not set"
    if not os.path.exists("/var/run/docker.sock"):
        return "/var/run/docker.sock not mounted"
    if not os.environ.get("VAULT_ADDR"):
        return "VAULT_ADDR not set"
    return ""


_skip = _e2e_skip_reason()
pytestmark = pytest.mark.skipif(bool(_skip), reason=f"e2e skipped: {_skip}")

from fastapi.testclient import TestClient  # noqa: E402

from app.core.auth import get_password_hash  # noqa: E402
from app.core.entitlements import registry  # noqa: E402
from app.db.models import (  # noqa: E402
    Distro,
    Group,
    Role,
    System,
    SystemMetadata,
    User,
)
from app.db.session import SessionLocal  # noqa: E402
from app.db.ssh_security_models import SSHHostKey, SSHSecurityPolicy  # noqa: E402
from app.services.ssh_service import SSHConnectionError, SSHService  # noqa: E402

from ._harness import ensure_vault_config  # noqa: E402

TARGET_IMAGE = "almalinux:9"
TARGET_NETWORK = os.environ.get("PRAXIS_E2E_NETWORK", "praxis_backend_net")
TARGET_LOGIN = "praxis"
TARGET_PASSWORD = "praxis-p423-bootstrap"
ALT_PORT = 2222
CONTROL_PORT = 22

# One tag per run so a repeat never collides with a leftover container, user,
# credential or host from an aborted run.
RUN_TAG = uuid.uuid4().hex[:8]


# --------------------------------------------------------------------- targets


def _bootstrap_target(container, port: int) -> None:
    steps = [
        "dnf -y -q install openssh-server sudo passwd procps-ng",
        "ssh-keygen -A",
        f"useradd -m -s /bin/bash {TARGET_LOGIN}",
        f"echo '{TARGET_PASSWORD}' | passwd --stdin {TARGET_LOGIN}",
        f"echo '{TARGET_LOGIN} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/praxis",
        "chmod 440 /etc/sudoers.d/praxis",
        "sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' "
        "/etc/ssh/sshd_config",
        f"/usr/sbin/sshd -p {port}",
    ]
    for step in steps:
        code, out = container.exec_run(["bash", "-lc", step])
        assert code == 0, (
            f"target bootstrap failed: {step}\nexit={code}\n"
            f"{out.decode('utf-8', errors='replace')[:400]}"
        )


def _wait_listening(container, port: int, timeout: float = 30.0) -> None:
    probe = f"exec 3<>/dev/tcp/127.0.0.1/{port} && exec 3>&-"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, _ = container.exec_run(["bash", "-lc", probe])
        if code == 0:
            return
        time.sleep(0.5)
    raise RuntimeError(f"sshd never listened on {port}")


_KEY_FILES = {
    "ssh-ed25519": "/etc/ssh/ssh_host_ed25519_key.pub",
    "ssh-rsa": "/etc/ssh/ssh_host_rsa_key.pub",
    "ecdsa-sha2-nistp256": "/etc/ssh/ssh_host_ecdsa_key.pub",
}


def _offered_public_key(container, key_type: str) -> str:
    """The base64 body of the host key of ``key_type`` the target now holds."""
    path = _KEY_FILES[key_type]
    code, out = container.exec_run(["bash", "-lc", f"cat {path}"])
    assert code == 0, out.decode("utf-8", errors="replace")[:200]
    return out.decode("utf-8", errors="replace").split()[1]


def _rotate_host_keys(container, port: int) -> None:
    """Give the target a completely new identity, the way a reinstall would."""
    code, out = container.exec_run(
        [
            "bash",
            "-lc",
            "pkill -x sshd; sleep 1; rm -f /etc/ssh/ssh_host_*; ssh-keygen -A; "
            f"/usr/sbin/sshd -p {port}",
        ]
    )
    assert code == 0, out.decode("utf-8", errors="replace")[:400]
    _wait_listening(container, port)


@pytest.fixture(scope="module")
def docker_client():
    import docker

    return docker.from_env()


def _start_target(docker_client, name: str, port: int) -> Dict[str, object]:
    try:
        docker_client.containers.get(name).remove(force=True)
    except Exception:  # pylint: disable=broad-except
        pass
    container = docker_client.containers.run(
        TARGET_IMAGE,
        command="sleep infinity",
        detach=True,
        remove=False,
        name=name,
        network=TARGET_NETWORK,
        hostname=name,
    )
    _bootstrap_target(container, port)
    _wait_listening(container, port)
    container.reload()
    networks = container.attrs["NetworkSettings"]["Networks"]
    net = networks.get(TARGET_NETWORK) or next(iter(networks.values()))
    return {
        "name": name,
        "ip": net["IPAddress"],
        "port": port,
        "container": container,
    }


@pytest.fixture(scope="module")
def el_targets(docker_client) -> Iterator[Dict[str, Dict[str, object]]]:
    """Two identical AlmaLinux hosts differing only in the port sshd answers on."""
    started: Dict[str, Dict[str, object]] = {}
    try:
        started["alt"] = _start_target(
            docker_client, f"praxis-p423-alt-{RUN_TAG}", ALT_PORT
        )
        started["control"] = _start_target(
            docker_client, f"praxis-p423-ctl-{RUN_TAG}", CONTROL_PORT
        )
        yield started
    finally:
        # Keeping the targets for inspection is a decision about cleanup only.
        # Returning out of the ``finally`` instead would also swallow whatever
        # exception was propagating out of the fixture.
        if os.environ.get("PRAXIS_E2E_KEEP", "").lower() not in ("1", "true", "yes"):
            for target in started.values():
                try:
                    target["container"].remove(force=True)
                except Exception:  # pylint: disable=broad-except
                    pass


# ------------------------------------------------------------------- backend


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_role(db, name: str) -> Role:
    role = db.query(Role).filter(Role.name == name).first()
    if role is None:
        role = Role(name=name, description=f"{name} role")
        db.add(role)
        db.commit()
    return role


def _ensure_catalogue(db, admin: User) -> Tuple[Distro, Group, SSHSecurityPolicy]:
    """The catalogue entry, group and verifying policy an operator would have."""
    distro = db.query(Distro).filter_by(name="AlmaLinux", version="9").first()
    if distro is None:
        distro = Distro(
            name="AlmaLinux",
            version="9",
            release_date=date(2022, 5, 26),
            end_of_life_date=date(2032, 5, 31),
        )
        db.add(distro)
    group = db.query(Group).filter(Group.name == "All Systems").first()
    if group is None:
        group = Group(name="All Systems", description="Default group")
        db.add(group)
    policy = (
        db.query(SSHSecurityPolicy).filter(SSHSecurityPolicy.name == "Default").first()
    )
    if policy is None:
        policy = SSHSecurityPolicy(
            name="Default",
            description="Verifying default policy",
            require_host_key_verification=True,
            created_by=admin.id,
        )
        db.add(policy)
    db.commit()
    assert policy.require_host_key_verification is not False
    return distro, group, policy


@pytest.fixture(scope="module")
def admin(db_session) -> User:
    for name in ("admin", "maintainer", "auditor", "viewer"):
        _ensure_role(db_session, name)
    username = f"p423-admin-{RUN_TAG}"
    user = User(
        username=username,
        email=f"{username}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    user.roles.append(_ensure_role(db_session, "admin"))
    db_session.add(user)
    db_session.commit()
    try:
        yield user
    finally:
        # Audit rows and the seeded policy reference this user, so it is
        # retired rather than deleted, the way leftover hosts are.
        user.is_active = False
        user.username = f"{username}-retired"
        db_session.commit()


@pytest.fixture(scope="module")
def api(db_session, admin) -> Iterator[TestClient]:
    """The real application, on the real database and the real Vault."""
    from app.api.main import app
    from app.db.session import get_db

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Enrollment runs from a module-scoped fixture, ahead of the per-test
    # entitlement default, so the edition is set here. The free host cap is a
    # licensing contract with its own tests; what this suite proves is the
    # host-key path.
    registry.enable_enterprise()

    app.dependency_overrides[get_db] = override_get_db
    ensure_vault_config(db_session)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        res = client.post(
            "/auth/login",
            data={"username": admin.username, "password": "testpass123"},
        )
        assert res.status_code == 200, res.text
        client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})
        yield client
    app.dependency_overrides.clear()
    registry.reset()


@pytest.fixture(scope="module")
def credential_id(api, db_session) -> Iterator[int]:
    """A real Vault-backed password credential, created through its own route."""
    name = f"p423-cred-{RUN_TAG}"
    res = api.post(
        "/credentials",
        json={
            "name": name,
            "auth_method": "password",
            "username": TARGET_LOGIN,
            "password": TARGET_PASSWORD,
        },
    )
    assert res.status_code == 201, res.text
    created = res.json()["id"]
    yield created
    # 400 means hosts still reference it: a finished host is renamed rather
    # than deleted, because audit rows point at it.
    res = api.delete(f"/credentials/{created}")
    assert res.status_code in (200, 204, 400, 404), res.text
    db_session.expire_all()


def _retire_stale_hosts(db, hostname: str, ip: str) -> None:
    """Free the unique hostname and address for a fresh row.

    A hard delete is unsafe because audit tables reference ``systems`` without
    cascade, so a leftover from an aborted run is renamed and readdressed into
    a documentation-range address instead.
    """
    stale = (
        db.query(System)
        .filter((System.hostname == hostname) | (System.ip_address == ip))
        .all()
    )
    for system in stale:
        tag = uuid.uuid4().hex[:8]
        system.hostname = f"{system.hostname}-retired-{tag}"
        system.ip_address = f"2001:db8::{tag[:4]}:{tag[4:]}"
    if stale:
        db.commit()


def _system(db, system_id: int) -> System:
    db.expire_all()
    return db.query(System).filter(System.id == system_id).one()


# ----------------------------------------------------------- guided onboarding


def _enroll(api, target, credential_id, distro, group, policy) -> Dict[str, object]:
    """Walk the wizard exactly as the UI does, and return what Finish created."""
    address = target["ip"]
    port = target["port"]

    res = api.post("/onboarding/drafts")
    assert res.status_code == 201, res.text
    draft = res.json()["draft"]
    public_id = draft["id"]

    res = api.put(
        f"/onboarding/drafts/{public_id}/connect",
        json={"address": address, "ssh_port": port, "hostname": target["name"]},
    )
    assert res.status_code == 200, res.text

    res = api.put(
        f"/onboarding/drafts/{public_id}/authenticate",
        json={"credential_id": credential_id, "ssh_security_policy_id": policy.id},
    )
    assert res.status_code == 200, res.text

    # First verification stops at the unknown host key and offers it for review.
    res = api.post(f"/onboarding/drafts/{public_id}/verify")
    assert res.status_code == 200, res.text
    draft = res.json()["draft"]
    offered = draft["host_key"]
    assert offered["fingerprint"], draft
    assert offered["decision"] == "pending"
    assert draft["verification"]["verified"] is False, draft["verification"]
    assert any(
        check["reason_code"] == "host_key_unknown"
        for check in draft["verification"]["checks"]
    ), draft["verification"]

    res = api.put(
        f"/onboarding/drafts/{public_id}/host-key",
        json={"fingerprint": offered["fingerprint"], "accept": True},
    )
    assert res.status_code == 200, res.text
    assert res.json()["draft"]["host_key"]["decision"] == "trusted"

    # With the key approved, verification authenticates with the credential.
    res = api.post(f"/onboarding/drafts/{public_id}/verify")
    assert res.status_code == 200, res.text
    draft = res.json()["draft"]
    assert draft["verification"]["verified"] is True, draft["verification"]

    res = api.post(f"/onboarding/drafts/{public_id}/discover")
    assert res.status_code == 200, res.text
    draft = res.json()["draft"]
    assert draft["discovery"]["package_family"] == "rpm", draft["discovery"]

    res = api.put(
        f"/onboarding/drafts/{public_id}/discovery-confirmation",
        json={"distro_id": distro.id},
    )
    assert res.status_code == 200, res.text

    res = api.put(
        f"/onboarding/drafts/{public_id}/organize",
        json={"group_id": group.id, "environment": "Production"},
    )
    assert res.status_code == 200, res.text

    res = api.post(f"/onboarding/drafts/{public_id}/confirm")
    assert res.status_code == 200, res.text
    confirmed = res.json()
    assert confirmed["preview"]["ssh_port"] == port
    finalize_token = confirmed["draft"]["finalize_token"]
    state_version = confirmed["draft"]["state_version"]

    res = api.post(
        f"/onboarding/drafts/{public_id}/finish",
        json={"finalize_token": finalize_token, "state_version": state_version},
    )
    assert res.status_code == 200, res.text
    finished = res.json()
    assert finished["created"] is True
    assert finished["status"] == "Active", finished
    return {"system_id": finished["system_id"], "fingerprint": offered["fingerprint"]}


@pytest.fixture(scope="module")
def enrolled(
    api, db_session, admin, el_targets, credential_id
) -> Iterator[Dict[str, Dict]]:
    """Both hosts enrolled through the wizard, cleaned up afterwards."""
    distro, group, policy = _ensure_catalogue(db_session, admin)
    for target in el_targets.values():
        _retire_stale_hosts(db_session, target["name"], target["ip"])
    results = {
        key: _enroll(api, target, credential_id, distro, group, policy)
        for key, target in el_targets.items()
    }
    yield results
    for target in el_targets.values():
        _retire_stale_hosts(db_session, target["name"], target["ip"])


# ------------------------------------------------------------------- the proof


def test_enrollment_persists_the_non_default_port_and_approved_key(
    db_session, el_targets, enrolled
):
    """Step 4 of the arc: what the wizard wrote down."""
    outcome = enrolled["alt"]
    system = _system(db_session, outcome["system_id"])
    metadata = (
        db_session.query(SystemMetadata)
        .filter(SystemMetadata.system_id == system.id)
        .one()
    )
    assert metadata.ssh_port == ALT_PORT
    assert system.ip_address == el_targets["alt"]["ip"]

    host_key = (
        db_session.query(SSHHostKey).filter(SSHHostKey.system_id == system.id).one()
    )
    assert host_key.verified is True
    assert host_key.fingerprint == outcome["fingerprint"]

    policy = system.ssh_security_policy
    assert policy is not None
    assert policy.require_host_key_verification is not False


def test_managed_reconnect_on_a_non_default_port(db_session, enrolled):
    """The regression itself: the ordinary managed-host path reconnects to a
    host on 2222 using the key approved during onboarding."""
    system_id = enrolled["alt"]["system_id"]
    with SSHService(db_session) as svc:
        result = svc.execute_command(system_id, "cat /etc/os-release")
    assert result["status"] == "success", result
    assert "AlmaLinux" in result["stdout"]


def test_managed_reconnect_on_the_default_port_control(db_session, enrolled):
    """The control that already worked, proving the change did not move it."""
    system_id = enrolled["control"]["system_id"]
    with SSHService(db_session) as svc:
        result = svc.execute_command(system_id, "cat /etc/os-release")
    assert result["status"] == "success", result
    assert "AlmaLinux" in result["stdout"]


def test_verified_key_is_preloaded_under_the_endpoint_name(db_session, enrolled):
    """The connection the reconnect made is pinned to ``[ip]:2222``, not to the
    bare address paramiko never asks for on this endpoint."""
    from app.services.ssh_service import configure_host_key_policy

    system = _system(db_session, enrolled["alt"]["system_id"])
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db_session, system)
    assert isinstance(client._policy, paramiko.RejectPolicy)
    names = []
    for entry in client.get_host_keys()._entries:
        names.extend(entry.hostnames)
    assert f"[{system.ip_address}]:{ALT_PORT}" in names
    assert system.ip_address not in names


def test_rotated_host_key_fails_closed_with_a_sanitized_error(
    db_session, el_targets, enrolled
):
    """A host that comes back with a different key is refused, and the refusal
    says what to do without quoting key material or credentials."""
    target = el_targets["alt"]
    container = target["container"]
    system_id = enrolled["alt"]["system_id"]

    stored = (
        db_session.query(SSHHostKey).filter(SSHHostKey.system_id == system_id).one()
    )
    before = stored.public_key

    _rotate_host_keys(container, ALT_PORT)
    assert _offered_public_key(container, stored.key_type) != before

    with SSHService(db_session) as svc:
        svc.close_connection(system_id)
        with pytest.raises(SSHConnectionError) as exc:
            svc.get_connection(system_id)

    message = str(exc.value)
    assert "Host key MISMATCH" in message
    assert "SSH Security > Host Keys" in message
    assert before not in message
    assert TARGET_PASSWORD not in message
    assert "does not match: got" not in message

    # The approved row was not quietly replaced by the key that was refused.
    db_session.expire_all()
    after = db_session.query(SSHHostKey).filter(SSHHostKey.system_id == system_id).one()
    assert after.public_key == before
