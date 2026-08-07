"""Integration-test fixtures (PRA-144).

These tests need docker-in-docker (a reachable `/var/run/docker.sock`) and a
real Vault reachable at ``VAULT_ADDR``. They are skipped unless
``PRAXIS_E2E=1`` is set and both prerequisites are satisfied.

Unlike the unit-test fixtures in ``tests/conftest.py``, we do NOT use the
``mock_vault`` auto-patch here — cert signing has to hit real Vault — and we
do NOT use the SAVEPOINT-rollback ``db`` fixture, because the services under
test commit cross-session from a background SSH path.
"""

from __future__ import annotations

import os
import time
from typing import Iterator

import pytest


def _e2e_available() -> tuple[bool, str]:
    if os.environ.get("PRAXIS_E2E", "").lower() not in ("1", "true", "yes"):
        return False, "PRAXIS_E2E not set"
    if not os.path.exists("/var/run/docker.sock"):
        return False, "/var/run/docker.sock not mounted"
    if not os.environ.get("VAULT_ADDR"):
        return False, "VAULT_ADDR not set"
    return True, ""


_available, _skip_reason = _e2e_available()

pytestmark = pytest.mark.skipif(not _available, reason=f"e2e skipped: {_skip_reason}")


TARGET_IMAGE = "ubuntu:22.04"
TARGET_NAME = "praxis-e2e-target"
TARGET_PASSWORD = "praxis-e2e-bootstrap"
TARGET_NETWORK = os.environ.get("PRAXIS_E2E_NETWORK", "praxis_backend_net")


@pytest.fixture(scope="module")
def docker_client():
    import docker

    return docker.from_env()


@pytest.fixture(scope="module")
def ssh_target(docker_client) -> Iterator[dict]:
    """Bring up a throwaway Ubuntu 22.04 container with sshd + sudo.

    Yields ``{"hostname", "ip", "port", "container"}``. Tears the container
    down at module teardown regardless of test outcome.
    """
    # Clean any leftover from a prior failed run.
    try:
        old = docker_client.containers.get(TARGET_NAME)
        old.remove(force=True)
    except Exception:  # pylint: disable=broad-except
        pass

    container = docker_client.containers.run(
        TARGET_IMAGE,
        command="sleep infinity",
        detach=True,
        remove=False,
        name=TARGET_NAME,
        network=TARGET_NETWORK,
        hostname=TARGET_NAME,
    )

    try:
        bootstrap = [
            "apt-get update -qq",
            # iproute2 is pulled in for parity with real hosts, but readiness below
            # does NOT depend on `ss` — minimal ubuntu:22.04 ships without it.
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "openssh-server sudo iproute2",
            "mkdir -p /run/sshd",
            "chmod 0755 /run/sshd",
            # Generate host keys explicitly — the apt postinst may not in a container
            # without systemd, and a keyless sshd refuses to start.
            "ssh-keygen -A",
            f"echo 'root:{TARGET_PASSWORD}' | chpasswd",
            "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config",
            "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config",
            "/usr/sbin/sshd",
        ]
        for cmd in bootstrap:
            exit_code, out = container.exec_run(["bash", "-lc", cmd])
            assert exit_code == 0, (
                f"bootstrap step failed: {cmd}\nexit={exit_code}\n"
                f"output={out.decode('utf-8', errors='replace')[:400]}"
            )

        container.reload()
        networks = container.attrs["NetworkSettings"]["Networks"]
        net = networks.get(TARGET_NETWORK) or next(iter(networks.values()))
        ip = net["IPAddress"]

        # Wait for sshd to be listening. Probe with bash's /dev/tcp built-in so the
        # check needs NO extra tools (`ss`/`netstat`/`nc` may be absent on a minimal
        # image — the original `ss` probe false-negatived here even though sshd was
        # up).
        probe = "exec 3<>/dev/tcp/127.0.0.1/22 && exec 3>&-"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            code, _ = container.exec_run(["bash", "-lc", probe])
            if code == 0:
                break
            time.sleep(0.5)
        else:
            # Capture diagnostics BEFORE teardown so a start failure is inspectable.
            diag_cmds = [
                "cat /etc/os-release | head -2",
                "ls -la /etc/ssh/ssh_host_*_key 2>&1 | head",
                "/usr/sbin/sshd -t 2>&1 | head",
                "ps -ef | grep -E '[s]shd' || echo 'no sshd process'",
                "cat /var/log/auth.log 2>/dev/null | tail -20 || echo 'no auth.log'",
            ]
            diag = []
            for c in diag_cmds:
                dc, dout = container.exec_run(["bash", "-lc", c])
                diag.append(
                    f"$ {c}\n[{dc}] {dout.decode('utf-8', errors='replace')[:500]}"
                )
            raise RuntimeError(
                "sshd did not start/listen on target within 30s.\n" + "\n".join(diag)
            )

        yield {
            "hostname": TARGET_NAME,
            "ip": ip,
            "port": 22,
            "container": container,
            "password": TARGET_PASSWORD,
        }
    finally:
        # Best-effort cleanup. Set PRAXIS_E2E_KEEP=1 to leave the container up for
        # post-failure inspection (`docker exec -it praxis-e2e-target bash`).
        if os.environ.get("PRAXIS_E2E_KEEP", "").lower() in ("1", "true", "yes"):
            return
        try:
            container.remove(force=True)
        except Exception:  # pylint: disable=broad-except
            pass
