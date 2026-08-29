"""PRA-413: Access Broker enrollment primitives against real deb and EL hosts.

Proves on disposable containers what a mocked SSH session cannot: that the
privileged-install and sshd-reload programs actually work where enrollment was
failing. Both targets run ``sshd`` launched directly, with no systemd bus. The
deb target additionally has a Debian-style ``service`` command while the EL
target has none, which is exactly the split that broke the old
``systemctl reload sshd || service ssh reload`` chain.

Vault is deliberately not required here. These tests exercise the host-facing
primitives, so they gate on ``PRAXIS_E2E`` and a usable docker socket only; the
cert-auth half of enrollment stays with the Vault-backed suites.
"""

from __future__ import annotations

import io
import os
import socket
import time

import pytest


def _e2e_skip_reason() -> str:
    if os.environ.get("PRAXIS_E2E", "").lower() not in ("1", "true", "yes"):
        return "PRAXIS_E2E not set"
    if not os.path.exists("/var/run/docker.sock"):
        return "/var/run/docker.sock not mounted"
    return ""


_skip = _e2e_skip_reason()
pytestmark = pytest.mark.skipif(bool(_skip), reason=f"e2e skipped: {_skip}")

import paramiko  # noqa: E402

from app.services.ssh_identity_service import (  # noqa: E402
    CA_KEY_PATH,
    PRINCIPALS_DIR,
    PRINCIPALS_SCRIPT_BODY,
    PRINCIPALS_SCRIPT_PATH,
    RELOAD_MECHANISM_PREFIX,
    build_managed_state_capture_command,
    build_managed_state_discard_command,
    build_managed_state_restore_command,
    build_privileged_install_command,
    build_sshd_reload_command,
    managed_file_backup_path,
    parse_managed_state,
    parse_reload_mechanism,
)
from app.services.ssh_service import (  # noqa: E402
    CertificateSSHClient,
    load_pinned_host_key,
)

BOOTSTRAP_LOGIN = "praxis"
BOOTSTRAP_PASSWORD = "praxis-pra413-bootstrap"
ROOT_PASSWORD = "praxis-pra413-root"
BANNER_PATH = "/etc/praxis-pra413-banner"
BANNER_TEXT = "praxis-pra413-reload-proof"

# The supported-host families the defect was reported against. Both are started
# without an init system so ``sshd`` is a plain foreground-launched daemon.
HOST_MATRIX = (
    {
        "key": "deb",
        "image": "ubuntu:26.04",
        "packages": (
            "apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y -qq openssh-server sudo"
        ),
    },
    {
        "key": "el",
        "image": "almalinux:9",
        "packages": "dnf install -y -q openssh-server sudo",
    },
)

_BOOTSTRAP = f"""
set -eu
mkdir -p /run/sshd && chmod 0755 /run/sshd
ssh-keygen -A
useradd -m -s /bin/bash {BOOTSTRAP_LOGIN}
echo '{BOOTSTRAP_LOGIN}:{BOOTSTRAP_PASSWORD}' | chpasswd
echo "root:{ROOT_PASSWORD}" | chpasswd
printf '{BOOTSTRAP_LOGIN} ALL=(ALL) NOPASSWD: ALL\\n' > /etc/sudoers.d/{BOOTSTRAP_LOGIN}
chmod 0440 /etc/sudoers.d/{BOOTSTRAP_LOGIN}
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
/usr/sbin/sshd
"""


def _exec(container, command: str):
    code, output = container.exec_run(["sh", "-c", command])
    return code, output.decode("utf-8", errors="replace")


def _endpoint(container) -> tuple:
    """Reachable ``(host, port)`` for the target from wherever pytest runs.

    The suite runs both on a developer host (published port) and inside the
    backend container on a shared docker network (container address), so the
    reachable endpoint is probed rather than assumed.
    """
    container.reload()
    settings = container.attrs["NetworkSettings"]
    candidates = []
    for network in settings.get("Networks", {}).values():
        if network.get("IPAddress"):
            candidates.append((network["IPAddress"], 22))
    published = settings.get("Ports", {}).get("22/tcp") or []
    for binding in published:
        candidates.append(("127.0.0.1", int(binding["HostPort"])))

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        for host, port in candidates:
            try:
                with socket.create_connection((host, port), timeout=2):
                    return host, port
            except OSError:
                continue
        time.sleep(1)
    raise RuntimeError(f"target {container.name} never accepted a TCP connection")


@pytest.fixture(scope="module")
def docker_client():
    import docker

    return docker.from_env()


@pytest.fixture(scope="module", params=HOST_MATRIX, ids=lambda spec: spec["key"])
def target(request, docker_client):
    """A disposable host of one family with sshd running under no init system."""
    spec = request.param
    name = f"praxis-pra413-{spec['key']}"
    try:
        docker_client.containers.get(name).remove(force=True)
    except Exception:  # pylint: disable=broad-except
        pass

    container = docker_client.containers.run(
        spec["image"],
        command="sleep infinity",
        detach=True,
        name=name,
        hostname=name,
        ports={"22/tcp": None},
    )
    try:
        for step in (spec["packages"], _BOOTSTRAP):
            code, output = _exec(container, step)
            assert code == 0, f"{spec['key']} bootstrap failed: {output[:600]}"
        host, port = _endpoint(container)
        yield {
            "key": spec["key"],
            "image": spec["image"],
            "container": container,
            "host": host,
            "port": port,
        }
    finally:
        if os.environ.get("PRAXIS_E2E_KEEP", "").lower() not in ("1", "true", "yes"):
            try:
                container.remove(force=True)
            except Exception:  # pylint: disable=broad-except
                pass


def _connect(target, login=BOOTSTRAP_LOGIN, password=BOOTSTRAP_PASSWORD, attempts=6):
    """Open a session, retrying over the window in which a daemon is re-execing."""
    last = None
    for attempt in range(attempts):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target["host"],
                port=target["port"],
                username=login,
                password=password,
                allow_agent=False,
                look_for_keys=False,
                timeout=20,
                banner_timeout=20,
            )
            return client
        except Exception as error:  # pylint: disable=broad-except
            last = error
            client.close()
            if attempt + 1 < attempts:
                time.sleep(2)
    raise AssertionError(f"could not reach {target['key']} target: {last}")


@pytest.fixture
def session(target):
    client = _connect(target)
    try:
        yield client
    finally:
        client.close()


def _run(client, command: str):
    _, stdout, stderr = client.exec_command(command, timeout=60)
    exit_code = stdout.channel.recv_exit_status()
    return (
        exit_code,
        stdout.read().decode("utf-8", errors="replace"),
        stderr.read().decode("utf-8", errors="replace"),
    )


def _stat(client, path: str) -> str:
    code, out, _ = _run(client, f"stat -c '%a %U %G' {path}")
    assert code == 0, f"{path} is missing"
    return out.strip()


def _read(client, path: str) -> str:
    """Read a managed file's bytes with privilege.

    Managed files are root-owned and some are not world-readable, so reading as
    the bootstrap login would return empty output and make a permission problem
    look like a content mismatch.
    """
    code, out, err = _run(client, f"sudo -n cat {path}")
    assert code == 0, f"could not read {path}: {err}"
    return out


# ------------------------------------------------------- privileged install


def test_target_runs_sshd_without_an_init_system(session):
    """Guard the premise: these are the conditions enrollment used to fail on."""
    code, _, _ = _run(session, "test -d /run/systemd/system")
    assert code != 0, "target unexpectedly booted with systemd"
    assert _run(session, "test -x /usr/sbin/sshd")[0] == 0


def test_privileged_install_writes_content_mode_and_owner(session):
    ca_key = "ssh-ed25519 AAAATESTCAPRA413 praxis-ca"
    code, _, err = _run(
        session, build_privileged_install_command(f"{ca_key}\n", CA_KEY_PATH, "0644")
    )
    assert code == 0, err
    assert _stat(session, CA_KEY_PATH) == "644 root root"
    assert _read(session, CA_KEY_PATH) == f"{ca_key}\n"


def test_privileged_install_is_idempotent_and_leaves_no_staging_file(session):
    program = build_privileged_install_command(
        "ssh-ed25519 AAAAREPEAT praxis-ca\n", CA_KEY_PATH, "0644"
    )
    for _ in range(2):
        assert _run(session, program)[0] == 0
    assert _stat(session, CA_KEY_PATH) == "644 root root"
    code, out, _ = _run(session, f"ls {CA_KEY_PATH}.praxis-tmp")
    assert code != 0, f"staging copy left behind: {out}"


def test_principals_helper_and_seed_install_with_required_modes(session):
    assert (
        _run(
            session,
            build_privileged_install_command(
                PRINCIPALS_SCRIPT_BODY, PRINCIPALS_SCRIPT_PATH, "0755"
            ),
        )[0]
        == 0
    )
    assert _stat(session, PRINCIPALS_SCRIPT_PATH) == "755 root root"

    assert (
        _run(session, f"sudo -n install -d -m 0755 -o root -g root {PRINCIPALS_DIR}")[0]
        == 0
    )
    seed = f"{PRINCIPALS_DIR}/{BOOTSTRAP_LOGIN}"
    assert (
        _run(
            session,
            build_privileged_install_command(f"{BOOTSTRAP_LOGIN}\n", seed, "0644"),
        )[0]
        == 0
    )
    assert _stat(session, seed) == "644 root root"
    # sshd runs the helper as an unprivileged user, so it must work there too.
    code, out, _ = _run(session, f"{PRINCIPALS_SCRIPT_PATH} {BOOTSTRAP_LOGIN}")
    assert code == 0
    assert out.strip() == BOOTSTRAP_LOGIN
    assert _run(session, f"{PRINCIPALS_SCRIPT_PATH} nobody-here")[0] == 0


# ------------------------------------------------- managed-file transaction
#
# The rollback point an enrollment takes before it overwrites a managed file.
# Proving this against a real filesystem is what makes the deploy and revoke
# rollback paths trustworthy: mode and ownership have to survive the round trip.

_ROLLBACK_TAG = "itest"
_MANAGED_PROBE = "/etc/praxis-pra413-managed"


def _capture(session, path):
    backup = managed_file_backup_path(path, _ROLLBACK_TAG)
    code, out, err = _run(session, build_managed_state_capture_command(path, backup))
    assert code == 0, err
    state = parse_managed_state(out)
    assert state is not None, out
    return backup, state


def test_capture_reports_absent_and_rollback_deletes_what_it_created(session):
    _run(session, f"sudo -n rm -f {_MANAGED_PROBE} {_MANAGED_PROBE}.praxis-itest.bak")
    backup, existed = _capture(session, _MANAGED_PROBE)
    assert existed is False
    # Nothing was copied aside, because there was nothing to copy.
    assert _run(session, f"test -e {backup}")[0] != 0

    assert (
        _run(
            session,
            build_privileged_install_command("created\n", _MANAGED_PROBE, "0600"),
        )[0]
        == 0
    )
    assert _stat(session, _MANAGED_PROBE) == "600 root root"

    code, _, err = _run(
        session, build_managed_state_restore_command(_MANAGED_PROBE, backup, existed)
    )
    assert code == 0, err
    assert _run(session, f"test -e {_MANAGED_PROBE}")[0] != 0
    assert _run(session, f"test -e {backup}")[0] != 0


def test_capture_and_restore_preserve_bytes_mode_and_ownership(session):
    """The redeployment case: prior content must come back byte for byte."""
    _run(session, f"sudo -n rm -f {_MANAGED_PROBE} {_MANAGED_PROBE}.praxis-itest.bak")
    assert (
        _run(
            session,
            build_privileged_install_command(
                "original bytes\n", _MANAGED_PROBE, "0640"
            ),
        )[0]
        == 0
    )
    assert _stat(session, _MANAGED_PROBE) == "640 root root"

    backup, existed = _capture(session, _MANAGED_PROBE)
    assert existed is True
    assert _stat(session, backup) == "640 root root"

    # Overwrite with different bytes and a different mode, as a redeploy would.
    assert (
        _run(
            session,
            build_privileged_install_command("replacement\n", _MANAGED_PROBE, "0644"),
        )[0]
        == 0
    )
    assert _read(session, _MANAGED_PROBE) == "replacement\n"

    code, _, err = _run(
        session, build_managed_state_restore_command(_MANAGED_PROBE, backup, existed)
    )
    assert code == 0, err
    assert _read(session, _MANAGED_PROBE) == "original bytes\n"
    assert _stat(session, _MANAGED_PROBE) == "640 root root"
    # The rollback copy is consumed by the restore.
    assert _run(session, f"test -e {backup}")[0] != 0
    _run(session, f"sudo -n rm -f {_MANAGED_PROBE}")


def test_capture_clears_a_rollback_copy_left_by_an_interrupted_run(session):
    _run(session, f"sudo -n rm -f {_MANAGED_PROBE}")
    backup = managed_file_backup_path(_MANAGED_PROBE, _ROLLBACK_TAG)
    assert (
        _run(session, build_privileged_install_command("stale\n", backup, "0644"))[0]
        == 0
    )
    _, existed = _capture(session, _MANAGED_PROBE)
    # The path does not exist, so the stale copy must be gone rather than left
    # to be restored over a file this operation never touched.
    assert existed is False
    assert _run(session, f"test -e {backup}")[0] != 0


def test_discard_removes_the_rollback_copy(session):
    _run(session, f"sudo -n rm -f {_MANAGED_PROBE}")
    assert (
        _run(
            session,
            build_privileged_install_command("keep\n", _MANAGED_PROBE, "0644"),
        )[0]
        == 0
    )
    backup, existed = _capture(session, _MANAGED_PROBE)
    assert existed is True
    assert _run(session, build_managed_state_discard_command(backup))[0] == 0
    assert _run(session, f"test -e {backup}")[0] != 0
    # Discarding a rollback copy never touches the live file.
    assert _read(session, _MANAGED_PROBE) == "keep\n"
    _run(session, f"sudo -n rm -f {_MANAGED_PROBE}")


# ------------------------------------------------------------------- reload


def _master_pid(client) -> str:
    return _run(client, "cat /run/sshd.pid")[1].strip()


def test_reload_applies_the_configuration_without_dropping_the_session(target, session):
    """The whole point: the daemon re-reads its config wherever it is supervised."""
    assert (
        _run(
            session,
            build_privileged_install_command(f"{BANNER_TEXT}\n", BANNER_PATH, "0644"),
        )[0]
        == 0
    )
    before = _master_pid(session)
    _run(
        session,
        f"printf '\\nBanner {BANNER_PATH}\\n' | sudo -n tee -a /etc/ssh/sshd_config"
        " > /dev/null",
    )
    try:
        code, out, err = _run(session, build_sshd_reload_command())
        assert code == 0, err
        mechanism = parse_reload_mechanism(out)
        assert mechanism, out
        assert RELOAD_MECHANISM_PREFIX not in err

        # The session that applied the change keeps working.
        assert _run(session, "echo alive")[1].strip() == "alive"
        # The daemon was reloaded, not restarted out from under the fleet.
        assert _master_pid(session) == before
        # A brand-new connection sees the new configuration.
        fresh = _connect(target)
        try:
            banner = fresh.get_transport().get_banner()
        finally:
            fresh.close()
        assert banner is not None and BANNER_TEXT in banner.decode()
    finally:
        _run(
            session,
            f"sudo -n sed -i '\\|Banner {BANNER_PATH}|d' /etc/ssh/sshd_config",
        )
        _run(session, build_sshd_reload_command())


def test_reload_reports_the_mechanism_its_family_actually_needs(target, session):
    code, out, err = _run(session, build_sshd_reload_command())
    assert code == 0, err
    mechanism = parse_reload_mechanism(out)
    # No systemd bus is running, so the systemd branch must not claim the reload.
    assert mechanism and not mechanism.startswith("systemd-"), mechanism
    if target["key"] == "el":
        # EL minimal images ship no ``service`` command and no init scripts, so
        # the only safe path left is a signal to the located daemon.
        assert mechanism.startswith("sighup:"), mechanism


def test_reload_refuses_a_configuration_sshd_would_reject(target, session):
    _run(session, "sudo -n cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.pra413")
    try:
        _run(
            session,
            "printf 'PraxisNotADirective yes\\n' | sudo -n tee -a"
            " /etc/ssh/sshd_config > /dev/null",
        )
        code, out, err = _run(session, build_sshd_reload_command())
        assert code == 91, (code, out, err)
        assert "sshd rejected the configuration" in err
        assert parse_reload_mechanism(out) is None
        # The running daemon was never signalled, so logins still work.
        _connect(target).close()
    finally:
        _run(
            session,
            "sudo -n cp -a /etc/ssh/sshd_config.pra413 /etc/ssh/sshd_config",
        )
        _run(session, "sudo -n rm -f /etc/ssh/sshd_config.pra413")


SECOND_DAEMON_PID_FILE = "/tmp/pra413-second-sshd.pid"


def _disable_service_managers(container):
    """Strip the host down to a directly launched daemon with no supervisor."""
    _exec(
        container,
        "if [ -x /usr/sbin/service ]; then"
        " mv /usr/sbin/service /usr/sbin/service.pra413; fi",
    )
    _exec(
        container,
        "for script in /etc/init.d/sshd /etc/init.d/ssh; do"
        ' [ -f "$script" ] && chmod -x "$script"; done; true',
    )


def _restore_service_managers(container):
    _exec(
        container,
        "if [ -x /usr/sbin/service.pra413 ]; then"
        " mv /usr/sbin/service.pra413 /usr/sbin/service; fi",
    )
    _exec(
        container,
        "for script in /etc/init.d/sshd /etc/init.d/ssh; do"
        ' [ -f "$script" ] && chmod +x "$script"; done; true',
    )


def _kill_master(container):
    """Stop the master daemon only; sessions it already forked stay alive."""
    _exec(container, "kill $(cat /run/sshd.pid) 2>/dev/null; rm -f /run/sshd.pid")
    time.sleep(1)


def _reset_daemon(container):
    """Leave exactly one directly launched sshd with a fresh pid file."""
    _exec(
        container,
        "for entry in /proc/[0-9]*; do pid=${entry#/proc/};"
        ' exe=$(readlink "$entry/exe" 2>/dev/null) || continue;'
        ' [ "$exe" = /usr/sbin/sshd ] || continue; kill -9 "$pid"; done; true',
    )
    _exec(container, f"rm -f /run/sshd.pid {SECOND_DAEMON_PID_FILE}")
    code, output = _exec(container, "/usr/sbin/sshd")
    assert code == 0, f"could not restart sshd: {output[:400]}"
    time.sleep(1)


def test_install_and_reload_work_for_a_root_credential_without_sudo(target):
    """A minimal image registered with a root credential may ship no sudo."""
    container = target["container"]
    _exec(
        container,
        "if [ -e /usr/bin/sudo ]; then mv /usr/bin/sudo /usr/bin/sudo.off; fi",
    )
    try:
        root = _connect(target, login="root", password=ROOT_PASSWORD)
        try:
            assert _run(root, "command -v sudo")[0] != 0
            assert _run(root, "id -u")[1].strip() == "0"
            code, _, err = _run(
                root,
                build_privileged_install_command(
                    "ssh-ed25519 AAAAROOTPATH praxis-ca\n", CA_KEY_PATH, "0644"
                ),
            )
            assert code == 0, err
            assert _stat(root, CA_KEY_PATH) == "644 root root"

            code, out, err = _run(root, build_sshd_reload_command())
            assert code == 0, err
            assert parse_reload_mechanism(out), out
        finally:
            root.close()
    finally:
        _exec(
            container,
            "if [ -e /usr/bin/sudo.off ]; then mv /usr/bin/sudo.off /usr/bin/sudo; fi",
        )


# --------------------------------------- RSA certificate authentication, live
#
# Proves against a real sshd that an RSA certificate is accepted and names the
# signature algorithm that was actually agreed. Supported servers dropped the
# SHA-1 "ssh-rsa" family from their default PubkeyAcceptedAlgorithms, so a
# certificate offered under it is never evaluated; only a live handshake shows
# which one the two sides settled on.
#
# The certificate authority here is generated inside the target, so the proof
# needs no Vault: what is under test is the algorithm negotiation, not minting.

_TEST_CA = "/tmp/pra413-ca"
_TEST_USER_KEY = "/tmp/pra413-user"

_RETIRED_ALGORITHMS = ("ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "ssh-dss")


def _remote_banner(target) -> str:
    probe = paramiko.Transport((target["host"], target["port"]))
    try:
        probe.start_client(timeout=20)
        return probe.remote_version
    finally:
        probe.close()


def _issue_certificate(session):
    """Mint an RSA user certificate on the target and return (key, cert) text."""
    _run(session, f"rm -f {_TEST_CA}* {_TEST_USER_KEY}*")
    assert _run(session, f"ssh-keygen -q -t rsa -b 2048 -N '' -f {_TEST_CA}")[0] == 0
    assert (
        _run(session, f"ssh-keygen -q -t rsa -b 2048 -N '' -f {_TEST_USER_KEY}")[0] == 0
    )
    # -t rsa-sha2-512 is the CA signature algorithm; modern OpenSSH rejects a
    # SHA-1 CA signature regardless of what the client offers.
    code, _, err = _run(
        session,
        f"ssh-keygen -q -s {_TEST_CA} -I pra413 -n {BOOTSTRAP_LOGIN} "
        f"-t rsa-sha2-512 -V +5m {_TEST_USER_KEY}.pub",
    )
    assert code == 0, err
    key_text = _run(session, f"cat {_TEST_USER_KEY}")[1]
    cert_text = _run(session, f"cat {_TEST_USER_KEY}-cert.pub")[1]
    ca_text = _run(session, f"cat {_TEST_CA}.pub")[1]
    return key_text, cert_text, ca_text


def _certificate_key(key_text, cert_text):
    key = paramiko.RSAKey.from_private_key(io.StringIO(key_text))
    key.load_certificate(cert_text)
    return key


@pytest.fixture
def certificate_trust(target, session):
    """Trust a throwaway CA on the target, and take it away again afterwards."""
    key_text, cert_text, ca_text = _issue_certificate(session)
    _run(session, "sudo -n cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.pra413ca")
    try:
        assert (
            _run(
                session, build_privileged_install_command(ca_text, CA_KEY_PATH, "0644")
            )[0]
            == 0
        )
        _run(
            session,
            f"printf '\nTrustedUserCAKeys {CA_KEY_PATH}\n' | sudo -n tee -a"
            " /etc/ssh/sshd_config > /dev/null",
        )
        code, _, err = _run(session, build_sshd_reload_command())
        assert code == 0, err
        yield _certificate_key(key_text, cert_text)
    finally:
        _run(
            session,
            "sudo -n cp -a /etc/ssh/sshd_config.pra413ca /etc/ssh/sshd_config",
        )
        _run(session, "sudo -n rm -f /etc/ssh/sshd_config.pra413ca")
        _run(session, f"sudo -n rm -f {CA_KEY_PATH}")
        _run(session, f"rm -f {_TEST_CA}* {_TEST_USER_KEY}*")
        _run(session, build_sshd_reload_command())


# ------------------------------------------- pinned host keys, live
#
# ``ssh-keygen -A`` gives each target the host key set a real install has, so
# what the daemon offers here is what trust-on-first-use would capture in the
# field. Reading it back is what proves a pinned key can be verified again on
# the next connection.


def _offered_host_key(target, key_algorithms=None):
    """Connect far enough to read the host key the daemon presents."""
    client = CertificateSSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {}
    if key_algorithms is not None:
        offered = set(paramiko.Transport._key_info) - set(key_algorithms)
        kwargs["disabled_algorithms"] = {"keys": sorted(offered)}
    try:
        client.connect(
            hostname=target["host"],
            port=target["port"],
            username=BOOTSTRAP_LOGIN,
            password=BOOTSTRAP_PASSWORD,
            allow_agent=False,
            look_for_keys=False,
            timeout=20,
            **kwargs,
        )
        return client.get_transport().get_remote_server_key()
    finally:
        client.close()


@pytest.mark.parametrize(
    "key_algorithms,expected",
    [
        (["ecdsa-sha2-nistp256"], "ecdsa-sha2-nistp256"),
        (["ssh-ed25519"], "ssh-ed25519"),
        (["rsa-sha2-512", "rsa-sha2-256"], "ssh-rsa"),
    ],
    ids=["ecdsa", "ed25519", "rsa"],
)
def test_a_host_key_a_real_sshd_offers_can_be_pinned(target, key_algorithms, expected):
    """Capture and re-read agree against a live daemon, per algorithm.

    The RSA case is the one worth stating: the daemon and Praxis agree an
    ``rsa-sha2-*`` host key algorithm, and the key that arrives is still named
    ``ssh-rsa`` because that is what the material is called. Pinning has to
    accept that name without accepting the SHA-1 signature algorithm sharing
    it.
    """
    offered = _offered_host_key(target, key_algorithms)
    assert offered.get_name() == expected

    reloaded = load_pinned_host_key(
        offered.get_name(), offered.get_base64(), hostname=target["host"]
    )

    assert reloaded.asbytes() == offered.asbytes()
    assert reloaded == offered


def test_rsa_certificate_authenticates_under_an_rsa_sha2_algorithm(
    target, certificate_trust
):
    """The headline contract: an RSA certificate is accepted, under RSA-SHA2."""
    client = CertificateSSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=target["host"],
            port=target["port"],
            username=BOOTSTRAP_LOGIN,
            pkey=certificate_trust,
            allow_agent=False,
            look_for_keys=False,
            timeout=20,
        )
        transport = client.get_transport()
        agreed = transport._agreed_pubkey_algorithm
        assert agreed.startswith("rsa-sha2-"), agreed
        assert agreed.endswith("-cert-v01@openssh.com"), agreed
        # The peer's real banner is read, not substituted.
        assert "OpenSSH" in transport.remote_version
        _, stdout, _ = client.exec_command("echo cert_ok", timeout=30)
        assert stdout.read().decode().strip() == "cert_ok"
    finally:
        client.close()


def test_the_live_handshake_agrees_no_retired_algorithm(target, certificate_trust):
    """What a real sshd and Praxis settle on, end to end.

    A mocked negotiation can only show what Praxis offers. This shows what was
    agreed with a live daemon: no SHA-1 signature, no SHA-1 key exchange.
    """
    client = CertificateSSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=target["host"],
            port=target["port"],
            username=BOOTSTRAP_LOGIN,
            pkey=certificate_trust,
            allow_agent=False,
            look_for_keys=False,
            timeout=20,
        )
        transport = client.get_transport()

        # Retained from the negotiation: the signature algorithm the daemon
        # accepted, and the host key algorithm it was identified under.
        assert transport._agreed_pubkey_algorithm not in _RETIRED_ALGORITHMS
        assert transport._agreed_pubkey_algorithm.startswith("rsa-sha2-")
        assert transport.host_key_type not in _RETIRED_ALGORITHMS
        assert not transport.host_key_type.endswith("-sha1")

        # Paramiko discards the key exchange engine once the exchange is done,
        # so the agreed name is not readable afterwards. What is readable is
        # the proposal, and a completed handshake means the daemon chose from
        # it: offering no SHA-1 and no GSSAPI group is therefore proof that
        # neither was agreed.
        assert transport.is_active()
        for name in transport.preferred_kex:
            assert not name.endswith("-sha1"), name
            assert not name.startswith("gss-"), name
        for name in transport.preferred_pubkeys + transport.preferred_keys:
            assert name not in _RETIRED_ALGORITHMS, name
    finally:
        client.close()


# ---------------------------------------------------- controlled systemd host
#
# Neither container boots systemd, so unit selection is exercised by replacing
# systemctl with a recorder that reports exactly one unit active. The real
# daemon is never signalled on these paths, which is the point: the helper must
# stop at the first mechanism that works.

_ACTIVE_UNIT_FILE = "/tmp/pra413-active-unit"
_SYSTEMCTL_STUB = f"""#!/bin/sh
active=$(cat {_ACTIVE_UNIT_FILE} 2>/dev/null || echo none)
action=$1
shift
if [ "$1" = "--quiet" ]; then shift; fi
case "$action" in
  is-active) [ "$1" = "$active" ] && exit 0; exit 3 ;;
  reload) [ "$1" = "$active" ] && exit 0; exit 1 ;;
esac
exit 1
"""


@pytest.fixture
def systemd_stub(target):
    """Make the target look like a systemd host with one controllable unit."""
    container = target["container"]
    _exec(container, "mkdir -p /run/systemd/system")
    _exec(container, "mv /usr/bin/systemctl /usr/bin/systemctl.pra413")
    _exec(
        container,
        "cat > /usr/bin/systemctl <<'PRA413_STUB'\n"
        + _SYSTEMCTL_STUB
        + "PRA413_STUB\nchmod 0755 /usr/bin/systemctl",
    )

    def _set_active(unit: str) -> None:
        _exec(container, f"printf '%s' {unit} > {_ACTIVE_UNIT_FILE}")

    try:
        yield _set_active
    finally:
        _exec(container, "mv -f /usr/bin/systemctl.pra413 /usr/bin/systemctl")
        _exec(container, f"rm -rf /run/systemd/system {_ACTIVE_UNIT_FILE}")


@pytest.mark.parametrize(
    "unit,expected",
    [
        ("sshd.service", "systemd-unit:sshd.service"),
        ("ssh.service", "systemd-unit:ssh.service"),
        ("sshd.socket", "systemd-socket:sshd.socket"),
        ("ssh.socket", "systemd-socket:ssh.socket"),
    ],
)
def test_reload_selects_the_active_systemd_unit(session, systemd_stub, unit, expected):
    systemd_stub(unit)
    code, out, err = _run(session, build_sshd_reload_command())
    assert code == 0, err
    assert parse_reload_mechanism(out) == expected


def test_reload_falls_past_systemd_when_no_sshd_unit_is_active(session, systemd_stub):
    systemd_stub("unrelated.service")
    code, out, err = _run(session, build_sshd_reload_command())
    assert code == 0, err
    mechanism = parse_reload_mechanism(out)
    assert mechanism and not mechanism.startswith("systemd-"), mechanism


# ------------------------------------------- directly launched daemon paths
#
# These tests dismantle the target's service managers and daemons, so they run
# last and reset the host through the container rather than through the SSH
# session they are about to break.


def test_reload_signals_the_daemon_directly_when_no_service_manager_exists(
    target, session
):
    container = target["container"]
    _disable_service_managers(container)
    try:
        master = _master_pid(session)
        code, out, err = _run(session, build_sshd_reload_command())
        assert code == 0, err
        assert parse_reload_mechanism(out) == f"sighup:pid-file:{master}"

        # And again with the pid file gone, so the process table is the only
        # source of truth for which process is the master.
        _exec(container, "mv /run/sshd.pid /run/sshd.pid.pra413")
        code, out, err = _run(session, build_sshd_reload_command())
        assert code == 0, err
        assert parse_reload_mechanism(out) == f"sighup:process-table:{master}"
    finally:
        _reset_daemon(container)
        _restore_service_managers(container)
    _connect(target).close()


def test_reload_fails_closed_when_the_master_is_ambiguous(target, session):
    """Never guess, never signal every sshd: refuse and say why."""
    container = target["container"]
    _disable_service_managers(container)
    try:
        _exec(container, "mv /run/sshd.pid /run/sshd.pid.pra413")
        code, output = _exec(
            container,
            f"/usr/sbin/sshd -p 2222 -o PidFile={SECOND_DAEMON_PID_FILE}",
        )
        assert code == 0, output
        time.sleep(1)

        code, out, err = _run(session, build_sshd_reload_command())
        assert code == 93, (code, out, err)
        assert "ambiguous" in err
        assert parse_reload_mechanism(out) is None
        # Neither daemon was signalled, so the host still serves logins.
        assert _run(session, "echo alive")[1].strip() == "alive"
    finally:
        _reset_daemon(container)
        _restore_service_managers(container)
    _connect(target).close()


def test_reload_fails_closed_when_no_daemon_is_running(target, session):
    container = target["container"]
    _disable_service_managers(container)
    try:
        _kill_master(container)
        code, out, err = _run(session, build_sshd_reload_command())
        assert code == 93, (code, out, err)
        assert "no running sshd master process" in err
        assert parse_reload_mechanism(out) is None
    finally:
        _reset_daemon(container)
        _restore_service_managers(container)
    _connect(target).close()
