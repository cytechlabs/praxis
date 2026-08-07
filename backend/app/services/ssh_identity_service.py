"""
SSH identity service: deploy and revoke Vault CA trust on remote systems (PRA-44).

Zero-trust model: once the Vault SSH CA public key is installed at
/etc/ssh/trusted_user_ca_keys and referenced from sshd_config, all
future SSH connections from Praxis use short-lived Vault-signed user
certs. Username/password stays functional as a fallback.

PRA-138 extends this with:
  * ``/usr/local/bin/praxis-principals`` — shell wrapper that sshd invokes via
    ``AuthorizedPrincipalsCommand`` to resolve per-login authorised cert
    principals from ``/etc/praxis/principals.d/<login>`` (populated by
    PRA-137 provisioning).
  * ``AuthorizedPrincipalsCommand`` + ``AuthorizedPrincipalsCommandUser``
    directives appended to sshd_config with their own marker.
  * Self-test that mints a short-lived cert for the bootstrap credential's
    username and attempts a cert-auth login after reload. On failure, the
    sshd_config backup is restored and sshd reloaded again.
"""

import logging
import shlex
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.access_models import HostUserState
from ..db.models import System
from . import ssh_allowlist_diagnostics as allowlist_diag
from .ssh_service import SSHConnectionError, SSHService
from .vault_service import VaultConnectionError, VaultSecretError, VaultService

logger = logging.getLogger(__name__)

CA_KEY_PATH = "/etc/ssh/trusted_user_ca_keys"
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
SSHD_CONFIG_MARKER = "# Praxis zero-trust CA (PRA-44)"
SSHD_CONFIG_DIRECTIVE = f"TrustedUserCAKeys {CA_KEY_PATH}"

# PRA-138: AuthorizedPrincipalsCommand wiring
PRINCIPALS_SCRIPT_PATH = "/usr/local/bin/praxis-principals"
PRINCIPALS_DIR = "/etc/praxis/principals.d"
SSHD_PRINCIPALS_MARKER = "# Praxis principals hook (PRA-138)"
SSHD_PRINCIPALS_DIRECTIVES = (
    f"AuthorizedPrincipalsCommand {PRINCIPALS_SCRIPT_PATH} %u\n"
    "AuthorizedPrincipalsCommandUser nobody"
)

# Idempotent wrapper script. Prints the contents of
# /etc/praxis/principals.d/<login> (one cert principal per line) or nothing
# if the file is missing. Never errors — sshd treats non-zero exit as deny.
PRINCIPALS_SCRIPT_BODY = """\
#!/bin/sh
# praxis-principals <login> — emits authorised SSH cert principals for a login.
# Consumed by sshd's AuthorizedPrincipalsCommand directive (PRA-138).
set -eu
login="$1"
file="/etc/praxis/principals.d/$login"
if [ -r "$file" ]; then
  cat "$file"
fi
"""


class SSHIdentityError(Exception):
    """Exception raised for SSH identity deployment errors."""


class SSHIdentityService:
    """Deploy / revoke Vault SSH CA trust on remote systems."""

    def __init__(self, db: Session):
        self.db = db
        self.ssh_service = SSHService(db)
        self.vault_service = VaultService(db)

    def deploy_ca_trust(self, system_id: int) -> Dict[str, Any]:
        """Push the Vault SSH CA public key to a system and enable TrustedUserCAKeys.

        Uses the system's existing credential (username/password) to open the
        onboarding SSH session. Idempotent — safe to call on already-deployed
        systems.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        try:
            ca_pubkey = self.vault_service.get_ssh_ca_public_key()
        except (VaultConnectionError, VaultSecretError) as e:
            raise SSHIdentityError(f"Vault SSH CA not available: {e}") from e

        if not ca_pubkey:
            raise SSHIdentityError("Vault returned no CA public key")

        ca_pubkey = ca_pubkey.strip()

        # Use onboarding SSH session (password or existing key — not cert auth)
        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        # Write the CA pubkey (quoted heredoc to avoid shell escaping)
        cmd_write = (
            f"sudo install -m 0644 -o root -g root /dev/stdin {CA_KEY_PATH} "
            f"<<'PRAXIS_CA_EOF'\n{ca_pubkey}\nPRAXIS_CA_EOF"
        )
        self._run(client, cmd_write, f"write {CA_KEY_PATH}")

        # Add the TrustedUserCAKeys directive if not already present
        cmd_sshd = (
            f"if ! grep -qF '{SSHD_CONFIG_DIRECTIVE}' {SSHD_CONFIG_PATH}; then "
            f"echo '' | sudo tee -a {SSHD_CONFIG_PATH} > /dev/null && "
            f"echo '{SSHD_CONFIG_MARKER}' | sudo tee -a {SSHD_CONFIG_PATH} > /dev/null && "
            f"echo '{SSHD_CONFIG_DIRECTIVE}' | sudo tee -a {SSHD_CONFIG_PATH} > /dev/null; "
            f"fi"
        )
        self._run(client, cmd_sshd, "update sshd_config")

        # Reload sshd (try systemctl first, fall back to service)
        cmd_reload = "sudo systemctl reload sshd || sudo service ssh reload"
        self._run(client, cmd_reload, "reload sshd")

        system.ca_trust_deployed = True
        system.ca_trust_deployed_at = datetime.utcnow()
        self.db.commit()

        logger.info("CA trust deployed to system %s (%s)", system.hostname, system_id)
        return {
            "status": "deployed",
            "system_id": system_id,
            "hostname": system.hostname,
            "deployed_at": system.ca_trust_deployed_at.isoformat() + "Z",
        }

    def revoke_ca_trust(self, system_id: int) -> Dict[str, Any]:
        """Remove the CA public key and TrustedUserCAKeys directive from a system."""
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        # Remove the CA key file
        self._run(client, f"sudo rm -f {CA_KEY_PATH}", "remove CA key file")

        # Remove the directive and marker from sshd_config (single sed call)
        cmd_sshd = (
            f"sudo sed -i '/{SSHD_CONFIG_MARKER}/d; "
            f"\\|{SSHD_CONFIG_DIRECTIVE}|d' {SSHD_CONFIG_PATH}"
        )
        self._run(client, cmd_sshd, "clean sshd_config")

        cmd_reload = "sudo systemctl reload sshd || sudo service ssh reload"
        self._run(client, cmd_reload, "reload sshd")

        system.ca_trust_deployed = False
        system.ca_trust_deployed_at = None
        self.db.commit()

        logger.info("CA trust revoked from system %s (%s)", system.hostname, system_id)
        return {
            "status": "revoked",
            "system_id": system_id,
            "hostname": system.hostname,
        }

    def _run(
        self, client, command: str, description: str, raise_on_fail: bool = True
    ) -> Dict[str, Any]:
        """Run a command over SSH.

        Returns ``{"exit_code", "stdout", "stderr"}``. Raises SSHIdentityError
        when ``raise_on_fail`` and exit code is non-zero.
        """
        _, stdout, stderr = client.exec_command(command, timeout=30)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if exit_code != 0 and raise_on_fail:
            raise SSHIdentityError(
                f"Step '{description}' failed (exit {exit_code}): {err}"
            )
        return {"exit_code": exit_code, "stdout": out, "stderr": err}

    # ------------------------------------------------------------------ PRA-138
    # AuthorizedPrincipalsCommand hook + praxis-principals wrapper script.

    def deploy_principals_hook(self, system_id: int) -> Dict[str, Any]:
        """Install the praxis-principals script and wire sshd to consult it.

        Pre-reqs:
          - system.ca_trust_deployed must be True (CA pubkey already on host).

        Steps (idempotent):
          1. Write /usr/local/bin/praxis-principals + chmod 755.
          2. Seed /etc/praxis/principals.d/<bootstrap_login> with the
             bootstrap username so cert-auth works for the control plane
             itself and the self-test has a valid principal.
          3. Back up sshd_config, append marker + directives.
          4. Validate with ``sshd -t``. Restore backup + abort on failure.
          5. Reload sshd.
          6. Self-test: mint a cert for the bootstrap user and attempt cert
             auth. On failure, restore backup + reload and raise.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")
        if not system.ca_trust_deployed:
            raise SSHIdentityError(
                "CA trust not deployed; deploy_ca_trust must run first"
            )

        credential = system.credentials
        bootstrap_login = (credential.username or "").strip() if credential else ""
        if not bootstrap_login:
            raise SSHIdentityError(
                "System credential has no username; cannot seed principals"
            )

        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        # 1. Write the principals wrapper script
        script_heredoc = (
            f"sudo install -m 0755 -o root -g root /dev/stdin {PRINCIPALS_SCRIPT_PATH} "
            f"<<'PRAXIS_SCRIPT_EOF'\n{PRINCIPALS_SCRIPT_BODY}PRAXIS_SCRIPT_EOF"
        )
        self._run(client, script_heredoc, "install praxis-principals")

        # 2. Seed bootstrap user's principals file (directory must exist first)
        self._run(
            client,
            f"sudo install -d -m 0755 -o root -g root {PRINCIPALS_DIR}",
            "create /etc/praxis/principals.d",
        )
        seed_cmd = (
            f"sudo install -m 0644 -o root -g root /dev/stdin "
            f"{PRINCIPALS_DIR}/{shlex.quote(bootstrap_login)} "
            f"<<'PRAXIS_PRIN_EOF'\n{bootstrap_login}\nPRAXIS_PRIN_EOF"
        )
        self._run(client, seed_cmd, "seed bootstrap principals")

        # 3. Back up sshd_config and append directives
        backup_path = f"{SSHD_CONFIG_PATH}.praxis138.bak"
        self._run(
            client,
            f"sudo cp -a {SSHD_CONFIG_PATH} {backup_path}",
            "back up sshd_config",
        )
        sshd_append = (
            f"if ! grep -qF '{SSHD_PRINCIPALS_MARKER}' {SSHD_CONFIG_PATH}; then "
            f"printf '\\n%s\\n%s\\n' '{SSHD_PRINCIPALS_MARKER}' "
            f"{shlex.quote(SSHD_PRINCIPALS_DIRECTIVES)} "
            f"| sudo tee -a {SSHD_CONFIG_PATH} > /dev/null; "
            "fi"
        )
        self._run(client, sshd_append, "append AuthorizedPrincipalsCommand")

        # 4. Validate
        validate = self._run(
            client,
            f"sudo sshd -t -f {SSHD_CONFIG_PATH}",
            "sshd -t validate",
            raise_on_fail=False,
        )
        if validate["exit_code"] != 0:
            self._restore_sshd_backup(client, backup_path)
            raise SSHIdentityError(f"sshd -t rejected new config: {validate['stderr']}")

        # 5. Reload
        self._run(
            client,
            "sudo systemctl reload sshd || sudo service ssh reload",
            "reload sshd",
        )

        # 6. Self-test cert auth
        try:
            self.self_test_cert_auth(system_id)
        except SSHIdentityError as e:
            logger.error(
                "principals hook self-test failed on %s: %s; rolling back",
                system.hostname,
                e,
            )
            self._restore_sshd_backup(client, backup_path, reload_sshd=True)
            raise

        system.principals_hook_deployed = True
        system.principals_hook_deployed_at = datetime.utcnow()
        self.db.commit()

        logger.info(
            "principals hook deployed to %s (system %s)", system.hostname, system_id
        )
        return {
            "status": "deployed",
            "system_id": system_id,
            "hostname": system.hostname,
            "deployed_at": system.principals_hook_deployed_at.isoformat() + "Z",
        }

    def revoke_principals_hook(self, system_id: int) -> Dict[str, Any]:
        """Remove the PRA-138 sshd directives + praxis-principals script."""
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        # Strip the marker + the two directives that follow it
        cmd_sshd = f"sudo sed -i '/{SSHD_PRINCIPALS_MARKER}/,+2d' {SSHD_CONFIG_PATH}"
        self._run(client, cmd_sshd, "clean sshd_config")
        self._run(
            client,
            f"sudo rm -f {PRINCIPALS_SCRIPT_PATH}",
            "remove praxis-principals script",
        )
        self._run(
            client,
            "sudo systemctl reload sshd || sudo service ssh reload",
            "reload sshd",
        )

        system.principals_hook_deployed = False
        system.principals_hook_deployed_at = None
        self.db.commit()

        logger.info(
            "principals hook revoked from %s (system %s)", system.hostname, system_id
        )
        return {
            "status": "revoked",
            "system_id": system_id,
            "hostname": system.hostname,
        }

    def enroll_access_broker(self, system_id: int) -> Dict[str, Any]:
        """One-shot enrollment: CA trust + principals hook + self-test.

        Convenience wrapper for the operator-facing "Enroll" button. Safe to
        re-run; each step is idempotent.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        if not system.ca_trust_deployed:
            self.deploy_ca_trust(system_id)
        if not system.principals_hook_deployed:
            self.deploy_principals_hook(system_id)

        # PRA-234: CA trust + principals hook succeeding does NOT prove the
        # broker is usable. Native sshd AllowUsers/AllowGroups policy can still
        # reject provisioned logins at the account gate. Surface that here as a
        # non-fatal warning so the enrollment banner cannot over-claim. Failure
        # to run the check must never fail enrollment itself.
        allowlist: Dict[str, Any]
        try:
            allowlist = self.check_access_allowlist(system_id)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "allow-list check failed during enrollment of %s: %s",
                system.hostname,
                e,
            )
            allowlist = {"checked": False, "blocked_logins": [], "results": []}

        return {
            "status": "enrolled",
            "system_id": system_id,
            "hostname": system.hostname,
            "ca_trust_deployed": system.ca_trust_deployed,
            "principals_hook_deployed": system.principals_hook_deployed,
            "allowlist": allowlist,
            "allowlist_blocked_logins": allowlist.get("blocked_logins", []),
        }

    def self_test_cert_auth(self, system_id: int) -> Dict[str, Any]:
        """Verify cert-auth works end-to-end.

        Opens a fresh SSH connection (not pooled) using Vault-signed cert
        authentication and runs ``echo praxis_selftest_ok``. Raises
        SSHIdentityError on any failure.
        """
        # The ssh_service pool caches password-auth clients; force a fresh
        # cert-auth connection by clearing the pool entry first.
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        with self.ssh_service._connection_lock:
            self.ssh_service._connection_pool.pop(system.hostname, None)

        try:
            # get_connection with force_password_auth=False will attempt cert
            # auth first when ca_trust_deployed is True.
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=False
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"cert-auth connection failed: {e}") from e

        result = self._run(
            client, "echo praxis_selftest_ok", "self-test exec", raise_on_fail=False
        )
        if result["exit_code"] != 0 or "praxis_selftest_ok" not in result["stdout"]:
            raise SSHIdentityError("self-test command did not return expected output")

        return {"status": "ok", "system_id": system_id}

    # --------------------------------------------------------------- PRA-234
    # Native sshd account allow-list (AllowUsers/AllowGroups/DenyUsers/
    # DenyGroups) compatibility detection. Enrollment and the bootstrap
    # self-test both pass on a host hardened with e.g. ``AllowUsers praxis``,
    # yet a provisioned login such as ``operator`` is rejected at the allow-list
    # gate before the CA cert is evaluated. These helpers surface that instead
    # of letting Connect collapse into a generic publickey failure.

    def diagnose_login_allowlist(
        self, system_id: int, login: str, client=None
    ) -> allowlist_diag.AllowlistDiagnosis:
        """Diagnose whether native sshd allow-lists would reject ``login``.

        Uses a bootstrap (password/existing-credential) SSH session — which
        still works because the bootstrap login is what the operator hardened
        the host around — to read effective sshd policy via ``sshd -T`` and the
        login's group membership. Never edits host policy. Returns an
        ``AllowlistDiagnosis``; ``checked=False`` when the probe could not run,
        so callers must not fabricate a denial.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        if client is None:
            try:
                client, _ = self.ssh_service.get_connection(
                    system_id, force_password_auth=True
                )
            except SSHConnectionError as e:
                return allowlist_diag.AllowlistDiagnosis(
                    login=login,
                    checked=False,
                    blocked=False,
                    indeterminate_reason=f"bootstrap SSH connection failed: {e}",
                )

        run = allowlist_diag.runner_for_client(client)
        try:
            return allowlist_diag.diagnose_login_allowlist(run, login)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "allow-list diagnosis errored on %s for %s: %s",
                system.hostname,
                login,
                e,
            )
            return allowlist_diag.AllowlistDiagnosis(
                login=login,
                checked=False,
                blocked=False,
                indeterminate_reason=f"allow-list probe error: {e}",
            )

    def check_access_allowlist(
        self, system_id: int, logins: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Check allow-list compatibility for provisioned logins on a host.

        When ``logins`` is omitted, every provisioned ``HostUserState`` login on
        the system is checked. Reuses a single bootstrap connection. Returns a
        summary the enrollment flow, a dedicated endpoint, and the UI banner can
        all consume, so a healthy CA/principals deployment does not imply the
        broker is usable when eligible logins are blocked by host policy.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        if logins is None:
            rows = (
                self.db.query(HostUserState)
                .filter(
                    HostUserState.system_id == system_id,
                    HostUserState.state == "provisioned",
                )
                .all()
            )
            logins = sorted({r.login for r in rows})

        results: List[Dict[str, Any]] = []
        client = None
        if logins:
            try:
                client, _ = self.ssh_service.get_connection(
                    system_id, force_password_auth=True
                )
            except SSHConnectionError as e:
                # No connection at all — report every login as unverified rather
                # than claiming a denial we could not observe.
                for login in logins:
                    results.append(
                        allowlist_diag.AllowlistDiagnosis(
                            login=login,
                            checked=False,
                            blocked=False,
                            indeterminate_reason=(
                                f"bootstrap SSH connection failed: {e}"
                            ),
                        ).to_dict(system.hostname)
                    )
                return {
                    "system_id": system_id,
                    "hostname": system.hostname,
                    "checked": False,
                    "blocked_logins": [],
                    "results": results,
                }

        for login in logins:
            diag = self.diagnose_login_allowlist(system_id, login, client=client)
            results.append(diag.to_dict(system.hostname))

        blocked = [r["login"] for r in results if r["blocked"]]
        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "checked": any(r["checked"] for r in results) if results else True,
            "blocked_logins": blocked,
            "results": results,
        }

    def _restore_sshd_backup(
        self, client, backup_path: str, reload_sshd: bool = False
    ) -> None:
        """Restore the sshd_config backup taken at the start of deploy."""
        self._run(
            client,
            f"sudo cp -a {backup_path} {SSHD_CONFIG_PATH}",
            "restore sshd_config backup",
        )
        if reload_sshd:
            self._run(
                client,
                "sudo systemctl reload sshd || sudo service ssh reload",
                "reload sshd (rollback)",
                raise_on_fail=False,
            )
