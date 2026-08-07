"""Shared helpers for the real-host access-control integration suite (PRA-292).

Imported by ``test_pra137_e2e`` and ``test_pra292_real_host_access_control``. Keeps
the cert-mint / cert-login / in-container exec plumbing in one place so every
real-host test proves the SAME post-PRA-288 identity model: the SSH connection uses
the Linux login as the username, while the certificate principal is the immutable
``cert_principal_for_user(user)`` (``praxis-user-<id>``).

No ``docker`` import here — collection must stay clean on hosts without the SDK; the
container object is passed in by the ``ssh_target`` fixture.
"""

from __future__ import annotations

import uuid
from typing import Tuple

import paramiko

from app.services.vault_service import VaultService


def ensure_vault_config(db):
    """Ensure an ACTIVE internal Vault config row exists so ``VaultService`` can
    authenticate against the bundled Vault.

    ``initialize_client`` needs BOTH ``VAULT_TOKEN`` and an active ``VaultConfig``
    row (server URL / internal flag). A production deployment seeds that config at
    setup; a freshly-migrated ``praxis_test`` DB has none, so cert signing fails
    closed with "No active Vault configuration found". Idempotent — creates the
    internal config only when one is not already active.
    """
    vault = VaultService(db)
    if vault.get_active_config() is None:
        vault.create_config(is_internal=True, server_url=None, user_id=None)
    return vault


def retire_target_system(db, hostname: str) -> None:
    """Rerun-safety: free the unique ``systems.hostname`` for a fresh row by RENAMING
    any leftover System from a prior aborted run aside.

    A hard delete is unsafe — audit tables (``ssh_security_logs``, ``sessions``, …)
    FK-reference ``systems`` WITHOUT ``ON DELETE CASCADE`` — so we rename the orphan
    (an FK-safe UPDATE) rather than delete it. The stale row is harmless in a test DB
    and its host-user state is ignored because a fresh System (new id) is created.
    """
    import uuid as _uuid

    from app.db.models import System

    stale = db.query(System).filter(System.hostname == hostname).all()
    for s in stale:
        s.hostname = f"{hostname}-retired-{_uuid.uuid4().hex[:8]}"
    if stale:
        db.commit()


def run_in_target(container, cmd: str) -> Tuple[int, str]:
    """Run ``cmd`` in the disposable target and return ``(exit_code, output)``."""
    code, out = container.exec_run(["bash", "-lc", cmd])
    return code, out.decode("utf-8", errors="replace")


def mint_user_cert(db, pkey: paramiko.RSAKey, principal: str, ttl: int = 300) -> None:
    """Sign ``pkey`` for ``principal`` via real Vault and attach the cert."""
    vault = VaultService(db)
    pub_openssh = f"{pkey.get_name()} {pkey.get_base64()}"
    signed = vault.sign_ssh_user_cert(
        public_key=pub_openssh,
        principal=principal,
        ttl_seconds=ttl,
        key_id=f"e2e-{uuid.uuid4().hex[:8]}",
    )
    pkey.load_certificate(signed)


def cert_key_for(db, principal: str, ttl: int = 300) -> paramiko.RSAKey:
    """A fresh RSA key with a Vault-signed cert for ``principal`` attached."""
    pkey = paramiko.RSAKey.generate(2048)
    mint_user_cert(db, pkey, principal, ttl)
    return pkey


def cert_login(
    ip: str, port: int, username: str, pkey: paramiko.RSAKey, timeout: int = 10
):
    """Open a cert-auth SSH connection as Linux ``username``. Caller closes it."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=ip,
        port=port,
        username=username,
        pkey=pkey,
        allow_agent=False,
        look_for_keys=False,
        timeout=timeout,
    )
    return client
