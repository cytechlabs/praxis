"""Shared sudo-aware argv wrapping for patch dispatch (PRA-175).

PRA-171 patch update dispatch and PRA-173 rollback dispatch build
raw ``apt-get`` / ``dnf`` / ``apt-mark`` argv and hand them straight
to the transport layer, bypassing the existing
``SSHService.execute_privileged_command`` privilege escalation.
PRA-172 reboot dispatch hardcoded a ``sudo systemctl reboot`` prefix
regardless of credential intent. Both gaps mean dispatch ignored
``credential.sudo_method`` and either failed as non-root or
misbehaved when the credential expected a password-stdin handoff.

This module provides one place to translate
``(credential, planned_argv)`` into ``(effective_argv, sudo_stdin)``
so every default dispatcher uses the same vocabulary:

* ``none`` (or no credential) — argv stays as planned, no stdin.
* ``nopasswd`` — argv is prefixed with ``["sudo", "-n"]``; stdin is
  ``None``.
* ``password`` — argv is prefixed with ``["sudo", "-S"]`` and the
  sudo password (from the credential's Vault path, key
  ``sudo_password``) is returned as a stdin bytes payload terminated
  with a single newline so ``sudo -S`` accepts it on the first
  prompt. A missing Vault path or missing secret yields an empty
  stdin (``b"\\n"``) so the dispatcher still sees a structured
  privilege failure rather than hanging on the sudo password
  prompt indefinitely.

Callers pass the result through to ``transport.run_command(argv,
stdin=...)``. Tests that bypass the default dispatcher with a fake
``DispatchCallable`` are unaffected — the wrap lives only on the
real-transport path.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import Credential

logger = logging.getLogger(__name__)


SUDO_METHOD_NONE = "none"
SUDO_METHOD_NOPASSWD = "nopasswd"
SUDO_METHOD_PASSWORD = "password"

VALID_SUDO_METHODS = frozenset(
    {SUDO_METHOD_NONE, SUDO_METHOD_NOPASSWD, SUDO_METHOD_PASSWORD}
)

# PRA-229 PATCH-03: structured reasons for a credential whose sudo_method is not
# usable. Recorded on the dispatch row so operators see an actionable condition
# instead of a silent raw-argv fallback that fails opaquely as non-root.
SUDO_METHOD_MISSING = "missing_sudo_method"
SUDO_METHOD_UNKNOWN = "unknown_sudo_method"


class SudoMethodError(Exception):
    """A resolved credential has a null/blank or unrecognized ``sudo_method``.

    The default patch/rollback dispatcher and the reboot dispatcher catch this
    and record a bounded, operator-actionable failure on the dispatch row rather
    than silently running the planned argv unescalated. ``sudo_method`` is an
    operator-set enum value (not secret material), so it is safe to echo.
    """

    def __init__(self, reason: str, sudo_method, credential_id=None) -> None:
        self.reason = reason  # SUDO_METHOD_MISSING | SUDO_METHOD_UNKNOWN
        self.sudo_method = sudo_method
        self.credential_id = credential_id
        super().__init__(reason)

    def operator_message(self) -> str:
        cid = (
            f"credential id={self.credential_id} "
            if self.credential_id is not None
            else "the resolved credential "
        )
        if self.reason == SUDO_METHOD_MISSING:
            return (
                f"{cid}has no sudo_method configured; set it to 'none', "
                "'nopasswd', or 'password' before dispatching privileged "
                "package operations"
            )
        return (
            f"{cid}has an unrecognized sudo_method {self.sudo_method!r}; set it "
            "to 'none', 'nopasswd', or 'password'"
        )


def wrap_argv_for_sudo(
    db: Session,
    credential: Optional[Credential],
    argv: List[str],
) -> Tuple[List[str], Optional[bytes]]:
    """Return ``(effective_argv, sudo_stdin)`` for ``argv``.

    ``credential`` may be ``None`` (system has no credential row
    resolvable at dispatch time) — that case behaves like
    ``sudo_method=none`` and preserves the planned argv unchanged.

    Reads ``sudo_password`` from the credential's ``vault_path``
    only when ``sudo_method == "password"`` so the Vault call is
    skipped on the common ``none`` / ``nopasswd`` paths.

    Raises :class:`SudoMethodError` (PRA-229) when a resolved credential has a
    null/blank or unrecognized ``sudo_method`` so the dispatcher records a
    structured operator condition instead of silently falling back to raw argv.
    """
    if not argv:
        return list(argv), None

    if credential is None:
        # No credential resolvable — no privilege escalation intended.
        return list(argv), None

    raw_method = credential.sudo_method
    if raw_method is None or (isinstance(raw_method, str) and not raw_method.strip()):
        raise SudoMethodError(
            SUDO_METHOD_MISSING, raw_method, getattr(credential, "id", None)
        )
    method = raw_method.lower()
    if method not in VALID_SUDO_METHODS:
        raise SudoMethodError(
            SUDO_METHOD_UNKNOWN, raw_method, getattr(credential, "id", None)
        )

    if method == SUDO_METHOD_NONE:
        return list(argv), None

    if method == SUDO_METHOD_NOPASSWD:
        return ["sudo", "-n", *argv], None

    # method == SUDO_METHOD_PASSWORD
    sudo_password = _read_sudo_password(db, credential)
    # Always feed a trailing newline so sudo -S consumes one line
    # from stdin even when the configured password is empty (which
    # surfaces as a deterministic sudo auth failure instead of a
    # hung command waiting for the password prompt).
    stdin_bytes = ((sudo_password or "") + "\n").encode("utf-8")
    return ["sudo", "-S", *argv], stdin_bytes


def _read_sudo_password(db: Session, credential: Credential) -> str:
    """Read ``sudo_password`` from the credential's Vault path.

    Returns an empty string if the credential has no Vault path,
    the secret is missing, or the Vault call raises. The dispatcher
    will surface this as a structured sudo auth failure rather than
    hang on the password prompt (see ``wrap_argv_for_sudo``).
    """
    vault_path = getattr(credential, "vault_path", None)
    if not vault_path:
        logger.warning(
            "dispatch_sudo: credential id=%s sudo_method=password but no "
            "vault_path; sudo -S will receive an empty password",
            getattr(credential, "id", None),
        )
        return ""

    # Lazy import so importing this module doesn't drag the Vault
    # client into pure-helper unit tests.
    from .vault_service import VaultService

    try:
        secret = VaultService(db).read_secret(vault_path)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "dispatch_sudo: Vault read failed for credential id=%s "
            "vault_path=%r: %s",
            getattr(credential, "id", None),
            vault_path,
            exc,
        )
        return ""
    if not secret:
        return ""
    return secret.get("sudo_password") or ""


def resolve_system_credential(db: Session, system) -> Optional[Credential]:
    """Resolve the credential row for a ``System`` at dispatch time.

    Returns ``None`` if the system has no ``credentials_id`` or the
    referenced credential row was deleted. ``None`` is treated as
    ``sudo_method=none`` by :func:`wrap_argv_for_sudo`.
    """
    if system is None:
        return None
    cred_id = getattr(system, "credentials_id", None)
    if cred_id is None:
        return None
    return db.query(Credential).filter(Credential.id == cred_id).first()
