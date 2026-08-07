"""Host user provisioning service (PRA-137).

Creates and removes Linux accounts on managed hosts to satisfy AccessGrants.
Uses the existing ``SSHService.execute_privileged_command`` path so the
bootstrap credential + sudo method the operator already configured is reused.

Operations:
    * ``ensure_user`` — create (or converge) a local account with the OS groups,
      sudoers snippet, and authorized cert principals dictated by the fleet
      role. Idempotent — safe to call repeatedly.
    * ``remove_user`` — archive the home dir, strip sudoers drop-in + principals
      file, delete the account. Returns the archive path on success.

The ``/etc/praxis/principals.d/<login>`` file this writes will be consumed by
sshd via ``AuthorizedPrincipalsCommand`` in PRA-138. In this effort we write
the files but don't yet wire sshd — the reconciliation ledger is complete.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from ..db.access_models import AccessGrant, FleetRole, HostUserState
from ..db.models import System
from .access_authorization_service import active_grant_filter, cert_principal_for_user
from .ssh_service import SSHConnectionError, SSHService

logger = logging.getLogger(__name__)

# Unix username rules: lowercase start, [a-z0-9_-], max 32 chars.
# Matches the stricter POSIX-portable subset; rejects anything that could
# break a shell command line.
_LOGIN_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_GROUP_RE = _LOGIN_RE  # OS group names follow the same rules.
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")

ARCHIVE_DIR = "/var/backups/praxis/homedirs"
PRINCIPALS_DIR = "/etc/praxis/principals.d"
SUDOERS_DIR = "/etc/sudoers.d"

# PRA-286: host-side ownership proof. Every account Praxis CREATES gets a
# root-owned marker under this Praxis-controlled directory. Praxis modifies or
# deletes an account only when the marker verifies — a pre-existing Linux account
# with the same username (no marker) is never implicitly adopted or deleted.
MANAGED_USERS_DIR = "/etc/praxis/managed-users"
MARKER_VERSION = 1

# Shell function that proves ownership of a Praxis-managed account. It fails closed
# on: missing marker, wrong owner uid, group/world-writable perms, or any content
# that is not EXACTLY the canonical single-line marker JSON for this login.
#
# The final check is a STRICT anchored whole-file structural match, not a substring
# grep: ``grep -z`` treats the whole file as one record, so ``^...$`` rejects extra
# fields, reordered fields, multiple lines, trailing garbage, or malformed JSON that
# merely CONTAINS the sentinel strings. This is the proof gate before every account
# modify/delete, so malformed-but-string-matching data must not pass.
#
# The expected owner uid is the 3rd arg (production always passes 0 = root; tests
# pass their own uid so the logic is exercisable without root). Contains no secret.
_MARKER_VERIFY_FN = r"""praxis_verify_marker() {
  _l="$1"; _m="$2"; _o="$3"
  [ -f "$_m" ] || return 1
  [ "$(stat -c %u "$_m" 2>/dev/null)" = "$_o" ] || return 1
  [ -z "$(find "$_m" -maxdepth 0 -perm /022 2>/dev/null)" ] || return 1
  grep -zEq "^[{]\"marker_version\":1,\"praxis_managed\":true,\"login\":\"$_l\",\"system_id\":(null|[0-9]+),\"created_at\":\"[0-9A-Za-z:.+-]+\"[}][[:space:]]*$" "$_m" || return 1
  return 0
}"""


def marker_path(login: str) -> str:
    """Root-owned ownership marker path for ``login``."""
    return f"{MANAGED_USERS_DIR}/{login}.json"


def build_marker_json(login: str, system_id: Optional[int]) -> str:
    """Compact JSON marker body. No secrets — stable ownership metadata only.
    The compact separators keep it matchable by the shell ``grep -F`` checks."""
    return json.dumps(
        {
            "marker_version": MARKER_VERSION,
            "praxis_managed": True,
            "login": login,
            "system_id": system_id,
            "created_at": datetime.utcnow().isoformat() + "Z",
        },
        separators=(",", ":"),
    )


def marker_verify_function_sh() -> str:
    """The ownership-verification shell function (exposed for tests)."""
    return _MARKER_VERIFY_FN


# ---------------------------------------------------------------- errors


class ProvisioningError(RuntimeError):
    """Raised when a provisioning step fails or input validation rejects a value."""


# ------------------------------------------------------------- validation


def _validate_login(login: str) -> None:
    if not _LOGIN_RE.match(login):
        raise ProvisioningError(f"invalid login name: {login!r}")


def _validate_group(name: str) -> None:
    if not _GROUP_RE.match(name):
        raise ProvisioningError(f"invalid OS group name: {name!r}")


def _validate_principal(principal: str) -> None:
    if not _PRINCIPAL_RE.match(principal):
        raise ProvisioningError(f"invalid cert principal: {principal!r}")


# ---------------------------------------------------- principals resolution


def _principals_for(db: Session, system_id: int, login: str) -> List[str]:
    """Cert principals authorized to land as ``login`` on ``system_id``.

    PRA-288: the principal is the IMMUTABLE Praxis user principal
    (``praxis-user-<id>``), NOT the mutable username and NOT the (possibly shared)
    Linux login — so a rename cannot break cert auth and a recreated username cannot
    inherit stale authority. Multiple users authorizing the same login (role_account
    mode) yield multiple immutable principals, one per active authorized user.
    """
    # PRA-284: an expired grant must not keep a cert principal authorized to land
    # on the host — only currently-active grants contribute to the principals file.
    # PRA-290: grants only exist for active users, so deactivation/revocation drops
    # the principal on the next recompute.
    rows = (
        db.query(AccessGrant.user_id)
        .filter(
            AccessGrant.system_id == system_id,
            AccessGrant.login == login,
            active_grant_filter(),
        )
        .distinct()
        .all()
    )
    principals = sorted({cert_principal_for_user(r[0]) for r in rows})
    for p in principals:
        _validate_principal(p)
    return principals


# ---------------------------------------------------- state ledger helpers


def _upsert_state(
    db: Session,
    *,
    system_id: int,
    login: str,
    mode: str,
    state: str,
    last_error: Optional[str] = None,
    home_archive_path: Optional[str] = None,
    clear_privilege_pending: bool = False,
) -> HostUserState:
    row = (
        db.query(HostUserState)
        .filter(
            HostUserState.system_id == system_id,
            HostUserState.login == login,
        )
        .first()
    )
    if row is None:
        row = HostUserState(system_id=system_id, login=login, mode=mode)
        db.add(row)
    row.mode = mode
    row.state = state
    row.last_error = last_error
    if home_archive_path is not None:
        row.home_archive_path = home_archive_path
    # PRA-282: a successful converge/removal reaches the 1.0 baseline on the host,
    # so the reconcile marker is cleared. Error paths never pass this, so a host
    # that could not be reached stays flagged (and visibly ``error``).
    if clear_privilege_pending:
        row.privilege_reconcile_pending = False
    row.last_reconciled_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    return row


# -------------------------------------------------------- script building


def _sq(s: str) -> str:
    """Shell-quote a value for safe inclusion in a sudo bash -c '...' string."""
    return shlex.quote(s)


def _ensure_script(
    login: str,
    os_groups: List[str],
    principals: List[str],
    system_id: Optional[int] = None,
) -> str:
    """Build the idempotent provisioning script.

    PRA-286 ownership gate — no implicit adoption of unmanaged accounts:
      * account MISSING  -> create it (useradd), write + verify a root-owned
        ownership marker (we own it), then converge;
      * account EXISTS + marker verifies -> converge;
      * account EXISTS + marker missing/invalid -> refuse: do NOT usermod, do NOT
        replace groups or write principals as if owned; exit non-zero so the caller
        records ``HostUserState.state = "error"``.

    Converge (only after ownership is proven):
      1. Syncs OS group membership (usermod -G replaces the list)
      2. Removes any /etc/sudoers.d/praxis-<login> drop-in (PRA-282)
      3. Writes /etc/praxis/principals.d/<login> with the authorized principals
    """
    marker = marker_path(login)
    marker_json = build_marker_json(login, system_id)
    parts: List[str] = [
        "set -e",
        _MARKER_VERIFY_FN,
        f"mkdir -p {_sq(MANAGED_USERS_DIR)}",
        f"chmod 700 {_sq(MANAGED_USERS_DIR)}",
        f"chown root:root {_sq(MANAGED_USERS_DIR)}",
        f"mkdir -p {_sq(PRINCIPALS_DIR)}",
        f"chmod 755 {_sq(PRINCIPALS_DIR)}",
        f"MARKER={_sq(marker)}",
        # PRA-286 ownership gate.
        f"if id {_sq(login)} >/dev/null 2>&1; then",
        (
            f'  praxis_verify_marker {_sq(login)} "$MARKER" 0 || {{ '
            f'echo "PRAXIS_OWNERSHIP_ERROR: account {login} exists but is not '
            f'Praxis-managed (no valid ownership marker); refusing to modify" '
            f">&2; exit 3; }}"
        ),
        "else",
        f"  useradd -m -s /bin/bash {_sq(login)}",
        f"  ( umask 077; printf '%s\\n' {_sq(marker_json)} > \"$MARKER\" )",
        '  chown root:root "$MARKER"',
        '  chmod 600 "$MARKER"',
        (
            f'  praxis_verify_marker {_sq(login)} "$MARKER" 0 || {{ '
            f'echo "PRAXIS_MARKER_ERROR: failed to create/verify ownership marker '
            f'for {login}" >&2; exit 4; }}'
        ),
        "fi",
    ]

    # --- ownership proven above; converge -----------------------------------
    # Sync OS group membership. Group names differ across distros
    # (e.g. wheel on RHEL vs sudo on Debian), so we filter the configured
    # list down to groups that actually exist on the target host via
    # ``getent group``. Missing groups are skipped rather than failing the
    # whole provisioning. Using ``usermod -G`` replaces supplementary
    # groups, so an empty filtered list correctly removes prior memberships.
    if os_groups:
        wanted = " ".join(_sq(g) for g in os_groups)
        parts.append(
            "praxis_groups=''; "
            f"for g in {wanted}; do "
            'if getent group "$g" >/dev/null 2>&1; then '
            'if [ -n "$praxis_groups" ]; then '
            'praxis_groups="$praxis_groups,$g"; '
            'else praxis_groups="$g"; fi; '
            "fi; done; "
            f'usermod -G "$praxis_groups" {_sq(login)}'
        )
    else:
        parts.append(f"usermod -G '' {_sq(login)}")

    # Sudoers drop-in: PRA-282 — user-facing managed accounts never receive a
    # standing sudoers drop-in in Praxis 1.0. Always remove any drop-in that a
    # pre-1.0 deployment may have written for this login. Privileged host work is
    # done only by named Praxis automation (credential sudo_method), never a
    # per-user /etc/sudoers.d grant.
    sudoers_path = f"{SUDOERS_DIR}/praxis-{login}"
    parts.append(f"rm -f {_sq(sudoers_path)}")

    # Principals file
    principals_path = f"{PRINCIPALS_DIR}/{login}"
    body = "\n".join(principals) + ("\n" if principals else "")
    parts.append(
        "cat > "
        + _sq(principals_path)
        + " <<'PRAXIS_PRIN_EOF'\n"
        + body
        + "PRAXIS_PRIN_EOF"
    )
    parts.append(f"chmod 644 {_sq(principals_path)}")

    return "\n".join(parts)


def _remove_script(login: str) -> str:
    """Build the removal script.

    PRA-286: the account/home are deleted only when ownership is proven. Praxis-
    namespaced artifacts (sudoers drop-in, principals file) are always safe to
    remove — they belong to Praxis — but removing them is NOT account adoption.
    Archive, ``userdel``, and marker verification failures are REAL errors (no
    ``|| true``) so PRA-285 retry/status surfaces the host.
    """
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    archive_path = f"{ARCHIVE_DIR}/{login}-{ts}.tar.gz"
    sudoers_path = f"{SUDOERS_DIR}/praxis-{login}"
    principals_path = f"{PRINCIPALS_DIR}/{login}"
    marker = marker_path(login)
    script = "\n".join(
        [
            "set -e",
            _MARKER_VERIFY_FN,
            f"MARKER={_sq(marker)}",
            # Praxis-namespaced artifacts are always ours to remove (not adoption).
            f"rm -f {_sq(sudoers_path)}",
            f"rm -f {_sq(principals_path)}",
            f"if id {_sq(login)} >/dev/null 2>&1; then",
            # PRA-286 ownership gate: never delete an account/home we cannot prove
            # we own.
            (
                f'  praxis_verify_marker {_sq(login)} "$MARKER" 0 || {{ '
                f'echo "PRAXIS_OWNERSHIP_ERROR: account {login} is not Praxis-managed '
                f'(no valid ownership marker); refusing to delete account/home" >&2; '
                f"exit 3; }}"
            ),
            f"  mkdir -p {_sq(ARCHIVE_DIR)}",
            f"  chmod 700 {_sq(ARCHIVE_DIR)}",
            # Archive home if present. tar failure is an ERROR (no || true).
            (
                f"  if [ -d /home/{login} ]; then "
                f"tar czf {_sq(archive_path)} -C /home {_sq(login)}; fi"
            ),
            # userdel failure (busy account, etc.) is an ERROR (no || true).
            f"  userdel -r {_sq(login)}",
            '  rm -f "$MARKER"',
            "else",
            # Account already gone — remove any stray marker; idempotent success.
            '  rm -f "$MARKER"',
            "fi",
            f"echo PRAXIS_ARCHIVE={_sq(archive_path)}",
        ]
    )
    return script


# ------------------------------------------------------------- public API


def ensure_user(
    db: Session,
    system: System,
    login: str,
    fleet_role: FleetRole,
) -> HostUserState:
    """Converge ``login`` on ``system`` to match ``fleet_role`` + grants.

    Idempotent. Safe to call repeatedly.
    """
    _validate_login(login)

    try:
        os_groups = json.loads(fleet_role.os_groups_json or "[]") or []
    except ValueError:
        os_groups = []
    for g in os_groups:
        _validate_group(g)

    principals = _principals_for(db, system.id, login)

    script = _ensure_script(
        login=login,
        os_groups=os_groups,
        principals=principals,
        system_id=system.id,
    )

    ssh = SSHService(db)
    try:
        result = ssh.execute_privileged_command(
            system.id, f"bash -c {_sq(script)}", timeout=60
        )
    except SSHConnectionError as e:
        return _upsert_state(
            db,
            system_id=system.id,
            login=login,
            mode=fleet_role.login_mode,
            state="error",
            last_error=f"ssh: {e}",
        )
    finally:
        # PRA-342: this SSHService is ephemeral (one per reconcile/provision call),
        # so its pooled connection must be closed here — remote lifecycle cannot
        # rely on idle cleanup that never runs on a discarded instance. Otherwise
        # each failing converge orphans an `sshd: praxis@notty` session.
        ssh.close_all_connections()

    if result.get("exit_code") != 0:
        return _upsert_state(
            db,
            system_id=system.id,
            login=login,
            mode=fleet_role.login_mode,
            state="error",
            last_error=(result.get("stderr") or result.get("stdout") or "unknown")[
                :2000
            ],
        )

    # PRA-282: a successful converge has removed any legacy sudoers drop-in and
    # applied the (now unprivileged) group set, so the host matches the 1.0
    # baseline — clear the privilege-reconcile marker. A failed converge above
    # returned with state="error" and left the marker set (visibly pending).
    return _upsert_state(
        db,
        system_id=system.id,
        login=login,
        mode=fleet_role.login_mode,
        state="provisioned",
        clear_privilege_pending=True,
    )


def remove_user(
    db: Session,
    system: System,
    login: str,
    mode: str,
) -> HostUserState:
    """Archive home dir, strip config, delete account. Idempotent."""
    _validate_login(login)

    script = _remove_script(login)
    ssh = SSHService(db)
    try:
        result = ssh.execute_privileged_command(
            system.id, f"bash -c {_sq(script)}", timeout=120
        )
    except SSHConnectionError as e:
        return _upsert_state(
            db,
            system_id=system.id,
            login=login,
            mode=mode,
            state="error",
            last_error=f"ssh: {e}",
        )
    finally:
        # PRA-342: close the ephemeral pool deterministically (see ensure_user).
        ssh.close_all_connections()

    if result.get("exit_code") != 0:
        return _upsert_state(
            db,
            system_id=system.id,
            login=login,
            mode=mode,
            state="error",
            last_error=(result.get("stderr") or result.get("stdout") or "unknown")[
                :2000
            ],
        )

    # Parse archive path from the script's trailing echo
    archive_path: Optional[str] = None
    for line in (result.get("stdout") or "").splitlines():
        line = line.strip()
        if line.startswith("PRAXIS_ARCHIVE="):
            archive_path = line.split("=", 1)[1].strip("'\"")
            break

    # PRA-282: the account (and its sudoers drop-in) is gone — clear the marker.
    return _upsert_state(
        db,
        system_id=system.id,
        login=login,
        mode=mode,
        state="removed",
        home_archive_path=archive_path,
        clear_privilege_pending=True,
    )
