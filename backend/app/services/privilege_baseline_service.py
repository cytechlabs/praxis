"""PRA-282: the Praxis 1.0 privilege baseline.

Praxis 1.0 ships **no standing user-facing privileged escalation**. There is no
Praxis-issued root shell, no password-sudo path, no break-glass root profile, no
raw sudoers authoring, and no fleet/group/system sudo inheritance. Privileged host
work is performed only by named, non-interactive Praxis automation (patching,
package jobs, host reconciliation) through a service-account credential
``sudo_method``; interactive root is out-of-band under the ops runbook.

This module holds the one-shot data-repair that brings an existing deployment's
stored fleet-access data to that baseline. It is invoked by the PRA-282 Alembic
migration and is also directly unit-tested, so the migration and the test share a
single implementation rather than duplicating SQL.

The repair is intentionally split from host cleanup: clearing the database is not
enough — any ``/etc/sudoers.d/praxis-<login>`` drop-in already deployed to a host
must be removed by reconciliation. This function therefore also flags every live
``host_user_states`` row (``privilege_reconcile_pending = True``) so the reconcile
path removes the on-host drop-in; a failed reconcile leaves the flag set and the
row visibly ``error`` until it succeeds.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple

import sqlalchemy as sa

# OS groups that confer standing host privilege (interactive sudo / root). Praxis
# 1.0 does not grant these to user-facing managed accounts. The reconciler and the
# fleet-role API both refuse to (re)introduce them.
PRIVILEGED_OS_GROUPS = frozenset({"wheel", "sudo", "root", "admin"})


def _strip_privileged_groups(os_groups_json: str) -> Tuple[str, bool]:
    """Return ``(new_json, changed)`` with privileged groups removed.

    Non-privileged groups (e.g. ``docker``) are preserved. Malformed JSON is left
    untouched (``changed=False``) rather than guessed at.
    """
    try:
        groups = json.loads(os_groups_json or "[]")
    except (TypeError, ValueError):
        return os_groups_json, False
    if not isinstance(groups, list):
        return os_groups_json, False
    kept = [
        g
        for g in groups
        if isinstance(g, str) and g.lower() not in PRIVILEGED_OS_GROUPS
    ]
    if len(kept) == len(groups):
        return os_groups_json, False
    return json.dumps(kept), True


def enforce_privilege_baseline(conn: Any) -> Dict[str, Any]:
    """Bring stored fleet-access data to the PRA-282 1.0 privilege baseline.

    Idempotent. For every fleet role it clears the raw ``sudoers_snippet`` and
    strips privileged OS groups; it then flags every live ``host_user_states`` row
    for privilege reconciliation so a subsequent reconcile removes any deployed
    sudoers drop-in.

    ``conn`` is any SQLAlchemy Connection or Session (anything exposing
    ``.execute``), so the Alembic migration passes ``op.get_bind()`` and tests pass
    a session. Returns an operator-facing summary of **counts and affected role
    names only** — never raw sudoers text (the pre-upgrade DB backup is the
    forensic recovery path for old policy text).
    """
    roles = conn.execute(
        sa.text("SELECT id, name, os_groups_json, sudoers_snippet FROM fleet_roles")
    ).fetchall()

    cleared_sudoers = set()
    stripped_groups = set()
    for row in roles:
        rid, name, groups_json, snippet = row[0], row[1], row[2], row[3]
        new_groups, changed = _strip_privileged_groups(groups_json)
        set_parts = []
        params: Dict[str, Any] = {"id": rid}
        if snippet is not None:
            set_parts.append("sudoers_snippet = NULL")
            cleared_sudoers.add(name)
        if changed:
            set_parts.append("os_groups_json = :groups")
            params["groups"] = new_groups
            stripped_groups.add(name)
        if set_parts:
            conn.execute(
                sa.text(
                    f"UPDATE fleet_roles SET {', '.join(set_parts)} WHERE id = :id"
                ),
                params,
            )

    marked = conn.execute(
        sa.text(
            "UPDATE host_user_states SET privilege_reconcile_pending = true "
            "WHERE state <> 'removed'"
        )
    ).rowcount

    return {
        "roles_sudoers_cleared": sorted(cleared_sudoers),
        "roles_groups_stripped": sorted(stripped_groups),
        "host_states_flagged": int(marked or 0),
    }
