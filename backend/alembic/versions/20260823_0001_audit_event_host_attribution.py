"""Attribute existing audit events to the hosts they affect.

The per-host audit query matches ``audit_events.target_system_id`` alone, and
several families of automated change events never filled that column in. Patch
plan, execution, and fleet-wide compliance events were written with a plan,
execution, or policy as their target, so a host that was patched under an
approved plan returned a history with the patch missing from it and no sign that
anything had been left out.

``audit_event_systems`` holds the hosts an event affects when the event has no
single subject host, and per-host retrieval reads it alongside the column. This
revision creates that table and populates both it and the column from what the
database already knows, so a history that predates the fix reads the same as one
recorded after it.

Attribution comes from the relational associations rather than from prose:

* an execution-host, reboot, or rollback-host event names exactly one host, so
  its host lands in ``target_system_id``, the same column the emitters now
  write;
* a plan or execution event spans that plan's or execution's host rows, and each
  becomes a link;
* a wave event spans only the hosts in its own wave, read from the event's
  recorded ``wave_index``; and
* a fleet-wide compliance event spans the hosts its evaluation run produced
  evidence for, matched on the run id the event recorded.

Two limits are deliberate. Retention sweep events name no host, because the
evidence that would identify one is what the sweep deleted. A run whose evidence
has since been pruned attributes to nothing, which is the honest answer for a
database that no longer holds the association.

Rerunning is safe. The column is only filled where it is empty, links are
inserted only where absent, and every host reference is checked against a live
``systems`` row so a snapshot that outlived its host cannot break the run.

The downgrade drops the table. Column values are left in place: a backfilled
host is a correct fact about the event and is indistinguishable from one written
at emission time, so removing them would take real attribution with them.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "audit_event_host_attribution"
down_revision: Union[str, None] = "command_policy_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Events whose target row names exactly one host. Each entry maps the event's
# ``target_kind`` to the table its ``target_id`` points at and the column on that
# table holding the host.
SINGLE_HOST_TARGETS = (
    (
        "patch_update_execution_host",
        "patch_update_execution_hosts",
        "system_id_snapshot",
    ),
    (
        "patch_update_execution_reboot",
        "patch_update_execution_reboots",
        "system_id_snapshot",
    ),
    (
        "patch_rollback_dispatch_host",
        "patch_rollback_dispatch_hosts",
        "system_id_snapshot",
    ),
)

# Events whose target row spans a set of hosts, mapped to the association table
# that lists them and its host column.
MULTI_HOST_TARGETS = (
    ("patch_update_plan", "patch_update_plan_hosts", "plan_id", "system_id"),
    (
        "patch_update_execution",
        "patch_update_execution_hosts",
        "execution_id",
        "system_id_snapshot",
    ),
)

# A wave event is an execution event, but it concerns only its own wave, so it is
# attributed from the recorded wave index instead of the whole execution.
WAVE_COMPLETED_ACTION = "patch_update_execution.wave_completed"

# Fleet-wide compliance events carry the id of the evaluation run whose evidence
# names the hosts. The per-host evaluation path already records its host in the
# column and is untouched here.
FLEET_COMPLIANCE_ACTIONS = (
    "compliance_evaluation.run",
    "compliance_evidence.persisted",
)

BATCH = 1000


def _has_tables(bind, *names: str) -> bool:
    existing = set(sa.inspect(bind).get_table_names())
    return all(name in existing for name in names)


def _context(raw: Optional[str]) -> Dict[str, Any]:
    """Decode a stored event context, treating anything unreadable as empty."""
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _link_rows(bind, pairs: List[Dict[str, int]]) -> None:
    """Insert event/host links, skipping any that already exist."""
    if not pairs:
        return
    bind.execute(
        sa.text("""
            INSERT INTO audit_event_systems
                (event_id, system_id, created_at, updated_at)
            SELECT :event_id, :system_id, NOW(), NOW()
            WHERE EXISTS (SELECT 1 FROM systems s WHERE s.id = :system_id)
            ON CONFLICT (event_id, system_id) DO NOTHING
            """),
        pairs,
    )


def _backfill_single_host_targets(bind) -> None:
    for target_kind, table, column in SINGLE_HOST_TARGETS:
        if not _has_tables(bind, table):
            continue
        bind.execute(
            sa.text(f"""
                UPDATE audit_events ae
                SET target_system_id = t.{column}
                FROM {table} t
                JOIN systems s ON s.id = t.{column}
                WHERE ae.target_kind = :target_kind
                  AND ae.target_id = CAST(t.id AS text)
                  AND ae.target_system_id IS NULL
                """),
            {"target_kind": target_kind},
        )


def _backfill_multi_host_targets(bind) -> None:
    for target_kind, table, parent_column, column in MULTI_HOST_TARGETS:
        if not _has_tables(bind, table):
            continue
        bind.execute(
            sa.text(f"""
                INSERT INTO audit_event_systems
                    (event_id, system_id, created_at, updated_at)
                SELECT DISTINCT ae.id, t.{column}, NOW(), NOW()
                FROM audit_events ae
                JOIN {table} t ON CAST(t.{parent_column} AS text) = ae.target_id
                JOIN systems s ON s.id = t.{column}
                WHERE ae.target_kind = :target_kind
                  AND ae.action <> :wave_action
                  AND (
                      ae.target_system_id IS NULL
                      OR ae.target_system_id <> t.{column}
                  )
                ON CONFLICT (event_id, system_id) DO NOTHING
                """),
            {"target_kind": target_kind, "wave_action": WAVE_COMPLETED_ACTION},
        )


def _backfill_wave_events(bind) -> None:
    """Attribute each wave event to the hosts of that wave only."""
    if not _has_tables(bind, "patch_update_execution_hosts"):
        return
    last_id = 0
    while True:
        rows = bind.execute(
            sa.text("""
                SELECT id, target_id, context_json
                FROM audit_events
                WHERE action = :action
                  AND target_id IS NOT NULL
                  AND id > :last_id
                ORDER BY id
                LIMIT :batch
                """),
            {"action": WAVE_COMPLETED_ACTION, "last_id": last_id, "batch": BATCH},
        ).fetchall()
        if not rows:
            return
        pairs: List[Dict[str, int]] = []
        for event_id, target_id, context_json in rows:
            last_id = event_id
            wave_index = _context(context_json).get("wave_index")
            if not isinstance(wave_index, int) or isinstance(wave_index, bool):
                continue
            hosts = bind.execute(
                sa.text("""
                    SELECT DISTINCT system_id_snapshot
                    FROM patch_update_execution_hosts
                    WHERE CAST(execution_id AS text) = :execution_id
                      AND wave_index = :wave_index
                      AND system_id_snapshot IS NOT NULL
                    """),
                {"execution_id": target_id, "wave_index": wave_index},
            ).fetchall()
            pairs.extend(
                {"event_id": event_id, "system_id": host_id} for (host_id,) in hosts
            )
        _link_rows(bind, pairs)


def _backfill_fleet_compliance_events(bind) -> None:
    """Attribute each fleet-wide compliance event to the hosts its run covered."""
    if not _has_tables(bind, "compliance_policy_evidence"):
        return
    last_id = 0
    while True:
        rows = bind.execute(
            sa.text("""
                SELECT id, context_json
                FROM audit_events
                WHERE action IN :actions
                  AND target_system_id IS NULL
                  AND id > :last_id
                ORDER BY id
                LIMIT :batch
                """).bindparams(sa.bindparam("actions", expanding=True)),
            {
                "actions": list(FLEET_COMPLIANCE_ACTIONS),
                "last_id": last_id,
                "batch": BATCH,
            },
        ).fetchall()
        if not rows:
            return
        pairs: List[Dict[str, int]] = []
        for event_id, context_json in rows:
            last_id = event_id
            run_id = _context(context_json).get("run_id")
            if not isinstance(run_id, str) or not run_id:
                continue
            hosts = bind.execute(
                sa.text("""
                    SELECT DISTINCT system_id
                    FROM compliance_policy_evidence
                    WHERE evaluation_run_id = :run_id
                    """),
                {"run_id": run_id},
            ).fetchall()
            pairs.extend(
                {"event_id": event_id, "system_id": host_id} for (host_id,) in hosts
            )
        _link_rows(bind, pairs)


def backfill(bind) -> None:
    """Run every attribution pass. Safe to call again on the same database."""
    _backfill_single_host_targets(bind)
    _backfill_multi_host_targets(bind)
    _backfill_wave_events(bind)
    _backfill_fleet_compliance_events(bind)


def upgrade() -> None:
    op.create_table(
        "audit_event_systems",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("system_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["audit_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["system_id"], ["systems.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", "system_id", name="uq_audit_event_system"),
    )
    op.create_index(
        op.f("ix_audit_event_systems_id"), "audit_event_systems", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_audit_event_systems_event_id"),
        "audit_event_systems",
        ["event_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_event_systems_system_id"),
        "audit_event_systems",
        ["system_id"],
        unique=False,
    )

    bind = op.get_bind()
    if not _has_tables(bind, "audit_events", "systems"):
        return
    backfill(bind)


def downgrade() -> None:
    op.drop_index(
        op.f("ix_audit_event_systems_system_id"), table_name="audit_event_systems"
    )
    op.drop_index(
        op.f("ix_audit_event_systems_event_id"), table_name="audit_event_systems"
    )
    op.drop_index(op.f("ix_audit_event_systems_id"), table_name="audit_event_systems")
    op.drop_table("audit_event_systems")
