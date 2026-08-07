"""PRA-172 slice 1: patch_update_execution_reboots.

Reboot orchestration substrate. Slice 1 only adds the persistent
queue table; the service layer ships eligibility detection, policy
gating, and read APIs. **No real reboot execution, no SSH/agent
dispatch, no verification loop** — those are later PRA-172 slices.

One row per ``patch_update_execution_hosts`` row, initialized after
the parent execution reaches a terminal state. The row records the
moment-in-time reboot-policy decision plus the source facts the
decision drew on, so the audit trail survives later policy or host
edits.

State vocabulary (CHECK-constrained at the DB level; ORM mirrors):

* ``not_required`` — host succeeded but no reboot required (policy
  ``if_required`` + ``host_facts.reboot_required`` is null/false, or
  no opinion was observable).
* ``pending``     — host is eligible for a reboot under policy.
* ``scheduled``   — RESERVED for a later slice; reboot has been
  scheduled into a window.
* ``rebooting``   — RESERVED; transport-level reboot in flight.
* ``verifying``   — RESERVED; host returned, verification underway.
* ``healthy``     — RESERVED; verification succeeded.
* ``failed``      — RESERVED; verification or reboot failed
  terminally.
* ``skipped``     — host is not eligible (policy ``never``, host
  did not succeed, or invalid policy context). Slice 1 only writes
  ``not_required`` / ``pending`` / ``skipped``.

Decision codes (carried in ``decision_code`` plus ``decision_details``
JSONB) make the gating machine-readable so later UI / operator
flows can surface the "why":

* ``host_fact_reboot_required`` — pending; ``host_facts.reboot_required``
  is True.
* ``policy_always`` — pending; ``reboot_policy=always``.
* ``fact_not_required`` — not_required; policy ``if_required`` and
  facts say no reboot is needed.
* ``policy_never`` — skipped; ``reboot_policy=never``.
* ``host_did_not_succeed`` — skipped; execution-host state is not
  ``succeeded`` (failed, skipped, canceled, paused).
* ``policy_invalid`` — skipped; ``policy_snapshot.reboot_policy`` is
  not one of {never, if_required, always}.
* ``policy_missing`` — skipped; ``policy_snapshot.reboot_policy`` was
  null/absent.

Reboot-window context (``reboot_window_id_snapshot`` plus a
``reboot_window_status`` key inside ``decision_details``) is recorded
even when the queue decision is ``pending``: missing or invalid
window context must be explicit, not silent, so the later slice that
schedules reboots has the structured details to act on.

Indexes / constraints:

* UNIQUE ``(execution_id, execution_host_id)`` — one queue row per
  execution-host. Re-running the init service must upsert, not
  duplicate.
* INDEX ``(execution_id, state)`` — for the per-execution state
  rollup the read API computes.
* INDEX ``(execution_id, wave_index)`` — for per-wave drill-down.
* INDEX ``(plan_id_snapshot)`` — for the plan-scoped read endpoint
  (one plan can have multiple executions over time).

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra172_reboot_queue"
down_revision: Union[str, None] = "pra171_dispatch"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


REBOOT_STATES = (
    "not_required",
    "pending",
    "scheduled",
    "rebooting",
    "verifying",
    "healthy",
    "failed",
    "skipped",
)

REBOOT_POLICY_SNAPSHOT_VALUES = (
    "never",
    "if_required",
    "always",
    "unknown",
)


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.create_table(
        "patch_update_execution_reboots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "execution_id",
            sa.Integer,
            sa.ForeignKey("patch_update_executions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "execution_host_id",
            sa.Integer,
            sa.ForeignKey("patch_update_execution_hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plan_id_snapshot", sa.Integer, nullable=False),
        sa.Column("system_id_snapshot", sa.Integer, nullable=True),
        sa.Column("system_hostname_snapshot", sa.String(255), nullable=True),
        sa.Column("wave_index", sa.Integer, nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reboot_policy_snapshot", sa.String(32), nullable=False),
        sa.Column("reboot_window_id_snapshot", sa.Integer, nullable=True),
        sa.Column("reboot_required_fact", sa.Boolean, nullable=True),
        sa.Column("decision_code", sa.String(64), nullable=False),
        sa.Column(
            "decision_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("scheduled_for_at", sa.DateTime, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint(
            "execution_id",
            "execution_host_id",
            name="uq_patch_update_execution_reboots_target",
        ),
        sa.CheckConstraint(
            _check_in("state", REBOOT_STATES),
            name="patch_update_execution_reboots_state_vocab",
        ),
        sa.CheckConstraint(
            _check_in("reboot_policy_snapshot", REBOOT_POLICY_SNAPSHOT_VALUES),
            name="patch_update_execution_reboots_policy_vocab",
        ),
        sa.CheckConstraint(
            "wave_index >= 0",
            name="patch_update_execution_reboots_wave_index_nonneg",
        ),
    )
    op.create_index(
        "ix_patch_update_execution_reboots_execution_state",
        "patch_update_execution_reboots",
        ["execution_id", "state"],
    )
    op.create_index(
        "ix_patch_update_execution_reboots_execution_wave",
        "patch_update_execution_reboots",
        ["execution_id", "wave_index"],
    )
    op.create_index(
        "ix_patch_update_execution_reboots_plan",
        "patch_update_execution_reboots",
        ["plan_id_snapshot"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_execution_reboots_plan",
        table_name="patch_update_execution_reboots",
    )
    op.drop_index(
        "ix_patch_update_execution_reboots_execution_wave",
        table_name="patch_update_execution_reboots",
    )
    op.drop_index(
        "ix_patch_update_execution_reboots_execution_state",
        table_name="patch_update_execution_reboots",
    )
    op.drop_table("patch_update_execution_reboots")
