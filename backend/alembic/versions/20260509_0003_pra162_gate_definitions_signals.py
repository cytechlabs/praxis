"""PRA-162 slice 4: patch_ring_gate_definitions + patch_ring_gate_signals.

Promotion gates for staged rollout. A ring can declare a set of gate
definitions; operators (or future plan/execution writers) record
stored signals matching ``signal_key``; the ring's promotion
readiness is computed entirely from these stored rows.

Tables:

* ``patch_ring_gate_definitions`` — what a ring requires to promote.
  ``gate_kind`` ∈ ``{boolean, threshold}``; ``comparator`` ∈
  ``{eq, ne, gt, gte, lt, lte}``; ``parameters`` JSONB; ``required``
  + ``enabled`` flags; unique ``(ring_id, signal_key)``.
* ``patch_ring_gate_signals`` — stored signal evidence. ``signal_key``
  matches a definition by string; optional FK to the definition is
  kept SET NULL so historical signals remain after a definition is
  removed. ``source_kind`` ∈ ``{manual, execution, reboot, probe,
  external}`` so future PRA-171 / PRA-172 writers can attach signals
  via the same path without an FK to tables that don't exist yet.

ORM ``__table_args__`` mirrors every constraint and index in this
migration (slice 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra162_gate_definitions_signals"
down_revision: Union[str, None] = "pra162_policy_ring_bindings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


GATE_KINDS = ("boolean", "threshold")
COMPARATORS = ("eq", "ne", "gt", "gte", "lt", "lte")
SIGNAL_STATUSES = ("pass", "fail")
SOURCE_KINDS = ("manual", "execution", "reboot", "probe", "external")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.create_table(
        "patch_ring_gate_definitions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "ring_id",
            sa.Integer,
            sa.ForeignKey("patch_rings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("signal_key", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("gate_kind", sa.String(32), nullable=False),
        sa.Column("comparator", sa.String(8), nullable=True),
        sa.Column("parameters", postgresql.JSONB, nullable=True),
        sa.Column(
            "required",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
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
            "ring_id",
            "signal_key",
            name="uq_patch_ring_gate_definitions_ring_signal_key",
        ),
        sa.CheckConstraint(
            _check_in("gate_kind", GATE_KINDS),
            name="patch_ring_gate_definitions_gate_kind_vocab",
        ),
        sa.CheckConstraint(
            f"comparator IS NULL OR {_check_in('comparator', COMPARATORS)}",
            name="patch_ring_gate_definitions_comparator_vocab",
        ),
    )
    op.create_index(
        "ix_patch_ring_gate_definitions_ring",
        "patch_ring_gate_definitions",
        ["ring_id"],
    )
    op.create_index(
        "ix_patch_ring_gate_definitions_ring_enabled",
        "patch_ring_gate_definitions",
        ["ring_id", "enabled"],
    )

    op.create_table(
        "patch_ring_gate_signals",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "ring_id",
            sa.Integer,
            sa.ForeignKey("patch_rings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "gate_definition_id",
            sa.Integer,
            sa.ForeignKey("patch_ring_gate_definitions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("signal_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("value", postgresql.JSONB, nullable=True),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_ref_kind", sa.String(64), nullable=True),
        sa.Column("source_ref_id", sa.String(128), nullable=True),
        sa.Column(
            "observed_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
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
        sa.CheckConstraint(
            _check_in("status", SIGNAL_STATUSES),
            name="patch_ring_gate_signals_status_vocab",
        ),
        sa.CheckConstraint(
            _check_in("source_kind", SOURCE_KINDS),
            name="patch_ring_gate_signals_source_kind_vocab",
        ),
    )
    # Latest-non-expired lookup driver: (ring_id, signal_key,
    # observed_at DESC). Postgres builds the index in the requested
    # order, and the planner can read it backwards/forwards.
    op.create_index(
        "ix_patch_ring_gate_signals_ring_signal_observed",
        "patch_ring_gate_signals",
        ["ring_id", "signal_key", sa.text("observed_at DESC")],
    )
    op.create_index(
        "ix_patch_ring_gate_signals_definition",
        "patch_ring_gate_signals",
        ["gate_definition_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_ring_gate_signals_definition",
        table_name="patch_ring_gate_signals",
    )
    op.drop_index(
        "ix_patch_ring_gate_signals_ring_signal_observed",
        table_name="patch_ring_gate_signals",
    )
    op.drop_table("patch_ring_gate_signals")
    op.drop_index(
        "ix_patch_ring_gate_definitions_ring_enabled",
        table_name="patch_ring_gate_definitions",
    )
    op.drop_index(
        "ix_patch_ring_gate_definitions_ring",
        table_name="patch_ring_gate_definitions",
    )
    op.drop_table("patch_ring_gate_definitions")
