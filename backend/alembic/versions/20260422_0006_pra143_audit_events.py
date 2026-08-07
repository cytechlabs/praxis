"""PRA-143: structured audit events + pluggable external sinks

Revision ID: pra143_audit
Revises: pra142_xferaudits
Create Date: 2026-04-22

Adds:
  - audit_events — stable versioned event ledger. Every security-relevant
    action in the app emits a row. Always persisted regardless of whether
    external sinks are configured.
  - audit_sinks — operator-configured external sinks (syslog / http / file).
  - audit_sink_deliveries — per-sink per-event delivery ledger with retry
    and status (pending / delivered / failed / dead_letter).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra143_audit"
down_revision: Union[str, None] = "pra142_xferaudits"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -------------------------------------------------------------- events
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        # Schema version — bumps only on breaking changes.
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("event_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column(
            "timestamp",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        # Dotted action vocab: session.open, command.exec, file.upload, etc.
        sa.Column("action", sa.String(64), nullable=False),
        # success | failure | denied
        sa.Column("outcome", sa.String(20), nullable=False, server_default="success"),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_username", sa.String(200), nullable=True),
        sa.Column("actor_ip", sa.String(64), nullable=True),
        sa.Column(
            "target_system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target_kind", sa.String(40), nullable=True),
        sa.Column("target_id", sa.String(200), nullable=True),
        # JSON blob — per-action shape documented in docs/audit-schema.md
        sa.Column("context_json", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index(
        "ix_audit_events_target_system_id", "audit_events", ["target_system_id"]
    )
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])
    op.create_index("ix_audit_events_outcome", "audit_events", ["outcome"])

    # --------------------------------------------------------------- sinks
    op.create_table(
        "audit_sinks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        # syslog | http | file
        sa.Column("kind", sa.String(20), nullable=False),
        # For http: target URL. For syslog: host:port. For file: path.
        sa.Column("target", sa.String(1024), nullable=False),
        # Optional HMAC secret (http sinks). Stored directly — sinks are
        # shared-with-operator infrastructure, not user secrets. Add vault
        # indirection later if customers push back.
        sa.Column("hmac_secret", sa.String(256), nullable=True),
        # Transport-specific config JSON (syslog facility, http headers, ...)
        sa.Column("config_json", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ----------------------------------------------------- sink deliveries
    op.create_table(
        "audit_sink_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "sink_id",
            sa.Integer(),
            sa.ForeignKey("audit_sinks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.Integer(),
            sa.ForeignKey("audit_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # pending | delivered | failed | dead_letter
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_audit_sink_deliveries_sink_id", "audit_sink_deliveries", ["sink_id"]
    )
    op.create_index(
        "ix_audit_sink_deliveries_status", "audit_sink_deliveries", ["status"]
    )
    op.create_index(
        "ix_audit_sink_deliveries_next_attempt",
        "audit_sink_deliveries",
        ["next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_sink_deliveries_next_attempt", table_name="audit_sink_deliveries"
    )
    op.drop_index("ix_audit_sink_deliveries_status", table_name="audit_sink_deliveries")
    op.drop_index(
        "ix_audit_sink_deliveries_sink_id", table_name="audit_sink_deliveries"
    )
    op.drop_table("audit_sink_deliveries")
    op.drop_table("audit_sinks")
    op.drop_index("ix_audit_events_outcome", table_name="audit_events")
    op.drop_index("ix_audit_events_timestamp", table_name="audit_events")
    op.drop_index("ix_audit_events_target_system_id", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_user_id", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_table("audit_events")
