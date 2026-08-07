"""PRA-178 Slice 2 — durable report-run record (+ Slice 5 schedules).

A ``ReportRun`` row captures one execution of a report/export. Slice 2
only persists rows triggered by the Slice 1 manual export routes
(``triggered_by='user'``); later PRA-178 slices that add a scheduler
will reuse the same row shape by writing ``triggered_by='system_scheduled'``
without another schema migration.

Locks (mirror the matching alembic migration):

* ``report_kind`` / ``triggered_by`` / ``state`` / ``format`` vocabularies
  are enforced at the DB layer via CHECK constraints; the service
  module exposes the same string constants so callers stay in sync.
* ``filters_snapshot`` is JSONB; the service layer is responsible for
  bounding/sanitizing what gets written. Operator-supplied filters
  only — no headers, tokens, cookies, or session blobs.
* ``triggered_by_user_id`` is ``ON DELETE SET NULL`` so removing the
  actor's user row preserves the report-run history; the actor's
  username is snapshotted in ``triggered_by_username`` at write time.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from .base import Base


class ReportRun(Base):  # pylint: disable=too-few-public-methods
    """Durable record of one report/export run (PRA-178 Slice 2).

    Slice 2 persists one row per successful (or failed) manual export
    triggered by the Slice 1 export routes. ``state='started'`` is
    reserved for future long-running exports that need to record a
    durable row before completion.

    The row is intentionally additive to the Slice 1 ``*_export.requested``
    audit events — both are written for the same export so an external
    auditor can correlate a request id (in the audit event) with the
    persisted report-run lineage. The audit event is the wire-format
    contract; the report-run row is the local lookup surface.
    """

    __tablename__ = "report_runs"

    # Explicit id column so the ORM does not inherit the index=True
    # attribute from Base (the migration defines the PK index name).
    id = Column(Integer, primary_key=True, autoincrement=True)

    report_kind = Column(String(64), nullable=False)
    triggered_by = Column(String(32), nullable=False, server_default="user")
    triggered_by_user_id = Column(
        Integer,
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )
    triggered_by_username = Column(String(255), nullable=True)
    format = Column(String(16), nullable=True)
    filters_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    row_count = Column(Integer, nullable=True)
    state = Column(String(16), nullable=False, server_default="started")
    error_message = Column(String(2048), nullable=True)

    started_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )
    completed_at = Column(DateTime, nullable=True)

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )

    triggered_by_user = relationship("User", foreign_keys=[triggered_by_user_id])

    __table_args__ = (
        CheckConstraint(
            "report_kind IN ("
            "'patch_executions', "
            "'compliance_remediation_requests', "
            "'compliance_evidence', "
            "'patch_update_plans', "
            "'patch_reboot_queues', "
            "'patch_rollback_runs', "
            "'compliance_remediation_plans', "
            "'compliance_remediation_executions', "
            "'package_outdated', "
            "'package_compliance'"
            ")",
            name="report_runs_report_kind_vocab",
        ),
        CheckConstraint(
            "triggered_by IN ('user', 'system_scheduled')",
            name="report_runs_triggered_by_vocab",
        ),
        CheckConstraint(
            "state IN ('started', 'succeeded', 'failed')",
            name="report_runs_state_vocab",
        ),
        CheckConstraint(
            "format IS NULL OR format IN ('csv', 'json', 'jsonl')",
            name="report_runs_format_vocab",
        ),
        CheckConstraint(
            "row_count IS NULL OR row_count >= 0",
            name="report_runs_row_count_nonneg",
        ),
        Index(
            "ix_report_runs_kind_started_at",
            "report_kind",
            "started_at",
        ),
        Index("ix_report_runs_state", "state"),
        Index("ix_report_runs_triggered_by", "triggered_by"),
    )


class ReportSchedule(Base):  # pylint: disable=too-few-public-methods
    """PRA-178 Slice 5: durable recurring report definition.

    Operators define a recurring schedule (``daily`` / ``weekly`` /
    ``monthly``) for one of the supported export ``report_kind``s.
    The scheduler tick claims schedules whose ``next_run_at`` is in
    the past, fires the underlying export through the Slice 1/4
    service, persists a ``ReportRun`` row with
    ``triggered_by='system_scheduled'``, and advances
    ``next_run_at`` to the next cadence increment.

    Locks (mirror the matching alembic migration):

    * ``cadence`` is plain-language only (``daily`` / ``weekly`` /
      ``monthly``) per ``feedback_no_cron.md``.
    * ``filters_snapshot`` is JSONB; bounded + JSON-validated at
      the service layer (same shape as ``ReportRun.filters_snapshot``).
    * ``next_run_at`` is the claim anchor. NULL effectively
      disables the schedule.
    * ``created_by`` is ``ON DELETE SET NULL``.
    """

    __tablename__ = "report_schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)

    name = Column(String(128), nullable=False)
    report_kind = Column(String(64), nullable=False)
    cadence = Column(String(16), nullable=False)
    filters_snapshot = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    format = Column(String(16), nullable=False, server_default="csv")
    enabled = Column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    next_run_at = Column(DateTime, nullable=True)
    last_run_at = Column(DateTime, nullable=True)
    last_run_id = Column(Integer, nullable=True)
    last_run_state = Column(String(16), nullable=True)

    created_by = Column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )

    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        CheckConstraint(
            "report_kind IN ("
            "'patch_executions', "
            "'compliance_remediation_requests', "
            "'compliance_evidence', "
            "'patch_update_plans', "
            "'patch_reboot_queues', "
            "'patch_rollback_runs', "
            "'compliance_remediation_plans', "
            "'compliance_remediation_executions', "
            "'package_outdated', "
            "'package_compliance'"
            ")",
            name="report_schedules_report_kind_vocab",
        ),
        CheckConstraint(
            "cadence IN ('daily', 'weekly', 'monthly')",
            name="report_schedules_cadence_vocab",
        ),
        CheckConstraint(
            "format IN ('csv', 'json')",
            name="report_schedules_format_vocab",
        ),
        CheckConstraint(
            "last_run_state IS NULL OR last_run_state IN "
            "('started', 'succeeded', 'failed')",
            name="report_schedules_last_run_state_vocab",
        ),
        Index("ix_report_schedules_next_run_at", "next_run_at"),
        Index("ix_report_schedules_enabled", "enabled"),
        Index("ix_report_schedules_report_kind", "report_kind"),
    )
