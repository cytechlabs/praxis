"""PRA-153 slice #2: durable transport columns on audit ledgers.

Verifies the migration created the column on each target table and
the SQLAlchemy models declare it. Population semantics (when each
row should be ``"ssh"`` vs ``"agent"``) are covered by slice #3
when the audit emitters get wired through the transport factory.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine, inspect

from app.db.access_models import FileTransferAudit
from app.db.access_models import Session as SessionRow
from app.db.command_execution_models import CommandExecutionResult


def _columns(table: str) -> dict:
    engine = create_engine(os.environ["DATABASE_URL"])
    return {c["name"]: c for c in inspect(engine).get_columns(table)}


def test_sessions_has_nullable_transport_varchar8():
    cols = _columns("sessions")
    assert "transport" in cols, "PRA-153 migration did not add sessions.transport"
    col = cols["transport"]
    assert col["nullable"] is True
    # SQLAlchemy reports the type as VARCHAR(8) regardless of dialect.
    assert "VARCHAR(8)" in str(col["type"]).upper()


def test_file_transfer_audits_has_nullable_transport_varchar8():
    cols = _columns("file_transfer_audits")
    assert "transport" in cols
    assert cols["transport"]["nullable"] is True
    assert "VARCHAR(8)" in str(cols["transport"]["type"]).upper()


def test_command_execution_results_has_nullable_transport_varchar8():
    cols = _columns("command_execution_results")
    assert "transport" in cols
    assert cols["transport"]["nullable"] is True
    assert "VARCHAR(8)" in str(cols["transport"]["type"]).upper()


def test_session_model_declares_transport():
    assert "transport" in SessionRow.__table__.columns


def test_file_transfer_audit_model_declares_transport():
    assert "transport" in FileTransferAudit.__table__.columns


def test_command_execution_result_model_declares_transport():
    assert "transport" in CommandExecutionResult.__table__.columns
