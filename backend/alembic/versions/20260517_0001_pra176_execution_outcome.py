"""PRA-176 slice 2: execution-attempt outcome columns.

Adds bounded outcome columns to ``compliance_remediation_execution_attempts``
so the Slice 2 dispatch path can persist the package-manager command's
exit code, wall-clock duration, and a bounded stdout/stderr summary on
the same attempt row. Slice 1 reserved ``transport``,
``failure_reason``, ``error_message``, ``dispatched_at``, and
``completed_at``; this slice adds the four remaining fields.

Locks (PRA-176 Slice 2):

* All four columns are nullable so pre-existing Slice 1 ``pending``
  attempt rows (never dispatched) keep validating.
* ``stdout_summary`` and ``stderr_summary`` are ``Text`` (Postgres
  unbounded), but the service layer truncates writes to
  ``MAX_OUTPUT_BYTES = 64 KiB`` per field — mirrors the PRA-171
  dispatch outcome bound. Using ``Text`` instead of a bounded varchar
  avoids a future migration if the bound grows.
* ``exit_code`` is a plain ``Integer`` (can be negative for the
  transport-unavailable / transport-error structured codes that
  PRA-171 records as ``-1``).
* ``duration_ms`` is a plain ``Integer``; values are always >= 0.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra176_execution_outcome"
down_revision: Union[str, None] = "pra176_execution_attempts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_remediation_execution_attempts",
        sa.Column("exit_code", sa.Integer, nullable=True),
    )
    op.add_column(
        "compliance_remediation_execution_attempts",
        sa.Column("duration_ms", sa.Integer, nullable=True),
    )
    op.add_column(
        "compliance_remediation_execution_attempts",
        sa.Column("stdout_summary", sa.Text, nullable=True),
    )
    op.add_column(
        "compliance_remediation_execution_attempts",
        sa.Column("stderr_summary", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("compliance_remediation_execution_attempts", "stderr_summary")
    op.drop_column("compliance_remediation_execution_attempts", "stdout_summary")
    op.drop_column("compliance_remediation_execution_attempts", "duration_ms")
    op.drop_column("compliance_remediation_execution_attempts", "exit_code")
