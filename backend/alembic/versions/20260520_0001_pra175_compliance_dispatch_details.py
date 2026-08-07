"""PRA-175 Slice 3: compliance remediation attempt dispatch_details column.

Adds a single nullable=False JSONB ``dispatch_details`` column to
``compliance_remediation_execution_attempts`` so the compliance
dispatch path can persist the post-sudo-wrap effective argv
alongside the planned/raw argv, matching the JSONB evidence pattern
the patch-update / rollback / reboot surfaces already use.

Locks (PRA-175 Slice 3):

* The column is JSONB with ``server_default = '{}'::jsonb`` so the
  ADD COLUMN succeeds against existing pre-Slice-3 rows without a
  data backfill. ``nullable=False`` matches the
  ``patch_update_execution_reboots.dispatch_details`` pattern;
  applications never have to handle ``None``.
* The service layer is the only writer. Slice 3 records
  ``planned_argv`` (the argv the dispatcher built — same shape as
  the existing ``patch_update_execution_host.error_details.command``
  evidence) and ``effective_argv`` (the post-``wrap_argv_for_sudo``
  argv) plus ``transport`` and ``recorded_at``. The sudo password
  and stdin payload are NEVER persisted here.
* No CHECK constraint on the JSONB body. Operators/auditors can read
  the column directly without unpacking a schema; adding a CHECK
  would force every future evidence field into a migration. The
  pattern matches ``patch_update_execution_reboots.dispatch_details``
  / ``patch_update_execution_hosts.error_details``.

Why a migration (vs. crammed-into-Text): the Slice 3 spec
explicitly names ``ComplianceRemediationExecutionAttempt.dispatch_details``
and the other three PRA-175 surfaces already use JSONB columns of
the same name; an ad-hoc Text encoding would lose structured
queryability and diverge from the established pattern.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra175_compliance_dispatch"
down_revision: Union[str, None] = "pra169_scheduler_job_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_remediation_execution_attempts",
        sa.Column(
            "dispatch_details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("compliance_remediation_execution_attempts", "dispatch_details")
