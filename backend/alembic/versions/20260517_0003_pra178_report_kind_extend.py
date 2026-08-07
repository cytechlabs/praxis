"""PRA-178 slice 4: extend report_runs.report_kind CHECK vocabulary.

Adds 5 new ``report_kind`` values for the broader Slice 4 export
classes (patch update plans, patch reboot queues, patch rollback
runs, compliance remediation plans, compliance remediation execution
attempts). Strictly additive — existing rows and writers keep
working.

The Slice 2 migration introduced the CHECK constraint with three
values (``patch_executions``, ``compliance_remediation_requests``,
``compliance_evidence``); this migration drops + recreates the
CHECK so the new values are accepted at the DB layer too. The model
keeps the same union; the service module exposes constants for the
new values.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra178_report_kind_extend"
down_revision: Union[str, None] = "pra178_report_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("report_runs_report_kind_vocab", "report_runs", type_="check")
    op.create_check_constraint(
        "report_runs_report_kind_vocab",
        "report_runs",
        "report_kind IN ("
        "'patch_executions', "
        "'compliance_remediation_requests', "
        "'compliance_evidence', "
        "'patch_update_plans', "
        "'patch_reboot_queues', "
        "'patch_rollback_runs', "
        "'compliance_remediation_plans', "
        "'compliance_remediation_executions'"
        ")",
    )


def downgrade() -> None:
    op.drop_constraint("report_runs_report_kind_vocab", "report_runs", type_="check")
    op.create_check_constraint(
        "report_runs_report_kind_vocab",
        "report_runs",
        "report_kind IN ("
        "'patch_executions', "
        "'compliance_remediation_requests', "
        "'compliance_evidence'"
        ")",
    )
