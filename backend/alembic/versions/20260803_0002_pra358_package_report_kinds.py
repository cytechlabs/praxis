"""PRA-358: extend report_kind CHECK vocab with package posture reports.

Adds two ``report_kind`` values — ``package_outdated`` and ``package_compliance``
— to both ``report_runs.report_kind_vocab`` and
``report_schedules.report_kind_vocab`` so Package Reports exports/schedules are
first-class in the report-kind contract. Strictly additive; existing rows and
writers keep working.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra358_package_report_kinds"
down_revision: Union[str, None] = "pra355_plan_archive"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_KINDS_8 = (
    "'patch_executions', "
    "'compliance_remediation_requests', "
    "'compliance_evidence', "
    "'patch_update_plans', "
    "'patch_reboot_queues', "
    "'patch_rollback_runs', "
    "'compliance_remediation_plans', "
    "'compliance_remediation_executions'"
)
_KINDS_10 = _KINDS_8 + ", 'package_outdated', 'package_compliance'"


def _set_vocab(table: str, constraint: str, kinds: str) -> None:
    op.drop_constraint(constraint, table, type_="check")
    op.create_check_constraint(
        constraint,
        table,
        f"report_kind IN ({kinds})",
    )


def upgrade() -> None:
    _set_vocab("report_runs", "report_runs_report_kind_vocab", _KINDS_10)
    _set_vocab("report_schedules", "report_schedules_report_kind_vocab", _KINDS_10)


def downgrade() -> None:
    _set_vocab("report_runs", "report_runs_report_kind_vocab", _KINDS_8)
    _set_vocab("report_schedules", "report_schedules_report_kind_vocab", _KINDS_8)
