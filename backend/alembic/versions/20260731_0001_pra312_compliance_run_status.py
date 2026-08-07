"""PRA-312: persist compliance policy last-run outcome for operator visibility.

Adds a nullable ``compliance_policies.last_run_status`` ('success' | 'error').
``last_run_at`` already records WHEN a policy last evaluated successfully, but there
was no signal for WHETHER the most recent run succeeded or errored — so the operator
UI could not distinguish a clean run from a failed one, only "never run" vs "ran".

Additive + nullable: existing rows get NULL (never-run / pre-existing), which the UI
reads as "not yet evaluated". No backfill, no behavior change to eligibility or
evidence retention.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra312_run_status"
down_revision: Union[str, None] = "pra287_rec_retention"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_policies",
        sa.Column("last_run_status", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("compliance_policies", "last_run_status")
