"""PRA-160 slice #1: extend mirror_sync_runs.run_kind to include 'import'.

PRA-158 #2a introduced the ``run_kind`` column with values
``sync | sign_only``. PRA-160's importer (slice #3) creates one
``mirror_sync_runs`` row per imported mirror to record the imported
manifest sha256 + byte count + manifest path on the airgap side. That
row's ``run_kind`` is ``import``.

Locks (PRA-160 design conversation):
  * Imported runs are created in a single transaction with
    ``status='ok'`` directly. They never pass through ``running`` and
    are never scheduler-owned (the scheduler skips
    ``source_mode='imported_offline'`` mirrors entirely; the
    constraint extension here is a belt to that suspenders).
  * The check constraint is dropped + recreated to add ``import`` —
    Postgres CHECK constraints aren't editable in place. The
    ORM ``__table_args__`` mirror update lands in the same slice #1
    commit so ``Base.metadata.create_all`` (used by some test fixtures)
    matches.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra160_run_kind_import"
down_revision: Union[str, None] = "pra160_airgap_bundles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "mirror_sync_runs_run_kind_valid",
        "mirror_sync_runs",
        type_="check",
    )
    op.create_check_constraint(
        "mirror_sync_runs_run_kind_valid",
        "mirror_sync_runs",
        "run_kind IN ('sync', 'sign_only', 'import')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "mirror_sync_runs_run_kind_valid",
        "mirror_sync_runs",
        type_="check",
    )
    op.create_check_constraint(
        "mirror_sync_runs_run_kind_valid",
        "mirror_sync_runs",
        "run_kind IN ('sync', 'sign_only')",
    )
