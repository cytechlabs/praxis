"""PRA-282: lock the Praxis 1.0 privilege baseline (remove standing user sudo).

Praxis 1.0 ships no standing user-facing privileged escalation. This migration
corrects the launch-incompatible data that the PRA-137 seed shipped:

* the built-in ``admin`` and ``maintainer`` fleet roles were seeded with
  ``ALL=(ALL) NOPASSWD:ALL`` (and ``admin`` with the ``wheel``/``sudo`` OS
  groups). Every fleet role's raw ``sudoers_snippet`` is cleared and every
  privileged OS group (``wheel``/``sudo``/``root``/``admin``) is stripped from
  every role — built-in and custom alike. Raw sudoers text is NOT preserved as
  dormant product config; the pre-upgrade DB backup is the forensic recovery path.

Clearing the database is not enough: any ``/etc/sudoers.d/praxis-<login>`` drop-in
already deployed to a host must be removed by reconciliation. A new
``host_user_states.privilege_reconcile_pending`` marker is added and set on every
live account so the reconcile path removes the on-host drop-in (a failed reconcile
leaves the marker set and the row ``error`` until it succeeds). The PRA-285
reconcile scheduler consumes this marker; the fleet reconciliation service exposes
a bounded interim drain (``reconcile_pending_privilege``) in the meantime.

The data-repair logic lives in ``app.services.privilege_baseline_service`` so it is
shared with the unit tests. ``downgrade`` drops the marker column but does NOT
restore cleared sudoers text (that is intentional — the old posture is
launch-incompatible; restore from a pre-upgrade backup if truly required).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra282_privilege_baseline"
down_revision: Union[str, None] = "pra225_mirror_serve_token_id"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "host_user_states",
        sa.Column(
            "privilege_reconcile_pending",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    # Correct stored fleet-access data + flag live host accounts for on-host
    # sudoers drop-in removal. Imported lazily so the migration module stays cheap
    # to import; the service only depends on json + sqlalchemy.
    from app.services.privilege_baseline_service import enforce_privilege_baseline

    enforce_privilege_baseline(op.get_bind())


def downgrade() -> None:
    # NB: cleared sudoers snippets and stripped privileged groups are NOT restored
    # (the old ALL=(ALL) NOPASSWD:ALL posture is launch-incompatible). Restore from
    # a pre-upgrade database backup if the prior policy text is genuinely required.
    op.drop_column("host_user_states", "privilege_reconcile_pending")
