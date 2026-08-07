"""PRA-160 slice #1: airgap_bundles + airgap_imports tables.

Two history tables for the airgap export/import surface:

``airgap_bundles`` — exports built ON THIS Praxis instance.
``airgap_imports`` — bundles imported INTO this instance (slice #3
populates rows; slice #1 only creates the table so the schema is
landed when slice #3's importer arrives).

Locks (PRA-160 design conversation):
  * ``airgap_bundles.kind`` ∈ ``full | delta`` from day one. Slice #1
    only emits descriptor-only rows, but the kind column describes
    the eventual bundle semantics so we never carry a ``descriptor_only``
    kind that would have to migrate later.
  * ``airgap_bundles.status`` ∈ ``building | descriptor_ready | ok | failed``.
    Slice #1 transitions ``building → descriptor_ready`` after the
    descriptor JSON + signature land. Slice #2 picks up from
    ``descriptor_ready`` and transitions to ``ok`` after tar
    assembly + payload sha + bundle re-sign.
  * Naming lock: the path column is ``bundle_descriptor_path``, never
    ``manifest_json_path`` — "manifest" is reserved for mirror
    manifests throughout M15. The eventual tar path column (slice #2)
    will be ``bundle_path``, never ``payload_path``.
  * ``parent_bundle_id`` is set only for ``kind='delta'`` (single
    parent in v1 — no multi-parent merges).
  * Planner-validation refusals do NOT create a row; they emit
    ``airgap_export_refused`` audit only. A row exists iff the
    planner accepted the request.
  * ``airgap_imports`` columns are forward-declared. Slice #1 ships
    the table; slice #3's importer is the only writer. ``imported_at``
    nullable so a future "in-progress" tracking row could be added
    without a column add — but the v1 importer writes the row only
    after a successful import (``status='ok'``) so v1 rows are always
    fully populated.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra160_airgap_bundles"
down_revision: Union[str, None] = "pra160_airgap_signing_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "airgap_bundles",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        # Public bundle identifier (UUID stringified; importer keys off
        # this, not the row id).
        sa.Column("bundle_id", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column(
            "parent_bundle_id",
            sa.String(64),
            nullable=True,
        ),
        sa.Column("status", sa.String(24), nullable=False),
        # Descriptor path is set as soon as the descriptor lands on
        # disk in slice #1; nullable so the brief ``building`` window
        # before the descriptor is signed has a sane state.
        sa.Column("bundle_descriptor_path", sa.String(512), nullable=True),
        # Slice #2 fills these in. Carved here so slice #2 doesn't
        # need a second column-add migration.
        sa.Column("bundle_path", sa.String(512), nullable=True),
        sa.Column("payload_sha256", sa.String(64), nullable=True),
        sa.Column("byte_count", sa.BigInteger, nullable=True),
        sa.Column(
            "signing_key_id",
            sa.Integer,
            sa.ForeignKey("airgap_bundle_signing_keys.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # Snapshot of operator-supplied request shape so an admin can
        # answer "what did this bundle ask for?" months later. Stored
        # as JSON-text (the full request including profile slugs,
        # snapshot selector, mirror-run overrides). Reasonable for
        # audit; not a query target.
        sa.Column("request_payload", sa.Text, nullable=True),
        sa.Column("error_text", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("finished_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("bundle_id", name="airgap_bundles_bundle_id_unique"),
        sa.CheckConstraint(
            "kind IN ('full', 'delta')",
            name="airgap_bundles_kind_valid",
        ),
        sa.CheckConstraint(
            "status IN ('building', 'descriptor_ready', 'ok', 'failed')",
            name="airgap_bundles_status_valid",
        ),
        sa.CheckConstraint(
            # full bundles never have a parent; delta bundles MUST
            # have one. DB-enforced so a swapped insert can't bypass
            # the rule even if the service skips its check.
            "(kind = 'full' AND parent_bundle_id IS NULL) "
            "OR (kind = 'delta' AND parent_bundle_id IS NOT NULL)",
            name="airgap_bundles_parent_matches_kind",
        ),
    )
    op.create_index(
        "ix_airgap_bundles_status_created",
        "airgap_bundles",
        ["status", "created_at"],
    )

    op.create_table(
        "airgap_imports",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("bundle_id", sa.String(64), nullable=False),
        sa.Column(
            "parent_bundle_id",
            sa.String(64),
            nullable=True,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=True),
        sa.Column("byte_count", sa.BigInteger, nullable=True),
        sa.Column("error_text", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("finished_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("bundle_id", name="airgap_imports_bundle_id_unique"),
        sa.CheckConstraint(
            "kind IN ('full', 'delta')",
            name="airgap_imports_kind_valid",
        ),
        sa.CheckConstraint(
            "status IN ('verifying', 'extracting', 'ok', 'failed')",
            name="airgap_imports_status_valid",
        ),
    )


def downgrade() -> None:
    op.drop_table("airgap_imports")
    op.drop_index(
        "ix_airgap_bundles_status_created",
        table_name="airgap_bundles",
    )
    op.drop_table("airgap_bundles")
