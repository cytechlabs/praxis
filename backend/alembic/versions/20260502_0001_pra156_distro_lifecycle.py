"""PRA-156 slice #3a: distro_lifecycle reference table.

Static end-of-life data keyed by ``(distro_id, release, support_kind)``.
Lookup is by the host-reported strings populated in PRA-155
(``host_facts.distro_id_facts``, ``host_facts.distro_release``) — NOT by
``systems.distro_id``, which is registration-time and may be stale.
Host facts are the fresh transport-neutral truth.

Why per-row ``support_kind``: a release like Ubuntu 22.04 has both a
standard EOL (2027) and an ESM EOL (2032). The override behavior that
consults non-standard rows lands in PRA-156 #3e via
``distro_lifecycle_override``. In #3a, ``LifecycleService.compute``
only consumes ``support_kind='standard'`` rows — ESM/extended rows are
seeded for #3e to consume later.

Seed source: ``backend/app/db/seed_data/distro_lifecycle.json``. The
migration loads that file at upgrade time so the migration data and
the operator-facing update path (``scripts/update-eol-data.py``) share
a single source of truth — no hand-maintained Python literal that can
drift from the JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra156_distro_lifecycle"
down_revision: Union[str, None] = "pra155_host_facts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Resolve the seed JSON relative to this migration so it works in any
# working directory. ``parents[2]`` walks versions/ → alembic/ →
# backend/, then we descend into app/db/seed_data.
_SEED_PATH = (
    Path(__file__).resolve().parents[2]
    / "app"
    / "db"
    / "seed_data"
    / "distro_lifecycle.json"
)


def _load_seed_entries() -> list[dict]:
    """Load and validate the seed JSON.

    Strict on shape: a missing or malformed seed file should fail the
    install loudly rather than ship an empty lifecycle table that
    silently makes every host ``unknown``.
    """
    with _SEED_PATH.open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RuntimeError(
            f"distro_lifecycle seed at {_SEED_PATH} has no 'entries' list"
        )
    required = ("distro_id", "release", "eol_date", "support_kind", "source", "as_of")
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RuntimeError(f"seed entry {idx} is not an object")
        missing = [k for k in required if k not in entry]
        if missing:
            raise RuntimeError(
                f"seed entry {idx} missing required keys: {','.join(missing)}"
            )
        if entry["support_kind"] not in {"standard", "esm", "extended"}:
            raise RuntimeError(
                f"seed entry {idx} has invalid support_kind={entry['support_kind']!r}"
            )
    return entries


def upgrade() -> None:
    op.create_table(
        "distro_lifecycle",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("distro_id", sa.String(64), nullable=False),
        sa.Column("release", sa.String(64), nullable=False),
        sa.Column("eol_date", sa.Date, nullable=False),
        sa.Column("support_kind", sa.String(16), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("as_of", sa.Date, nullable=False),
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
        sa.UniqueConstraint(
            "distro_id",
            "release",
            "support_kind",
            name="distro_lifecycle_unique_per_kind",
        ),
        sa.CheckConstraint(
            "support_kind IN ('standard', 'esm', 'extended')",
            name="distro_lifecycle_support_kind_valid",
        ),
    )
    # Lookup hot path is (distro_id, release) — every LifecycleService
    # call hits it. Index covers both the common standard-only lookup
    # and the future ESM/extended override lookup in #3e.
    op.create_index(
        "ix_distro_lifecycle_distro_release",
        "distro_lifecycle",
        ["distro_id", "release"],
    )

    entries = _load_seed_entries()
    distro_lifecycle = sa.table(
        "distro_lifecycle",
        sa.column("distro_id", sa.String),
        sa.column("release", sa.String),
        sa.column("eol_date", sa.Date),
        sa.column("support_kind", sa.String),
        sa.column("source", sa.String),
        sa.column("as_of", sa.Date),
    )
    op.bulk_insert(distro_lifecycle, entries)


def downgrade() -> None:
    op.drop_index("ix_distro_lifecycle_distro_release", table_name="distro_lifecycle")
    op.drop_table("distro_lifecycle")
